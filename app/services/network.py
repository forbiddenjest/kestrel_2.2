"""Validated cluster address pairs and node nftables rules."""
import ipaddress
import re
from fastapi import HTTPException

IFACE = re.compile(r"^[a-zA-Z0-9_.:-]{1,32}$")
GUEST_BRIDGE = "kbr0"
PROTOCOLS = {"tcp", "udp"}
# Destinations a guest must never reach. On Azure, 169.254.169.254 is the Instance
# Metadata Service (managed-identity tokens!) and 168.63.129.16 is the WireServer
# (host agent, DNS, health probes). The private ranges cover the VNet, peered VNets
# and on-prem routes, so a guest cannot pivot into the node's network.
BLOCKED_DESTINATIONS = ("169.254.0.0/16", "168.63.129.16/32", "10.0.0.0/8", "172.16.0.0/12",
                        "192.168.0.0/16", "100.64.0.0/10", "127.0.0.0/8", "224.0.0.0/4", "240.0.0.0/4")

def parse_ip_pairs(raw: str, node_subnet: str, node_ipv4: str) -> list[tuple[str, str]]:
    """node_ipv4 is the node's primary (SSH) address. It is never accepted in a pair:
    cluster_rules would DNAT it to a guest and cut off panel and operator SSH."""
    try:
        network = ipaddress.ip_network(node_subnet, strict=False)
        node_address = ipaddress.ip_address(node_ipv4)
    except ValueError as exc:
        raise HTTPException(422, "Invalid node address or subnet") from exc
    pairs, seen_priv, seen_pub = [], set(), set()
    if len(raw) > 64_000:
        raise HTTPException(422, "Too many IP pairs in one request")
    for number, line in enumerate(raw.splitlines(), 1):
        if not line.strip():
            continue
        pieces = line.strip("\r").split(",")
        if len(pieces) != 2 or any(part.strip() != part or not part for part in pieces):
            raise HTTPException(422, f"Invalid IP pair on line {number}")
        try:
            private, public = (ipaddress.ip_address(value) for value in pieces)
        except ValueError as exc:
            raise HTTPException(422, f"Invalid IPv4 address on line {number}") from exc
        if private.version != 4 or public.version != 4:
            raise HTTPException(422, "Only IPv4 addresses are supported")
        if private == node_address or public == node_address:
            raise HTTPException(422, f"Line {number} uses the node's own primary IP; it cannot be mapped to a guest")
        if private not in network:
            raise HTTPException(422, "Private IP must be inside the node subnet")
        if private in seen_priv or public in seen_pub:
            raise HTTPException(422, "Duplicate IP address")
        seen_priv.add(private); seen_pub.add(public); pairs.append((str(private), str(public)))
    if not pairs:
        raise HTTPException(422, "Add at least one private,public IP pair")
    return pairs

def valid_interface(name: str) -> bool:
    return bool(IFACE.fullmatch(name))

def validate_firewall_rule(protocol: str, port: int):
    if protocol not in PROTOCOLS or not 1 <= port <= 65535:
        raise HTTPException(422, "Use tcp or udp and a port between 1 and 65535")

def render_nat_rules(addresses, guest_subnet: str, interface: str, firewall: dict | None = None, bridge: str = GUEST_BRIDGE) -> str:
    """firewall maps guest IPv4 -> [(protocol, port)]; a guest with rules only accepts those inbound."""
    if not valid_interface(interface) or not valid_interface(bridge):
        raise ValueError("Invalid network interface")
    firewall = firewall or {}
    guest_network = ipaddress.ip_network(guest_subnet, strict=False)
    normalized = []
    for address in addresses:
        if hasattr(address, "private_ipv4"):
            private, guest = address.private_ipv4, address.guest_ipv4
        else:
            private, _public, guest = address
        private_ip, guest_ip = ipaddress.ip_address(private), ipaddress.ip_address(guest)
        if private_ip.version != 4 or guest_ip.version != 4 or guest_ip not in guest_network:
            raise ValueError("Address mapping does not match the configured IPv4 subnets")
        normalized.append((private_ip, guest_ip))
    blocked = ", ".join(BLOCKED_DESTINATIONS)
    lines = ["add table ip kestrel", "flush table ip kestrel", "table ip kestrel {",
             f" set blocked {{ type ipv4_addr; flags interval; elements = {{ {blocked} }} }}",
             # Guest -> node itself (gateway, node private IPs, WireServer-on-host paths).
             # Only replies to connections the node opened (console tunnel) get through.
             " chain input { type filter hook input priority filter; policy accept;",
             f"  iifname {bridge} ct state established,related accept",
             f"  iifname {bridge} icmp type echo-request limit rate 10/second accept",
             f"  iifname {bridge} drop",
             " }",
             " chain prerouting { type nat hook prerouting priority dstnat; policy accept;"]
    lines += [f"  ip daddr {private} dnat to {guest}" for private, guest in normalized]
    lines += [" }", " chain postrouting { type nat hook postrouting priority srcnat; policy accept;"]
    lines += [f"  ip saddr {guest} oifname {interface} snat to {private}" for private, guest in normalized]
    lines += [" }", " chain forward { type filter hook forward priority filter; policy drop;",
              # Isolation first, so even an existing conntrack entry cannot reach these.
              f"  iifname {bridge} ip daddr @blocked drop",
              f"  oifname {bridge} ip saddr @blocked drop",
              f"  iifname {bridge} ip saddr != {guest_network} drop",  # anti-spoofing
              "  ct state invalid drop",
              f"  ip saddr {guest_network} ip daddr {guest_network} drop",
              "  ct state established,related accept"]
    for _private, guest in normalized:
        rules = firewall.get(str(guest), [])
        inbound = f"  iifname {interface} oifname {bridge} ip daddr {guest}"
        if rules:
            lines.append(f"{inbound} icmp type echo-request accept")
            for protocol, port in sorted(set(rules)):
                if protocol not in PROTOCOLS or not 1 <= int(port) <= 65535:
                    raise ValueError("Invalid firewall rule")
                lines.append(f"{inbound} {protocol} dport {int(port)} accept")
        else:
            lines.append(f"{inbound} accept")
        lines.append(f"  iifname {bridge} oifname {interface} ip saddr {guest} accept")
    lines += [" }", "}",
              # Guests get no IPv6 at all: no route to the node or the VNet over link-local.
              "add table ip6 kestrel6", "flush table ip6 kestrel6", "table ip6 kestrel6 {",
              f" chain input {{ type filter hook input priority filter; policy accept; iifname {bridge} drop; }}",
              f" chain forward {{ type filter hook forward priority filter; policy accept; iifname {bridge} drop; oifname {bridge} drop; }}",
              "}"]
    return "\n".join(lines) + "\n"
