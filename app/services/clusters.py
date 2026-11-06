"""Cluster enrollment, setup script rendering and node rule assembly."""
import ipaddress, re, secrets, shlex
from datetime import timedelta
from pathlib import Path
from jinja2 import Environment, FileSystemLoader, StrictUndefined
from app.models import ClusterIP, FirewallRule, Image, Machine, utcnow
from app.security import decrypt_node_key, digest_token
from app.services.machines import guest_gateway
from app.services.network import GUEST_BRIDGE, render_nat_rules, valid_interface

# Shipped inside the package so a normal (non-editable) install can render it.
NODE_DIR = Path(__file__).resolve().parents[1] / "node"


class Shell(str):
    """Text already made safe for its position in the shell script (quoted or heredoc body)."""


_SAFE_TOKEN = re.compile(r"^[A-Za-z0-9_.:/-]*$")


def _finalize(value):
    """Every {{ }} in the setup script must be a quoted value, a heredoc body, an integer or
    a plain token (IP, interface, netmask). Anything else aborts rendering, so a value
    that was not explicitly quoted can never reach the root shell."""
    if isinstance(value, Shell) or (isinstance(value, int) and not isinstance(value, bool)):
        return value
    text = str(value)
    if _SAFE_TOKEN.fullmatch(text):
        return text
    raise ValueError("Unquoted value in node setup script")


def heredoc(text: str, terminator: str) -> Shell:
    if any(line.strip() == terminator for line in text.splitlines()):
        raise ValueError("Heredoc body contains its terminator")
    return Shell(text)


# Shell output, not HTML, so HTML autoescaping does not apply; _finalize enforces shell
# safety for every interpolation instead.
_env = Environment(loader=FileSystemLoader(str(NODE_DIR)), autoescape=False, undefined=StrictUndefined, keep_trailing_newline=True, finalize=_finalize)  # nosec B701 - shell script, see _finalize  # noqa: S701 - shell template; _finalize gates every value
_env.filters["q"] = lambda value: Shell(shlex.quote(str(value)))

PRIVATE_GUEST_RANGES = tuple(ipaddress.ip_network(n) for n in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"))


def validate_cluster(node_ipv4: str, ssh_port: int, guest_subnet: str, uplink_interface: str):
    try:
        node = ipaddress.ip_address(node_ipv4); subnet = ipaddress.ip_network(guest_subnet, strict=False)
    except ValueError as exc:
        raise ValueError("Enter a valid node IPv4 address and guest subnet") from exc
    if node.version != 4 or subnet.version != 4: raise ValueError("IPv4 is required")
    if node.is_loopback or node.is_multicast or node.is_unspecified or node.is_link_local: raise ValueError("Node IPv4 must be a routable unicast address")
    if not 1 <= ssh_port <= 65535: raise ValueError("Invalid SSH port")
    if not valid_interface(uplink_interface): raise ValueError("Invalid uplink interface")
    if subnet.prefixlen > 28: raise ValueError("Guest subnet is too small")
    if subnet.prefixlen < 16: raise ValueError("Guest subnet must be /16 or smaller")
    # Guests live on a private bridge; a public range would hijack real internet routes.
    if not any(subnet.subnet_of(r) for r in PRIVATE_GUEST_RANGES): raise ValueError("Guest subnet must be a private (RFC 1918) range")
    node_net = ipaddress.ip_interface(f"{node_ipv4}/24").network
    if subnet.overlaps(node_net) or node in subnet: raise ValueError("Guest subnet must not overlap the node's own network")

def issue_setup_token(cluster):
    token = secrets.token_urlsafe(32)
    cluster.setup_token_hash = digest_token(token)
    cluster.setup_token_expires = utcnow() + timedelta(minutes=15)
    return token

def node_subnet(cluster) -> str:
    return str(ipaddress.ip_interface(cluster.node_ipv4 + "/24").network)

def secondary_private_ips(db, cluster) -> list[str]:
    rows = db.query(ClusterIP).filter(ClusterIP.cluster_id == cluster.id).order_by(ClusterIP.id).all()
    return [row.private_ipv4 for row in rows if row.private_ipv4 != cluster.node_ipv4]

def cluster_rules(db, cluster) -> str:
    addresses = db.query(ClusterIP).filter(ClusterIP.cluster_id == cluster.id).order_by(ClusterIP.id).all()
    firewall: dict[str, list] = {}
    rows = (db.query(ClusterIP.guest_ipv4, FirewallRule.protocol, FirewallRule.port)
            .join(Machine, Machine.id == ClusterIP.machine_id).join(FirewallRule, FirewallRule.machine_id == Machine.id)
            .filter(ClusterIP.cluster_id == cluster.id).all())
    for guest, protocol, port in rows:
        firewall.setdefault(guest, []).append((protocol, port))
    return render_nat_rules(addresses, cluster.guest_subnet, cluster.uplink_interface, firewall)

def render_setup_script(db, cluster) -> str:
    from app.services.libvirt import panel_public_key
    network = ipaddress.ip_network(cluster.guest_subnet, strict=False)
    images = db.query(Image).filter(Image.active.is_(True)).order_by(Image.id).all()
    return _env.get_template("setup.sh.j2").render(
        uplink=cluster.uplink_interface, bridge=GUEST_BRIDGE, node_prefix=24,
        private_ips=secondary_private_ips(db, cluster), rules=heredoc(cluster_rules(db, cluster), "RULES"),
        panel_key=panel_public_key(decrypt_node_key(cluster.ssh_key_encrypted)),
        gateway=guest_gateway(cluster.guest_subnet), guest_prefix=network.prefixlen, guest_netmask=str(network.netmask),
        images=[{"id": int(i.id), "kind": i.kind, "url": i.url, "sha": i.checksum} for i in images],
        node_service=heredoc((NODE_DIR / "kestrel-node.service").read_text(encoding="utf-8"), "UNIT"),
    )
