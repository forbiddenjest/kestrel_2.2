"""All libvirt and node-SSH access is confined to this service.

Every remote command is a fixed argv template; the only variable parts are values
validated here (vm names, integer image ids, IPv4 addresses, sizes).
"""
import asyncio, hashlib, ipaddress, json, logging, os, re, secrets, shlex, shutil, tempfile
from contextlib import contextmanager
from urllib.parse import urlencode
import asyncssh
import libvirt
from passlib.hash import sha512_crypt
from app.security import decrypt_node_key
from app.config import settings

log = logging.getLogger("kestrel.hypervisor")

class HypervisorError(RuntimeError): pass

VM_RE = re.compile(r"^vm[0-9]+$")
STATE_DIR = "/var/lib/kestrel"
STAGED_RULES = f"{STATE_DIR}/staged/rules.nft"
STAGED_IPS = f"{STATE_DIR}/staged/private_ips"
NETWORK_NAME = "kestrel"
RULES_APPLY_TIMEOUT = 30

def _vm(name: str) -> str:
    if not VM_RE.fullmatch(name or ""): raise HypervisorError("Invalid VM name")
    return name

def _machine_dir(vm_name: str) -> str: return f"{STATE_DIR}/machines/{_vm(vm_name)}"
def base_image_path(image_id: int) -> str: return f"{STATE_DIR}/images/{int(image_id)}.img"
def iso_path(image_id: int) -> str: return f"{STATE_DIR}/isos/{int(image_id)}.iso"
def _mac(vm_name: str) -> str:
    digest = hashlib.sha256(vm_name.encode()).digest()
    return "52:54:00:%02x:%02x:%02x" % (digest[0], digest[1], digest[2])

# ---------- node identity / connections ----------

def _known_hosts_line(cluster) -> str:
    if not cluster.node_host_key:
        raise HypervisorError("This node has no verified SSH host key")
    host_line = cluster.node_host_key.strip().split()
    if len(host_line) < 2:
        raise HypervisorError("Stored node host key is invalid")
    expected_name = f"[{cluster.node_ipv4}]:{cluster.ssh_port}" if cluster.ssh_port != 22 else cluster.node_ipv4
    return f"{expected_name} {host_line[-2]} {host_line[-1]}\n"

def _write_private(path: str, content: str):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as handle:
        handle.write(content)

@contextmanager
def _node_identity_files(cluster):
    """Per-call private copy of the node key and pinned host key.

    asyncssh never needs these (keys stay in memory). libvirt's SSH transports only
    accept file paths, so the decrypted key exists on disk for the duration of
    libvirt.open() only, in a fresh 0700 directory unique to this call, and is removed
    as soon as the connection is authenticated. Concurrent calls for different
    clusters therefore never share or overwrite a file.
    """
    known_hosts = _known_hosts_line(cluster)
    base = settings.runtime_dir or None
    directory = tempfile.mkdtemp(prefix=f"node{int(cluster.id)}-", dir=base)  # mode 0700
    try:
        key_path, hosts_path = os.path.join(directory, "key"), os.path.join(directory, "known_hosts")
        _write_private(key_path, decrypt_node_key(cluster.ssh_key_encrypted))
        _write_private(hosts_path, known_hosts)
        yield key_path, hosts_path
    finally:
        shutil.rmtree(directory, ignore_errors=True)

def panel_private_key(cluster):
    return asyncssh.import_private_key(decrypt_node_key(cluster.ssh_key_encrypted))

def panel_public_key(private_key_text: str) -> str:
    return asyncssh.import_private_key(private_key_text).export_public_key().decode().strip()

async def _node_connection(cluster):
    try:
        return await asyncssh.connect(cluster.node_ipv4, port=cluster.ssh_port, username="panel",
            client_keys=[panel_private_key(cluster)],
            known_hosts=asyncssh.import_known_hosts(_known_hosts_line(cluster)), connect_timeout=8)
    except HypervisorError: raise
    except Exception as exc:
        raise HypervisorError("Node connection failed") from exc

async def _run(connection, argv: list[str], timeout: int = 120):
    result = await connection.run(shlex.join(argv), check=False, timeout=timeout)
    if result.exit_status != 0:
        raise HypervisorError(f"Node command failed: {argv[0]}")
    return result.stdout or ""

async def _write(connection, path: str, content: str, mode: int = 0o600):
    async with connection.start_sftp_client() as sftp:
        async with sftp.open(path, "w") as handle:
            await handle.write(content)
        await sftp.chmod(path, mode)

def libvirt_uri(cluster, key_path: str, hosts_path: str) -> str:
    """qemu+libssh, not qemu+ssh: only the libssh/libssh2 transports honour known_hosts and
    known_hosts_verify. qemu+ssh shells out to the OS ssh binary, which ignores both and
    consults ~/.ssh/known_hosts instead. known_hosts_verify=normal refuses unknown or
    changed host keys; sshauth=privkey stops it falling back to agent/password prompts."""
    ipaddress.IPv4Address(cluster.node_ipv4)
    query = urlencode({"keyfile": key_path, "known_hosts": hosts_path, "known_hosts_verify": "normal", "sshauth": "privkey"})
    return f"qemu+libssh://panel@{cluster.node_ipv4}:{int(cluster.ssh_port)}/system?{query}"

def _connect(cluster):
    with _node_identity_files(cluster) as (key_path, hosts_path):
        try: return libvirt.open(libvirt_uri(cluster, key_path, hosts_path))
        except libvirt.libvirtError as exc: raise HypervisorError("Hypervisor connection failed") from exc

# ---------- power / status ----------

def _crashed(state: int, reason: int) -> bool:
    return state == getattr(libvirt, "VIR_DOMAIN_CRASHED", 6) or (state == getattr(libvirt, "VIR_DOMAIN_SHUTOFF", 5) and reason == getattr(libvirt, "VIR_DOMAIN_SHUTOFF_CRASHED", 3))

def power_action(cluster, vm_name: str, action: str):
    conn = _connect(cluster)
    try:
        domain = conn.lookupByName(_vm(vm_name))
        if action == "start": domain.create()
        elif action == "stop": domain.shutdown()
        elif action == "restart": domain.reboot(0)
        elif action == "force-stop": domain.destroy()
        else: raise HypervisorError("Unsupported machine action")
        # create() and destroy() are synchronous; shutdown() and reboot() only ask the
        # guest (ACPI) and return immediately, so report the transition and let the
        # reconcile loop confirm the final state.
        return {"start": "running", "force-stop": "stopped", "stop": "stopping", "restart": "restarting"}[action]
    except libvirt.libvirtError as exc: raise HypervisorError("Machine action failed") from exc
    finally: conn.close()

def domain_status(cluster, vm_name: str, conn=None):
    """Pass an open conn to reuse one libvirt connection for many domains."""
    own = conn is None
    conn = conn or _connect(cluster)
    try:
        state, reason = conn.lookupByName(_vm(vm_name)).state()[:2]
        if state == libvirt.VIR_DOMAIN_RUNNING: return "running"
        return "crashed" if _crashed(state, reason) else "stopped"
    except libvirt.libvirtError: return "unknown"
    finally:
        if own: conn.close()

def open_connection(cluster):
    """Public handle for callers that batch several domains on one node per cycle."""
    return _connect(cluster)

# ---------- domain definition ----------

def _kbytes_per_second(mbps) -> int:
    """libvirt <bandwidth> uses KiB/s-ish 'kilobytes per second'; 1 Mbps = 125 KB/s."""
    return max(0, int(mbps or 0)) * 125

def bandwidth_xml(spec: dict) -> str:
    """Per-port speed caps. inbound = traffic towards the guest, outbound = from the guest."""
    parts = []
    for direction, key in (("inbound", "speed_in_mbps"), ("outbound", "speed_out_mbps")):
        rate = _kbytes_per_second(spec.get(key))
        if rate:
            parts.append(f"<{direction} average='{rate}' peak='{rate}' burst='{max(1024, rate // 8)}'/>")
    return f"<bandwidth>{''.join(parts)}</bandwidth>" if parts else ""

def domain_xml(spec: dict) -> str:
    vm = _vm(spec["vm_name"]); directory = _machine_dir(vm)
    guest_ip = str(ipaddress.IPv4Address(spec["guest_ip"]))
    iso = spec.get("iso_image_id")
    boot_cdrom = spec.get("boot_device") == "cdrom" and iso
    iso_source = f"<source file='{iso_path(iso)}'/>" if iso else ""
    return f"""<domain type='kvm'>
  <name>{vm}</name>
  <memory unit='MiB'>{int(spec['memory_mb'])}</memory>
  <vcpu>{int(spec['vcpu'])}</vcpu>
  <os><type arch='x86_64' machine='q35'>hvm</type></os>
  <features><acpi/><apic/></features>
  <cpu mode='host-model'/>
  <on_poweroff>destroy</on_poweroff><on_reboot>restart</on_reboot><on_crash>destroy</on_crash>
  <devices>
    <disk type='file' device='disk'><driver name='qemu' type='qcow2' discard='unmap'/><source file='{directory}/disk.qcow2'/><target dev='vda' bus='virtio'/><boot order='{2 if boot_cdrom else 1}'/></disk>
    <disk type='file' device='cdrom'><driver name='qemu' type='raw'/><source file='{directory}/seed.iso'/><target dev='sda' bus='sata'/><readonly/></disk>
    <disk type='file' device='cdrom'><driver name='qemu' type='raw'/>{iso_source}<target dev='sdb' bus='sata'/><readonly/><boot order='{1 if boot_cdrom else 2}'/></disk>
    <interface type='network'><source network='{NETWORK_NAME}'/><mac address='{_mac(vm)}'/><model type='virtio'/><port isolated='yes'/>{bandwidth_xml(spec)}<filterref filter='clean-traffic'><parameter name='IP' value='{guest_ip}'/></filterref></interface>
    <channel type='unix'><target type='virtio' name='org.qemu.guest_agent.0'/></channel>
    <serial type='pty'/><console type='pty'/>
    <graphics type='vnc' port='-1' autoport='yes' listen='127.0.0.1'/>
    <video><model type='virtio'/></video>
    <memballoon model='virtio'/>
  </devices>
</domain>"""

def _cloud_init(spec: dict, password: str | None, authorized_key: str, host_key_private: str, host_key_public: str):
    """password=None (node transfer) leaves the existing guest password untouched."""
    network = ipaddress.ip_network(spec["guest_subnet"], strict=False)
    guest_ip = ipaddress.ip_address(spec["guest_ip"]); gateway = ipaddress.ip_address(spec["gateway"])
    if guest_ip not in network or gateway not in network: raise HypervisorError("Guest address outside subnet")
    account = {"name": "ubuntu", "groups": ["sudo"], "shell": "/bin/bash", "sudo": "ALL=(ALL) NOPASSWD:ALL",
               "lock_passwd": False, "ssh_authorized_keys": [authorized_key]}  # nosec B105 - cloud-init flag, not a password
    if password is not None:
        account["hashed_passwd"] = sha512_crypt.hash(password)
    user_data = {
        "hostname": spec["hostname"], "manage_etc_hosts": True,
        "users": [account],
        "ssh_pwauth": True, "ssh_deletekeys": True,
        "ssh_keys": {"ed25519_private": host_key_private, "ed25519_public": host_key_public},
        "package_update": True, "packages": ["qemu-guest-agent"],
        "runcmd": [["systemctl", "enable", "--now", "qemu-guest-agent"]],
    }
    network_config = {"version": 2, "ethernets": {"eth0": {
        "match": {"macaddress": _mac(spec["vm_name"])}, "set-name": "eth0",
        "addresses": [f"{guest_ip}/{network.prefixlen}"], "routes": [{"to": "default", "via": str(gateway)}],
        "nameservers": {"addresses": ["1.1.1.1", "8.8.8.8"]}}}}
    meta = {"instance-id": f"{spec['vm_name']}-{secrets.token_hex(4)}", "local-hostname": spec["hostname"]}
    # JSON is valid YAML, which avoids hand-escaping user-visible values.
    return "#cloud-config\n" + json.dumps(user_data), json.dumps(network_config), json.dumps(meta)

def new_guest_host_key():
    key = asyncssh.generate_private_key("ssh-ed25519")
    return key.export_private_key().decode(), key.export_public_key().decode().strip()

async def _build_disk_and_seed(connection, spec: dict, password: str, authorized_key: str, host_private: str, host_public: str):
    vm = _vm(spec["vm_name"]); directory = _machine_dir(vm)
    base = base_image_path(spec["image_id"]); size = f"{int(spec['disk_gb'])}G"
    await _run(connection, ["test", "-r", base])
    # 0751: libvirt-qemu is not in the panel/libvirt group and must be able to traverse to
    # the disk files; libvirt's dynamic ownership relabels the files themselves.
    await _run(connection, ["install", "-d", "-m", "0751", directory])
    await _run(connection, ["rm", "-f", "--", f"{directory}/disk.qcow2", f"{directory}/seed.iso"])
    await _run(connection, ["qemu-img", "create", "-q", "-f", "qcow2", "-F", "qcow2", "-b", base, f"{directory}/disk.qcow2", size], timeout=300)
    await _write_seed(connection, spec, password, authorized_key, host_private, host_public)

async def _write_seed(connection, spec: dict, password, authorized_key: str, host_private: str, host_public: str):
    directory = _machine_dir(spec["vm_name"])
    user_data, network_config, meta = _cloud_init(spec, password, authorized_key, host_private, host_public)
    await _write(connection, f"{directory}/user-data", user_data)
    await _write(connection, f"{directory}/network-config", network_config)
    await _write(connection, f"{directory}/meta-data", meta)
    try:
        await _run(connection, ["cloud-localds", "-N", f"{directory}/network-config", f"{directory}/seed.iso", f"{directory}/user-data", f"{directory}/meta-data"])
    finally:
        await _run(connection, ["rm", "-f", "--", f"{directory}/user-data", f"{directory}/network-config", f"{directory}/meta-data"])

def _define_and_start(cluster, spec: dict):
    conn = _connect(cluster)
    try:
        domain = conn.defineXML(domain_xml(spec))
        domain.setAutostart(1)
        domain.create()
    except libvirt.libvirtError as exc: raise HypervisorError("Machine definition failed") from exc
    finally: conn.close()

def _destroy_and_undefine(cluster, vm_name: str):
    conn = _connect(cluster)
    try:
        try: domain = conn.lookupByName(_vm(vm_name))
        except libvirt.libvirtError: return
        if domain.isActive(): domain.destroy()
        domain.undefineFlags(libvirt.VIR_DOMAIN_UNDEFINE_MANAGED_SAVE | libvirt.VIR_DOMAIN_UNDEFINE_SNAPSHOTS_METADATA)
    except libvirt.libvirtError as exc: raise HypervisorError("Machine removal failed") from exc
    finally: conn.close()

# ---------- lifecycle ----------

async def provision(cluster, spec: dict, password: str) -> str:
    """Create overlay + seed, define and boot. Returns the guest host public key to pin."""
    host_private, host_public = new_guest_host_key()
    authorized_key = panel_public_key(decrypt_node_key(cluster.ssh_key_encrypted))
    connection = await _node_connection(cluster)
    try: await _build_disk_and_seed(connection, spec, password, authorized_key, host_private, host_public)
    finally: connection.close()
    await asyncio.to_thread(_define_and_start, cluster, spec)
    return host_public

async def rebuild(cluster, spec: dict, password: str) -> str:
    await asyncio.to_thread(_destroy_and_undefine, cluster, spec["vm_name"])
    return await provision(cluster, spec, password)

async def delete(cluster, vm_name: str):
    await asyncio.to_thread(_destroy_and_undefine, cluster, vm_name)
    connection = await _node_connection(cluster)
    try: await _run(connection, ["rm", "-rf", "--", _machine_dir(vm_name)])
    finally: connection.close()

# ---------- resize / speed ----------

def redefine(cluster, spec: dict):
    """Persist vCPU, memory and port-speed changes; live-apply the speed caps if running."""
    conn = _connect(cluster)
    try:
        conn.defineXML(domain_xml(spec))
        domain = conn.lookupByName(_vm(spec["vm_name"]))
        if domain.isActive() and hasattr(domain, "setInterfaceParameters"):
            params = {}
            for prefix, key in (("inbound", "speed_in_mbps"), ("outbound", "speed_out_mbps")):
                rate = _kbytes_per_second(spec.get(key))
                params.update({f"{prefix}.average": rate, f"{prefix}.peak": rate, f"{prefix}.burst": max(1024, rate // 8) if rate else 0})
            try: domain.setInterfaceParameters(_mac(spec["vm_name"]), params, libvirt.VIR_DOMAIN_AFFECT_LIVE)
            except libvirt.libvirtError: pass  # persistent config still applies on next boot
    except libvirt.libvirtError as exc: raise HypervisorError("Machine update failed") from exc
    finally: conn.close()

async def grow_disk(cluster, vm_name: str, disk_gb: int):
    """Grow only (shrinking would destroy data). Guest growpart extends the root fs on boot."""
    connection = await _node_connection(cluster)
    try: await _run(connection, ["qemu-img", "resize", "-q", f"{_machine_dir(vm_name)}/disk.qcow2", f"{int(disk_gb)}G"], timeout=300)
    finally: connection.close()

def _is_active(cluster, vm_name: str) -> bool:
    conn = _connect(cluster)
    try:
        try: return bool(conn.lookupByName(_vm(vm_name)).isActive())
        except libvirt.libvirtError: return False
    finally: conn.close()

# ---------- transfer between nodes ----------

TRANSFER_CHUNK = 4 * 1024 * 1024

async def _graceful_stop(cluster, vm_name: str, grace: int = 120):
    if not await asyncio.to_thread(_is_active, cluster, vm_name): return
    try: await asyncio.to_thread(power_action, cluster, vm_name, "stop")
    except HypervisorError: pass
    loop = asyncio.get_running_loop(); deadline = loop.time() + grace
    while loop.time() < deadline:
        if not await asyncio.to_thread(_is_active, cluster, vm_name): return
        await asyncio.sleep(3)
    await asyncio.to_thread(power_action, cluster, vm_name, "force-stop")

async def copy_disk(source, target, vm_name: str) -> str:
    """Stop, flatten and stream the disk source -> panel -> target over the two pinned SSH
    sessions (encrypted end to end, never written to panel disk), then verify SHA-256 on
    both ends. Returns the digest. The source copy is left untouched until finish_transfer."""
    vm = _vm(vm_name); directory = _machine_dir(vm)
    flat = f"{directory}/transfer.qcow2"
    await _graceful_stop(source, vm)
    src = await _node_connection(source)
    try:
        dst = await _node_connection(target)
        try:
            await _run(dst, ["install", "-d", "-m", "0751", directory])
            await _run(src, ["rm", "-f", "--", flat])
            # Flatten: the target may not have the same base image (or it may differ).
            await _run(src, ["qemu-img", "convert", "-q", "-O", "qcow2", f"{directory}/disk.qcow2", flat], timeout=7200)
            expected = (await _run(src, ["sha256sum", flat], timeout=3600)).split()[0]
            reader = await src.create_process(shlex.join(["cat", "--", flat]), encoding=None)
            writer = await dst.create_process(shlex.join(["dd", f"of={directory}/disk.qcow2.part", "bs=4M", "status=none"]), encoding=None)
            while True:
                chunk = await reader.stdout.read(TRANSFER_CHUNK)
                if not chunk: break
                writer.stdin.write(chunk)
                await writer.stdin.drain()
            writer.stdin.write_eof()
            await writer.wait_closed(); await reader.wait_closed()
            if reader.exit_status != 0 or writer.exit_status != 0:
                raise HypervisorError("Disk stream failed")
            actual = (await _run(dst, ["sha256sum", f"{directory}/disk.qcow2.part"], timeout=3600)).split()[0]
            if actual != expected:
                await _run(dst, ["rm", "-f", "--", f"{directory}/disk.qcow2.part"])
                raise HypervisorError("Transferred disk failed its checksum")
            await _run(dst, ["mv", "-f", "--", f"{directory}/disk.qcow2.part", f"{directory}/disk.qcow2"])
            return expected
        finally: dst.close()
    finally:
        try: await _run(src, ["rm", "-f", "--", flat])
        except Exception: log.warning("Could not remove transfer scratch file for %s", vm)
        src.close()

async def boot_transferred(target, spec: dict) -> str:
    """New seed (new address, new pinned host key, password unchanged), define, start."""
    host_private, host_public = new_guest_host_key()
    authorized_key = panel_public_key(decrypt_node_key(target.ssh_key_encrypted))
    connection = await _node_connection(target)
    try: await _write_seed(connection, spec, None, authorized_key, host_private, host_public)
    finally: connection.close()
    await asyncio.to_thread(_define_and_start, target, spec)
    return host_public

async def discard_copy(cluster, vm_name: str):
    """Undo a half-finished transfer on the target (or retire the source afterwards)."""
    await delete(cluster, vm_name)

def set_guest_password(cluster, vm_name: str, password: str):
    conn = _connect(cluster)
    try: conn.lookupByName(_vm(vm_name)).setUserPassword("ubuntu", password, 0)
    except libvirt.libvirtError as exc: raise HypervisorError("Guest agent password update failed") from exc
    finally: conn.close()

def _affect_flags(domain):
    return libvirt.VIR_DOMAIN_AFFECT_CONFIG | (libvirt.VIR_DOMAIN_AFFECT_LIVE if domain.isActive() else 0)

def set_media(cluster, spec: dict):
    """Mount (iso_image_id set) or eject the install disc, and apply boot order to the persistent config."""
    conn = _connect(cluster)
    try:
        domain = conn.lookupByName(_vm(spec["vm_name"]))
        iso = spec.get("iso_image_id")
        source = f"<source file='{iso_path(iso)}'/>" if iso else ""
        device = f"<disk type='file' device='cdrom'><driver name='qemu' type='raw'/>{source}<target dev='sdb' bus='sata'/><readonly/></disk>"
        domain.updateDeviceFlags(device, _affect_flags(domain))
        conn.defineXML(domain_xml(spec))  # boot order only takes effect on next boot
    except libvirt.libvirtError as exc: raise HypervisorError("Media update failed") from exc
    finally: conn.close()

async def sync_image(cluster, image):
    if not str(image.url).startswith("https://") or not re.fullmatch(r"[a-f0-9]{64}", image.checksum):
        raise HypervisorError("Image source is not verified")
    target = base_image_path(image.id) if image.kind == "cloud" else iso_path(image.id)
    connection = await _node_connection(cluster)
    try:
        await _run(connection, ["curl", "-fsSL", "--proto", "=https", "--retry", "3", "-o", f"{target}.part", image.url], timeout=1800)
        digest = (await _run(connection, ["sha256sum", f"{target}.part"], timeout=600)).split()[0]
        if digest != image.checksum:
            await _run(connection, ["rm", "-f", "--", f"{target}.part"])
            raise HypervisorError("Image checksum mismatch")
        await _run(connection, ["mv", "-f", "--", f"{target}.part", target])
    finally: connection.close()

async def push_rules(cluster, rules: str, private_ips: list[str]):
    """Stage rules for the root-owned kestrel-rules.path unit, which validates and applies them."""
    for address in private_ips: ipaddress.IPv4Address(address)
    connection = await _node_connection(cluster)
    try:
        await _write(connection, STAGED_IPS, "\n".join(private_ips) + "\n", 0o640)
        await _write(connection, STAGED_RULES, rules, 0o640)
        expected = hashlib.sha256(rules.encode()).hexdigest()
        wanted_ips = set(private_ips)
        loop = asyncio.get_running_loop(); deadline = loop.time() + RULES_APPLY_TIMEOUT
        while True:
            # Success needs both: the rules hash the root unit records after `nft -f`,
            # and every private IP actually present on the uplink (netplan applied).
            # The rules hash alone matches when only the IP list changed.
            result = await connection.run(shlex.join(["cat", f"{STATE_DIR}/applied.sha256"]), check=False, timeout=10)
            rules_ok = result.exit_status == 0 and (result.stdout or "").strip() == expected
            ips_ok = True
            if rules_ok and wanted_ips:
                present = await connection.run(shlex.join(["ip", "-4", "-o", "addr", "show", "dev", cluster.uplink_interface]), check=False, timeout=10)
                found = {part.split("/")[0] for line in (present.stdout or "").splitlines() for part in line.split()[3:4]}
                ips_ok = present.exit_status == 0 and wanted_ips <= found
            if rules_ok and ips_ok:
                return
            if loop.time() >= deadline:
                raise HypervisorError("Node did not apply the updated rules")
            await asyncio.sleep(0.5)
    finally: connection.close()

async def verify_node(cluster) -> dict:
    connection = await _node_connection(cluster)
    try:
        checks = json.loads(await _run(connection, ["/usr/local/sbin/kestrel-node", "health"], timeout=20))
        return {key: bool(checks.get(key)) for key in ("libvirt", "forwarding", "ips", "rules", "network")}
    finally: connection.close()

def node_capacity(cluster) -> tuple[int, int]:
    conn = _connect(cluster)
    try:
        info = conn.getInfo()
        return int(info[2]), int(info[1])
    finally: conn.close()

# ---------- console: SSH to the guest through the node ----------

async def fetch_guest_host_key(cluster, guest_ip: str) -> str:
    """Re-pin: read the guest's current ed25519 host key through the node tunnel.

    Trust-on-first-use, so it is administrator-only and audited. Authentication with
    the panel key must still succeed, which proves this is the panel-provisioned guest."""
    ipaddress.IPv4Address(guest_ip)
    node = await _node_connection(cluster)
    try:
        guest = await asyncssh.connect(guest_ip, port=22, tunnel=node, username="ubuntu", client_keys=[panel_private_key(cluster)],
            known_hosts=None, server_host_key_algs=["ssh-ed25519"], connect_timeout=10)
        try:
            key = guest.get_server_host_key()
            if key is None: raise HypervisorError("Guest presented no host key")
            return key.export_public_key().decode().strip()
        finally:
            guest.close()
    except HypervisorError: raise
    except Exception as exc:
        raise HypervisorError("Could not reach the guest to read its host key") from exc
    finally:
        node.close()

async def open_console(cluster, machine, cols: int = 120, rows: int = 32):
    """machine/cluster may be detached ORM objects; only already-loaded attributes are read."""
    ip = machine.cluster_ip.guest_ipv4 if machine.cluster_ip else None
    if not ip or not machine.guest_host_key: raise HypervisorError("Console unavailable")
    ipaddress.IPv4Address(ip)
    node = await _node_connection(cluster)
    try:
        key_type, key_data = machine.guest_host_key.split()[:2]
        guest = await asyncssh.connect(ip, port=22, tunnel=node, username="ubuntu", client_keys=[panel_private_key(cluster)],
            known_hosts=asyncssh.import_known_hosts(f"{ip} {key_type} {key_data}\n"), connect_timeout=10)
        process = await guest.create_process(term_type="xterm-256color", term_size=(cols, rows), encoding=None)
        return (node, guest), process
    except Exception as exc:
        node.close(); raise HypervisorError("Console unavailable") from exc
