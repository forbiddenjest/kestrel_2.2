"""Retention and best-effort real libvirt telemetry."""
from datetime import timedelta
from contextlib import suppress
from defusedxml import ElementTree as ET
import libvirt
from app.config import settings
from app.models import MetricSample, utcnow
from app.services.libvirt import _connect

def purge_metrics(db):
    cutoff = utcnow() - timedelta(days=settings.metrics_retention_days)
    db.query(MetricSample).filter(MetricSample.sampled_at < cutoff).delete(synchronize_session=False)

def collect_machine_metrics(cluster, vm_name, previous=None, connection=None):
    """Pass connection to reuse one libvirt connection per node per collection cycle."""
    own = connection is None
    connection = connection or _connect(cluster)
    if connection is None:
        return None
    try:
        domain = connection.lookupByName(vm_name)
        state, _max_memory, _memory, vcpus, cpu_time = domain.info()
        if state != 1:
            return None
        memory = domain.memoryStats()
        memory_used_mb = max(0, int(memory.get("rss", 0) / 1024))
        disk_read = disk_write = network_rx = network_tx = 0
        root = ET.fromstring(domain.XMLDesc(0))
        for target in root.findall("./devices/disk/target"):
            dev = target.get("dev")
            if dev:
                with suppress(libvirt.libvirtError, IndexError, TypeError, ValueError):
                    stats = domain.blockStats(dev)
                    disk_read += max(0, int(stats[1]))
                    disk_write += max(0, int(stats[3]))
        for target in root.findall("./devices/interface/target"):
            dev = target.get("dev")
            if dev:
                with suppress(libvirt.libvirtError, IndexError, TypeError, ValueError):
                    stats = domain.interfaceStats(dev)
                    network_rx += max(0, int(stats[0]))
                    network_tx += max(0, int(stats[4]))
        cpu = None
        if previous and previous.sampled_at:
            old = previous.sampled_at
            if old.tzinfo is None:
                old = old.replace(tzinfo=utcnow().tzinfo)
            elapsed = max((utcnow() - old).total_seconds(), 0.001)
            delta = max(0, int(cpu_time) - int(previous.cpu_time_ns))
            cpu = min(100.0, (delta / (elapsed * 1_000_000_000 * max(int(vcpus), 1))) * 100.0)
        try:
            epoch = f"{int(cluster.id)}:{int(domain.ID())}"
        except Exception:
            epoch = None
        return {"cpu_percent": cpu, "cpu_time_ns": int(cpu_time), "memory_used_mb": memory_used_mb, "disk_read_bytes": disk_read, "disk_write_bytes": disk_write, "network_rx_bytes": network_rx, "network_tx_bytes": network_tx, "epoch": epoch}
    finally:
        if own:
            connection.close()
