"""Test harness: isolated SQLite database, stubbed libvirt (no hypervisor needed)."""
import os, sys, tempfile, types

_tmp = tempfile.mkdtemp(prefix="kestrel-test-")
os.environ.setdefault("KESTREL_DATABASE_URL", f"sqlite:///{_tmp}/test.db")
os.environ.setdefault("KESTREL_SECRET_KEY", "test-secret-key-" + "x" * 32)
os.environ.setdefault("KESTREL_ENCRYPTION_KEY", "Ufz3m0t2b8iZbJk1lW3c0bT6jQwq9r0D7kJmE4yH5aE=")
os.environ.setdefault("KESTREL_ENVIRONMENT", "development")
os.environ.setdefault("KESTREL_SECURE_COOKIES", "false")
os.environ.setdefault("KESTREL_TRUSTED_HOST", "testserver")

if "libvirt" not in sys.modules:  # libvirt-python needs system libraries; stub for unit tests
    stub = types.ModuleType("libvirt")
    class libvirtError(Exception): pass
    stub.libvirtError = libvirtError
    stub.VIR_DOMAIN_RUNNING = 1
    stub.VIR_DOMAIN_AFFECT_CONFIG = 2
    stub.VIR_DOMAIN_AFFECT_LIVE = 1
    stub.VIR_DOMAIN_UNDEFINE_MANAGED_SAVE = 1
    stub.VIR_DOMAIN_UNDEFINE_SNAPSHOTS_METADATA = 2
    stub.open = lambda uri: (_ for _ in ()).throw(libvirtError("no hypervisor in tests"))
    sys.modules["libvirt"] = stub

import pytest
from fastapi.testclient import TestClient
from app.db import Base, SessionLocal, engine
from app import models  # noqa: F401  (register tables)
from app.models import Cluster, ClusterIP, Image, Machine, User
from app.security import encrypt_node_key, hash_password, new_session


@pytest.fixture(autouse=True)
def fresh_db():
    Base.metadata.drop_all(engine)
    Base.metadata.create_all(engine)
    yield


@pytest.fixture
def db():
    session = SessionLocal()
    try:
        yield session
    finally:
        session.close()


@pytest.fixture
def client():
    from app.main import app
    return TestClient(app)


def make_user(db, email, role="user"):
    user = User(email=email, password_hash=hash_password("correct-horse-battery"), role=role)
    db.add(user); db.commit()
    return user


def login(client, db, user):
    raw, csrf, _ = new_session(db, user)
    db.commit()
    client.cookies.set("kestrel_session", raw)
    client.cookies.set("kestrel_csrf", csrf)
    return csrf


def make_cluster(db, name="nyc-01", ips=3, **extra):
    cluster = Cluster(name=name, node_ipv4="10.0.0.1", ssh_port=22, guest_subnet="192.168.122.0/24", uplink_interface="eth0",
                      ssh_key_encrypted=encrypt_node_key("dummy"), node_host_key="10.0.0.1 ssh-ed25519 AAAA", state="active", **extra)
    db.add(cluster); db.flush()
    for n in range(ips):
        db.add(ClusterIP(cluster_id=cluster.id, private_ipv4=f"10.0.0.{10+n}", public_ipv4=f"198.51.100.{10+n}", guest_ipv4=f"192.168.122.{101+n}"))
    db.commit()
    return cluster


def make_machine(db, owner, cluster, mid="vm-aaaaa", vm="vm100001", state="running"):
    image = db.query(Image).first()
    if not image:
        image = Image(name="Ubuntu", url="https://x/y.img", checksum="a" * 64, kind="cloud"); db.add(image); db.flush()
    machine = Machine(id=mid, vm_name=vm, owner_id=owner.id, cluster_id=cluster.id, image_id=image.id, vcpu=2, memory_mb=2048, disk_gb=20, state=state)
    db.add(machine); db.flush()
    ip = db.query(ClusterIP).filter(ClusterIP.cluster_id == cluster.id, ClusterIP.machine_id.is_(None)).first()
    ip.machine_id = machine.id
    db.commit()
    return machine
