"""Create the initial Kestrel schema.

Explicit DDL frozen at the 1.0 schema. Later model changes belong in later
revisions; this file must never import app.models.

Databases created by the old 0001 (which ran create_all on whatever the models
were at the time) are already stamped past this revision, so they are not
affected; 0002 tolerates the extra columns those databases may already have.
"""
from alembic import op
import sqlalchemy as sa

revision = "0001_initial_schema"
down_revision = None
branch_labels = None
depends_on = None

TZ = sa.DateTime(timezone=True)


def upgrade():
    op.create_table(
        "users",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("email", sa.String(255), nullable=False),
        sa.Column("password_hash", sa.String(255), nullable=False),
        sa.Column("role", sa.String(16), nullable=False),
        sa.Column("active", sa.Boolean(), nullable=False),
        sa.Column("force_password_change", sa.Boolean(), nullable=False),
        sa.Column("failed_attempts", sa.Integer(), nullable=False),
        sa.Column("locked_until", TZ, nullable=True),
        sa.Column("created_at", TZ, nullable=False),
    )
    op.create_index("ix_users_email", "users", ["email"], unique=True)

    op.create_table(
        "login_attempts",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("account_key", sa.String(64), nullable=False),
        sa.Column("ip_key", sa.String(64), nullable=False),
        sa.Column("attempted_at", TZ, nullable=False),
        sa.Column("blocked_until", TZ, nullable=True),
    )
    op.create_index("ix_login_attempts_account_key", "login_attempts", ["account_key"])
    op.create_index("ix_login_attempts_ip_key", "login_attempts", ["ip_key"])
    op.create_index("ix_login_attempts_attempted_at", "login_attempts", ["attempted_at"])

    op.create_table(
        "sessions",
        sa.Column("token_hash", sa.String(64), primary_key=True),
        sa.Column("csrf_hash", sa.String(64), nullable=False),
        sa.Column("user_id", sa.Integer(), sa.ForeignKey("users.id", ondelete="CASCADE"), nullable=False),
        sa.Column("expires_at", TZ, nullable=False),
        sa.Column("created_at", TZ, nullable=False),
    )
    op.create_index("ix_sessions_user_id", "sessions", ["user_id"])
    op.create_index("ix_sessions_expires_at", "sessions", ["expires_at"])

    op.create_table(
        "clusters",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("name", sa.String(80), nullable=False, unique=True),
        sa.Column("node_ipv4", sa.String(45), nullable=False),
        sa.Column("ssh_port", sa.Integer(), nullable=False),
        sa.Column("guest_subnet", sa.String(43), nullable=False),
        sa.Column("uplink_interface", sa.String(32), nullable=False),
        sa.Column("ssh_key_encrypted", sa.Text(), nullable=False),
        sa.Column("node_host_key", sa.Text(), nullable=True),
        sa.Column("state", sa.String(20), nullable=False),
        sa.Column("setup_token_hash", sa.String(64), nullable=True),
        sa.Column("setup_token_expires", TZ, nullable=True),
        sa.Column("cpu_capacity", sa.Integer(), nullable=False),
        sa.Column("memory_capacity_mb", sa.Integer(), nullable=False),
        sa.Column("disk_capacity_gb", sa.Integer(), nullable=False),
        sa.Column("created_at", TZ, nullable=False),
    )

    op.create_table(
        "images",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("name", sa.String(100), nullable=False, unique=True),
        sa.Column("url", sa.Text(), nullable=False),
        sa.Column("checksum", sa.String(128), nullable=False),
        sa.Column("kind", sa.String(16), nullable=False),
        sa.Column("active", sa.Boolean(), nullable=False),
        sa.Column("created_at", TZ, nullable=False),
    )

    op.create_table(
        "machines",
        sa.Column("id", sa.String(8), primary_key=True),
        sa.Column("vm_name", sa.String(16), nullable=False, unique=True),
        sa.Column("owner_id", sa.Integer(), sa.ForeignKey("users.id", ondelete="RESTRICT"), nullable=False),
        sa.Column("cluster_id", sa.Integer(), sa.ForeignKey("clusters.id", ondelete="RESTRICT"), nullable=False),
        sa.Column("image_id", sa.Integer(), sa.ForeignKey("images.id", ondelete="SET NULL"), nullable=True),
        sa.Column("vcpu", sa.Integer(), nullable=False),
        sa.Column("memory_mb", sa.Integer(), nullable=False),
        sa.Column("disk_gb", sa.Integer(), nullable=False),
        sa.Column("state", sa.String(20), nullable=False),
        sa.Column("uptime_seconds", sa.Integer(), nullable=False),
        sa.Column("created_at", TZ, nullable=False),
    )
    op.create_index("ix_machines_owner_id", "machines", ["owner_id"])
    op.create_index("ix_machines_cluster_id", "machines", ["cluster_id"])

    op.create_table(
        "cluster_ips",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("cluster_id", sa.Integer(), sa.ForeignKey("clusters.id", ondelete="CASCADE"), nullable=False),
        sa.Column("private_ipv4", sa.String(45), nullable=False),
        sa.Column("public_ipv4", sa.String(45), nullable=False),
        sa.Column("guest_ipv4", sa.String(45), nullable=False),
        sa.Column("machine_id", sa.String(8), sa.ForeignKey("machines.id", ondelete="SET NULL"), nullable=True, unique=True),
        sa.UniqueConstraint("cluster_id", "private_ipv4"),
        sa.UniqueConstraint("cluster_id", "public_ipv4"),
        sa.UniqueConstraint("cluster_id", "guest_ipv4"),
    )
    op.create_index("ix_cluster_ips_cluster_id", "cluster_ips", ["cluster_id"])

    op.create_table(
        "jobs",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("kind", sa.String(32), nullable=False),
        sa.Column("machine_id", sa.String(8), sa.ForeignKey("machines.id", ondelete="SET NULL"), nullable=True),
        sa.Column("actor_id", sa.Integer(), sa.ForeignKey("users.id", ondelete="SET NULL"), nullable=True),
        sa.Column("payload", sa.Text(), nullable=False),
        sa.Column("state", sa.String(16), nullable=False),
        sa.Column("result", sa.Text(), nullable=True),
        sa.Column("created_at", TZ, nullable=False),
        sa.Column("updated_at", TZ, nullable=False),
    )
    op.create_index("ix_jobs_kind", "jobs", ["kind"])
    op.create_index("ix_jobs_machine_id", "jobs", ["machine_id"])
    op.create_index("ix_jobs_state", "jobs", ["state"])

    op.create_table(
        "metric_samples",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("machine_id", sa.String(8), sa.ForeignKey("machines.id", ondelete="CASCADE"), nullable=False),
        sa.Column("cpu_percent", sa.Float(), nullable=True),
        sa.Column("cpu_time_ns", sa.Integer(), nullable=False),
        sa.Column("memory_used_mb", sa.Integer(), nullable=False),
        sa.Column("disk_read_bytes", sa.Integer(), nullable=False),
        sa.Column("disk_write_bytes", sa.Integer(), nullable=False),
        sa.Column("network_rx_bytes", sa.Integer(), nullable=False),
        sa.Column("network_tx_bytes", sa.Integer(), nullable=False),
        sa.Column("sampled_at", TZ, nullable=False),
    )
    op.create_index("ix_metric_samples_machine_id", "metric_samples", ["machine_id"])
    op.create_index("ix_metric_samples_sampled_at", "metric_samples", ["sampled_at"])
    op.create_index("ix_metric_machine_time", "metric_samples", ["machine_id", "sampled_at"])

    op.create_table(
        "audit_logs",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("actor_id", sa.Integer(), sa.ForeignKey("users.id", ondelete="SET NULL"), nullable=True),
        sa.Column("action", sa.String(80), nullable=False),
        sa.Column("target", sa.String(160), nullable=False),
        sa.Column("remote_ip", sa.String(45), nullable=False),
        sa.Column("result", sa.String(20), nullable=False),
        sa.Column("created_at", TZ, nullable=False),
    )
    op.create_index("ix_audit_logs_actor_id", "audit_logs", ["actor_id"])
    op.create_index("ix_audit_logs_action", "audit_logs", ["action"])
    op.create_index("ix_audit_logs_created_at", "audit_logs", ["created_at"])


def downgrade():
    for table in ("audit_logs", "metric_samples", "jobs", "cluster_ips", "machines", "images", "clusters", "sessions", "login_attempts", "users"):
        op.drop_table(table)
