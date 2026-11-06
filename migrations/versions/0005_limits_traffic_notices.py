"""Account quotas, usernames, traffic accounting, OS families and notices."""
from alembic import op
import sqlalchemy as sa

revision = "0005_limits_traffic_notices"
down_revision = "0004_roles_locations_settings"
branch_labels = None
depends_on = None

USER_COLS = ["max_vms", "max_vcpu", "max_memory_mb", "max_disk_gb", "max_ips"]
MACHINE_INT = ["bandwidth_limit_gb", "speed_in_mbps", "speed_out_mbps"]
MACHINE_BIG = ["traffic_rx_bytes", "traffic_tx_bytes", "traffic_last_rx", "traffic_last_tx"]


def upgrade():
    with op.batch_alter_table("users") as batch:
        batch.add_column(sa.Column("username", sa.String(32), nullable=True))
        for col in USER_COLS:
            batch.add_column(sa.Column(col, sa.Integer(), nullable=False, server_default="0"))
        batch.create_unique_constraint("uq_users_username", ["username"])
    with op.batch_alter_table("images") as batch:
        batch.add_column(sa.Column("os_family", sa.String(16), nullable=False, server_default="other"))
    with op.batch_alter_table("machines") as batch:
        for col in MACHINE_INT:
            batch.add_column(sa.Column(col, sa.Integer(), nullable=False, server_default="0"))
        for col in MACHINE_BIG:
            batch.add_column(sa.Column(col, sa.BigInteger(), nullable=False, server_default="0"))
        batch.add_column(sa.Column("traffic_period", sa.String(7), nullable=False, server_default=""))
        batch.add_column(sa.Column("suspend_reason", sa.String(32), nullable=False, server_default=""))
    op.create_table(
        "traffic_daily",
        sa.Column("id", sa.BigInteger().with_variant(sa.Integer(), "sqlite"), primary_key=True),
        sa.Column("machine_id", sa.String(8), sa.ForeignKey("machines.id", ondelete="CASCADE"), nullable=False, index=True),
        sa.Column("day", sa.String(10), nullable=False),
        sa.Column("rx_bytes", sa.BigInteger(), nullable=False, server_default="0"),
        sa.Column("tx_bytes", sa.BigInteger(), nullable=False, server_default="0"),
        sa.UniqueConstraint("machine_id", "day"),
    )
    op.create_table(
        "notices",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("kind", sa.String(16), nullable=False, server_default="info"),
        sa.Column("title", sa.String(120), nullable=False),
        sa.Column("message", sa.String(1000), nullable=False, server_default=""),
        sa.Column("active", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=True),
    )
    # Flags now derive from the ISO country code in location_id.
    op.execute("UPDATE clusters SET flag_url = ''")


def downgrade():
    op.drop_table("notices")
    op.drop_table("traffic_daily")
    with op.batch_alter_table("machines") as batch:
        for col in MACHINE_INT + MACHINE_BIG + ["traffic_period", "suspend_reason"]:
            batch.drop_column(col)
    with op.batch_alter_table("images") as batch:
        batch.drop_column("os_family")
    with op.batch_alter_table("users") as batch:
        batch.drop_constraint("uq_users_username", type_="unique")
        for col in USER_COLS + ["username"]:
            batch.drop_column(col)
