"""64-bit metric counters and machine start time for uptime."""
from alembic import op
import sqlalchemy as sa

revision = "0003_bigint_metrics_uptime"
down_revision = "0002_lifecycle"
branch_labels = None
depends_on = None

COUNTERS = ("cpu_time_ns", "disk_read_bytes", "disk_write_bytes", "network_rx_bytes", "network_tx_bytes")


def upgrade():
    bind = op.get_bind()
    with op.batch_alter_table("metric_samples") as batch:
        for name in COUNTERS:
            batch.alter_column(name, type_=sa.BigInteger(), existing_type=sa.Integer(), existing_nullable=False)
        if bind.dialect.name != "sqlite":  # SQLite INTEGER is already 64-bit and must stay INTEGER to autoincrement
            batch.alter_column("id", type_=sa.BigInteger(), existing_type=sa.Integer())
    with op.batch_alter_table("machines") as batch:
        batch.add_column(sa.Column("started_at", sa.DateTime(timezone=True), nullable=True))


def downgrade():
    with op.batch_alter_table("machines") as batch:
        batch.drop_column("started_at")
    with op.batch_alter_table("metric_samples") as batch:
        for name in COUNTERS:
            batch.alter_column(name, type_=sa.Integer(), existing_type=sa.BigInteger(), existing_nullable=False)
