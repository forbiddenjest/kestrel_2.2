"""Machine lifecycle columns and per-machine firewall rules."""
from alembic import op
import sqlalchemy as sa

revision = "0002_lifecycle"
down_revision = "0001_initial_schema"
branch_labels = None
depends_on = None

def upgrade():
    # 0001 builds from current metadata, so a fresh database may already have these.
    inspector = sa.inspect(op.get_bind())
    columns = {c["name"] for c in inspector.get_columns("machines")}
    with op.batch_alter_table("machines") as batch:
        if "guest_host_key" not in columns: batch.add_column(sa.Column("guest_host_key", sa.Text(), nullable=True))
        if "iso_image_id" not in columns: batch.add_column(sa.Column("iso_image_id", sa.Integer(), sa.ForeignKey("images.id", name="fk_machines_iso", ondelete="SET NULL"), nullable=True))
        if "boot_device" not in columns: batch.add_column(sa.Column("boot_device", sa.String(8), nullable=False, server_default="disk"))
    if "firewall_rules" not in inspector.get_table_names():
        op.create_table("firewall_rules",
            sa.Column("id", sa.Integer(), primary_key=True),
            sa.Column("machine_id", sa.String(8), sa.ForeignKey("machines.id", ondelete="CASCADE"), nullable=False, index=True),
            sa.Column("protocol", sa.String(4), nullable=False),
            sa.Column("port", sa.Integer(), nullable=False),
            sa.Column("created_at", sa.DateTime(timezone=True)),
            sa.UniqueConstraint("machine_id", "protocol", "port"))

def downgrade():
    op.drop_table("firewall_rules")
    with op.batch_alter_table("machines") as batch:
        batch.drop_column("boot_device"); batch.drop_column("iso_image_id"); batch.drop_column("guest_host_key")
