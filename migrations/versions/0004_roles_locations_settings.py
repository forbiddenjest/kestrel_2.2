"""Cluster location metadata and panel settings (support link)."""
from alembic import op
import sqlalchemy as sa

revision = "0004_roles_locations_settings"
down_revision = "0003_bigint_metrics_uptime"
branch_labels = None
depends_on = None


def upgrade():
    with op.batch_alter_table("clusters") as batch:
        batch.add_column(sa.Column("location", sa.String(80), nullable=False, server_default=""))
        batch.add_column(sa.Column("location_id", sa.String(80), nullable=False, server_default=""))
        batch.add_column(sa.Column("flag_url", sa.String(500), nullable=False, server_default=""))
    op.create_table(
        "settings",
        sa.Column("key", sa.String(64), primary_key=True),
        sa.Column("value", sa.Text(), nullable=False, server_default=""),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=True),
    )


def downgrade():
    op.drop_table("settings")
    with op.batch_alter_table("clusters") as batch:
        batch.drop_column("flag_url")
        batch.drop_column("location_id")
        batch.drop_column("location")
