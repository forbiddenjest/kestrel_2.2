"""Traffic counter epoch, plus schema alignment found by `alembic check`.

* machines.traffic_epoch: identifies the QEMU process the last traffic counters came
  from, so a guest restart never double counts or loses bytes.
* users.username: the unique constraint from 0005 becomes the unique index the model
  declares (same guarantee, and username look-ups at sign-in use it).
* created/updated timestamps that the application always sets become NOT NULL.
"""
from alembic import op
import sqlalchemy as sa

revision = "0006_traffic_epoch"
down_revision = "0005_limits_traffic_notices"
branch_labels = None
depends_on = None

TIMESTAMPS = (("firewall_rules", "created_at"), ("notices", "created_at"), ("settings", "updated_at"))


def upgrade():
    with op.batch_alter_table("machines") as batch:
        batch.add_column(sa.Column("traffic_epoch", sa.String(32), nullable=False, server_default=""))
    with op.batch_alter_table("users") as batch:
        batch.drop_constraint("uq_users_username", type_="unique")
        batch.create_index("ix_users_username", ["username"], unique=True)
    for table, column in TIMESTAMPS:
        op.execute(sa.text(f"UPDATE {table} SET {column} = CURRENT_TIMESTAMP WHERE {column} IS NULL"))
        with op.batch_alter_table(table) as batch:
            batch.alter_column(column, existing_type=sa.DateTime(timezone=True), nullable=False)


def downgrade():
    for table, column in TIMESTAMPS:
        with op.batch_alter_table(table) as batch:
            batch.alter_column(column, existing_type=sa.DateTime(timezone=True), nullable=True)
    with op.batch_alter_table("users") as batch:
        batch.drop_index("ix_users_username")
        batch.create_unique_constraint("uq_users_username", ["username"])
    with op.batch_alter_table("machines") as batch:
        batch.drop_column("traffic_epoch")
