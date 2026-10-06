"""create_tables

Revision ID: d4893003ca2b
Revises: 
Create Date: 2026-09-10 20:59:04.563807

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'd4893003ca2b'
down_revision: Union[str, Sequence[str], None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    #from database import init_fallback_db
    #init_fallback_db()
    op.create_table(
        'threat_detections',
        sa.Column('id', sa.Integer(), autoincrement=True, nullable=False),
        sa.Column('event_id', sa.Text(), nullable=False),
        sa.Column('device_id', sa.Text(), nullable=False),
        sa.Column('threat_type', sa.Text(), nullable=False),
        sa.Column('confidence_score', sa.Float(), nullable=False),
        sa.Column('audio_path', sa.Text(), nullable=False),
        sa.Column('timestamp', sa.Integer(), nullable=False),
        sa.Column('duration_sec',sa.Float(), nullable=False),
        sa.Column('sample_rate', sa.Integer(), nullable=False),
        sa.Column('channels', sa.Integer(), nullable=False),
        sa.Column('bit_depth', sa.Integer(), nullable=False),
        sa.PrimaryKeyConstraint('id')
    )

    op.create_table(
        'voltage',
        sa.Column('id', sa.Integer(), autoincrement=True, nullable=False),
        sa.Column('timestamp', sa.Integer(), nullable=False),
        sa.Column('value', sa.Float(), nullable=False),
        sa.PrimaryKeyConstraint('id')
    )

    op.create_table(
        'device_telemetry',
        sa.Column('id', sa.Integer(), autoincrement=True, nullable=False),
        sa.Column('timestamp', sa.Integer(), nullable=False),
        sa.Column('cpu_temp', sa.Float(), nullable=False),
        sa.Column('cpu_usage_pct', sa.Float(), nullable=False),
        sa.Column('ram_usage_pct', sa.Float(), nullable=False),
        sa.Column('disk_free_gb', sa.Float(), nullable=False),
        sa.Column('disk_usage_pct', sa.Float(), nullable=False),
        sa.Column('uptime_hours', sa.Float(), nullable=False),
        sa.PrimaryKeyConstraint('id')
    )

def downgrade() -> None:
    """Downgrade schema."""
    op.drop_table('device_telemetry')
    op.drop_table('voltage')
    op.drop_table('threat_detections')
