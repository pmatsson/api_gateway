"""Case insensitive email

Revision ID: 137ee54fd373
Revises: c619e555696
Create Date: 2021-09-30 17:12:20.572177

"""
import sqlalchemy as sa
from alembic import op
from citext import CIText

# revision identifiers, used by Alembic.
revision = "137ee54fd373"
down_revision = "c619e555696"


def upgrade():
    op.execute('CREATE EXTENSION IF NOT EXISTS citext')
    op.alter_column("users", "email", existing_type=sa.String(255), type_=CIText())


def downgrade():
    op.alter_column("users", "email", existing_type=CIText(), type_=sa.String(255))
