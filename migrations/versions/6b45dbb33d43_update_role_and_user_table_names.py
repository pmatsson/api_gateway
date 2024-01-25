"""Update role and user table names

Revision ID: 6b45dbb33d43
Revises: 8e0d08daa203
Create Date: 2024-01-25 18:22:14.165462

"""
from typing import Sequence, Union

from alembic import op

# revision identifiers, used by Alembic.
revision: str = '6b45dbb33d43'
down_revision: Union[str, None] = '8e0d08daa203'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.rename_table('roles', 'role')
    op.rename_table('users', 'user')


def downgrade() -> None:
    op.rename_table('role', 'roles')
    op.rename_table('user', 'users')
