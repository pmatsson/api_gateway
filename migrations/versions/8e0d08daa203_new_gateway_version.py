"""New gateway version

Revision ID: 8e0d08daa203
Revises: 137ee54fd373
Create Date: 2024-01-25 11:36:56.081089

"""
import uuid
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy import text

# revision identifiers, used by Alembic.
revision: str = "8e0d08daa203"
down_revision: Union[str, None] = "137ee54fd373"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # email_change_request >>>
    op.create_table(
        "email_change_request",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("token", sa.String(length=255), nullable=True),
        sa.Column("user_id", sa.Integer(), nullable=True),
        sa.Column("new_email", sa.Text(), nullable=True),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("token"),
    )

    # <<< email_change_request

    # password_change_request >>>
    op.create_table(
        "password_change_request",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("token", sa.String(length=255), nullable=True),
        sa.Column("user_id", sa.Integer(), nullable=True),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("token"),
    )
    # <<< password_change_request

    # users >>>
    op.alter_column("users", "ratelimit_level", new_column_name="ratelimit_quota")
    op.alter_column("users", "name", new_column_name="given_name")
    op.add_column("users", sa.Column("family_name", sa.String(length=255), nullable=True))
    op.add_column(
        "users",
        sa.Column(
            "fs_uniquifier",
            sa.String(length=64),
            nullable=False,
            server_default=text("(gen_random_uuid())"),
        ),
    )

    user_ids = op.get_bind().execute("SELECT id FROM users")

    for user_id in user_ids:
        op.execute(
            f"UPDATE users SET fs_uniquifier = '{uuid.uuid4().hex}' WHERE id = {user_id[0]}"
        )

    op.create_unique_constraint("uq_users_fs_uniquifier", "users", ["fs_uniquifier"])
    op.alter_column("users", "fs_uniquifier", server_default=None)
    # <<< users

    # oauth2client >>>
    op.drop_index("oauth2client_name_key", table_name="oauth2client")
    op.drop_index("oauth2client_user_id_key", table_name="oauth2client")
    op.drop_constraint("oauth2client_user_id_fkey", "oauth2client", type_="foreignkey")
    op.rename_table("oauth2client", "oauth2client_old")

    op.create_table(
        "oauth2client",
        sa.Column("client_id", sa.String(length=48), nullable=True),
        sa.Column("client_secret", sa.String(length=120), nullable=True),
        sa.Column("client_id_issued_at", sa.Integer(), nullable=False),
        sa.Column("client_secret_expires_at", sa.Integer(), nullable=False),
        sa.Column("client_metadata", sa.Text(), nullable=True),
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("user_id", sa.String(), nullable=True),
        sa.Column("ratelimit_multiplier", sa.Float(), nullable=True),
        sa.Column("individual_ratelimit_multipliers", sa.JSON(), nullable=True),
        sa.Column("last_activity", sa.DateTime(), nullable=True),
        sa.ForeignKeyConstraint(
            ["user_id"],
            ["users.fs_uniquifier"],
            name="fk_oauth2client_user_id",
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id"),
    )

    op.create_index(op.f("ix_oauth2client_client_id"), "oauth2client", ["client_id"], unique=False)

    op.execute(
        """INSERT INTO oauth2client (client_id, client_secret, client_id_issued_at, client_secret_expires_at, user_id, ratelimit_multiplier, last_activity, client_metadata)
                SELECT client_id, client_secret, 0, 0, (SELECT fs_uniquifier FROM users WHERE id = user_id), ratelimit, last_activity,
                row_to_json((SELECT d FROM (SELECT name AS client_name, description, website, is_confidential, created, is_internal, _default_scopes, _redirect_uris) d))
                FROM oauth2client_old"""
    )
    # <<< oauth2client

    # oauth2token >>>
    op.drop_index("oauth2token_client_id_key", table_name="oauth2token")
    op.drop_index("oauth2token_is_personal_key", table_name="oauth2token")
    op.drop_constraint("oauth2token_refresh_token_key", "oauth2token", type_="unique")
    op.drop_index("oauth2token_user_id_key", table_name="oauth2token")
    op.drop_constraint("oauth2token_client_id_fkey", "oauth2token", type_="foreignkey")
    op.drop_constraint("oauth2token_user_id_fkey", "oauth2token", type_="foreignkey")
    op.rename_table("oauth2token", "oauth2token_old")

    op.create_table(
        "oauth2token",
        sa.Column("token_type", sa.String(length=40), nullable=True),
        sa.Column("access_token", sa.String(length=255), nullable=False),
        sa.Column("refresh_token", sa.String(length=255), nullable=True),
        sa.Column("scope", sa.Text(), nullable=True),
        sa.Column("issued_at", sa.Integer(), nullable=False),
        sa.Column("access_token_revoked_at", sa.Integer(), nullable=False),
        sa.Column("refresh_token_revoked_at", sa.Integer(), nullable=False),
        sa.Column("expires_in", sa.BigInteger(), nullable=False),
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("user_id", sa.String(), nullable=True),
        sa.Column("client_id", sa.Integer(), nullable=True),
        sa.Column("is_personal", sa.Boolean(), default=False),
        sa.Column("is_internal", sa.Boolean, default=False),
        sa.ForeignKeyConstraint(
            ["client_id"], ["oauth2client.id"], name="fk_oauth2token_client_id", ondelete="CASCADE"
        ),
        sa.ForeignKeyConstraint(
            ["user_id"], ["users.fs_uniquifier"], name="fk_oauth2token_user_id", ondelete="CASCADE"
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("access_token"),
    )
    op.create_index(
        op.f("ix_oauth2token_refresh_token"), "oauth2token", ["refresh_token"], unique=False
    )

    op.execute(
        """INSERT INTO oauth2token (token_type, access_token, refresh_token, scope, issued_at, access_token_revoked_at, refresh_token_revoked_at, expires_in, user_id, client_id, is_personal, is_internal)
                SELECT token_type, access_token, refresh_token, _scopes, 0, 0, 0, EXTRACT(EPOCH FROM expires), (SELECT fs_uniquifier FROM users WHERE id = user_id), (SELECT id FROM oauth2client WHERE client_id = oto.client_id), is_personal, is_internal
                FROM oauth2token_old AS oto"""
    )

    # <<< oauth2token

    # roles_users >>>
    op.alter_column("roles_users", "user_id", existing_type=sa.INTEGER(), nullable=False)

    op.alter_column("roles_users", "role_id", existing_type=sa.INTEGER(), nullable=False)
    # <<< roles_users

    op.drop_table("oauth2client_old")
    op.drop_table("oauth2token_old")

    # ### end Alembic commands ###


def downgrade() -> None:
    op.drop_index(op.f("ix_oauth2token_refresh_token"), table_name="oauth2token")
    op.drop_index(op.f("ix_oauth2client_client_id"), table_name="oauth2client")
    op.drop_constraint("fk_oauth2client_user_id", "oauth2client", type_="foreignkey")
    op.drop_constraint("fk_oauth2token_client_id", "oauth2token", type_="foreignkey")
    op.drop_constraint("fk_oauth2token_user_id", "oauth2token", type_="foreignkey")
    op.drop_constraint("uq_users_fs_uniquifier", "users", type_="unique")

    # roles_users >>>
    op.alter_column("roles_users", "role_id", existing_type=sa.INTEGER(), nullable=True)

    op.alter_column("roles_users", "user_id", existing_type=sa.INTEGER(), nullable=True)
    # <<< roles_users

    # oauth2client >>>
    op.create_table(
        "oauth2client_old",
        sa.Column("name", sa.String(length=255), nullable=False),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("website", sa.String(length=255), nullable=True),
        sa.Column("user_id", sa.Integer(), nullable=True),
        sa.Column("client_id", sa.String(length=255), nullable=False),
        sa.Column("client_secret", sa.String(length=255), nullable=False),
        sa.Column("is_confidential", sa.Boolean(), nullable=True),
        sa.Column("is_internal", sa.Boolean(), nullable=True),
        sa.Column("last_activity", sa.DateTime(), nullable=True),
        sa.Column("_redirect_uris", sa.Text(), nullable=True),
        sa.Column("_default_scopes", sa.Text(), nullable=True),
        sa.Column("ratelimit", sa.Float(), nullable=True),
        sa.Column("created", sa.DateTime(), nullable=False),
        sa.ForeignKeyConstraint(
            ["user_id"], ["users.id"], name="oauth2client_user_id_fkey", ondelete="CASCADE"
        ),
        sa.PrimaryKeyConstraint("client_id"),
    )

    op.execute(
        """INSERT INTO oauth2client_old (client_id, client_secret, user_id, ratelimit, last_activity, name, description, website, is_confidential, _default_scopes, _redirect_uris, created, is_internal)
                SELECT client_id, client_secret, (SELECT id FROM users WHERE fs_uniquifier = user_id), ratelimit_multiplier, last_activity, (client_metadata::json->>'client_name'), (client_metadata::json->>'description'), (client_metadata::json->>'website'), (COALESCE((client_metadata::json->>'is_confidential'), 'true'))::boolean, (client_metadata::json->>'_default_scopes'), (client_metadata::json->>'_redirect_uris'), (COALESCE((client_metadata::json->>'created')::timestamp, NOW()))::timestamp, (COALESCE((client_metadata::json->>'is_internal'), 'false'))::boolean
                FROM oauth2client"""
    )

    op.create_index("oauth2client_user_id_key", "oauth2client_old", ["user_id"])
    op.create_index("oauth2client_name_key", "oauth2client_old", ["name"])
    # <<< oauth2client

    # oauth2token >>>
    op.create_table(
        "oauth2token_old",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("user_id", sa.Integer(), nullable=True),
        sa.Column("client_id", sa.String(length=255), nullable=True),
        sa.Column("token_type", sa.String(length=40), nullable=True),
        sa.Column("access_token", sa.String(length=255), nullable=False),
        sa.Column("refresh_token", sa.String(length=255), nullable=True),
        sa.Column("_scopes", sa.Text(), nullable=True),
        sa.Column("expires", sa.DateTime(), nullable=True),
        sa.Column("is_personal", sa.Boolean(), default=False, nullable=True),
        sa.Column("is_internal", sa.Boolean, default=False, nullable=True),
        sa.ForeignKeyConstraint(
            ["user_id"], ["users.id"], name="oauth2token_user_id_fkey", ondelete="CASCADE"
        ),
        sa.ForeignKeyConstraint(
            ["client_id"],
            ["oauth2client_old.client_id"],
            name="oauth2token_client_id_fkey",
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("access_token"),
        sa.UniqueConstraint("refresh_token"),
    )

    op.execute(
        """INSERT INTO oauth2token_old (token_type, access_token, refresh_token, _scopes, expires, user_id, client_id, is_personal, is_internal)
                SELECT token_type, access_token, refresh_token, scope, to_timestamp(expires_in), (SELECT id FROM users WHERE fs_uniquifier = user_id), (SELECT client_id FROM oauth2client WHERE id = ot.id), COALESCE(is_personal, false), COALESCE(is_internal, false)
                FROM oauth2token as ot"""
    )

    op.create_index("oauth2token_client_id_key", "oauth2token_old", ["client_id"])
    op.create_index("oauth2token_user_id_key", "oauth2token_old", ["user_id"])
    op.create_index("oauth2token_is_personal_key", "oauth2token_old", ["is_personal"])
    op.create_unique_constraint(
        "oauth2token_refresh_token_key", "oauth2token_old", ["refresh_token"]
    )
    # <<< oauth2token

    # users >>>
    op.drop_column("users", "fs_uniquifier")
    op.drop_column("users", "family_name")
    op.alter_column("users", "given_name", new_column_name="name")
    op.alter_column("users", "ratelimit_quota", new_column_name="ratelimit_level")
    # <<< users

    # password_change_request >>>
    op.drop_table("password_change_request")
    # <<< password_change_request

    # email_change_request >>>
    op.drop_table("email_change_request")
    # <<< email_change_request

    op.drop_table("oauth2client")
    op.rename_table("oauth2client_old", "oauth2client")
    op.drop_table("oauth2token")
    op.rename_table("oauth2token_old", "oauth2token")

    # # ### end Alembic commands ###
