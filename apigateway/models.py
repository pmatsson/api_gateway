from typing import List

import sqlalchemy as sa
from authlib.integrations.sqla_oauth2 import OAuth2ClientMixin, OAuth2TokenMixin
from citext import CIText
from flask import current_app
from flask_login import AnonymousUserMixin
from flask_security import RoleMixin, UserMixin
from flask_security.utils import hash_password, verify_password
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.ext.hybrid import hybrid_property
from sqlalchemy.orm import relationship
from werkzeug.datastructures import ImmutableList
from werkzeug.security import gen_salt

base_model = declarative_base()


roles_users = sa.Table(
    "roles_users",
    base_model.metadata,
    sa.Column("user_id", sa.ForeignKey("user.id"), primary_key=True),
    sa.Column("role_id", sa.ForeignKey("role.id"), primary_key=True),
)


class User(base_model, UserMixin):
    __tablename__ = "user"

    # 'fs_uniquifier' serves as the main identifier for a user
    # The 'id' column is maintained for data persistence as 'fs_uniquifier' can be altered.
    # the get_id() method of the UserMixin class returns the 'fs_uniquifier' value

    id = sa.Column(sa.Integer, primary_key=True)
    email = sa.Column(CIText(), unique=True)
    _password = sa.Column(sa.String(255), name="password")
    given_name = sa.Column(sa.String(255))
    family_name = sa.Column(sa.String(255))
    active = sa.Column(sa.Boolean())
    confirmed_at = sa.Column(sa.DateTime())
    last_login_at = sa.Column(sa.DateTime())
    login_count = sa.Column(sa.Integer)
    registered_at = sa.Column(sa.DateTime())
    ratelimit_quota = sa.Column(sa.Float)
    _allowed_scopes = sa.Column(sa.Text)
    fs_uniquifier = sa.Column(sa.String(64), unique=True, nullable=False)
    roles = relationship("Role", secondary=roles_users)

    @property
    def password(self):
        return self._password

    @password.setter
    def password(self, password):
        self._password = hash_password(password)

    password = sa.orm.synonym("_password", descriptor=password)

    @hybrid_property
    def is_anonymous_bootstrap_user(self) -> bool:
        return current_app.config["ANONYMOUS_BOOTSTRAP_USER_EMAIL"] == self.email

    @property
    def allowed_scopes(self) -> List[str]:
        if self._allowed_scopes:
            return self._allowed_scopes.split(" ")
        else:
            return current_app.config["USER_DEFAULT_SCOPES"]

    def validate_password(self, password) -> bool:
        return verify_password(password, self.password)


class AnonymousUser(AnonymousUserMixin):
    """AnonymousUser definition"""

    def __init__(self):
        self.roles = ImmutableList()

    def has_role(self, *args):
        """Returns `False`"""
        return False

    @hybrid_property
    def is_anonymous_bootstrap_user(self):
        return False


class Role(base_model, RoleMixin):
    __tablename__ = "role"

    id = sa.Column(sa.Integer(), primary_key=True)
    name = sa.Column(sa.String(80), unique=True)
    description = sa.Column(sa.String(255))

    def __eq__(self, other):
        return self.name == other or self.name == getattr(other, "name", None)

    def __ne__(self, other):
        return self.name != other and self.name != getattr(other, "name", None)


class OAuth2Client(base_model, OAuth2ClientMixin):
    __tablename__ = "oauth2client"

    id = sa.Column(sa.Integer, primary_key=True, autoincrement=True)
    user_id = sa.Column(sa.String, sa.ForeignKey("user.fs_uniquifier", ondelete="CASCADE"))
    ratelimit_multiplier = sa.Column(sa.Float, default=1.0)
    individual_ratelimit_multipliers = sa.Column(sa.JSON)
    last_activity = sa.Column(sa.DateTime, nullable=True)

    user = relationship("User")

    def gen_salt(self):
        self.reset_client_id()
        self.reset_client_secret()

    def reset_client_id(self):
        self.client_id = gen_salt(current_app.config.get("OAUTH2_CLIENT_ID_SALT_LEN"))

    def reset_client_secret(self):
        self.client_secret = gen_salt(current_app.config.get("OAUTH2_CLIENT_SECRET_SALT_LEN"))


class OAuth2Token(base_model, OAuth2TokenMixin):
    __tablename__ = "oauth2token"

    id = sa.Column(sa.Integer, primary_key=True, autoincrement=True)
    user_id = sa.Column(sa.String, sa.ForeignKey("user.fs_uniquifier", ondelete="CASCADE"))
    user = relationship("User")
    client_id = sa.Column(sa.Integer(), sa.ForeignKey("oauth2client.id", ondelete="CASCADE"))
    client = relationship("OAuth2Client")
    is_personal = sa.Column(sa.Boolean, default=False)
    is_internal = sa.Column(sa.Boolean, default=False)
    expires_in = sa.Column(sa.BigInteger, nullable=False, default=0)

    def expires_at(self):
        if not self.expires_in:
            return 0

        return self.issued_at + self.expires_in


class EmailChangeRequest(base_model):
    __tablename__ = "email_change_request"

    id = sa.Column(sa.Integer, primary_key=True, autoincrement=True)
    token = sa.Column(sa.String(255), unique=True)
    user_id = sa.Column(sa.Integer(), sa.ForeignKey("user.id", ondelete="CASCADE"))
    user = relationship("User")
    new_email = sa.Column(sa.Text)


class PasswordChangeRequest(base_model):
    __tablename__ = "password_change_request"

    id = sa.Column(sa.Integer, primary_key=True, autoincrement=True)
    token = sa.Column(sa.String(255), unique=True)
    user_id = sa.Column(sa.Integer(), sa.ForeignKey("user.id", ondelete="CASCADE"))
    user = relationship("User")
