import sqlalchemy as sa
from authlib.integrations.sqla_oauth2 import OAuth2ClientMixin, OAuth2TokenMixin
from flask import current_app
from flask_security import RoleMixin, UserMixin
from flask_security.utils import hash_password, verify_password
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.ext.hybrid import hybrid_property
from sqlalchemy.orm import relationship
from werkzeug.security import gen_salt

base_model = declarative_base()


class User(base_model, UserMixin):
    __tablename__ = "user"

    id = sa.Column(sa.Integer, primary_key=True)
    email = sa.Column(sa.Text, unique=True)
    _password = sa.Column(sa.String(255), name="password")
    name = sa.Column(sa.String(255))
    active = sa.Column(sa.Boolean())
    confirmed_at = sa.Column(sa.DateTime())
    last_login_at = sa.Column(sa.DateTime())
    login_count = sa.Column(sa.Integer)
    registered_at = sa.Column(sa.DateTime())
    ratelimit_quota = sa.Column(sa.Integer)
    _allowed_scopes = sa.Column(sa.Text)
    fs_uniquifier = sa.Column(sa.String(64), unique=True, nullable=False)

    @property
    def password(self):
        return self._password

    @password.setter
    def password(self, password):
        self._password = hash_password(password)

    password = sa.orm.synonym("_password", descriptor=password)

    @hybrid_property
    def is_bootstrap_user(self):
        return current_app.config["BOOTSTRAP_USER_EMAIL"] == self.email

    def validate_password(self, password) -> bool:
        return verify_password(password, self.password)


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
    user_id = sa.Column(sa.Integer, sa.ForeignKey("user.fs_uniquifier", ondelete="CASCADE"))
    ratelimit_multiplier = sa.Column(sa.Float, default=0.0)
    individual_ratelimit_multipliers = sa.Column(sa.JSON)

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
    user_id = sa.Column(sa.Integer, sa.ForeignKey("user.fs_uniquifier", ondelete="CASCADE"))
    user = relationship("User")
    client_id = sa.Column(sa.String(48), sa.ForeignKey("oauth2client.client_id"))
    client = relationship("OAuth2Client")
