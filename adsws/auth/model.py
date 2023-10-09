import sqlalchemy as sa
from flask import current_app
from flask_security import UserMixin
from flask_security.utils import hash_password, verify_password
from sqlalchemy.ext.hybrid import hybrid_property

from adsws.model import base_model


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
    ratelimit_level = sa.Column(sa.Integer)
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
