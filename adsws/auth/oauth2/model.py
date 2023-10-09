import sqlalchemy as sa
from flask import current_app
from werkzeug.security import gen_salt
from sqlalchemy.orm import relationship
from authlib.integrations.sqla_oauth2 import OAuth2ClientMixin, OAuth2TokenMixin
from adsws.model import base_model


class OAuth2Client(base_model, OAuth2ClientMixin):
    __tablename__ = "oauth2client"

    id = sa.Column(sa.Integer, primary_key=True, autoincrement=True)
    user_id = sa.Column(sa.Integer, sa.ForeignKey("user.fs_uniquifier", ondelete="CASCADE"))
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
