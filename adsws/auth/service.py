from adsws.service import ADSWSService
from flask import Flask
import datetime
from flask_login import current_user
from werkzeug.security import gen_salt
from authlib.integrations.flask_oauth2 import ResourceProtector
from adsws.auth.oauth2.model import OAuth2Token, OAuth2Client
from adsws.exceptions import NoClientError
from authlib.integrations.sqla_oauth2 import (
    create_bearer_token_validator,
)


class AuthService(ADSWSService):
    def __init__(self, name: str = "AUTH"):
        super().__init__(name)
        self.require_oauth = ResourceProtector()

    def init_app(self, app: Flask):
        super().init_app(app)
        bearer_cls = create_bearer_token_validator(app.db.session, OAuth2Token)
        self.require_oauth.register_token_validator(bearer_cls())

    def load_client(self, client_id: str):
        client = OAuth2Client.query.filter_by(client_id=client_id).first()

        if client is None:
            raise NoClientError(f"Client {client_id} not found")

        token = OAuth2Token.query.filter_by(client_id=client_id).first()

        if token is None:
            token = self.create_temporary_token(client)

        return client, token

    def bootstrap_anon_user(self):
        if not current_user.is_bootstrap_user:
            raise Exception("Only bootstrap user can create temporary tokens")

        # client_name = self._app.config.get('BOOTSTRAP_CLIENT_NAME', 'BB client')
        # scopes = ''.join(self._app.config.get('BOOTSTRAP_SCOPES', []))

        client = OAuth2Client(
            user_id=current_user.get_id(),
            # name=client_name,
            # description=client_name,
            # is_confidential=False,
            # is_internal=True,
            # _default_scopes=scopes,
            # ratelimit=1.0
        )

        client.gen_salt()
        token = self.create_temporary_token(client)

        self._app.db.session.add(client)
        self._app.db.session.add(token)
        self._app.db.session.commit()

        return client, token

    def create_temporary_token(self, client: OAuth2Client):
        if not current_user.is_bootstrap_user:
            raise Exception("Only bootstrap user can create temporary tokens")

        salt_length = self._app.config.get("OAUTH2_CLIENT_ID_SALT_LEN", 40)
        expires = self._app.config.get("BOOTSTRAP_TOKEN_EXPIRES", 3600 * 24)

        if isinstance(expires, int):
            expires = datetime.datetime.utcnow() + datetime.timedelta(seconds=expires)

        return OAuth2Token(
            client_id=client.client_id,
            user_id=client.user_id,
            # expires=expires,
            access_token=gen_salt(salt_length),
            refresh_token=gen_salt(salt_length),
        )
