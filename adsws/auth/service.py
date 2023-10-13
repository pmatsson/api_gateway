"""
This module defines the AuthService class, which is responsible for handling authentication and authorization
for the ADSWS application. It provides methods for loading clients and tokens, as well as bootstrapping users
and creating temporary tokens.
"""
import datetime
from typing import Tuple

from authlib.integrations.flask_oauth2 import ResourceProtector
from authlib.integrations.sqla_oauth2 import create_bearer_token_validator
from flask import Flask
from flask_login import current_user
from sqlalchemy import func
from werkzeug.security import gen_salt

from adsws.auth.oauth2.model import OAuth2Client, OAuth2Token
from adsws.exceptions import NoClientError, ValidationError
from adsws.service import ADSWSService


class AuthService(ADSWSService):
    """A class that provides authentication services for ADSWS."""

    def __init__(self, name: str = "AUTH"):
        """Initializes the AuthService.

        Args:
            name (str, optional): The name of the AuthService. Defaults to "AUTH".
        """
        super().__init__(name)
        self.require_oauth = ResourceProtector()

    def init_app(self, app: Flask):
        """Initializes the AuthService with the Flask app.

        Args:
            app (Flask): The Flask app to initialize the AuthService with.
        """
        super().init_app(app)
        bearer_cls = create_bearer_token_validator(app.db.session, OAuth2Token)
        self.require_oauth.register_token_validator(bearer_cls())

    def load_client(self, client_id: str) -> Tuple[OAuth2Client, OAuth2Token]:
        """Loads the OAuth2Client and OAuth2Token for the given client_id.

        Args:
            client_id (str): The ID of the client to load.

        Raises:
            NoClientError: If the client with the given ID is not found.

        Returns:
            Tuple[OAuth2Client, OAuth2Token]: A tuple containing the OAuth2Client and OAuth2Token for the given client_id.
        """
        client = OAuth2Client.query.filter_by(client_id=client_id).first()

        if client is None:
            raise NoClientError(f"Client {client_id} not found")

        token = OAuth2Token.query.filter_by(client_id=client_id).first()

        if token is None:
            token = self._create_temporary_token(client)

        return client, token

    def bootstrap_user(
        self,
        client_name: str = None,
        scope: str = None,
        ratelimit: float = 1.0,
        expires: datetime.datetime = datetime.datetime(2500, 1, 1),
        create_client: bool = False,
    ) -> Tuple[OAuth2Client, OAuth2Token]:
        """Bootstraps a user with an OAuth2Client and OAuth2Token.

        Args:
            client_name (type, optional): The name of the client. Defaults to None.
            scopes (type, optional): The scopes for the client. Defaults to None.
            ratelimit (float, optional): The ratelimit for the client. Defaults to 1.0.
            expires (type, optional): The expiration date for the token. Defaults to datetime.datetime(2500, 1, 1).
            create_client (bool, optional): Whether to create a new client or not. Defaults to False.

        Returns:
            Tuple[OAuth2Client, OAuth2Token]: A tuple containing the OAuth2Client and OAuth2Token for the user.
        """
        if current_user.is_bootstrap_user:
            return self.bootstrap_anonymous_user()

        self._check_ratelimit(ratelimit)
        client_name = client_name or self._app.config.get("BOOTSTRAP_CLIENT_NAME", "BB client")

        clients = (
            OAuth2Client.query.filter_by(user_id=current_user.get_id())
            .order_by(OAuth2Client.client_id_issued_at.desc())
            .all()
        )

        # Metadata is a computed property so we need to filter after the query
        client = next((c for c in clients if c.client_name == client_name), None)

        if client is None or create_client:
            client = OAuth2Client(user_id=current_user.get_id())
            client.set_client_metadata({"client_name": client_name, "description": client_name})

            client.gen_salt()
            self._app.db.session.add(client)

            token = self._create_user_token(client, expires=expires)
            self._app.db.session.add(token)

            self._logger.info("Created BB client for {email}".format(email=current_user.email))
        else:
            token = OAuth2Token.query.filter_by(
                client_id=client.client_id,
                user_id=current_user.get_id(),
            ).first()

            if token is None:
                token = self._create_user_token(client, expires=expires)

                self._app.db.session.add(token)
                self._logger.info("Created BB client for {email}".format(email=current_user.email))

        self._app.db.session.commit()

        return client, token

    def bootstrap_anonymous_user(self) -> Tuple[OAuth2Client, OAuth2Token]:
        """Bootstraps an anonymous user with an OAuth2Client and OAuth2Token.

        Raises:
            ValidationError: If the current user is not an anonymous bootstrap user.

        Returns:
            Tuple[OAuth2Client, OAuth2Token]: A tuple containing the OAuth2Client and OAuth2Token for the anonymous user.
        """
        if not current_user.is_bootstrap_user:
            raise ValidationError("Only anonymous bootstrap user can create temporary tokens")

        client = OAuth2Client(
            user_id=current_user.get_id(),
        )

        client.gen_salt()
        token = self._create_temporary_token(client)

        self._app.db.session.add(client)
        self._app.db.session.add(token)
        self._app.db.session.commit()

        return client, token

    def _create_user_token(
        self,
        client: OAuth2Client,
        expires=datetime.datetime(2500, 1, 1),
    ) -> OAuth2Token:
        """Creates an OAuth2Token for the given OAuth2Client.

        Args:
            client (OAuth2Client): The OAuth2Client to create the token for.
            expires (type, optional): The expiration date for the token. Defaults to datetime.datetime(2500, 1, 1).

        Returns:
            OAuth2Token: The created OAuth2Token.
        """
        salt_length = self._app.config.get("OAUTH2_CLIENT_ID_SALT_LEN", 40)

        token = OAuth2Token(
            client_id=client.client_id,
            user_id=client.user_id,
            access_token=gen_salt(salt_length),
            refresh_token=gen_salt(salt_length),
        )

        return token

    def _create_temporary_token(self, client: OAuth2Client) -> OAuth2Token:
        """Creates a temporary OAuth2Token for the given OAuth2Client.

        Args:
            client (OAuth2Client): The OAuth2Client to create the token for.

        Raises:
            ValidationError: If the current user is not an anonymous bootstrap user.

        Returns:
            OAuth2Token: The created temporary OAuth2Token.
        """
        if not current_user.is_bootstrap_user:
            raise ValidationError("Only bootstrap user can create temporary tokens")

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

    def _check_ratelimit(self, ratelimit: float):
        """
        Check if the current user has enough capacity to create a new client.

        Args:
            ratelimit (float): The amount of capacity requested for the new client.

        Raises:
            ValidationError: If the current user account does not have enough capacity to create a new client.
        """
        allowed_limit = current_user.ratelimit_level or 2.0
        if allowed_limit == -1:
            return

        used = (
            self._app.db.session.query(func.sum(OAuth2Client.ratelimit).label("sum"))
            .filter(OAuth2Client.user_id == current_user.get_id())
            .first()[0]
            or 0.0
        )

        if allowed_limit - (used + ratelimit) < 0:
            raise ValidationError(
                "The current user account (%s) does not have enough capacity to create a new client. Requested: %s, Available: %s"
                % (current_user.email, ratelimit, allowed_limit - used)
            )
