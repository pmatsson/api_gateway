""" Module defining API Gateway services. """
import datetime
import logging
import os
from typing import Tuple, TypedDict
from urllib.parse import urljoin

import requests
from authlib.integrations.flask_oauth2 import ResourceProtector
from authlib.integrations.sqla_oauth2 import create_bearer_token_validator
from flask import Flask
from flask_login import current_user
from sqlalchemy import func
from werkzeug.security import gen_salt

from apigateway.exceptions import NoClientError, ValidationError
from apigateway.model import OAuth2Client, OAuth2Token
from apigateway.views import ProxyView


class GatewayService:
    """Base class for initializing a service, setting up logging and config."""

    def __init__(self, name: str, app: Flask = None):
        self._name = name
        if app is not None:
            self.init_app(app)

    def init_app(self, app: Flask):
        """_summary_

        Args:
            app (Flask): _description_
        """
        if app is None:
            return

        self._app = app
        self._logger = logging.getLogger(f"{app.name}.{self._name}")

        if not hasattr(app, "extensions"):
            app.extensions = {}

        app.extensions[self._name.lower()] = self

        app.__setattr__(f"{self._name.lower()}_service", self)

    def get_config(self, key: str, default: any = None):
        """_summary_

        Args:
            key (str): _description_
            default (any, optional): _description_. Defaults to None.

        Returns:
            _type_: _description_
        """
        return self._app.config.get(self._name + "_" + key, default)


class AuthService(GatewayService):
    """A class that provides authentication services for the API Gateway."""

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


class ProxyService(GatewayService):
    """A class for registering remote webservices and resources with the Flask application."""

    def __init__(self, auth_service: GatewayService, name: str = "PROXY"):
        super().__init__(name)
        self.auth_service = auth_service

    def register_services(self):
        """Registers all services specified in the configuration file."""
        services = self.get_config("WEBSERVICES", {})
        for url, deploy_path in services.items():
            self.register_service(url, deploy_path)

    def register_service(self, base_url: str, deploy_path: str):
        """Registers a single service with the Flask application

        Args:
            base_url (str): The base URL of the service.
            deploy_path (str): The deployment path of the service
        """
        self._logger.info("Registering service %s at %s", base_url, deploy_path)

        try:
            resource_json = self._fetch_resource_document(base_url)
        except requests.exceptions.RequestException as ex:
            self._logger.error("Could not fetch resource document for %s: %s", base_url, ex)
            return

        for remote_path, properties in resource_json.items():
            self._logger.debug("Registering resource %s", remote_path)

            properties.setdefault(
                "rate_limit",
                self.get_config("DEFAULT_RATE_LIMIT", [1000, 86400]),
            )
            properties.setdefault("scopes", self.get_config("DEFAULT_SCOPES", []))

            rule_name = local_path = os.path.join(deploy_path, remote_path[1:])
            self._app.add_url_rule(
                rule_name,
                endpoint=local_path,
                view_func=self.auth_service.require_oauth()(
                    ProxyView.as_view(rule_name, deploy_path, base_url)
                ),
                methods=properties["methods"],
            )

    def _fetch_resource_document(self, base_url: str) -> TypedDict:
        """
        Fetches the resource document for a given base URL.

        Args:
            base_url (str): The base URL of the service.

        Returns:
            A dictionary containing the resource document.
        """

        resource_url = urljoin(base_url, self.get_config("RESOURCE_ENDPOINT", "/"))

        try:
            response = requests.get(resource_url, timeout=self.get_config("RESOURCE_TIMEOUT", 5))
            return response.json()
        except (requests.exceptions.ConnectionError, requests.exceptions.Timeout) as ex:
            raise ex
