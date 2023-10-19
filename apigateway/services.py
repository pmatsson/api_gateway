""" Module defining API Gateway services. """
import datetime
import logging
import os
import time
from contextlib import suppress
from typing import Callable, Optional, Tuple, TypedDict, Union
from urllib.parse import urljoin

import requests
from authlib.integrations.flask_oauth2 import ResourceProtector
from authlib.integrations.sqla_oauth2 import create_bearer_token_validator
from flask import Flask, g, request
from flask.wrappers import Response
from flask_limiter import Limiter
from flask_limiter.extension import LimitDecorator
from flask_limiter.util import get_remote_address
from flask_login import current_user
from redis import Redis, StrictRedis
from sqlalchemy import func
from werkzeug.security import gen_salt

from apigateway.exceptions import NoClientError, ValidationError
from apigateway.models import OAuth2Client, OAuth2Token
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

        app.__setattr__(self._name.lower(), self)

    def get_service_config(self, key: str, default: any = None):
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

    def __init__(self, name: str = "AUTH_SERVICE"):
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

    def __init__(self, name: str = "PROXY_SERVICE"):
        super().__init__(name)

    def register_services(self):
        """Registers all services specified in the configuration file."""
        services = self.get_service_config("WEBSERVICES", {})
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
                self.get_service_config("DEFAULT_RATE_LIMIT", [1000, 86400]),
            )
            properties.setdefault("scopes", self.get_service_config("DEFAULT_SCOPES", []))
            properties.setdefault("authorization", True)

            # Create the view
            rule_name = local_path = os.path.join(deploy_path, remote_path[1:])
            proxy_view = ProxyView.as_view(rule_name, deploy_path, base_url)

            # Decorate view with the rate limiter service
            proxy_view = self._app.limiter_service.shared_limit(
                counts=properties["rate_limit"][0],
                per_second=properties["rate_limit"][1],
            )(proxy_view)

            # Decorate view with the auth service, unless explicitly disabled
            if properties["authorization"]:
                proxy_view = self._app.auth_service.require_oauth()(proxy_view)

            # Register the view with Flask
            self._app.add_url_rule(
                rule_name,
                endpoint=local_path,
                view_func=proxy_view,
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

        resource_url = urljoin(base_url, self.get_service_config("RESOURCE_ENDPOINT", "/"))

        try:
            response = requests.get(
                resource_url, timeout=self.get_service_config("RESOURCE_TIMEOUT", 5)
            )
            return response.json()
        except (requests.exceptions.ConnectionError, requests.exceptions.Timeout) as ex:
            raise ex


class LimiterService(GatewayService, Limiter):
    """A service that provides rate limiting functionality for API endpoints.

    This service extends the `GatewayService` and `Limiter` classes to provide rate limiting functionality
    for API endpoints. It defines methods for registering hooks to track request processing time and
    shared limits for rate limiting.

    """

    def __init__(self, name: str = "LIMITER_SERVICE"):
        """Initializes a new instance of the `LimiterService` class.

        Args:
            name (str, optional): The name of the service. Defaults to "LIMITER_SERVICE".
        """
        GatewayService.__init__(self, name)
        Limiter.__init__(self, key_func=self._key_func)
        self._symbolic_ratelimits = {}

    def init_app(self, app: Flask):
        """Initializes the service with the specified Flask application.

        This method initializes the service with the specified Flask application by setting default
        configuration values and registering hooks.

        Args:
            app (Flask): The Flask application to initialize the service with.
        """
        GatewayService.init_app(self, app)

        app.config.setdefault("RATELIMIT_STORAGE_URI", self.get_service_config("STORAGE_URI"))
        app.config.setdefault("RATELIMIT_STRATEGY", self.get_service_config("STRATEGY"))

        Limiter.init_app(self, app)

        self.register_hooks(app)

    def register_hooks(self, app: Flask):
        """Registers hooks for tracking request processing time.

        This method registers hooks for tracking request processing time before and after each request.

        Args:
            app (Flask): The Flask application to register the hooks with.
        """

        @app.before_request
        def _before_request_hook():
            g.request_start_time = time.time()

        @app.after_request
        def _after_request_hook(response: Response):
            processing_time: float = time.time() - g.request_start_time

            key: str = f"{self._name}//{request.endpoint}/time"

            existing_value: float = float(self._app.redis_service.get(key) or -1)
            if existing_value < 0:
                self._app.redis_service.set(key, processing_time)
            else:
                mean_value = (existing_value + processing_time) / 2
                self._app.redis_service.incrbyfloat(key, mean_value - existing_value)

            return response

    def shared_limit(
        self,
        limit_value: Optional[str] = None,
        counts: Optional[int] = None,
        per_second: Optional[int] = None,
        scope: Optional[str] = None,
        key_func: Optional[Callable[[], str]] = None,
        error_message: Optional[str] = None,
        exempt_when: Optional[Callable[[], bool]] = None,
        override_defaults: bool = True,
        deduct_when: Optional[Callable[[Response], bool]] = None,
        cost: Optional[Union[int, Callable[[], int]]] = None,
    ) -> LimitDecorator:
        """Decorator to be applied to multiple routes sharing the same rate limit.

        Args:
            limit_value (Optional[str], optional): The limit value for the rate limit. Either this or
                counts and per_second must be provided. Defaults to None.
            counts (Optional[int], optional): The number of counts for the rate limit. Defaults to None.
            per_second (Optional[int], optional): The number of counts per second for the rate limit.
                Defaults to None.
            scope (Optional[str], optional): The scope of the rate limit. Defaults to None.
            key_func (Optional[Callable[[], str]], optional): The key function for the rate limit.
                Defaults to None.
            error_message (Optional[str], optional): The error message for the rate limit. Defaults to None.
            exempt_when (Optional[Callable[[], bool]], optional): The exempt when function for the rate
                limit. Defaults to None.
            override_defaults (bool, optional): Whether to override the default values for the rate limit.
                Defaults to True.
            deduct_when (Optional[Callable[[Response], bool]], optional): The deduct when function for
                the rate limit. Defaults to None.
            cost (Optional[Union[int, Callable[[], int]]], optional): The cost function for the rate limit.
                Defaults to None.

        Raises:
            ValueError: If neither limit_value nor counts and per_second are provided.

        Returns:
            LimitDecorator: The rate limit decorator.
        """
        if limit_value is None and (counts is None or per_second is None):
            raise ValueError("Either limit_value or counts and per_second must be provided")

        return Limiter.shared_limit(
            self,
            limit_value if limit_value else lambda: self.calculate_limit_value(counts, per_second),
            scope if scope else self._scope_func,
            key_func=key_func if key_func else self._key_func,
            error_message=error_message,
            exempt_when=exempt_when,
            override_defaults=override_defaults,
            deduct_when=deduct_when,
            cost=cost if cost else self._cost_func,
        )

    def calculate_limit_value(self, counts: int, per_second: int) -> str:
        """Calculates the limit string for the specified counts and per second values.

        Args:
            counts (int): The maximum number of requests allowed per `per_second`.
            per_second (int): The time window in seconds for the rate limit.
        Returns:
            str: The limit string value for the rate limit.
        """
        factor = 1
        with suppress(AttributeError):
            factor = request.oauth.client.ratelimit

        if request.endpoint in self._symbolic_ratelimits:
            counts: int = self._symbolic_ratelimits[request.endpoint]["count"]
            per_second: int = self._symbolic_ratelimits[request.endpoint]["per_second"]

        return "{0}/{1} second".format(int(counts * factor), per_second)

    def _cost_func(self) -> int:
        """Calculates the cost for the rate limit.

        This method calculates the cost for the rate limit based on the processing time of the request.

        Returns:
            int: The cost for the rate limit.
        """
        processing_time_seconds = float(
            self._app.redis_service.get(f"{self._name}//{request.endpoint}/time") or 0
        )

        return 1 if processing_time_seconds <= 1 else int(2 ** (processing_time_seconds - 1))

    def _key_func(self) -> str:
        """Returns the key for the rate limit.

        This method returns the key for the rate limit based on the API endpoint.

        Returns:
            str: The key for the rate limit.
        """
        if request.endpoint in self._symbolic_ratelimits:
            return self._symbolic_ratelimits[request.endpoint]["key"]
        return request.endpoint

    def _scope_func(self, endpoint_name: str) -> str:
        """Returns the scope for the rate limit.

        This method returns the scope for the rate limit based on the OAuth user.
        If the user coild not be determined the remote address is used.

        Args:
            endpoint_name (str): The name of the API endpoint.

        Returns:
            str: The scope for the rate limit.
        """
        if hasattr(request, "oauth") and request.oauth.client:
            return "{email}:{client}".format(
                email=request.oauth.user.email, client=request.oauth.client.client_id
            )

        elif current_user.is_authenticated and not current_user.is_bootstrap_user:
            return "{email}".format(email=current_user.email)

        else:
            return get_remote_address()


class RedisService(GatewayService):
    """A service class for interacting with a Redis database.

    Args:
        name (str): The name of the service.
        strict (bool): Whether to use strict Redis or not.
        **kwargs: Additional keyword arguments to pass to the Redis client.

    """

    def __init__(self, name: str = "REDIS_SERVICE", strict: bool = True, **kwargs):
        super().__init__(name)
        self._redis_client = None
        self._provider_class = StrictRedis if strict else Redis
        self._provider_kwargs = kwargs

    def init_app(self, app: Flask):
        super().init_app(app)

        redis_url = self.get_service_config("URL", "redis://localhost:6379/0")
        self._redis_client = self._provider_class.from_url(redis_url, **self._provider_kwargs)

    def get_connection_pool(self):
        if self._redis_client:
            return self._redis_client.connection_pool
        else:
            return None

    def __getattr__(self, name):
        return getattr(self._redis_client, name, None)

    def __getitem__(self, name):
        return self._redis_client[name]

    def __setitem__(self, name, value):
        self._redis_client[name] = value

    def __delitem__(self, name):
        del self._redis_client[name]
