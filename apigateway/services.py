""" Module defining API Gateway services. """

import hashlib
import json
import logging
import os
import re
import time
from datetime import datetime
from functools import wraps
from typing import Callable, Tuple
from urllib.parse import urljoin

import requests
from authlib.integrations.flask_oauth2 import current_token, token_authenticated
from authlib.integrations.sqla_oauth2 import create_bearer_token_validator
from cachelib.serializers import RedisSerializer
from flask import Flask, g, request
from flask.wrappers import Response
from flask_caching import Cache
from flask_limiter import Limiter
from flask_limiter.extension import LimitDecorator
from flask_limiter.util import get_remote_address
from flask_login import current_user
from flask_security import Security, SQLAlchemyUserDatastore
from itsdangerous import URLSafeTimedSerializer
from kafka import KafkaProducer
from redis import Redis, StrictRedis
from redis.exceptions import ConnectionError, TimeoutError
from sqlalchemy import func
from werkzeug.datastructures import Headers
from werkzeug.security import gen_salt

from apigateway import extensions
from apigateway.exceptions import NoClientError, NotFoundError, ValidationError
from apigateway.models import AnonymousUser, OAuth2Client, OAuth2Token, Role, User
from apigateway.utils import GatewayResourceProtector, ProxyView


class GatewayService:
    """Base class for initializing a service, setting up logging and config."""

    def __init__(self, name: str, app: Flask = None):
        self._name = name
        if app is not None:
            self.init_app(app)

    def init_app(self, app: Flask):
        """Initializes the application with this service.

        Args:
            app (Flask): The Flask application to initialize.
        """
        if app is None:
            return

        self._logger = logging.getLogger(f"{app.name}.{self._name}")

        if not hasattr(app, "extensions"):
            app.extensions = {}

        app.extensions[self._name.lower()] = self

        app.__setattr__(self._name.lower(), self)

        self._app = app

    def get_service_config(self, key: str, default: any = None) -> any:
        """Get the value of a configuration setting for this service.
        The name of the service is prepended to the key to form the full configuration key.

        Args:
            key (str): The name of the configuration setting to retrieve.
            default (any, optional): The default value to return if the configuration setting is not found. Defaults to None.

        Returns:
            any: The value of the configuration setting, or the default value if the setting is not found.
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
        self.require_oauth = GatewayResourceProtector()

    def init_app(self, app: Flask):
        """Initializes the AuthService with the Flask app.

        Args:
            app (Flask): The Flask app to initialize the AuthService with.
        """
        super().init_app(app)
        bearer_cls = create_bearer_token_validator(app.db.session, OAuth2Token)
        self.require_oauth.register_token_validator(bearer_cls())
        self._register_hooks(app)

    def _register_hooks(self, app: Flask):
        """Registers hooks that manipulates the headers of the request.

        Args:
            app (Flask): The Flask application to register the hooks with.
        """

        @app.before_request
        def before_request_hook():
            """Adds the X-api-uid header to the request if the user is authenticated with a session cookie."""
            headers = Headers(request.headers.items())
            if current_user.is_authenticated:
                headers.add_header("X-api-uid", current_user.id)
            elif "X-api-uid" in request.headers:
                headers.remove("X-api-uid")

            request.headers = headers

        def _token_authenticated(sender, token: OAuth2Token = None, **kwargs):
            """Adds the X-api-uid header to the request if the user is authenticated with an auth token"""

            if token.user:
                headers = Headers(request.headers.items())
                headers.add_header("X-api-uid", token.user.id)
                request.headers = headers

        token_authenticated.connect(_token_authenticated, weak=False)

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

        token = OAuth2Token.query.filter_by(client_id=client.id).first()

        if token is None or token.is_expired():
            token = self._create_temporary_token(client)
            extensions.db.session.add(token)

        client.last_activity = datetime.now()
        extensions.db.session.add(client)
        extensions.db.session.commit()

        return client, token

    def bootstrap_user(
        self,
        client_name: str = None,
        scope: str = None,
        ratelimit_multiplier: float = 1.0,
        expires: datetime = datetime(2050, 1, 1),
        create_client: bool = False,
        individual_ratelimit_multipliers: dict = None,
    ) -> Tuple[OAuth2Client, OAuth2Token]:
        """Bootstraps a user with an OAuth2Client and OAuth2Token.

        Args:
            client_name (type, optional): The name of the client. Defaults to None.
            scopes (type, optional): The scopes for the client. Defaults to None.
            ratelimit_multiplier (float, optional): The ratelimit factor for the client. Defaults to 1.0.
            expires (type, optional): The expiration date for the token. Defaults to datetime(2050, 1, 1).
            create_client (bool, optional): Whether to create a new client or not. Defaults to False.
            individual_ratelimit_multipliers (dict, optional): A dictionary of individual ratelimit multipliers for specific endpoints. Defaults to None.

        Returns:
            Tuple[OAuth2Client, OAuth2Token]: A tuple containing the OAuth2Client and OAuth2Token for the user.
        """
        if current_user.is_anonymous_bootstrap_user:
            return self.bootstrap_anonymous_user()

        client_name = client_name or self._app.config.get("BOOTSTRAP_CLIENT_NAME", "BB client")

        clients = (
            OAuth2Client.query.filter_by(user_id=current_user.get_id())
            .order_by(OAuth2Client.client_id_issued_at.desc())
            .all()
        )

        # Metadata is a computed property so we need to filter after the query
        client = next((c for c in clients if c.client_name == client_name), None)

        if client is None or create_client:
            self._validate_ratelimit(ratelimit_multiplier)
            self._validate_scopes(scope)

            client = OAuth2Client(
                user_id=current_user.get_id(),
                ratelimit_multiplier=ratelimit_multiplier,
                individual_ratelimit_multipliers=individual_ratelimit_multipliers,
                last_activity=datetime.now(),
            )
            client.set_client_metadata(
                {
                    "client_name": client_name,
                    "description": client_name,
                    "scope": scope or " ".join(self._app.config.get("USER_DEFAULT_SCOPES", "")),
                }
            )

            client.gen_salt()
            extensions.db.session.add(client)
            extensions.db.session.commit()

            token = self._create_user_token(client, expires=expires)
            extensions.db.session.add(token)

            self._logger.info("Created BB client for {email}".format(email=current_user.email))
        else:
            token = OAuth2Token.query.filter_by(
                client_id=client.id,
                user_id=current_user.get_id(),
            ).first()

            if token is None:
                token = self._create_user_token(client, expires=expires)

                extensions.db.session.add(token)
                self._logger.info("Created BB client for {email}".format(email=current_user.email))

            client.last_activity = datetime.now()
            extensions.db.session.add(client)

        extensions.db.session.commit()

        return client, token

    def bootstrap_anonymous_user(self) -> Tuple[OAuth2Client, OAuth2Token]:
        """Bootstraps an anonymous user with an OAuth2Client and OAuth2Token.

        Raises:
            ValidationError: If the current user is not an anonymous bootstrap user.

        Returns:
            Tuple[OAuth2Client, OAuth2Token]: A tuple containing the OAuth2Client and OAuth2Token for the anonymous user.
        """
        if not current_user.is_anonymous_bootstrap_user:
            raise ValidationError("Only anonymous bootstrap user can create temporary tokens")

        client = OAuth2Client(
            user_id=current_user.get_id(),
            last_activity=datetime.now(),
        )

        client.set_client_metadata(
            {
                "client_name": self._app.config.get("BOOTSTRAP_CLIENT_NAME", "BB client"),
                "description": "Anonymous client",
                "scope": " ".join(self._app.config.get("BOOTSTRAP_SCOPES", "")),
            }
        )

        client.gen_salt()
        extensions.db.session.add(client)
        extensions.db.session.commit()

        token = self._create_temporary_token(client)
        extensions.db.session.add(token)
        extensions.db.session.commit()

        return client, token

    def _create_user_token(
        self,
        client: OAuth2Client,
        expires=datetime(2050, 1, 1),
    ) -> OAuth2Token:
        """Creates an OAuth2Token for the given OAuth2Client.

        Args:
            client (OAuth2Client): The OAuth2Client to create the token for.
            expires (type, optional): The expiration date for the token. Defaults to datetime(2050, 1, 1).

        Returns:
            OAuth2Token: The created OAuth2Token.
        """
        salt_length = self._app.config.get("OAUTH2_CLIENT_ID_SALT_LEN", 40)

        token = OAuth2Token(
            token_type="bearer",
            client_id=client.id,
            user_id=client.user_id,
            access_token=gen_salt(salt_length),
            refresh_token=gen_salt(salt_length),
            scope=client.scope,
            expires_in=(expires - datetime.now()).total_seconds(),
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
        if not current_user.is_anonymous_bootstrap_user:
            raise ValidationError("Only bootstrap user can create temporary tokens")

        salt_length = self._app.config.get("OAUTH2_CLIENT_ID_SALT_LEN", 40)
        expires_in: int = self._app.config.get("BOOTSTRAP_TOKEN_EXPIRES", 3600 * 24)

        return OAuth2Token(
            token_type="bearer",
            client_id=client.id,
            user_id=client.user_id,
            access_token=gen_salt(salt_length),
            refresh_token=gen_salt(salt_length),
            scope=client.scope,
            expires_in=expires_in,
        )

    def _validate_ratelimit(self, requested_ratelimit: float):
        """
        Check if the current user has enough capacity to create a new client.

        Args:
            requested_ratelimit (float): The amount of capacity requested for the new client.

        Raises:
            ValidationError: If the current user account does not have enough capacity to create a new client.
        """
        quota = current_user.ratelimit_quota or 2.0
        if quota == -1:
            return

        used_ratelimit = (
            extensions.db.session.query(func.sum(OAuth2Client.ratelimit_multiplier).label("sum"))
            .filter(OAuth2Client.user_id == current_user.get_id())
            .first()[0]
            or 0.0
        )

        if quota - (used_ratelimit + requested_ratelimit) < 0:
            raise ValidationError(
                "The current user account (%s) does not have enough capacity to create a new client. Requested: %s, Available: %s"
                % (current_user.email, requested_ratelimit, quota - used_ratelimit)
            )

    def _validate_scopes(self, scopes: str):
        allowed_scopes = set(current_user.allowed_scopes)

        if "*" in allowed_scopes or scopes is None:
            return

        requested_scopes = set(scopes.split())

        if not allowed_scopes.issuperset(requested_scopes):
            raise ValidationError(
                "The current user account (%s) does not have the requested scopes. Requested: %s, Allowed: %s"
                % (current_user.email, requested_scopes, allowed_scopes)
            )


class ProxyService(GatewayService):
    """A class for registering remote webservices and resources with the Flask application."""

    def __init__(self, name: str = "PROXY_SERVICE"):
        super().__init__(name)

    def register_services(self):
        """Registers all services specified in the configuration file."""
        self.allowed_headers = self.get_service_config("ALLOWED_HEADERS", [])

        services = self.get_service_config("WEBSERVICES", {})
        for url, deploy_path in services.items():
            self.register_service(url, deploy_path)

        self._register_hooks(self._app)

    def _register_hooks(self, app: Flask):
        """Registers hooks that manipulate the response headers.

        Args:
            app (Flask): The Flask app to register hooks for.
        """

        @app.after_request
        def _after_request_hook(response: Response):
            filtered_headers = {
                key: value
                for key, value in response.headers.items()
                if key in self.allowed_headers
            }

            response.headers.clear()

            for key, value in filtered_headers.items():
                response.headers.add_header(key, value)

            return response

    def register_service(self, base_url: str, deploy_path: str, csrf_exempt: bool = True):
        """Registers a single service with the Flask application

        Args:
            base_url (str): The base URL of the service.
            deploy_path (str): The deployment path of the service
            csrf_exempt (bool, optional): Whether to exempt the services from CSRF protection. Defaults to True.
        """
        self._logger.info("Registering service %s at %s", base_url, deploy_path)

        try:
            resource_json = self._fetch_resource_document(base_url)
        except requests.exceptions.RequestException as ex:
            self._logger.error("Could not fetch resource document for %s: %s", base_url, ex)
            return

        self._logger.debug("Discovered %s endpoints:", deploy_path)
        for remote_path, properties in resource_json.items():
            self._logger.debug("- %s", remote_path)

            properties.setdefault(
                "rate_limit",
                self.get_service_config("DEFAULT_RATE_LIMIT", [1000, 86400]),
            )
            properties.setdefault("scopes", self.get_service_config("DEFAULT_SCOPES", []))
            properties.setdefault("authorization", True)
            properties.setdefault("cache", None)

            # Create the view
            rule_name = local_path = (
                deploy_path
                if remote_path == "/"
                else os.path.join(deploy_path, remote_path.rstrip("/")[1:])
            )
            proxy_view = ProxyView.as_view(rule_name, deploy_path, base_url)

            if csrf_exempt:
                extensions.csrf.exempt(proxy_view)

            # If configured by the webservice, decorate view with the cache service
            if properties["cache"] is not None:
                cache = properties["cache"]
                proxy_view = extensions.cache_service.cached(
                    timeout=cache.get("timeout", 60000),
                    include_query_parameters=cache.get("query_parameters", True),
                    excluded_parameters=cache.get("excluded_parameters", []),
                )(proxy_view)

            # Decorate view with the rate limiter service
            counts = properties["rate_limit"][0]
            per_second = properties["rate_limit"][1]
            proxy_view = extensions.limiter_service.shared_limit(
                counts=counts,
                per_second=per_second,
            )(proxy_view)

            extensions.limiter_service.group_endpoint(local_path, counts, per_second)

            # Decorate view with the auth service, unless explicitly disabled
            if properties["authorization"]:
                proxy_view = extensions.auth_service.require_oauth(properties["scopes"])(
                    proxy_view
                )

            # Register the view with Flask
            self._app.add_url_rule(
                rule_name,
                endpoint=local_path,
                view_func=proxy_view,
                methods=properties["methods"],
                provide_automatic_options=True,
            )

    def _fetch_resource_document(self, base_url: str) -> dict:
        """
        Fetches the resource document for a given base URL.

        Args:
            base_url (str): The base URL of the service.

        Returns:
            A dictionary containing the resource document.
        """

        resource_url = urljoin(base_url, self.get_service_config("RESOURCE_ENDPOINT", "/"))

        try:
            timeout = self.get_service_config("RESOURCE_TIMEOUT", 5)
            response = requests.get(resource_url, timeout=timeout)
            response.raise_for_status()

            extensions.storage_service.set(resource_url, response.json())
            return response.json()
        except requests.exceptions.RequestException as ex:
            if extensions.storage_service.has(resource_url):
                self._logger.debug("Using cached resource document for %s", resource_url)
                return extensions.storage_service.get(resource_url)
            else:
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
        Limiter.__init__(
            self, key_func=self._key_func, in_memory_fallback_enabled=True, auto_check=False
        )
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
        app.config.setdefault(
            "RATELIMIT_HEADERS_ENABLED", self.get_service_config("HEADERS_ENABLED", True)
        )

        Limiter.init_app(self, app)

        self._ratelimit_groups = self.get_service_config("GROUPS", {})

        self._register_hooks(app)

    def _register_hooks(self, app: Flask):
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

            key: str = f"{self._name}//{self._key_func()}/time"

            existing_value: float = float(extensions.storage_service.get(key) or -1)
            if existing_value < 0:
                extensions.storage_service.set(key, processing_time)
            else:
                mean_value = (existing_value + processing_time) / 2
                extensions.storage_service.incrbyfloat(key, mean_value - existing_value)

            return response

        def _token_authenticated(sender, token=None, **kwargs):
            client = OAuth2Client.query.filter_by(id=token.client_id).first()
            level = getattr(client, "ratelimit", 1.0) if client else 0.0
            headers = Headers(request.headers.items())
            headers.add_header("X-Adsws-Ratelimit-Level", str(level))
            request.headers = headers

        token_authenticated.connect(_token_authenticated, weak=False)

    def limit(
        self,
        limit_value: str = None,
        counts: int = None,
        per_second: int = None,
        scope: str = None,
        key_func: Callable[[], str] = None,
        error_message: str = None,
        exempt_when: Callable[[], bool] = None,
        override_defaults: bool = True,
        deduct_when: Callable[[Response], bool] = None,
        cost: int | Callable[[], int] = None,
    ):
        return self._limit_and_check(
            limit_value,
            counts,
            per_second,
            scope,
            key_func,
            error_message,
            exempt_when,
            override_defaults,
            deduct_when,
            cost,
            shared=False,
        )

    def shared_limit(
        self,
        limit_value: str = None,
        counts: int = None,
        per_second: int = None,
        scope: str = None,
        key_func: Callable[[], str] = None,
        error_message: str = None,
        exempt_when: Callable[[], bool] = None,
        override_defaults: bool = True,
        deduct_when: Callable[[Response], bool] = None,
        cost: int | Callable[[], int] = None,
    ):
        return self._limit_and_check(
            limit_value,
            counts,
            per_second,
            scope,
            key_func,
            error_message,
            exempt_when,
            override_defaults,
            deduct_when,
            cost,
            shared=True,
        )

    def group_endpoint(self, endpoint: str, counts: int, per_second: int):
        for group, values in self._ratelimit_groups.items():
            if any(re.match(pattern, endpoint) for pattern in values.get("patterns", [])):
                if group not in self._symbolic_ratelimits.keys():
                    self._symbolic_ratelimits[group] = {
                        "name": group,
                        "counts": values.get("counts", counts),
                        "per_second": values.get("per_second", per_second),
                    }

                self._logger.debug(f'"{endpoint}" added to limiter group "{group}"')
                self._symbolic_ratelimits[endpoint] = self._symbolic_ratelimits[group]
                break

    def clear_limits(self, request_endpoint: str, scope: str):
        if request_endpoint == "*":
            self._logger.info("Clearing all limits")
            self.reset()
        else:
            defaults, decorated = self.limit_manager.resolve_limits(self._app, request_endpoint)
            all_limits = list(defaults) + list(decorated)
            for limit in all_limits:
                key = limit.limit.key_for(request_endpoint, scope)
                self._logger.info("Clearing limit for key %s", key)
                self.storage.clear(key)

            extensions.storage_service.delete(
                f"{self._name}//{self._key_func(request_endpoint)}/time"
            )

    def _limit_and_check(
        self,
        limit_value: str = None,
        counts: int = None,
        per_second: int = None,
        scope: str = None,
        key_func: Callable[[], str] = None,
        error_message: str = None,
        exempt_when: Callable[[], bool] = None,
        override_defaults: bool = True,
        deduct_when: Callable[[Response], bool] = None,
        cost: int | Callable[[], int] = None,
        shared: bool = False,
    ):
        if limit_value is None and (counts is None or per_second is None):
            raise ValueError("Either limit_value or counts and per_second must be provided")

        def inner(func):
            LimitDecorator(
                self,
                limit_value=(
                    limit_value
                    if limit_value
                    else lambda: self._calculate_limit_value(counts, per_second)
                ),
                scope=scope if scope else self._scope_func,
                shared=shared,
                key_func=key_func if key_func else self._key_func,
                error_message=error_message,
                exempt_when=exempt_when,
                override_defaults=override_defaults,
                deduct_when=deduct_when,
                cost=cost if cost else self._cost_func,
            )(func)

            @wraps(func)
            def check(*args, **kwargs):
                self.check()
                return func(*args, **kwargs)

            return check

        return inner

    def _calculate_limit_value(self, counts: int, per_second: int) -> str:
        """Calculates the limit string for the specified counts and per second values.

        This function is called on each request which is why it is possible to have individual
        rate limits for each user.

        Args:
            counts (int): The maximum number of requests allowed per `per_second`.
            per_second (int): The time window in seconds for the rate limit.
        Returns:
            str: The limit string value for the rate limit.
        """
        client = getattr(current_token, "client", None)
        multiplier = getattr(client, "ratelimit_multiplier", 1.0)
        individual_multipliers = getattr(client, "individual_ratelimit_multipliers", None)

        if individual_multipliers:
            multiplier = next(
                (
                    value
                    for pattern, value in individual_multipliers.items()
                    if re.match(pattern, request.endpoint)
                ),
                multiplier,
            )

        if request.endpoint in self._symbolic_ratelimits:
            counts: int = self._symbolic_ratelimits[request.endpoint]["counts"]
            per_second: int = self._symbolic_ratelimits[request.endpoint]["per_second"]

        return "{0}/{1} second".format(int(counts * multiplier), per_second)

    def _cost_func(self) -> int:
        """Calculates the cost for the rate limit.

        This method calculates the cost for the rate limit based on the processing time of the request.

        Returns:
            int: The cost for the rate limit.
        """
        processing_time_seconds = float(
            extensions.storage_service.get(f"{self._name}//{self._key_func()}/time") or 0
        )

        return 1 if processing_time_seconds <= 1 else int(2 ** (processing_time_seconds - 1))

    def _key_func(self, request_endpoint=None) -> str:
        """Returns the key for the rate limit.

        This method returns the key for the rate limit based on the API endpoint.

        Returns:
            str: The key for the rate limit.
        """

        request_endpoint = request_endpoint or request.endpoint

        if request_endpoint in self._symbolic_ratelimits:
            return self._symbolic_ratelimits[request_endpoint]["name"]
        return request_endpoint

    def _scope_func(self, endpoint_name: str) -> str:
        """Returns the scope for the rate limit.

        This method returns the scope for the rate limit based on the OAuth user.
        If the user coild not be determined the remote address is used.

        Args:
            endpoint_name (str): The name of the API endpoint.

        Returns:
            str: The scope for the rate limit.
        """
        if current_token:
            return "{email}:{client}".format(
                email=current_token.user.email, client=current_token.client_id
            )

        elif current_user.is_authenticated and not current_user.is_anonymous_bootstrap_user:
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

        redis_url = self.get_service_config("URL", "redis://redis:6379/0")
        self._redis_client = self._provider_class.from_url(redis_url, **self._provider_kwargs)

    def alive(self) -> bool:
        """Checks if the Redis database is alive.

        Returns:
            bool: True if the Redis database is alive, False otherwise.
        """
        try:
            return self._redis_client.ping()
        except:  # noqa
            return False

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


class StorageService(GatewayService):
    """A service class for interacting with storage.

    This class provides methods for setting, getting, deleting, and incrementing values in storage.
    It supports both Redis storage and fallbacks to memory storage in case Redis is down.
    """

    def __init__(self, name: str = "STORAGE_SERVICE"):
        super().__init__(name)
        self._fallback_storage: dict = {}

    def init_app(self, app: Flask, redis_service: RedisService):
        super().init_app(app)
        self._redis_service = redis_service
        self._redis_down = False
        self._serializer = RedisSerializer()

    def _serialize(self, value: any) -> str | bytes:
        """Serializes the given value.

        Args:
            value (any): The value to serialize.

        Returns:
            str | bytes: The serialized value.
        """
        if isinstance(value, (int, float, str)):
            return str(value)
        else:
            return self._serializer.dumps(value)

    def _transfer_to_redis(self):
        """
        Transfers the data from the fallback storage to Redis.

        This method iterates over the items in the fallback storage and transfers them to Redis.
        After the transfer is complete, the fallback storage is cleared.
        """
        for key, value in self._fallback_storage.items():
            if isinstance(value, dict):
                value = json.dumps(value)
            self._redis_service.set(key, self._serialize(value))
        self._fallback_storage.clear()

    def handle_redis_exception(func):
        def wrapper(self, *args, **kwargs):
            if self._redis_down and self._redis_service.alive():
                self._redis_down = False
                self._logger.info("Redis is back up, transferring data from fallback storage")
                self._transfer_to_redis()

            try:
                return func(self, *args, **kwargs)
            except (ConnectionError, TimeoutError):
                self._redis_down = True
                self._logger.warning("Redis is down, falling back to local storage")
                return func(self, *args, **kwargs)
            except Exception as ex:
                self._logger.error("Failed to handle Redis exception", ex)
                raise

        return wrapper

    @handle_redis_exception
    def set(self, key: str, value: str, timeout: int = None) -> bool:
        if not self._redis_down:
            value = self._serialize(value)

            if timeout is None:
                return bool(self._redis_service.set(key, value))
            else:
                return bool(self._redis_service.setex(key, timeout, value))
        else:
            self._fallback_storage[key] = value
            return True

    @handle_redis_exception
    def get(self, key: str) -> str:
        if not self._redis_down:
            value = self._redis_service.get(key)

            if value is not None:
                value = self._serializer.loads(value)

            return value
        else:
            return self._fallback_storage.get(key)

    @handle_redis_exception
    def delete(self, key: str) -> bool:
        if not self._redis_down:
            return bool(self._redis_service.delete(key))
        else:
            return bool(self._fallback_storage.pop(key, None))

    @handle_redis_exception
    def incr(self, key: str) -> int:
        if not self._redis_down:
            return self._redis_service.incr(key)
        else:
            self._fallback_storage[key] = self._fallback_storage.get(key, 0) + 1
            return self._fallback_storage[key]

    @handle_redis_exception
    def incrby(self, key: str, increment: int) -> int:
        if not self._redis_down:
            return self._redis_service.incrby(key, increment)
        else:
            self._fallback_storage[key] = self._fallback_storage.get(key, 0) + increment
            return self._fallback_storage[key]

    @handle_redis_exception
    def incrbyfloat(self, key: str, increment: float) -> float:
        if not self._redis_down:
            return self._redis_service.incrbyfloat(key, increment)
        else:
            self._fallback_storage[key] = self._fallback_storage.get(key, 0.0) + increment
            return self._fallback_storage[key]

    @handle_redis_exception
    def has(self, key: str) -> bool:
        if not self._redis_down:
            return bool(self._redis_service.exists(key))
        else:
            return key in self._fallback_storage


class CacheService(GatewayService, Cache):
    """A service class that provides caching functionality for the API Gateway."""

    def __init__(self, name: str = "CACHE_SERVICE"):
        GatewayService.__init__(self, name)
        Cache.__init__(self)

    def init_app(self, app: Flask):
        GatewayService.init_app(self, app)

        app.config.setdefault("CACHE_REDIS_URL", self.get_service_config("REDIS_URI"))
        app.config.setdefault("CACHE_TYPE", self.get_service_config("CACHE_TYPE", "RedisCache"))

        Cache.init_app(self, app)

    def clear_cache(self, request_path: str, parameters: dict) -> bool:
        """Clears the cache for the specified request path and parameters.

        Args:
            request_path (str): The request path.
            parameters (dict): The request parameters used to construct the cache key.

        Returns:
            bool: True if the cache is cleared successfully, False otherwise.
        """
        if request_path == "*":
            self._logger.info("Clearing all cache")
            return self.clear()

        params_tuple = list(parameters.items()) if parameters else []
        key = self._make_cache_key(request_path, params_tuple)
        self._logger.info("Clearing cache for key %s", key)
        return self.delete(key)

    def cached(
        self,
        timeout: int = None,
        unless: int = None,
        forced_update: int = None,
        response_filter: int = None,
        include_query_parameters: bool = True,
        excluded_parameters: list = [],
    ) -> Callable:
        """
        Decorator that caches the response of a function/method.

        Args:
            timeout (int, optional): The cache timeout in seconds. Defaults to None.
            unless (int, optional): The cache will not be used if the function/method returns a value equal to this parameter. Defaults to None.
            forced_update (int, optional): The cache will be forcibly updated if the function/method returns a value equal to this parameter. Defaults to None.
            response_filter (int, optional): The cache will be filtered using this parameter. Defaults to None.
            include_query_parameters (bool, optional): Determines whether to include query parameters in the cache key. Defaults to True.
            excluded_parameters (list, optional): List of parameters to exclude from the cache key. Defaults to [].

        Returns:
            Callable: The decorated function/method.
        """
        return Cache.cached(
            self,
            timeout=timeout,
            unless=unless,
            forced_update=forced_update,
            response_filter=response_filter,
            make_cache_key=lambda *args, **kwargs: self._make_cache_key_from_request(
                include_query_parameters, excluded_parameters
            ),
        )

    def _make_cache_key_from_request(
        self, include_query_parameters: bool, excluded_parameters: list
    ) -> str:
        """
        Generate a cache key based on the request.

        Args:
            include_query_parameters (bool): Flag indicating whether to include query parameters in the cache key.
            excluded_parameters (list): List of query parameters to exclude from the cache key.

        Returns:
            str: The generated cache key.
        """
        request_params = []
        if include_query_parameters:
            request_params = sorted(
                (k, v) for (k, v) in request.args.items(multi=True) if k not in excluded_parameters
            )

        return self._make_cache_key(request.path, request_params)

    def _make_cache_key(
        self,
        request_path: str,
        request_params: list[tuple[str, str]] = None,
        hash_method: Callable = hashlib.md5,
    ) -> str:
        """Generate a cache key for the given request.

        Args:
            request_path (str): The path of the request.
            request_params (list[tuple[str, str]], optional): The parameters of the request. Defaults to None.
            hash_method (Callable, optional): The hash method to use. Defaults to hashlib.md5.

        Returns:
            str: The generated cache key.
        """
        cache_key = "view/%s" % request_path

        if request_params:
            args_as_bytes = str(request_params).encode()
            cache_arg_hash = hash_method(args_as_bytes)
            cache_arg_hash = str(cache_arg_hash.hexdigest())

            cache_key += "/{}".format(cache_arg_hash)

        return cache_key


class SecurityService(GatewayService, Security):
    """A service for managing user authentication and authorization.

    This service provides methods for creating and managing users and roles, changing passwords and email addresses,
    and generating and verifying email verification tokens.


    """

    def __init__(self, name: str = "SECURITY_SERVICE"):
        GatewayService.__init__(self, name)
        Security.__init__(self, register_blueprint=False)

    def init_app(self, app: Flask):
        GatewayService.init_app(self, app)
        app.config.setdefault(
            "SECURITY_PASSWORD_HASH", self.get_service_config("PASSWORD_HASH", "pbkdf2_sha512")
        )
        app.config.setdefault(
            "SECURITY_PASSWORD_SALT",
            self.get_service_config("PASSWORD_SALT", app.config.get("SECRET_KEY")),
        )
        app.config.setdefault("SECURITY_STATIC_FOLDER", None)

        Security.init_app(
            self,
            app,
            datastore=SQLAlchemyUserDatastore(app.db, User, Role),
            anonymous_user=AnonymousUser,
        )

        self._token_serializer = URLSafeTimedSerializer(self.get_service_config("SECRET_KEY"))

    def create_user(self, email: str, password: str, **kwargs) -> User:
        """Creates a new user with the specified email and password.

        Args:
            email (str): The email of the user.
            password (str): The password of the user.
            roles (list, optional): The roles of the user. Defaults to None.
            kwargs (dict): Additional keyword arguments to pass to the user.

        Raises:
            ValueError: If the email or password is invalid.

        Returns:
            User: The created user.
        """

        email = self._mail_util.validate(email)
        pbad, password = self._password_util.validate(password, True)

        if pbad is not None:
            raise ValueError(", ".join(pbad))

        # Passwords are hashed in the setter of the model. No need to do it here.
        user = self.datastore.create_user(email=email, password=password, **kwargs)
        self.datastore.commit()

        return user

    def create_role(self, name: str, description: str = None, **kwargs) -> Role:
        """Creates a new role with the specified name and description.

        Args:
            name (str): The name of the role.
            description (str, optional): The description of the role. Defaults to None.
            kwargs (dict): Additional keyword arguments to pass to the role.

        Returns:
            Role: The created role.
        """
        role = self.datastore.create_role(name=name, description=description, **kwargs)
        self.datastore.commit()
        return role

    def add_role_to_user(self, user: User, role: Role) -> bool:
        """Adds the specified role to the specified user.

        Args:
            user (User): The user to add the role to.
            role (Role): The role to add to the user.

        Returns:
            bool: True if the role was added successfully, False otherwise.
        """
        if self.datastore.add_role_to_user(user, role):
            self.datastore.commit()
            return True
        else:
            return False

    def change_password(self, user: User, password: str) -> User:
        """
        Change the password for a given user.

        Args:
            user (User): The user object for which to change the password.
            password (str): The new password to set for the user.

        Raises:
            ValueError: If the new password is invalid.

        Returns:
            User: The updated user object.
        """
        pbad, password = self._password_util.validate(password, True)

        if pbad is not None:
            raise ValueError(", ".join(pbad))

        user = self.datastore.db.session.merge(user)
        user.password = password
        self.datastore.commit()

        return user

    def validate_email(self, email: str) -> bool:
        """
        Validate an email address.

        Args:
            email (str): The email address to validate.

        Returns:
            bool: True if the email address is valid, False otherwise.
        """
        try:
            self._mail_util.validate(email)
        except Exception:
            return False

        return True

    def change_email(self, user: User, email: str) -> User:
        """
        Change the email of a user.

        Args:
            user (User): The user object to update.
            email (str): The new email address for the user.

        Returns:
            User: The updated user object.
        """
        email = self._mail_util.validate(email)

        user = self.datastore.db.session.merge(user)
        user.email = email
        self.datastore.commit()

        return user

    def generate_email_token(self, user_id: str = None) -> str:
        """
        Generate an email verification token for the provided user.

        If no user id is provided, the current user is used.

        Returns:
            str: The email verification token.
        """
        if user_id is None:
            user_id = current_user.id

        return self.generate_token(user_id, salt=self.get_service_config("VERIFY_EMAIL_SALT"))

    def generate_password_token(self, user_id: str = None) -> str:
        """
        Generate a password reset token for the current user.

        Returns:
            str: The password reset token.
        """

        if user_id is None:
            user_id = current_user.id

        return self.generate_token(user_id, salt=self.get_service_config("VERIFY_PASSWORD_SALT"))

    def generate_token(self, content: str, salt: str):
        """
        Generate a token for the given content and salt.

        Returns:
            str: The generated token.
        """
        return self._token_serializer.dumps(content, salt=salt)

    def verify_password_token(self, token: str) -> User:
        """
        Verifies the password reset token and returns the associated user.

        Args:
            token (str): The password reset token to verify.

        Returns:
            User: The user associated with the token if it's valid, None otherwise.
        """
        salt = self.get_service_config("VERIFY_PASSWORD_SALT")
        return self.verify_token(token, salt)

    def verify_email_token(self, token: str) -> User:
        """
        Verifies the email confirmation token and returns the associated user.

        Args:
            token (str): The email confirmation token to verify.

        Returns:
            User: The user associated with the token if it's valid, None otherwise.
        """
        salt = self.get_service_config("VERIFY_EMAIL_SALT")
        return self.verify_token(token, salt)

    def verify_token(self, token: str, salt: str) -> User:
        """
        Verify email token and return the User object associated with the token.

        Args:
            token (str): The email verification token.

        Raises:
            ValueError: If the token is invalid or expired.
            NotFoundError: If no user is associated with the verification token.
            ValueError: If the user's email has already been validated.

        Returns:
            User: The user object associated with the verification token.
        """
        try:
            user_id = self._token_serializer.loads(token, max_age=86400, salt=salt)
        except Exception as ex:
            self._logger.warning(
                "{0} verification token not validated. Reason: {1}".format(token, ex)
            )
            raise ValueError("unknown verification token")

        user: User = User.query.filter_by(id=user_id).first()

        if user is None:
            raise NotFoundError("no user associated with that verification token")

        return user


class KafkaProducerService(GatewayService):
    def __init__(self, name: str = "KAFKA_PRODUCER_SERVICE"):
        GatewayService.__init__(self, name)

    def init_app(self, app: Flask):
        super().init_app(app)
        self._producer = self._init_producer()
        self._register_hooks(app)

    def _init_producer(self) -> KafkaProducer | None:
        try:
            return KafkaProducer(
                bootstrap_servers=",".join(
                    self.get_service_config("BOOTSTRAP_SERVERS", ["localhost:9092"])
                ),
                value_serializer=lambda v: json.dumps(v).encode("utf-8"),
                request_timeout_ms=self.get_service_config("REQUEST_TIMEOUT_MS", 500),
                acks=0,  # Fire and forget. We don't want issues with the broker to affect the Gateway.
            )
        except Exception as ex:
            self._logger.error("Could not connect to Kafka: %s", ex)
            return None

    def _register_hooks(self, app: Flask):
        @app.after_request
        def _after_request_hook(response: Response):
            if self._producer is not None:
                self._producer.send(
                    self.get_service_config("REQUEST_TOPIC"),
                    {
                        "user_id": current_user.get_id(),
                        "client_id": (
                            current_token.client_id
                            if current_token and hasattr(current_token, "client")
                            else ""
                        ),
                        "endpoint": request.endpoint,
                        "method": request.method,
                        "timestamp": datetime.now().isoformat(),
                        "status_code": response.status_code,
                    },
                )

            return response

    def __getattr__(self, name):
        return getattr(self._producer, name, None)

    def __getitem__(self, name):
        return self._producer[name]

    def __setitem__(self, name, value):
        self._producer[name] = value

    def __delitem__(self, name):
        del self._producer[name]
