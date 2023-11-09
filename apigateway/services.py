""" Module defining API Gateway services. """
import hashlib
import logging
import os
import re
import time
from datetime import datetime
from typing import Callable, Optional, Tuple, TypedDict, Union
from urllib.parse import urljoin

import requests
from authlib.integrations.flask_oauth2 import (
    ResourceProtector,
    current_token,
    token_authenticated,
)
from authlib.integrations.sqla_oauth2 import create_bearer_token_validator
from flask import Flask, g, request
from flask.wrappers import Response
from flask_caching import Cache
from flask_limiter import Limiter
from flask_limiter.extension import LimitDecorator
from flask_limiter.util import get_remote_address
from flask_login import current_user
from flask_security import Security, SQLAlchemyUserDatastore
from itsdangerous import URLSafeTimedSerializer
from redis import Redis, StrictRedis
from sqlalchemy import func
from werkzeug.datastructures import Headers
from werkzeug.security import gen_salt

from apigateway.exceptions import NoClientError, NotFoundError, ValidationError
from apigateway.models import OAuth2Client, OAuth2Token, Role, User
from apigateway.views import ProxyView


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

        self._app = app
        self._logger = logging.getLogger(f"{app.name}.{self._name}")

        if not hasattr(app, "extensions"):
            app.extensions = {}

        app.extensions[self._name.lower()] = self

        app.__setattr__(self._name.lower(), self)

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
        self.require_oauth = ResourceProtector()

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
            """Adds the X-Adsws-Uid header to the request if the user is authenticated."""
            if current_user.is_authenticated:
                headers = Headers(request.headers.items())
                headers.add_header("X-Adsws-Uid", current_user.get_id())
                request.headers = headers

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
        ratelimit_multiplier: float = 1.0,
        expires: datetime = datetime(2500, 1, 1),
        create_client: bool = False,
        individual_ratelimit_multipliers: dict = None,
    ) -> Tuple[OAuth2Client, OAuth2Token]:
        """Bootstraps a user with an OAuth2Client and OAuth2Token.

        Args:
            client_name (type, optional): The name of the client. Defaults to None.
            scopes (type, optional): The scopes for the client. Defaults to None.
            ratelimit_multiplier (float, optional): The ratelimit factor for the client. Defaults to 1.0.
            expires (type, optional): The expiration date for the token. Defaults to datetime(2500, 1, 1).
            create_client (bool, optional): Whether to create a new client or not. Defaults to False.
            individual_ratelimit_multipliers (dict, optional): A dictionary of individual ratelimit multipliers for specific endpoints. Defaults to None.

        Returns:
            Tuple[OAuth2Client, OAuth2Token]: A tuple containing the OAuth2Client and OAuth2Token for the user.
        """
        if current_user.is_anonymous_bootstrap_user:
            return self.bootstrap_anonymous_user()

        self._check_ratelimit(ratelimit_multiplier)
        client_name = client_name or self._app.config.get("BOOTSTRAP_CLIENT_NAME", "BB client")

        clients = (
            OAuth2Client.query.filter_by(user_id=current_user.get_id())
            .order_by(OAuth2Client.client_id_issued_at.desc())
            .all()
        )

        # Metadata is a computed property so we need to filter after the query
        client = next((c for c in clients if c.client_name == client_name), None)

        if client is None or create_client:
            client = OAuth2Client(
                user_id=current_user.get_id(),
                ratelimit_multiplier=ratelimit_multiplier,
                individual_ratelimit_multipliers=individual_ratelimit_multipliers,
            )
            client.set_client_metadata(
                {"client_name": client_name, "description": client_name, "scope": scope}
            )

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
        if not current_user.is_anonymous_bootstrap_user:
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
        expires=datetime(2500, 1, 1),
    ) -> OAuth2Token:
        """Creates an OAuth2Token for the given OAuth2Client.

        Args:
            client (OAuth2Client): The OAuth2Client to create the token for.
            expires (type, optional): The expiration date for the token. Defaults to datetime(2500, 1, 1).

        Returns:
            OAuth2Token: The created OAuth2Token.
        """
        salt_length = self._app.config.get("OAUTH2_CLIENT_ID_SALT_LEN", 40)

        token = OAuth2Token(
            token_type="bearer",
            client_id=client.client_id,
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
            client_id=client.client_id,
            user_id=client.user_id,
            access_token=gen_salt(salt_length),
            refresh_token=gen_salt(salt_length),
            scope=client.scope,
            expires_in=expires_in,
        )

    def _check_ratelimit(self, requested_ratelimit: float):
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
            self._app.db.session.query(func.sum(OAuth2Client.ratelimit_multiplier).label("sum"))
            .filter(OAuth2Client.user_id == current_user.get_id())
            .first()[0]
            or 0.0
        )

        if quota - (used_ratelimit + requested_ratelimit) < 0:
            raise ValidationError(
                "The current user account (%s) does not have enough capacity to create a new client. Requested: %s, Available: %s"
                % (current_user.email, requested_ratelimit, quota - used_ratelimit)
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

        for remote_path, properties in resource_json.items():
            self._logger.debug("Registering resource %s", remote_path)

            properties.setdefault(
                "rate_limit",
                self.get_service_config("DEFAULT_RATE_LIMIT", [1000, 86400]),
            )
            properties.setdefault("scopes", self.get_service_config("DEFAULT_SCOPES", []))
            properties.setdefault("authorization", True)
            properties.setdefault("cache", None)

            # Create the view
            rule_name = local_path = os.path.join(deploy_path, remote_path[1:])
            proxy_view = ProxyView.as_view(rule_name, deploy_path, base_url)

            if csrf_exempt:
                self._app.extensions["csrf"].exempt(proxy_view)

            # If configured by the webservice, decorate view with the cache service
            if properties["cache"] is not None:
                cache = properties["cache"]
                proxy_view = self._app.cache_service.cached(
                    timeout=cache.get("timeout", 60000),
                    query_parameters=cache.get("query_parameters", True),
                    excluded_parameters=cache.get("excluded_parameters", []),
                )(proxy_view)

            # Decorate view with the rate limiter service
            counts = properties["rate_limit"][0]
            per_second = properties["rate_limit"][1]
            proxy_view = self._app.limiter_service.shared_limit(
                counts=counts,
                per_second=per_second,
            )(proxy_view)

            self._app.limiter_service.group_endpoint(local_path, counts, per_second)

            # Decorate view with the auth service, unless explicitly disabled
            if properties["authorization"]:
                proxy_view = self._app.auth_service.require_oauth(properties["scopes"])(proxy_view)

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
            timeout = self.get_service_config("RESOURCE_TIMEOUT", 5)
            response = requests.get(resource_url, timeout=timeout)
            response.raise_for_status()

            self._app.cache_service.set(resource_url, response)
            return response.json()
        except requests.exceptions.RequestException as ex:
            if self._app.cache_service.has(resource_url):
                self._logger.debug("Using cached resource document for %s", resource_url)
                return self._app.cache_service.get(resource_url).json()
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

            key: str = f"{self._name}//{request.endpoint}/time"

            existing_value: float = float(self._app.redis_service.get(key) or -1)
            if existing_value < 0:
                self._app.redis_service.set(key, processing_time)
            else:
                mean_value = (existing_value + processing_time) / 2
                self._app.redis_service.incrbyfloat(key, mean_value - existing_value)

            return response

        def _token_authenticated(sender, token=None, **kwargs):
            client = OAuth2Client.query.filter_by(client_id=token.client_id).first()
            level = getattr(client, "ratelimit", 1.0) if client else 0.0

            request.headers.add_header("X-Adsws-Ratelimit-Level", str(level))

        token_authenticated.connect(_token_authenticated, weak=False)

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

    def group_endpoint(self, endpoint: str, counts: int, per_second: int):
        for group, values in self._ratelimit_groups.items():
            if any(re.match(pattern, endpoint) for pattern in values.get("patterns", [])):
                if group not in self._symbolic_ratelimits.keys():
                    self._symbolic_ratelimits[group] = {
                        "name": group,
                        "counts": values.get("counts", counts),
                        "per_second": values.get("per_second", per_second),
                    }

                self._symbolic_ratelimits[endpoint] = self._symbolic_ratelimits[group]
                break

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
            return self._symbolic_ratelimits[request.endpoint]["name"]
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

    def cached(
        self,
        timeout: Optional[int] = None,
        key_prefix: str = "view/%s",
        unless: Optional[Callable] = None,
        forced_update: Optional[Callable] = None,
        response_filter: Optional[Callable] = None,
        hash_method: Callable = hashlib.md5,
        query_parameters: Optional[bool] = True,
        excluded_parameters: Optional[list] = [],
    ) -> Callable:
        """Caches the response from an API request with the given parameters.

        Args:
            timeout (Optional[int], optional): The time in seconds for which the response should be cached.
            key_prefix (str, optional): The prefix to use for the cache key.
            unless (Optional[Callable], optional): A function that determines whether the response should be cached.
            forced_update (Optional[Callable], optional): A function that determines whether the cache should be updated.
            response_filter (Optional[Callable], optional): A function that filters the response before caching.
            hash_method (Callable, optional): The hash function to use for generating the cache key.
            query_parameters (Optional[bool], optional): Whether to include query parameters in the cache key.
            excluded_parameters (Optional[list], optional): A list of query parameters to exclude from the cache key.

        Returns:
            Callable: The cache view decorator.
        """
        return Cache.cached(
            self,
            timeout=timeout,
            key_prefix=key_prefix,
            unless=unless,
            forced_update=forced_update,
            response_filter=response_filter,
            hash_method=hash_method,
            make_cache_key=lambda *args, **kwargs: self._make_cache_key(
                query_parameters, excluded_parameters, hash_method, args, kwargs
            ),
        )

    def _make_cache_key(
        self,
        query_parameters: bool,
        excluded_parameters: list,
        hash_method: Callable,
        *args,
        **kwargs,
    ) -> str:
        """Generates a cache key for the given parameters.

        Args:
            query_parameters (bool): Whether to include query parameters in the cache key.
            excluded_parameters (list): A list of query parameters to exclude from the cache key.
            hash_method (Callable): The hash function to use for generating the cache key.
            *args: Positional arguments to include in the cache key.
            **kwargs: Keyword arguments to include in the cache key.

        Returns:
            str: The cache key.
        """
        cache_key = request.path

        if query_parameters:
            args_as_sorted_tuple = tuple(
                sorted(
                    (k, v)
                    for (k, v) in request.args.items(multi=True)
                    if k not in excluded_parameters
                )
            )

            args_as_bytes = str(args_as_sorted_tuple).encode()
            cache_arg_hash = hash_method(args_as_bytes)
            cache_arg_hash = str(cache_arg_hash.hexdigest())

            cache_key = cache_key + cache_arg_hash

        return cache_key


class SecurityService(GatewayService, Security):
    def __init__(self, name: str = "SECURITY_SERVICE"):
        GatewayService.__init__(self, name)
        Security.__init__(self)

    def init_app(self, app: Flask):
        GatewayService.init_app(self, app)
        app.config.setdefault(
            "SECURITY_PASSWORD_HASH", self.get_service_config("PASSWORD_HASH", "pbkdf2_sha512")
        )
        app.config.setdefault("SECURITY_PASSWORD_SALT", self.get_service_config("PASSWORD_SALT"))
        Security.init_app(self, app, datastore=SQLAlchemyUserDatastore(app.db, User, Role))

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

        user.password = password
        user = self._app.db.session.merge(user)
        self.datastore.put(user)
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
        except ValidationError:
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
        user.email = email
        user = self._app.db.session.merge(user)
        self.datastore.put(user)
        self.datastore.commit()

        return user

    def generate_email_token(self) -> str:
        """
        Generate an email verification token for the current user.

        Returns:
            str: The email verification token.
        """
        return self._token_serializer.dumps(
            current_user.id, salt=self.get_service_config("VERIFY_EMAIL_SALT")
        )

    def verify_email_token(self, token: str) -> User:
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
            user_id = self._token_serializer.loads(
                token, max_age=86400, salt=self.get_service_config("VERIFY_EMAIL_SALT")
            )
        except Exception as ex:
            self._logger.warning(
                "{0} verification token not validated. Reason: {1}".format(token, ex)
            )
            raise ValueError("unknown verification token")

        user: User = User.query.filter_by(id=user_id).first()

        if user is None:
            raise NotFoundError("no user associated with that verification token")

        return user
