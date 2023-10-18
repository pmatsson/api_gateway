import datetime
from typing import Tuple
from urllib.parse import urljoin

import requests
from flask import current_app, request, session
from flask.views import View
from flask_login import current_user, login_user, logout_user
from flask_restful import Resource, abort

from apigateway.models import User
from apigateway.schemas import (
    bootstrap_get_request_schema,
    bootstrap_get_response_schema,
    user_auth_post_request_schema,
)


class Bootstrap(Resource):
    def get(self):
        params = bootstrap_get_request_schema.load(request.json)

        if not current_user.is_authenticated:
            bootstrap_user: User = User.query.filter_by(is_bootstrap_user=True).first()
            if not login_user(bootstrap_user):
                abort(500, message="Could not login as bootstrap user")

        if current_user.is_bootstrap_user and (
            params.scope or params.client_name or params.redirect_uri
        ):
            abort(
                401,
                message="""Sorry, you cant change scope/name/redirect_uri when creating temporary OAuth application""",
            )

        if current_user.is_bootstrap_user:
            client_id: str = None
            if "oauth_client" in session:
                client_id = session["oauth_client"]
            elif hasattr(request, "oauth"):
                client_id = request.oauth.client_id

            if client_id:
                client, token = current_app.auth_service.load_client(client_id)

            if not client_id or client.user_id != current_user.get_id():
                client, token = current_app.auth_service.bootstrap_anonymous_user()

            session["oauth_client"] = client.client_id

        else:
            _, token = current_app.auth_service.bootstrap_user(
                params.client_name,
                scope=params.scope,
                ratelimit=params.ratelimit,
                expires=params.expires,
                create_client=params.create_new,
            )

        return bootstrap_get_response_schema.dump(token), 200


class UserAuthView(Resource):
    """Implements login and logout functionality"""

    def post(self):
        params = user_auth_post_request_schema.load(request.json)
        user: User = User.query.filter_by(email=params.email).first()

        if not user or not user.validate_password(params.password):
            abort(401, message="Invalid username or password")
        if not user.confirmed_at:
            abort(401, message="The account has not been verified")

        if current_user.is_authenticated:
            logout_user()

        login_user(user)

        user.last_login_at = datetime.datetime.now()
        user.login_count = user.login_count + 1 if user.login_count else 1

        return {"message": "Successfully logged in"}, 200


class ProxyView(View):
    """A view for proxying requests to a remote webservice."""

    def __init__(self, deploy_path: str, remote_base_url: str):
        """
        Initializes a ProxyView object.

        Args:
            deploy_path (str): The path to deploy the proxy view.
            remote_base_url (str): The base URL of the remote server to proxy requests to.
        """
        super().__init__()
        self._deploy_path = deploy_path
        self._remote_base_url = remote_base_url
        self._session = requests.Session()

    def dispatch_request(self, **kwargs) -> Tuple[bytes, int]:
        """
        Dispatches the request to the proxy view.

        Returns:
            Tuple[bytes, int]: A tuple containing the content of the response and the status code.
        """
        return self._proxy_request()

    def _proxy_request(self) -> Tuple[bytes, int]:
        """
        Proxies the request to the remote server.

        Returns:
            Tuple[bytes, int]: A tuple containing the content of the response and the status code.
        """
        try:
            remote_url = self._construct_remote_url()
            http_method_func = getattr(self._session, request.method.lower())

            current_app.logger.debug(
                "Proxying %s request to %s", request.method.upper(), remote_url
            )

            response: requests.Response = http_method_func(
                remote_url, data=request.get_data(), headers=request.headers
            )
            return response.content, response.status_code
        except (requests.exceptions.ConnectionError, requests.exceptions.Timeout):
            return b"504 Gateway Timeout", 504

    def _construct_remote_url(self) -> str:
        """
        Constructs the URL of the remote server.

        Returns:
            str: The URL of the remote server.
        """
        path = request.full_path.replace(self._deploy_path, "", 1)
        path = path[1:] if path.startswith("/") else path
        return urljoin(self._remote_base_url, path)
