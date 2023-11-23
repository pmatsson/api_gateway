from datetime import datetime
from typing import Tuple
from urllib.parse import urljoin

import requests
from authlib.integrations.flask_oauth2 import current_token
from flask import current_app, request, session, url_for
from flask.views import View
from flask_login import current_user, login_required, login_user, logout_user
from flask_restful import Resource, abort
from flask_wtf.csrf import generate_csrf

from apigateway.email_templates import (
    EmailChangedNotification,
    PasswordResetEmail,
    VerificationEmail,
    WelcomeVerificationEmail,
)
from apigateway.models import EmailChangeRequest, PasswordChangeRequest, User
from apigateway.schemas import (
    bootstrap_get_request_schema,
    bootstrap_get_response_schema,
    change_email_request_schema,
    change_password_request_schema,
    clear_cache_request_schema,
    reset_password_request_schema,
    user_auth_post_request_schema,
    user_register_post_request_schema,
)
from apigateway.utils import (
    require_non_anonymous_bootstrap_user,
    send_email,
    verify_recaptcha,
)


class BootstrapView(Resource):
    def get(self):
        params = bootstrap_get_request_schema.load(request.json)

        if not current_user.is_authenticated:
            bootstrap_user: User = User.query.filter_by(is_anonymous_bootstrap_user=True).first()
            if not bootstrap_user or not login_user(bootstrap_user):
                abort(500, message="Could not login as bootstrap user")

        if current_user.is_anonymous_bootstrap_user and (
            params.scope or params.client_name or params.redirect_uri
        ):
            abort(
                401,
                message="""Sorry, you cant change scope/name/redirect_uri when creating temporary OAuth application""",
            )

        if current_user.is_anonymous_bootstrap_user:
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
                client_name=params.client_name,
                scope=params.scope,
                ratelimit_multiplier=params.ratelimit,
                individual_ratelimit_multipliers=params.individual_ratelimits,
                expires=params.expires,
                create_client=params.create_new,
            )

        return bootstrap_get_response_schema.dump(token), 200


class UserAuthView(Resource):
    """Implements login and logout functionality"""

    @property
    def method_decorators(self):
        return [current_app.limiter_service.shared_limit("30/120 second")]

    def post(self):
        params = user_auth_post_request_schema.load(request.json)
        with current_app.session_scope() as session:
            user: User = session.query(User).filter_by(email=params.email).first()

            if not user or not user.validate_password(params.password):
                abort(401, message="Invalid username or password")
            if not user.confirmed_at:
                abort(401, message="The account has not been verified")

            if current_user.is_authenticated:
                logout_user()

            login_user(user)

            user.last_login_at = datetime.now()
            user.login_count = user.login_count + 1 if user.login_count else 1

            session.commit()

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

            return response.content, response.status_code, dict(response.headers)
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


class CSRFView(Resource):
    """
    Returns a csrf token
    """

    @property
    def method_decorators(self):
        return [current_app.limiter_service.shared_limit("50/600 second")]

    def get(self):
        """
        Returns a csrf token
        """
        return {"csrf": generate_csrf()}, 200


class StatusView(Resource):
    """A resource that provides a health check endpoint for the API Gateway"""

    def get(self):
        return {"app": current_app.name, "status": "online"}, 200


class OAuthProtectedView(Resource):
    """A resource that checks whether the request is authorized with OAuth2.0."""

    @property
    def method_decorators(self):
        return [current_app.auth_service.require_oauth()]

    def get(self):
        return {"app": current_app.name, "oauth": current_token.user.email}, 200


class UserManagementView(Resource):
    """A Resource for user registration.

    This resource handles user registration requests. It checks if the user is already registered
    and creates a new user if not"""

    @property
    def method_decorators(self):
        return {
            "post": [current_app.limiter_service.shared_limit("50/600 second")],
            "delete": [login_required, require_non_anonymous_bootstrap_user],
        }

    def post(self):
        params = user_register_post_request_schema.load(request.json)

        if not verify_recaptcha(request):
            return {"error": "captcha was not verified"}, 403

        user = User.query.filter_by(email=params.email).first()
        if user is not None:
            error_message = f"An account is already registered for {params.email}"
            return {"error": error_message}, 409

        try:
            current_app.security_service.create_user(
                given_name=params.given_name,
                family_name=params.family_name,
                email=params.email,
                password=params.password1,
                registered_at=datetime.now(),
                login_count=0,
            )

            send_email(
                sender=current_app.config["MAIL_DEFAULT_SENDER"],
                recipient=params.email,
                template=WelcomeVerificationEmail,
                verification_url="<TBD>",
            )

            return {"message": "success"}, 200
        except ValueError as e:
            return {"error": str(e)}, 400

    def delete(self):
        with current_app.session_scope() as session:
            user: User = session.query(User).filter_by(fs_uniquifier=current_user.get_id()).first()
            logout_user()
            session.delete(user)
            session.commit()

        return {"message": "success"}, 200


class LogoutView(Resource):
    """Logs out the current user"""

    def post(self):
        logout_user()
        return {"message": "success"}, 200


class ChangePasswordView(Resource):
    decorators = [login_required, require_non_anonymous_bootstrap_user]

    def post(self):
        params = change_password_request_schema.load(request.json)

        if not current_user.validate_password(params.old_password):
            return {"error": "please verify your current password"}, 401

        current_app.security_service.change_password(current_user, params.new_password1)
        return {"message": "success"}, 200


class ResetPasswordView(Resource):
    def get(self, token_or_email):
        user = current_app.security_service.verify_password_token(token=token_or_email)
        return {"email": user.email}, 200

    def post(self, token_or_email):
        if not verify_recaptcha(request):
            return {"error": "captcha was not verified"}, 403

        with current_app.session_scope() as session:
            user: User = session.query(User).filter_by(email=token_or_email).first()

            if user is None:
                return {"error": "no such user exists"}, 404

            if user.is_anonymous_bootstrap_user:
                return {"error": "cannot reset password for anonymous bootstrap user"}, 403

            if not user.confirmed_at:
                return {
                    "error": "this email was never verified. It will be deleted from out database within a day"
                }, 403

            token: str = current_app.security_service.generate_password_token()
            self._delete_existing_password_change_requests(session, user.id)
            self._create_password_change_request(session, token, user.id)

            self._send_password_reset_email(token, token_or_email)

            return {"message": "success"}, 200

    def put(self, token_or_email):
        params = reset_password_request_schema.load(request.json)

        with current_app.session_scope() as session:
            password_change_request = (
                session.query(PasswordChangeRequest).filter_by(token=token_or_email).first()
            )

            if password_change_request is None:
                return {"error": "no user associated with that verification token"}, 404

            user: User = current_app.security_service.change_password(
                password_change_request.user, params.password1
            )

            self._delete_existing_password_change_requests(session, user.id)

            login_user(user)

            return {"message": "success"}, 200

    def _delete_existing_password_change_requests(self, session, user_id: int):
        session.query(PasswordChangeRequest).filter(
            PasswordChangeRequest.user_id == user_id
        ).delete()

    def _create_password_change_request(self, session, token: str, user_id: int):
        password_change_request = PasswordChangeRequest(token=token, user_id=user_id)

        session.add(password_change_request)
        session.commit()

    def _send_password_reset_email(self, token: str, email: str):
        send_email(
            current_app.config["MAIL_DEFAULT_SENDER"],
            email,
            PasswordResetEmail,
            verification_url=url_for("resetpasswordview", token_or_email=token, _external=True),
        )


class ChangeEmailView(Resource):
    @property
    def method_decorators(self):
        return {
            "get": [current_app.limiter_service.shared_limit("20/600 second")],
            "post": [
                current_app.limiter_service.shared_limit("5/600 second"),
                login_required,
                require_non_anonymous_bootstrap_user,
            ],
        }

    def get(self, token):
        user = current_app.security_service.verify_email_token(token)
        with current_app.session_scope() as session:
            email_change_request = session.query(EmailChangeRequest).filter_by(token=token).first()

            if email_change_request is None:
                return {"error": "no user associated with that verification token"}, 404

            current_app.security_service.change_email(
                email_change_request.user, email_change_request.new_email
            )

            session.delete(email_change_request)
            session.commit()

            login_user(user)

            return {"message": "success"}, 200

    def post(self):
        params = change_email_request_schema.load(request.json)

        if not current_user.validate_password(params.password):
            return {"error": "the provided password is incorrect"}, 401

        if not current_app.security_service.validate_email(params.email):
            return {"error": "the provided email address is invalid"}, 400

        with current_app.session_scope() as session:
            if self._is_email_registered(session, params.email):
                return {"error": "{0} has already been registered".format(params.email)}, 403

            token: str = current_app.security_service.generate_email_token()

            self._delete_existing_email_change_requests(session)
            self._create_email_change_request(session, token, params.email)

            # Verify new email address
            self._send_verification_email(token, params.email)

            # Notify previous email address of change
            self._send_notify_email_change()

            return {"message": "success"}, 200

    def _delete_existing_email_change_requests(self, session):
        session.query(EmailChangeRequest).filter(
            EmailChangeRequest.user_id == current_user.id
        ).delete()

    def _create_email_change_request(self, session, token: str, new_email: str):
        email_change_request = EmailChangeRequest(
            token=token,
            user_id=current_user.id,
            new_email=new_email,
        )

        session.add(email_change_request)
        session.commit()

    def _is_email_registered(self, session, email: str):
        return session.query(User).filter_by(email=email).first() is not None

    def _send_verification_email(self, token, new_email: str):
        send_email(
            current_app.config["MAIL_DEFAULT_SENDER"],
            new_email,
            VerificationEmail,
            verification_url=url_for("changeemailview", token=token, _external=True),
        )

    def _send_notify_email_change(self):
        send_email(
            current_app.config["MAIL_DEFAULT_SENDER"],
            current_user.email,
            EmailChangedNotification,
        )


class ChacheManagementView(Resource):
    @property
    def method_decorators(self):
        return [current_app.auth_service.require_oauth("adsws:internal")]

    def delete(self):
        params = clear_cache_request_schema.load(request.json)
        current_app.cache_service.clear_cache(params.key, params.parameters)
        return {"success": "success"}, 200
