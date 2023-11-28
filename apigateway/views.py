import binascii
import hashlib
from datetime import datetime

from authlib.integrations.flask_oauth2 import current_token
from flask import current_app, request, session
from flask.sessions import SecureCookieSessionInterface
from flask_login import current_user, login_required, login_user, logout_user
from flask_restful import Resource, abort
from flask_wtf.csrf import generate_csrf

from apigateway import email_templates as templates
from apigateway import extensions, schemas
from apigateway.models import (
    EmailChangeRequest,
    OAuth2Client,
    OAuth2Token,
    PasswordChangeRequest,
    User,
)
from apigateway.utils import (
    get_json_body,
    require_non_anonymous_bootstrap_user,
    send_email,
    verify_recaptcha,
)


class BootstrapView(Resource):
    def get(self):
        params = schemas.bootstrap_request.load(get_json_body(request))

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
                client, token = extensions.auth_service.load_client(client_id)

            if not client_id or client.user_id != current_user.get_id():
                client, token = extensions.auth_service.bootstrap_anonymous_user()

            session["oauth_client"] = client.client_id

        else:
            _, token = extensions.auth_service.bootstrap_user(
                client_name=params.client_name,
                scope=params.scope,
                ratelimit_multiplier=params.ratelimit,
                individual_ratelimit_multipliers=params.individual_ratelimits,
                expires=params.expires,
                create_client=params.create_new,
            )

        return schemas.bootstrap_response.dump(token), 200


class UserAuthView(Resource):
    """Implements login and logout functionality"""

    decorators = [extensions.limiter_service.shared_limit("30/120 second")]

    def post(self):
        params = schemas.user_auth_request.load(get_json_body(request))
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


class CSRFView(Resource):
    """
    Returns a csrf token
    """

    decorators = [extensions.limiter_service.limit("50/600 second")]

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

    decorators = [extensions.auth_service.require_oauth()]

    def get(self):
        return {"app": current_app.name, "oauth": current_token.user.email}, 200


class UserManagementView(Resource):
    """A Resource for user registration.

    This resource handles user registration requests. It checks if the user is already registered
    and creates a new user if not"""

    decorators = [extensions.limiter_service.shared_limit("50/600 second")]

    def post(self):
        params = schemas.user_register_request.load(get_json_body(request))

        if not verify_recaptcha(request):
            return {"error": "captcha was not verified"}, 403

        user = User.query.filter_by(email=params.email).first()
        if user is not None:
            error_message = f"An account is already registered for {params.email}"
            return {"error": error_message}, 409

        try:
            user: User = extensions.security_service.create_user(
                given_name=params.given_name,
                family_name=params.family_name,
                email=params.email,
                password=params.password1,
                registered_at=datetime.now(),
                login_count=0,
            )

            token = extensions.security_service.generate_email_token(user.id)
            self._send_welcome_email(token, user.email)

            return {"message": "success"}, 200
        except ValueError as e:
            return {"error": str(e)}, 400

    @login_required
    @require_non_anonymous_bootstrap_user
    def delete(self):
        with current_app.session_scope() as session:
            user: User = session.query(User).filter_by(fs_uniquifier=current_user.get_id()).first()
            logout_user()
            session.delete(user)
            session.commit()

        return {"message": "success"}, 200

    def _send_welcome_email(self, token: str, email: str):
        verification_url = f"{current_app.config['VERIFY_URL']}/register/{token}"
        send_email(
            sender=current_app.config["MAIL_DEFAULT_SENDER"],
            recipient=email,
            template=templates.WelcomeVerificationEmail,
            verification_url=verification_url,
        )


class LogoutView(Resource):
    """Logs out the current user"""

    def post(self):
        logout_user()
        return {"message": "success"}, 200


class ChangePasswordView(Resource):
    @login_required
    @require_non_anonymous_bootstrap_user
    def post(self):
        params = schemas.change_password_request.load(get_json_body(request))

        if not current_user.validate_password(params.old_password):
            return {"error": "please verify your current password"}, 401

        extensions.security_service.change_password(current_user, params.new_password1)
        return {"message": "success"}, 200


class ResetPasswordView(Resource):
    def get(self, token_or_email):
        user = extensions.security_service.verify_password_token(token=token_or_email)
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

            token: str = extensions.security_service.generate_password_token()
            self._delete_existing_password_change_requests(session, user.id)
            self._create_password_change_request(session, token, user.id)

            self._send_password_reset_email(token, token_or_email)

            return {"message": "success"}, 200

    def put(self, token_or_email):
        params = schemas.reset_password_request.load(get_json_body(request))

        with current_app.session_scope() as session:
            password_change_request = (
                session.query(PasswordChangeRequest).filter_by(token=token_or_email).first()
            )

            if password_change_request is None:
                return {"error": "no user associated with that verification token"}, 404

            user: User = extensions.security_service.change_password(
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
        verification_url = f"{current_app.config['VERIFY_URL']}/reset-password/{token}"
        send_email(
            sender=current_app.config["MAIL_DEFAULT_SENDER"],
            recipient=email,
            template=templates.PasswordResetEmail,
            verification_url=verification_url,
        )


class ChangeEmailView(Resource):
    decorators = [
        extensions.limiter_service.shared_limit("5/600 second"),
        login_required,
        require_non_anonymous_bootstrap_user,
    ]

    def post(self):
        params = schemas.change_email_request.load(get_json_body(request))

        if not current_user.validate_password(params.password):
            return {"error": "the provided password is incorrect"}, 401

        if not extensions.security_service.validate_email(params.email):
            return {"error": "the provided email address is invalid"}, 400

        with current_app.session_scope() as session:
            if self._is_email_registered(session, params.email):
                return {"error": "{0} has already been registered".format(params.email)}, 403

            token: str = extensions.security_service.generate_email_token()

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
        verification_url = f"{current_app.config['VERIFY_URL']}/change-email/{token}"

        send_email(
            current_app.config["MAIL_DEFAULT_SENDER"],
            new_email,
            templates.VerificationEmail,
            verification_url=verification_url,
        )

    def _send_notify_email_change(self):
        send_email(
            current_app.config["MAIL_DEFAULT_SENDER"],
            current_user.email,
            templates.EmailChangedNotification,
        )


class VerifyEmailView(Resource):
    decorators = [extensions.limiter_service.shared_limit("20/600 second")]

    def get(self, token):
        user = extensions.security_service.verify_email_token(token)
        with current_app.session_scope() as session:
            email_change_request = session.query(EmailChangeRequest).filter_by(token=token).first()
            if email_change_request is not None:
                extensions.security_service.change_email(
                    email_change_request.user, email_change_request.new_email
                )

                session.delete(email_change_request)

            session.query(User).filter_by(id=user.id).update({"confirmed_at": datetime.utcnow()})
            session.commit()
            login_user(user)

            return {"message": "success"}, 200


class ChacheManagementView(Resource):
    decorators = [extensions.auth_service.require_oauth("adsws:internal")]

    def delete(self):
        params = schemas.clear_cache_request.load(get_json_body(request))
        extensions.cache_service.clear_cache(params.key, params.parameters)
        return {"success": "success"}, 200


class UserInfoView(Resource):
    """
    Implements getting user info from session ID, access token or
    client id. It should be limited to internal use only.
    """

    decorators = [
        extensions.limiter_service.shared_limit("500/43200 second"),
        extensions.auth_service.require_oauth("adsws:internal"),
    ]

    def get(self, account_data):
        """
        This endpoint provides the full identifying data associated to a given
        session, user id, access token or client id. Example:

        curl -H 'authorization: Bearer:xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx'
            'https://dev.adsabs.harvard.edu/v1/accounts/info/yyyy'

        Where 'yyyy' can be a session, access token, user id or client id.

        Notice that sessions are not server side, but client stored and server
        signed to avoid user manipulation.
        """
        ## Input data can be a session, a access token or a user id
        # 1) Try to treat input data as a session
        try:
            session_data = self._decodeFlaskCookie(account_data)
            if "oauth_client" in session_data:
                # Anonymous users always have their oauth_client id in the session
                token = OAuth2Token.query.filter_by(client_id=session_data["oauth_client"]).first()
                if token:
                    return self._translate(token, source="session:client_id")
                else:
                    # Token not found in database
                    return {"message": "Identifier not found [ERR 010]"}, 404

            elif "user_id" in session_data:
                # There can be more than one token per user (generally one for
                # BBB and one for API requests), when client id is not stored
                # in the session (typically for authenticated users) we pick
                # just the first in the database that corresponds to BBB since
                # sessions are used by BBB and not API requests
                client = OAuth2Client.query.filter_by(
                    user_id=session_data["user_id"], name="BB client"
                ).first()

                if client:
                    token = OAuth2Token.query.filter_by(
                        client_id=client.client_id, user_id=session_data["user_id"]
                    ).first()

                    if token:
                        return self._translate(token, source="session:user_id")
                    else:
                        # Token not found in database
                        return {"message": "Identifier not found [ERR 020]"}, 404
                else:
                    # Client ID not found in database
                    return {"message": "Identifier not found [ERR 030]"}, 404
            else:
                # This should not happen, all ADS created session should contain that parameter
                return {"message": "Missing oauth_client/user_id parameter in session"}, 500
        except Exception:
            # Try next identifier type
            pass

        # 2) Try to treat input data as access token
        token = OAuth2Token.query.filter_by(access_token=account_data).first()
        if token:
            return self._translate(token, source="access_token")

        # 3) Try to treat input data as client id
        token = OAuth2Token.query.filter_by(client_id=account_data).first()
        if token:
            return self._translate(token, source="client_id")

        # Data not decoded sucessfully/Identifier not found
        return {"message": "Identifier not found [ERR 050]"}, 404

    def _translate(self, token: OAuth2Token, source=None):
        user: User = token.user
        anonymous = user.is_anonymous_bootstrap_user

        hashed_client_id = self._hash_id(token.client_id)
        hashed_user_id = hashed_client_id if anonymous else self._hash_id(token.user_id)

        return {
            "hashed_user_id": hashed_user_id,  # Permanent, all the anonymous users will have hashed_client_id instead
            "hashed_client_id": hashed_client_id,  # A single user has a client ID for the BB token and another for the API, anonymous users have a unique client ID linked to the anonymous user id (id 1)
            "anonymous": anonymous,  # True, False or None if email could not be retreived/anonymous validation could not be executed
            "source": source,  # Identifier used to recover information: session:client_id, session:user_id, user_id, access_token, client_id
        }, 200

    def _decodeFlaskCookie(self, cookie_value):
        sscsi = SecureCookieSessionInterface()
        signingSerializer = sscsi.get_signing_serializer(current_app)
        return signingSerializer.loads(cookie_value)

    def _hash_id(self, id):
        # 10 rounds of SHA-256 hash digest algorithm for HMAC (pseudorandom function)
        # with a length of 2x32
        # NOTE: 100,000 rounds is recommended but it is too slow and security is not
        # that important here, thus we just do 10 rounds

        if id is None:
            return None

        return binascii.hexlify(
            hashlib.pbkdf2_hmac(
                "sha256",
                str(id).encode(),
                current_app.secret_key.encode(),
                10,
                dklen=32,
            )
        ).decode()
