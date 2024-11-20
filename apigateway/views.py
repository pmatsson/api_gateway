import binascii
import hashlib
import json
from copy import copy
from datetime import datetime
from urllib.parse import unquote

import requests
from authlib.integrations.flask_oauth2 import current_token
from flask import current_app, render_template, request, session
from flask.sessions import SecureCookieSessionInterface
from flask_login import current_user, login_required, login_user, logout_user
from flask_restful import Resource, abort
from flask_wtf.csrf import generate_csrf
from sqlalchemy import or_
from werkzeug.security import gen_salt

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
    make_json_diff,
    require_non_anonymous_bootstrap_user,
    send_account_registration_attempt_email,
    send_email,
    send_feedback_email,
    send_password_reset_email,
    send_welcome_email,
    verify_recaptcha,
)


class BootstrapView(Resource):

    decorators = [extensions.auth_service.require_oauth(optional=True)]

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
            elif current_token:
                client_id = current_token.client.client_id

            if client_id:
                client, token = extensions.auth_service.load_client(client_id)

            # Check if the client_id is valid and that there is no client/user mismatch
            if not client_id or (
                client.user_id != current_user.get_id()
                and not current_user.is_anonymous_bootstrap_user
            ):
                client, token = extensions.auth_service.bootstrap_anonymous_user()
                session["oauth_client"] = client.client_id

        else:
            client, token = extensions.auth_service.bootstrap_user(
                client_name=params.client_name,
                scope=params.scope,
                ratelimit_multiplier=params.ratelimit,
                individual_ratelimit_multipliers=params.individual_ratelimits,
                expires=params.expires,
                create_client=params.create_new,
            )

        response = {
            "access_token": token.access_token,
            "refresh_token": token.refresh_token,
            "expires_at": token.expires_at(),
            "token_type": token.token_type,
            "scopes": token.scope.split(" ") if token.scope else [],
            "username": token.user.email,
            "anonymous": token.user.is_anonymous_bootstrap_user,
            "client_id": client.client_id,
            "client_name": client.client_name,
            "client_secret": client.client_secret,
            "ratelimit": client.ratelimit_multiplier,
            "individual_ratelimits": client.individual_ratelimit_multipliers,
            "given_name": token.user.given_name,
            "family_name": token.user.family_name,
        }
        return schemas.bootstrap_response.dump(response), 200


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

            try:
                schemas.PasswordValidator()(params.password)
            except:  # noqa
                token: str = extensions.security_service.generate_password_token()
                send_password_reset_email(token, user.email)

                abort(
                    422,
                    message=(
                        "Your password does not meet the new requirements. "
                        "An email has been sent to you with instructions on how to reset your password."
                    ),
                )

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
            send_account_registration_attempt_email(params.email)
            current_app.logger.warning(
                "Registration attempt for existing user {0}".format(params.email)
            )
            return {"message": "success"}, 200

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
            send_welcome_email(token, user.email)

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

    @login_required
    @require_non_anonymous_bootstrap_user
    def put(self):
        params = schemas.update_user_request.load(get_json_body(request))

        with current_app.session_scope() as session:
            user: User = session.query(User).filter_by(fs_uniquifier=current_user.get_id()).first()
            user.given_name = params.given_name or user.given_name
            user.family_name = params.family_name or user.family_name
            session.commit()

        return {"message": "success"}, 200


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

            if user is not None:
                if user.is_anonymous_bootstrap_user:
                    return {"error": "cannot reset password for anonymous bootstrap user"}, 403

                if not user.confirmed_at:
                    return {
                        "error": "this email was never verified. It will be deleted from out database within a day"
                    }, 403

                token: str = extensions.security_service.generate_password_token()
                self._delete_existing_password_change_requests(session, user.id)
                self._create_password_change_request(session, token, user.id)

                send_password_reset_email(token, token_or_email)

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

    def put(self, email):
        with current_app.session_scope() as session:
            user = session.query(User).filter_by(email=email).first()
            if user is None:
                return {"message": "User not found"}, 404

            if user.confirmed_at:
                return {"message": "User already verified"}, 200

            token = extensions.security_service.generate_email_token(user.id)
            send_welcome_email(token, email)

            return {"message": "success"}, 200


class ChacheManagementView(Resource):
    """A view for managing the cache.

    This class provides an API endpoint for clearing the cache based on the provided key and parameters.


    Examples:

    Clearing the cache for a specific resource and parameters:

    DELETE
    {
        "key": "/scan/metadata/article/extra/123",
        "parameters": {"test": "123"}
    }

    """

    decorators = [extensions.auth_service.require_oauth("adsws:internal")]

    def delete(self):
        params = schemas.clear_cache_request.load(get_json_body(request))
        extensions.cache_service.clear_cache(params.key, params.parameters)
        return {"message": "success"}, 200


class LimiterManagementView(Resource):
    """A view for managing rate limits.

    This class provides an API endpoint for clearing rate limits based on the provided key and scope.

    Examples:

    Clearing the rate limit for a specific internal resource and user:

    DELETE
    {
        "key": "csrfview",
        "scope": "csrfview:user@example.com"
    }

    Clearing the rate limit for a external resource and user:

    DELETE
    {
        "key": "/scan/metadata/collection",
        "scope": "user@example.com"
    }


    """

    decorators = [extensions.auth_service.require_oauth("adsws:internal")]

    def delete(self):
        params = schemas.clear_limit_request.load(get_json_body(request))
        extensions.limiter_service.clear_limits(params.key, params.scope)
        return {"message": "success"}, 200


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
                token = OAuth2Token.query.filter(
                    OAuth2Client.client_id == session_data["oauth_client"]
                ).first()
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
                        client_id=client.id, user_id=session_data["user_id"]
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
        token = OAuth2Token.query.filter(OAuth2Client.client_id == account_data).first()
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


class UserFeedbackView(Resource):
    """
    Forwards a user's feedback to Slack and/or email
    """

    decorators = [
        extensions.limiter_service.shared_limit("500/600 second"),
        extensions.csrf.exempt,
    ]

    def post(self):
        params = get_json_body(request)
        current_app.logger.info(
            "Received feedback of type {0}: {1}".format(params.get("_subject"), params)
        )

        if not self._verify_captcha(params):
            return {"message": "Captcha was not verified"}, 403

        if not self._is_origin_allowed(params):
            return {"message": "No origin provided in feedback data"}, 400

        email_body, attachments, submitter_email = self._prepare_email_and_attachments(params)
        if not email_body:
            return {"message": "Unable to generate email body"}, 500

        # For associated articles append the relationship type to the subject
        subject = params.get("_subject")
        if subject == "Associated Articles":
            subject = "{0} ({1})".format(subject, params.get("relationship"))

        if not self._send_email(params, submitter_email, subject, email_body, attachments):
            current_app.logger.error(
                "Sending of email failed. Feedback data submitted by {0}: {1}".format(
                    submitter_email, params
                )
            )

        slack_data = self._prepare_slack_data(params, subject, email_body)
        if slack_data:
            slack_response = self._post_to_slack(slack_data)
            if "Slack API" in slack_response.text:
                return {
                    "message": "Re-directed due to malformed request or incorrect end point"
                }, 302
            elif slack_response.status_code != 200:
                return {"message": "Unknown error"}, slack_response.status_code

        return {"message": "success"}, 200

    def _verify_captcha(self, params):
        return verify_recaptcha(request) and params.get("g-recaptcha-response", False)

    def _is_origin_allowed(self, params):
        return params.get("origin", None) in current_app.config["FEEDBACK_ALLOWED_ORIGINS"]

    def _send_email(self, params, submitter_email, subject, email_body, attachments):
        try:
            send_feedback_email(
                params.get("name", "TownCrier"),
                submitter_email,
                subject,
                email_body,
                attachments,
            )
            return True
        except:  # noqa
            return False

    def _post_to_slack(self, slack_data):
        try:
            slack_response = requests.post(
                url=current_app.config["FEEDBACK_SLACK_END_POINT"],
                data=json.dumps(slack_data),
                timeout=60,
            )
        except (requests.exceptions.ConnectionError, requests.exceptions.Timeout) as ex:
            current_app.logger.error("Failed to post to slack", ex)
            abort(504)

        current_app.logger.info("Slack response: {0}".format(slack_response.status_code))

        # Slack annoyingly redirects if you have the wrong end point
        current_app.logger.info("Slack API" in slack_response.text)

        return slack_response

    def _prepare_email_and_attachments(self, params):
        """
        Prepares the email body and attachments for sending user feedback emails
        :param params: POST request data
        :return: email body and attachments
        """
        try:
            params_copy = copy(params)
            feedback_templates = current_app.config["FEEDBACK_TEMPLATES"]
            template = feedback_templates.get(params_copy["_subject"], None)
            if params.get("origin") == current_app.config["FEEDBACK_FORMS_ORIGIN"]:
                email_body, attachments = self._prepare_feedbackform_email(params_copy, template)
                submitter_email = params.get("email")

            elif params.get("origin") == current_app.config["BBB_FEEDBACK_ORIGIN"]:
                email_body, attachments = self._prepare_bbb_feedback_email(params_copy, template)
                submitter_email = params.get("_replyto")
            else:
                return None, None, None

        except Exception as e:
            current_app.logger.error("Error while processing feedback form data: {0}".format(e))
            return None, None, None

        return email_body, attachments, submitter_email

    def _prepare_slack_data(self, params, subject, email_body):
        forms_origin = current_app.config["FEEDBACK_FORMS_ORIGIN"]
        is_origin_feedback_form = params.get("origin") == forms_origin

        text = (
            'Received data from feedback form "{0}" from {1}'.format(subject, params.get("email"))
            if is_origin_feedback_form
            else "```Incoming Feedback```\n" + email_body
        )

        channel = params.get("channel", "#feedback")
        username = params.get("username", "TownCrier")
        icon_emoji = (
            current_app.config["FORM_SLACK_EMOJI"]
            if is_origin_feedback_form
            else current_app.config["FEEDBACK_SLACK_EMOJI"]
        )

        return {
            "text": text,
            "channel": channel,
            "username": username,
            "icon_emoji": icon_emoji,
        }

    def _prepare_feedbackform_email(self, params, template):
        """
        Prepares the email body and attachments for sending user feedback emails
        :param params: POST request data
        :return: email body and attachments
        """

        email_body = self._prepare_email_body(params, template)
        attachments = self._prepare_attachments(params, template)

        return email_body, attachments

    def _prepare_bbb_feedback_email(self, params, template):
        """
        Prepares the email body and attachments for sending user feedback emails
        :param params: POST request data
        :return: email body and attachments
        """

        keys_to_remove = ["channel", "username", "name", "_replyto", "g-recaptcha-response"]
        params = {k: v for k, v in params.items() if k not in keys_to_remove}

        params["_subject"] = "Bumblebee Feedback"
        params["comments"] = params["comments"].encode("utf-8")

        email_body = self._prepare_email_body(params, template)

        return email_body, []

    def _prepare_email_body(self, params, template):
        if not template:
            raise ValueError("No template found for {0}".format(params["_subject"]))

        if template.get("update", False):
            try:
                params["diff"] = make_json_diff(params["original"], params["updated"])
            except:  # noqa
                params["diff"] = unquote(params.get("diff", ""))
        elif template.get("new", False):
            try:
                params["new"]["author_list"] = ";".join([a for a in params["new"]["authors"]])
            except:  # noqa
                params["new"]["author_list"] = ""

        body = render_template(template["file"], data=params)
        body = body.replace("[tab]", "\t")

        return body

    def _prepare_attachments(self, params, template):
        attachments = []

        if template.get("new", False) or template.get("update", False):
            attachments.append((template["file"], params["new"]))

        if template.get("update", False):
            attachments.append(("original_record.json", params["original"]))

        return attachments


class PersonalTokenView(Resource):
    decorators = [
        extensions.limiter_service.shared_limit("500/43200 second"),
        login_required,
        require_non_anonymous_bootstrap_user,
    ]

    def get(self):
        clients = (
            OAuth2Client.query.filter_by(user_id=current_user.get_id())
            .order_by(OAuth2Client.client_id_issued_at.desc())
            .all()
        )

        client = next((c for c in clients if c.client_name == "ADS API client"), None)

        if not client:
            return {"message": "No ADS API client found"}, 200

        token = OAuth2Token.query.filter_by(
            client_id=client.id,
            user_id=current_user.get_id(),
        ).first()

        if not token:
            current_app.logger.error(
                "No token found for ADS API Client with id {0}. This should not happen!".format(
                    client.id
                )
            )
            return {"message": "No token found for ADS API client"}, 500

        response = {
            "access_token": token.access_token,
            "refresh_token": token.refresh_token,
            "expires_at": token.expires_at(),
            "token_type": token.token_type,
            "scopes": token.scope.split(" ") if token.scope else [],
            "username": token.user.email,
            "anonymous": token.user.is_anonymous_bootstrap_user,
            "client_id": client.client_id,
            "user_id": current_user.get_id(),
        }

        return schemas.personal_token_response.dump(response), 200

    def put(self):
        salt_length = current_app.config.get("OAUTH2_CLIENT_ID_SALT_LEN", 40)

        clients = (
            OAuth2Client.query.filter_by(user_id=current_user.get_id())
            .order_by(OAuth2Client.client_id_issued_at.desc())
            .all()
        )

        client = next((c for c in clients if c.client_name == "ADS API client"), None)

        with current_app.session_scope() as session:
            if not client:
                client = OAuth2Client(
                    user_id=current_user.get_id(),
                    last_activity=datetime.now(),
                )
                client.set_client_metadata(
                    {
                        "client_name": "ADS API client",
                        "description": "ADS API client",
                        "scope": " ".join(current_app.config.get("USER_API_DEFAULT_SCOPES", "")),
                        "is_internal": True,
                    }
                )
                client.gen_salt()

                session.add(client)
                session.commit()

                token = OAuth2Token(
                    token_type="Bearer",
                    client_id=client.id,
                    user_id=client.user_id,
                    access_token=gen_salt(salt_length),
                    refresh_token=gen_salt(salt_length),
                    scope=" ".join(current_app.config.get("USER_API_DEFAULT_SCOPES", "")),
                    expires_in=(datetime(2050, 1, 1) - datetime.now()).total_seconds(),
                )
                session.add(token)

            else:
                token = (
                    session.query(OAuth2Token)
                    .filter_by(
                        client_id=client.id,
                        user_id=current_user.get_id(),
                    )
                    .first()
                )

                if not token:
                    current_app.logger.error(
                        "No token found for ADS API Client with id {0}. This should not happen!".format(
                            client.id
                        )
                    )
                    return {"message": "No token found for the ADS API client"}, 500

                token.access_token = gen_salt(salt_length)

            session.commit()

            response = {
                "access_token": token.access_token,
                "refresh_token": token.refresh_token,
                "expires_at": token.expires_at(),
                "token_type": token.token_type,
                "scopes": token.scope.split(" ") if token.scope else [],
                "username": token.user.email,
                "anonymous": token.user.is_anonymous_bootstrap_user,
                "client_id": client.client_id,
                "user_id": current_user.get_id(),
            }

            return schemas.personal_token_response.dump(response), 200


class UserResolverView(Resource):
    """Resolves an email or uid into a string formatted user object"""

    decorators = [extensions.auth_service.require_oauth("adsws:internal")]

    def get(self, id):
        """
        :param identifier: email address or uid
        :return: json containing user info or 404
        """

        try:
            user_id = int(id)
        except ValueError:
            user_id = None

        u = User.query.filter(
            or_(
                User.id == user_id,
                User.email == id,
                User.fs_uniquifier == id,
            )
        ).first()

        if u is None:
            abort(404)

        return {
            "id": u.id,
            "email": u.email,
        }


class Resources(Resource):
    """Overview of available resources"""

    def get(self):
        r = {}
        app = current_app
        r[app.name] = {}
        r[app.name]["base"] = request.script_root

        for rule in app.url_map.iter_rules():
            is_external = rule.endpoint.startswith("/")
            split_rule = rule.rule[1:].split("/")

            first_path = split_rule[0] if is_external or len(split_rule) > 1 else "general"

            # If the first path is not in the dictionary, add it
            if first_path not in r[app.name]:
                r[app.name][first_path] = []

            # Append the rule to the corresponding first path
            r[app.name][first_path].append(rule.rule)

        return r
