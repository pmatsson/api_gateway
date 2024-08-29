import json
import smtplib
from email.message import EmailMessage
from functools import wraps
from typing import Tuple
from urllib.parse import urljoin

import jsondiff as jd
import requests
from authlib.integrations.flask_oauth2 import ResourceProtector
from flask import Request, current_app, request
from flask.views import View
from flask_login import current_user

from apigateway.email_templates import (
    AccountRegistrationAttemptEmail,
    EmailTemplate,
    PasswordResetEmail,
    WelcomeVerificationEmail,
)
from apigateway.exceptions import Oauth2HttpError


def require_non_anonymous_bootstrap_user(func):
    @wraps(func)
    def decorated_view(*args, **kwargs):
        if current_user.is_anonymous_bootstrap_user:
            return current_app.login_manager.unauthorized()

        return func(*args, **kwargs)

    return decorated_view


def send_email(
    sender: str,
    recipient: str,
    template: EmailTemplate,
    verification_url: str = "",
    mail_server: str = None,
):
    # Do not send emails if in debug mode
    if current_app.config.get("TESTING", False):
        current_app.logger.warning(
            "Email was NOT sent to '{}' with verification URL '{}' due to TESTING flag = True".format(
                recipient, verification_url
            )
        )
        return

    if not mail_server:
        mail_server = current_app.config.get("MAIL_SERVER", "localhost")

    message = EmailMessage()
    message["Subject"] = template.subject
    message["From"] = sender
    message["To"] = recipient
    message.set_content(template.msg_plain.format(endpoint=verification_url))
    message.add_alternative(
        template.msg_html.format(endpoint=verification_url, email_address=recipient),
        subtype="html",
    )

    with smtplib.SMTP(mail_server) as s:
        s.send_message(message)


def send_feedback_email(
    submitter_name: str,
    submitter_email: str,
    subject: str,
    body: str,
    attachments: list = None,
    mail_server: str = None,
):
    # Do not send emails if in debug mode
    if current_app.config.get("TESTING", False):
        current_app.logger.warning(
            "Feedback email with subject {} was NOT sent due to TESTING flag = True".format(
                subject
            )
        )
        return

    if not mail_server:
        mail_server = current_app.config.get("MAIL_SERVER", "localhost")

    default_email = current_app.config["FEEDBACK_EMAIL"]
    recipient = current_app.config["FEEDBACK_EMAIL_SUBJECT_OVERRIDE"].get(subject, default_email)

    message = EmailMessage()
    message["Subject"] = f"[{subject}] from {submitter_name} ({submitter_email})"
    message["From"] = f"ADS Administation <{default_email}>"
    message["To"] = recipient
    message["reply-to"] = f"{submitter_name} <{submitter_email}>"
    message.set_content(body)

    if attachments:
        for attachment in attachments:
            message.add_attachment(
                json.dumps(attachment[1]),
                filename=attachment[0],
                maintype="application",
                subtype="json",
            )

    with smtplib.SMTP(mail_server) as s:
        s.send_message(message)


def verify_recaptcha(request: Request, endpoint: str = None):
    """
    Verify a Google reCAPTCHA based on the data contained in the request.

    Args:
        request (Request): The request object containing the reCAPTCHA response.
        endpoint (str, optional): The Google reCAPTCHA endpoint. Defaults to the value of
                                  GOOGLE_RECAPTCHA_ENDPOINT in the app configuration.

    Returns:
        bool: True if reCAPTCHA verification is successful, False otherwise.
    """

    # Skip reCAPTCHA verification if in debug mode
    if current_app.config.get("TESTING", False):
        current_app.logger.warning("reCAPTCHA is NOT verified during testing")
        return True

    endpoint = endpoint or current_app.config["GOOGLE_RECAPTCHA_ENDPOINT"]
    data = get_json_body(request)
    payload = {
        "secret": current_app.config["GOOGLE_RECAPTCHA_PRIVATE_KEY"],
        "remoteip": request.remote_addr,
        "response": data.get("g-recaptcha-response"),
    }

    try:
        response = requests.post(endpoint, data=payload, timeout=60)
        response.raise_for_status()
    except (
        requests.exceptions.ConnectionError,
        requests.exceptions.Timeout,
        requests.exceptions.HTTPError,
    ):
        return False

    return response.json().get("success", False)


def get_json_body(request: Request):
    """
    Attempt to coerce json data from the request, falling
    back to the raw data if json could not be coerced.
    """
    try:
        return request.get_json(force=True)
    except Exception:
        return request.values


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

        self.default_request_timeout = current_app.config.get("DEFAULT_REQUEST_TIMEOUT", 60)
        self.pool_connections = current_app.config.get("REQUESTS_POOL_CONNECTIONS", 20)
        self.pool_maxsize = current_app.config.get("REQUESTS_POOL_MAXSIZE", 1000)
        self.max_retries = current_app.config.get("REQUESTS_MAX_RETRIES", 1)

        http_adapter = requests.adapters.HTTPAdapter(
            pool_connections=self.pool_connections,
            pool_maxsize=self.pool_maxsize,
            max_retries=self.max_retries,
            pool_block=False,
        )

        self._session.mount("http://", http_adapter)

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


class GatewayResourceProtector(ResourceProtector):
    def raise_error_response(self, error):
        body = json.dumps(dict({"message": error.description}))
        raise Oauth2HttpError(error.status_code, error.description, body, error.get_headers())


def _format_changes(field, changes, updated):
    formatted_changes = []
    if isinstance(changes, dict):
        formatted_changes = [f"{k} -- {v}" for k, v in changes.items()]
    elif isinstance(changes, list):
        for item in changes:
            try:
                if field == "references":
                    formatted_changes.append(
                        f"{updated['bibcode']}\t{item.replace('(bibcode) ', '').replace('(reference) ', '')}"
                    )
                else:
                    formatted_changes.append(str(item) + "\n")
            except:  # noqa
                formatted_changes.append(str(item) + "\n")
    else:
        formatted_changes.append(str(changes) + "\n")
    return formatted_changes


def make_json_diff(original: str, updated: str):
    diff_data = jd.diff(original, updated)

    results = []
    if diff_data.get("comments"):
        results.append(f"\n\nComments: {diff_data['comments']}\n\n")

    for field, changes in diff_data.items():
        if field == "comments":
            continue
        results.append(f">>>> {field}\n")
        results.extend(_format_changes(field, changes, updated))
        results.append(">>>>\n")

    return "\n".join(results)


def send_password_reset_email(token: str, email: str):
    verification_url = f"{current_app.config['VERIFY_URL']}/reset-password/{token}"
    send_email(
        sender=current_app.config["MAIL_DEFAULT_SENDER"],
        recipient=email,
        template=PasswordResetEmail,
        verification_url=verification_url,
    )


def send_welcome_email(token: str, email: str):
    verification_url = f"{current_app.config['VERIFY_URL']}/register/{token}"
    send_email(
        sender=current_app.config["MAIL_DEFAULT_SENDER"],
        recipient=email,
        template=WelcomeVerificationEmail,
        verification_url=verification_url,
    )


def send_account_registration_attempt_email(email: str):
    send_email(
        sender=current_app.config["MAIL_DEFAULT_SENDER"],
        recipient=email,
        template=AccountRegistrationAttemptEmail,
    )
