import smtplib
from email.message import EmailMessage
from functools import wraps
from typing import Tuple
from urllib.parse import urljoin

import requests
from flask import Request, current_app, request
from flask.views import View
from flask_login import current_user

from apigateway.email_templates import EmailTemplate


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
    mail_server: str = "localhost",
):
    # Do not send emails if in debug mode
    if current_app.config.get("TESTING", False):
        current_app.logger.warning(
            "Email was NOT sent to '{}' with verification URL '{}' due to testing".format(
                recipient, verification_url
            )
        )
        return

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
    data = get_post_data(request)
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


def get_post_data(request: Request):
    """
    Attempt to coerce POST json data from the request, falling
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
