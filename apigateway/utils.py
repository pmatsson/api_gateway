import smtplib
from email.message import EmailMessage
from functools import wraps

import requests
from flask import Request, current_app
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
    if current_app.config.get("DEBUG", False):
        current_app.logger.warning(
            "Email was NOT sent to '{}' with verification URL '{}' due to that debugging is enabled".format(
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
    if current_app.config.get("DEBUG", False):
        current_app.logger.warning("reCAPTCHA was NOT verified because debugging is enabled")
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
