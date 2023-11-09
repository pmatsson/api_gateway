import smtplib

# Import the email modules we'll need
from email.message import EmailMessage
from functools import wraps

from flask import current_app
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
    if not current_app.config.get("DEBUG", False):
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

    else:
        current_app.logger.warning(
            "Email was NOT sent to '{}' with verification URL '{}' due to that debugging is enabled".format(
                recipient, verification_url
            )
        )
