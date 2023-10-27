from functools import wraps

from flask import current_app
from flask_login import current_user


def require_non_anonymous_bootstrap_user(func):
    @wraps(func)
    def decorated_view(*args, **kwargs):
        if current_user.is_anonymous_bootstrap_user:
            return current_app.login_manager.unauthorized()

        return func(*args, **kwargs)

    return decorated_view
