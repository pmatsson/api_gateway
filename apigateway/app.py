from adsmutils import ADSFlask
from authlib.integrations.sqla_oauth2 import (
    create_query_client_func,
    create_save_token_func,
)
from flask import Flask, jsonify, session
from flask_wtf.csrf import CSRFError
from marshmallow import ValidationError

from apigateway.extensions import (
    alembic,
    auth_service,
    cache_service,
    csrf,
    db,
    flask_api,
    limiter_service,
    login_manager,
    ma,
    oauth2_server,
    proxy_service,
    redis_service,
    security_service,
)
from apigateway.models import OAuth2Client, OAuth2Token, User
from apigateway.views import (
    Bootstrap,
    ChangeEmailView,
    ChangePasswordView,
    CSRFView,
    LogoutView,
    OAuthProtectedView,
    StatusView,
    UserAuthView,
    UserManagementView,
)


def register_extensions(app: Flask):
    """Register extensions.

    Args:
        app (Flask): Application object
    """

    db.init_app(app)
    ma.init_app(app)
    alembic.init_app(app)

    oauth2_server.init_app(
        app,
        query_client=create_query_client_func(db.session, OAuth2Client),
        save_token=create_save_token_func(db.session, OAuth2Token),
    )

    login_manager.init_app(app)

    security_service.init_app(app)
    auth_service.init_app(app)
    proxy_service.init_app(app)
    redis_service.init_app(app)
    limiter_service.init_app(app)
    cache_service.init_app(app)

    flask_api.init_app(app)
    csrf.init_app(app)


def register_hooks(app: Flask):
    """Register hooks

    Args:
        app (Flask): Application object
    """

    @app.before_request
    def make_session_permanent():
        session.permanent = True

    @login_manager.user_loader
    def load_user(user_id):
        return User.query.filter_by(fs_uniquifier=user_id).first()

    @app.errorhandler(CSRFError)
    def csrf_error(e):
        app.logger.warning(f"CSRF Blocked: {e.description}")
        return jsonify({"error": "Invalid CSRF token"}), 400

    @app.errorhandler(ValidationError)
    def validation_error(e):
        app.logger.info(f"Validation Error: {e.messages}")
        error_messages = [", ".join(messages) for messages in e.messages.values()]
        return jsonify({"error": ", ".join(error_messages)}), 400


def register_views():
    """Registers the views for the Flask application."""
    flask_api.add_resource(Bootstrap, "/bootstrap")
    flask_api.add_resource(CSRFView, "/csrf")
    flask_api.add_resource(StatusView, "/status")
    flask_api.add_resource(OAuthProtectedView, "/protected")
    flask_api.add_resource(UserAuthView, "/user/login")
    flask_api.add_resource(LogoutView, "/user/logout")
    flask_api.add_resource(UserManagementView, "/user")
    flask_api.add_resource(ChangePasswordView, "/user/change-password")
    flask_api.add_resource(ChangeEmailView, "/user/change-email")


def create_app():
    """Create application and initialize dependencies.

    Returns:
        ADSFlask: Application object
    """

    app = ADSFlask(__name__, static_folder=None)

    register_views()
    register_extensions(app)
    register_hooks(app)

    proxy_service.register_services()

    return app
