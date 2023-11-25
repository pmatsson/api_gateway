from adsmutils import ADSFlask
from authlib.integrations.sqla_oauth2 import (
    create_query_client_func,
    create_save_token_func,
)
from flask import Flask, jsonify, session
from flask_restful import Api
from flask_wtf.csrf import CSRFError
from marshmallow import ValidationError

from apigateway import exceptions, extensions, views
from apigateway.models import OAuth2Client, OAuth2Token, User


def register_extensions(app: Flask):
    """Register extensions.

    Args:
        app (Flask): Application object
    """

    extensions.db.init_app(app)
    extensions.ma.init_app(app)
    extensions.alembic.init_app(app)

    extensions.cors.init_app(
        app,
        origins=app.config.get("CORS_DOMAINS"),
        allow_headers=app.config.get("CORS_HEADERS"),
        methods=app.config.get("CORS_METHODS"),
        supports_credentials=True,
    )

    extensions.oauth2_server.init_app(
        app,
        query_client=create_query_client_func(extensions.db.session, OAuth2Client),
        save_token=create_save_token_func(extensions.db.session, OAuth2Token),
    )

    extensions.login_manager.init_app(app)

    extensions.redis_service.init_app(app)
    extensions.security_service.init_app(app)
    extensions.auth_service.init_app(app)
    extensions.proxy_service.init_app(app)
    extensions.limiter_service.init_app(app)
    extensions.cache_service.init_app(app)
    extensions.kakfa_producer_service.init_app(app)
    extensions.storage_service.init_app(app, extensions.redis_service)

    extensions.csrf.init_app(app)


def register_hooks(app: Flask):
    """Register hooks

    Args:
        app (Flask): Application object
    """

    @app.before_request
    def make_session_permanent():
        session.permanent = True

    @extensions.login_manager.user_loader
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

    @app.errorhandler(exceptions.NotFoundError)
    def not_found_error(e):
        app.logger.info(f"Not Found Error: {e.value}")
        return jsonify({"error": e.value}), 404


def register_views(flask_api: Api):
    """Registers the views for the Flask application."""
    flask_api.add_resource(views.BootstrapView, "/bootstrap")
    flask_api.add_resource(views.CSRFView, "/csrf")
    flask_api.add_resource(views.StatusView, "/status")
    flask_api.add_resource(views.OAuthProtectedView, "/protected")
    flask_api.add_resource(views.UserAuthView, "/user/login")
    flask_api.add_resource(views.LogoutView, "/user/logout")
    flask_api.add_resource(views.UserManagementView, "/user")
    flask_api.add_resource(views.ChangePasswordView, "/user/change-password")
    flask_api.add_resource(views.ChangeEmailView, "/user/change-email")
    flask_api.add_resource(views.VerifyEmailView, "/verify/<string:token>")
    flask_api.add_resource(views.ResetPasswordView, "/user/reset-password/<string:token_or_email>")
    flask_api.add_resource(views.ChacheManagementView, "/cache")


def create_app(**config):
    """Create application and initialize dependencies.

    Returns:
        ADSFlask: Application object
    """

    app = ADSFlask(__name__, static_folder=None, local_config=config)
    flask_api = Api(app)
    register_extensions(app)
    register_views(flask_api)
    register_hooks(app)

    extensions.proxy_service.register_services()

    return app
