from adsmutils import ADSFlask
from authlib.integrations.flask_oauth2 import current_token
from authlib.integrations.sqla_oauth2 import (
    create_query_client_func,
    create_save_token_func,
)
from flask import Flask, abort, jsonify, request, session
from flask_restful import Api
from marshmallow import ValidationError as MarshmallowValidationError

from apigateway import exceptions, extensions, views
from apigateway.models import OAuth2Client, OAuth2Token, User


def register_extensions(app: Flask):
    """Register extensions.

    Args:
        app (Flask): Application object
    """

    extensions.db.init_app(app)
    extensions.ma.init_app(app)

    extensions.cors.init_app(
        app,
        origins=app.config.get("CORS_DOMAINS"),
        allow_headers=app.config.get("CORS_HEADERS"),
        methods=app.config.get("CORS_METHODS"),
        supports_credentials=True,
        intercept_exceptions=True,
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
    extensions.talisman.init_app(app, force_https=False)
    extensions.csrf.init_app(app)


def register_hooks(app: Flask):
    """Register hooks

    Args:
        app (Flask): Application object
    """

    @app.before_request
    def make_session_permanent():
        session.permanent = True

    @app.login_manager.user_loader
    def load_user(user_id):
        return User.query.filter_by(fs_uniquifier=user_id).first()

    @app.login_manager.unauthorized_handler
    def unauthorized():
        """
        flask_login callback when @login_required is not met.
        This overrides the default behavior or re-directing to a login view
        """
        abort(401)


def register_error_handlers(app: Flask):
    """Register error handlers for the Flask app.

    Args:
        app (Flask): The Flask app instance.
    """

    @app.errorhandler(MarshmallowValidationError)
    def marshmallow_validation_error(e):
        return jsonify({"message": e.normalized_messages()}), 400

    @app.errorhandler(exceptions.NotFoundError)
    def not_found_error(e):
        return jsonify({"message": e.value}), 404

    @app.errorhandler(exceptions.ValidationError)
    def validation_error(e):
        return jsonify({"message": e.value}), 400

    @app.errorhandler(exceptions.NoClientError)
    def no_client_error(e):
        return jsonify({"message": e.value}), 500

    @app.errorhandler(401)
    def on_401(e):
        return jsonify({"message": "Unauthorized"}), 401

    @app.errorhandler(405)
    def on_405(e):
        return jsonify({"message": "Method not allowed"}), 405

    @app.errorhandler(404)
    def on_404(e):
        return jsonify({"message": "Not found"}), 404


def register_verbose_exception_logging(app: Flask):
    """Configure logging."""

    def log_exception(exc_info):
        """
        Override default Flask.log_exception for more verbose logging on
        exceptions.
        """
        try:
            oauth_user = current_token.user_id
        except AttributeError:
            oauth_user = None

        app.logger.error(
            """
            Request:     {method} {path}
            IP:          {ip}
            Agent:       {agent_platform} | {agent_browser} {agent_browser_version}
            Raw Agent:   {agent}
            Oauth2:      {oauth_user}
            """.format(
                method=request.method,
                path=request.path,
                ip=request.remote_addr,
                agent_platform=request.user_agent.platform,
                agent_browser=request.user_agent.browser,
                agent_browser_version=request.user_agent.version,
                agent=request.user_agent.string,
                oauth_user=oauth_user,
            ),
            exc_info=exc_info,
        )

    app.log_exception = log_exception


def register_views(flask_api: Api):
    """Registers the views for the Flask application."""
    flask_api.add_resource(views.BootstrapView, "/accounts/bootstrap")
    flask_api.add_resource(views.CSRFView, "/accounts/csrf")
    flask_api.add_resource(views.StatusView, "/accounts/status")
    flask_api.add_resource(views.OAuthProtectedView, "/accounts/protected")
    flask_api.add_resource(views.UserAuthView, "/accounts/user/login")
    flask_api.add_resource(views.LogoutView, "/accounts/user/logout")
    flask_api.add_resource(views.UserManagementView, "/accounts/user")
    flask_api.add_resource(views.UserResolverView, "/accounts/user/<string:id>")
    flask_api.add_resource(views.PersonalTokenView, "/accounts/user/token")
    flask_api.add_resource(views.ChangePasswordView, "/accounts/user/change-password")
    flask_api.add_resource(views.ChangeEmailView, "/accounts/user/change-email")

    flask_api.add_resource(
        views.VerifyEmailView,
        "/accounts/verify/<string:token>",
        "/accounts/user/<string:email>/verify",
    )
    flask_api.add_resource(
        views.ResetPasswordView,
        "/accounts/user/reset-password/<string:token_or_email>",
    )
    flask_api.add_resource(views.UserInfoView, "/accounts/info/<string:account_data>")
    flask_api.add_resource(views.ChacheManagementView, "/admin/cache")
    flask_api.add_resource(views.LimiterManagementView, "/admin/limit")
    flask_api.add_resource(views.UserFeedbackView, "/feedback")
    flask_api.add_resource(views.Resources, "/resources")


def create_app(**config):
    """Create application and initialize dependencies.

    Returns:
        ADSFlask: Application object
    """

    app = ADSFlask(
        __name__,
        static_folder=None,
        template_folder="templates",
        local_config=config,
    )

    # old baggage... Consul used to store keys in hexadecimal form
    # so the production/staging databases both convert that into raw bytes
    # but those raw bytes were non-ascii chars (unsafe to pass through
    # env vars). So we must continue converting hex ...
    if app.config.get("SECRET_KEY", None):
        try:
            app.config["SECRET_KEY"] = bytes.fromhex(app.config["SECRET_KEY"])
            app.logger.warning("Converted SECRET_KEY from hex format into bytes")
        except ValueError:
            app.logger.warning("Most likely the SECRET_KEY is not in hex format")

    flask_api = Api(app)
    register_verbose_exception_logging(app)
    register_extensions(app)
    register_hooks(app)
    register_error_handlers(app)
    register_views(flask_api)

    extensions.proxy_service.register_services()

    return app
