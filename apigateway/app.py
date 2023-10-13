from adsmutils import ADSFlask
from authlib.integrations.sqla_oauth2 import (
    create_query_client_func,
    create_save_token_func,
)
from flask import Flask, session
from flask_security import SQLAlchemyUserDatastore

from apigateway.extensions import (
    alembic,
    auth_service,
    db,
    flask_api,
    flask_security,
    login_manager,
    ma,
    oauth2_server,
    proxy_service,
)
from apigateway.model import OAuth2Client, OAuth2Token, Role, User
from apigateway.views import Bootstrap, UserAuthView


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

    user_datastore = SQLAlchemyUserDatastore(db, User, Role)
    flask_security.init_app(app, user_datastore)

    auth_service.init_app(app)
    login_manager.init_app(app)
    proxy_service.init_app(app)

    flask_api.init_app(app)


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


def register_views():
    """Registers the views for the Flask application."""
    flask_api.add_resource(Bootstrap, "/bootstrap")
    flask_api.add_resource(UserAuthView, "/user")


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
