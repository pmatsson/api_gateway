import datetime

from flask import request, session
from flask_login import current_user, login_user, logout_user
from flask_restful import Resource, abort

from adsws.auth.model import User
from adsws.auth.schema import (
    bootstrap_get_request_schema,
    bootstrap_get_response_schema,
    user_auth_post_request_schema,
)
from adsws.extensions import auth_service


class Bootstrap(Resource):
    def get(self):
        params = bootstrap_get_request_schema.load(request.json)

        if not current_user.is_authenticated:
            bootstrap_user: User = User.query.filter_by(is_bootstrap_user=True).first()
            if not login_user(bootstrap_user):
                abort(500, message="Could not login as bootstrap user")

        if current_user.is_bootstrap_user and (
            params.scope or params.client_name or params.redirect_uri
        ):
            abort(
                401,
                message="""Sorry, you cant change scope/name/redirect_uri when creating temporary OAuth application""",
            )

        if current_user.is_bootstrap_user:
            client_id: str = None
            if "oauth_client" in session:
                client_id = session["oauth_client"]
            elif hasattr(request, "oauth"):
                client_id = request.oauth.client_id

            if client_id:
                client, token = auth_service.load_client(client_id)

            if not client_id or client.user_id != current_user.get_id():
                client, token = auth_service.bootstrap_anonymous_user()

            session["oauth_client"] = client.client_id

        else:
            _, token = auth_service.bootstrap_user(
                params.client_name,
                scope=params.scope,
                ratelimit=params.ratelimit,
                expires=params.expires,
                create_client=params.create_new,
            )

        return bootstrap_get_response_schema.dump(token), 200


class UserAuthView(Resource):
    """Implements login and logout functionality"""

    def post(self):
        params = user_auth_post_request_schema.load(request.json)
        user: User = User.query.filter_by(email=params.email).first()

        if not user or not user.validate_password(params.password):
            abort(401, message="Invalid username or password")
        if not user.confirmed_at:
            abort(401, message="The account has not been verified")

        if current_user.is_authenticated:
            logout_user()

        login_user(user)

        user.last_login_at = datetime.datetime.now()
        user.login_count = user.login_count + 1 if user.login_count else 1

        return {"message": "Successfully logged in"}, 200
