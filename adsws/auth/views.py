from flask import request, session
from flask_login import current_user, login_user
from flask_restful import Resource, abort

from adsws.auth.model import User
from adsws.auth.schema import (
    BootstrapGetRequestSchema,
    bootstrap_get_request_schema,
    bootstrap_get_response_schema,
)
from adsws.extensions import auth_service


class Bootstrap(Resource):
    def get(self):
        params: BootstrapGetRequestSchema = bootstrap_get_request_schema.load(request.json)

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
                client, token = auth_service.bootstrap_anon_user()

            session["oauth_client"] = client.client_id

        # TODO: Bootstrap non-anon user

        return bootstrap_get_response_schema.dump(token), 200
