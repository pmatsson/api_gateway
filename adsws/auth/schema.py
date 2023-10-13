import datetime
from dataclasses import dataclass, field

import marshmallow.validate
import marshmallow_dataclass
from flask_marshmallow.sqla import SQLAlchemyAutoSchema, SQLAlchemySchema, auto_field
from marshmallow import fields

from adsws.auth.model import User
from adsws.auth.oauth2.model import OAuth2Token


class UserSchema(SQLAlchemyAutoSchema):
    class Meta:
        model = User
        include_fk = True


@dataclass
class BootstrapGetRequestSchema:
    scope: str = field(default=None)
    ratelimit: float = field(
        default=1.0, metadata={"validate": marshmallow.validate.Range(min=0.0)}
    )
    create_new: bool = field(default=False)
    redirect_uri: str = field(default=None)
    client_name: str = field(default=None)
    expires: str = field(default=str(datetime.datetime(2500, 1, 1)))


class BootstrapGetResponseSchema(SQLAlchemySchema):
    class Meta:
        model = OAuth2Token
        include_fk = True
        include_relationships = True

    access_token = auto_field()
    refresh_token = auto_field()
    expire_in = auto_field("expires_in")
    token_type = fields.Constant("Bearer", dump_only=True)
    username = fields.Str(attribute="user.email", dump_only=True)
    scopes = auto_field("scope")
    anonymous = fields.Boolean(attribute="user.is_bootstrap_user", dump_only=True)
    client_id = fields.Str(attribute="client.client_id", dump_only=True)
    client_secret = fields.Str(attribute="client.client_secret", dump_only=True)
    ratelimit = fields.Float(attribute="client.ratelimit", dump_only=True)
    client_name = fields.Str(attribute="client.name", dump_only=True)


bootstrap_get_request_schema = marshmallow_dataclass.class_schema(BootstrapGetRequestSchema)()
bootstrap_get_response_schema = BootstrapGetResponseSchema()


@dataclass
class UserAuthPostRequestSchema:
    email: str = field(metadata={"validate": marshmallow.validate.Email()})
    password: str = field()


user_auth_post_request_schema = marshmallow_dataclass.class_schema(UserAuthPostRequestSchema)()
