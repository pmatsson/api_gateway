from dataclasses import dataclass, field
from datetime import datetime

import marshmallow.validate
import marshmallow_dataclass
from flask_marshmallow.sqla import SQLAlchemyAutoSchema, SQLAlchemySchema, auto_field
from marshmallow import ValidationError, fields, validates_schema

from apigateway.models import OAuth2Token, User


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
    expires: datetime = field(default=datetime(2500, 1, 1))
    individual_ratelimits: dict = field(default=None)


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
    anonymous = fields.Boolean(attribute="user.is_anonymous_bootstrap_user", dump_only=True)
    client_id = fields.Str(attribute="client.client_id", dump_only=True)
    client_secret = fields.Str(attribute="client.client_secret", dump_only=True)
    ratelimit = fields.Float(attribute="client.ratelimit_multiplier", dump_only=True)
    client_name = fields.Str(attribute="client.name", dump_only=True)
    individual_ratelimits = fields.Dict(
        attribute="client.individual_ratelimit_multipliers", dump_only=True
    )


bootstrap_get_request_schema = marshmallow_dataclass.class_schema(BootstrapGetRequestSchema)()
bootstrap_get_response_schema = BootstrapGetResponseSchema()


@dataclass
class UserAuthPostRequestSchema:
    email: str = field(metadata={"validate": marshmallow.validate.Email()})
    password: str = field()


user_auth_post_request_schema = marshmallow_dataclass.class_schema(UserAuthPostRequestSchema)()


@dataclass
class UserRegisterPostRequestSchema:
    email: str = field(metadata={"validate": marshmallow.validate.Email()})
    password1: str = field(
        metadata={
            "validate": [
                marshmallow.validate.Length(
                    min=8, error="Password must be at least 8 characters long"
                ),
                marshmallow.validate.Regexp(
                    regex=r"^(?=.*[A-Z])(?=.*\d).+$",
                    error="Password must contain at least one uppercase letter and one digit",
                ),
            ]
        }
    )
    password2: str = field()

    @validates_schema
    def validate_passwords_equal(self, data, **kwargs):
        if data["password1"] != data["password2"]:
            raise ValidationError("Passwords do not match", field_name="password2")


user_register_post_request_schema = marshmallow_dataclass.class_schema(
    UserRegisterPostRequestSchema
)()
