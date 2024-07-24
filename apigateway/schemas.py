import re
from dataclasses import dataclass, field
from datetime import datetime
from typing import List

import marshmallow.validate
import marshmallow_dataclass
from citext import CIText
from flask_marshmallow.sqla import SQLAlchemyAutoSchema
from marshmallow import ValidationError, fields, validates_schema
from marshmallow.validate import Validator
from marshmallow_sqlalchemy import ModelConverter

from apigateway.models import User


class PasswordValidator(Validator):
    """Validate a password."""

    PASSWORD_REGEX = re.compile(r"^(?=.*[A-Z])(?=.*[a-z])(?=.*\d).+$")

    def __call__(self, value: str) -> str:
        if len(value) < 8:
            raise ValidationError("Password must be at least 8 characters long")

        if not self.PASSWORD_REGEX.match(value):
            raise ValidationError(
                "Password must contain at least one uppercase letter, one lowercase letter, and one number"
            )

        return value


class CITextField(fields.String):
    pass


class CustomModelConverter(ModelConverter):
    SQLA_TYPE_MAPPING = ModelConverter.SQLA_TYPE_MAPPING.copy()
    SQLA_TYPE_MAPPING[CIText] = CITextField


class UserSchema(SQLAlchemyAutoSchema):
    class Meta:
        model = User
        include_fk = True
        model_converter = CustomModelConverter


@dataclass
class BootstrapGetRequestSchema:
    scope: str = field(default=None)
    ratelimit: float = field(
        default=1.0, metadata={"validate": marshmallow.validate.Range(min=0.0)}
    )
    create_new: bool = field(default=False)
    redirect_uri: str = field(default=None)
    client_name: str = field(default=None)
    expires: datetime = field(default=datetime(2050, 1, 1))
    individual_ratelimits: dict = field(default=None)


@dataclass
class BootstrapGetResponseSchema:
    access_token: str = field(default=None)
    refresh_token: str = field(default=None)
    expires_at: str = field(default=None)
    token_type: str = field(default="Bearer")
    username: str = field(default=None)
    scopes: List[str] = field(default_factory=list)
    anonymous: bool = field(default=None)
    client_id: str = field(default=None)
    client_secret: str = field(default=None)
    ratelimit: float = field(default=None)
    client_name: str = field(default=None)
    individual_ratelimits: dict = field(default=None)
    given_name: str = field(default=None)
    family_name: str = field(default=None)


@dataclass
class UserAuthPostRequestSchema:
    email: str = field(metadata={"validate": marshmallow.validate.Email()})
    password: str = field()


@dataclass
class UserRegisterPostRequestSchema:
    email: str = field(metadata={"validate": marshmallow.validate.Email()})
    password1: str = field(metadata={"validate": PasswordValidator()})
    password2: str = field()
    given_name: str = None
    family_name: str = None
    g_recaptcha_response: str = field(default=None, metadata={"data_key": "g-recaptcha-response"})

    @validates_schema
    def validate_passwords_equal(self, data, **kwargs):
        if data["password1"] != data["password2"]:
            raise ValidationError("Passwords do not match", field_name="password2")


@dataclass
class ChangePasswordRequestSchema:
    old_password: str = field()
    new_password1: str = field(metadata={"validate": PasswordValidator()})
    new_password2: str = field()

    @validates_schema
    def validate_passwords_equal(self, data, **kwargs):
        if data["new_password1"] != data["new_password2"]:
            raise ValidationError("Passwords do not match", field_name="new_password2")


@dataclass
class ChangeEmailRequestSchema:
    email: str = field(metadata={"validate": marshmallow.validate.Email()})
    password: str = field(metadata={"validate": PasswordValidator()})


@dataclass
class ResetPasswordRequestSchema:
    password1: str = field(metadata={"validate": PasswordValidator()})
    password2: str = field()

    @validates_schema
    def validate_passwords_equal(self, data, **kwargs):
        if data["password1"] != data["password2"]:
            raise ValidationError("Passwords do not match", field_name="password2")


@dataclass
class UpdateUserRequestSchema:
    given_name: str = None
    family_name: str = None


@dataclass
class ClearCacheRequestSchema:
    key: str = field()
    parameters: dict = None


@dataclass
class ClearLimitRequestSchema:
    key: str = field()
    scope: str = ""

    @validates_schema
    def validate_clear_all(self, data, **kwargs):
        if data["key"] == "*" and data["scope"] != "":
            raise ValidationError(
                "Do not provide a scope when clearing ALL limits", field_name="scope"
            )


@dataclass
class PersonalTokenViewGetResponseSchema:
    access_token: str = field(default=None)
    refresh_token: str = field(default=None)
    expires_at: str = field(default=None)
    token_type: str = field(default="Bearer")
    scopes: List[str] = field(default_factory=list)
    username: str = field(default=None)
    anonymous: bool = field(default=None)
    client_id: str = field(default=None)
    user_id: str = field(default=None)


bootstrap_request = marshmallow_dataclass.class_schema(BootstrapGetRequestSchema)()
bootstrap_response = marshmallow_dataclass.class_schema(BootstrapGetResponseSchema)()
user_auth_request = marshmallow_dataclass.class_schema(UserAuthPostRequestSchema)()
user_register_request = marshmallow_dataclass.class_schema(UserRegisterPostRequestSchema)()
change_password_request = marshmallow_dataclass.class_schema(ChangePasswordRequestSchema)()
update_user_request = marshmallow_dataclass.class_schema(UpdateUserRequestSchema)()
change_email_request = marshmallow_dataclass.class_schema(ChangeEmailRequestSchema)()
reset_password_request = marshmallow_dataclass.class_schema(ResetPasswordRequestSchema)()
clear_cache_request = marshmallow_dataclass.class_schema(ClearCacheRequestSchema)()
clear_limit_request = marshmallow_dataclass.class_schema(ClearLimitRequestSchema)()
personal_token_response = marshmallow_dataclass.class_schema(PersonalTokenViewGetResponseSchema)()
