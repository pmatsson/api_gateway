from authlib.integrations.flask_oauth2 import AuthorizationServer
from flask_alembic import Alembic
from flask_login import LoginManager
from flask_marshmallow import Marshmallow
from flask_sqlalchemy import SQLAlchemy as FlaskSQLAlchemy
from flask_wtf import CSRFProtect

from apigateway.models import base_model
from apigateway.services import (
    AuthService,
    CacheService,
    LimiterService,
    ProxyService,
    RedisService,
    SecurityService,
)

# Database
alembic = Alembic()
db = FlaskSQLAlchemy(model_class=base_model)
ma = Marshmallow()

# Auth
login_manager = LoginManager()
oauth2_server = AuthorizationServer()
csrf = CSRFProtect()

# Services
security_service = SecurityService()
auth_service = AuthService()
proxy_service = ProxyService()
redis_service = RedisService()
limiter_service = LimiterService()
cache_service = CacheService()
