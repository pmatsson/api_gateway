from authlib.integrations.flask_oauth2 import AuthorizationServer
from flask_alembic import Alembic
from flask_login import LoginManager
from flask_marshmallow import Marshmallow
from flask_restful import Api
from flask_security import Security
from flask_sqlalchemy import SQLAlchemy as FlaskSQLAlchemy

from apigateway.model import base_model
from apigateway.service import AuthService, ProxyService

# Database
alembic = Alembic()
db = FlaskSQLAlchemy(model_class=base_model)
ma = Marshmallow()

# Auth
login_manager = LoginManager()
oauth2_server = AuthorizationServer()
flask_security = Security()

# Services
auth_service = AuthService()
proxy_service = ProxyService(auth_service)

# Other
flask_api = Api()
