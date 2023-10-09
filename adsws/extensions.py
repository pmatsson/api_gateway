from flask_sqlalchemy import SQLAlchemy as FlaskSQLAlchemy
from authlib.integrations.flask_oauth2 import AuthorizationServer
from adsws.gateway.service import GatewayService
from adsws.auth.service import AuthService
from flask_restful import Api
from flask_alembic import Alembic
from adsws.model import base_model
from flask_login import LoginManager
from flask_marshmallow import Marshmallow

# Database
alembic = Alembic()
db = FlaskSQLAlchemy(model_class=base_model)
ma = Marshmallow()

# Auth
login_manager = LoginManager()
oauth2_server = AuthorizationServer()

# Services
auth_service = AuthService()
gateway_service = GatewayService(auth_service)

# Other
flask_api = Api()
