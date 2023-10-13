from os import environ

# General
DEBUG = True

# Logging
LOGGING_LEVEL = "DEBUG"
LOG_STDOUT = False

# Database
SQLALCHEMY_DATABASE_URI = "sqlite:////tmp/local.db"
SQLALCHEMY_TRACK_MODIFICATIONS = False
SECRET_KEY = environ.get("PROXY_SECRET_KEY", "secret")

# Session
PERMANENT_SESSION_LIFETIME = 3600 * 24 * 365.25  # 1 year in seconds
SESSION_REFRESH_EACH_REQUEST = True
BOOTSTRAP_USER_EMAIL = "anonymous@ads"
BOOTSTRAP_CLIENT_NAME = "BB client"

# Proxy service
PROXY_RESOURCE_ENDPOINT = "/resources"
PROXY_WEBSERVICES = {"http://192.168.1.187:8181": "/scan"}

# Auth
OAUTH2_CLIENT_ID_SALT_LEN = 40
OAUTH2_CLIENT_SECRET_SALT_LEN = 40
