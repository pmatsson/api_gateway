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

# Auth
OAUTH2_CLIENT_ID_SALT_LEN = 40
OAUTH2_CLIENT_SECRET_SALT_LEN = 40

# Session
PERMANENT_SESSION_LIFETIME = 3600 * 24 * 365.25  # 1 year in seconds
SESSION_REFRESH_EACH_REQUEST = True
BOOTSTRAP_USER_EMAIL = "anonymous@ads"
BOOTSTRAP_CLIENT_NAME = "BB client"

# Proxy service
PROXY_SERVICE_RESOURCE_ENDPOINT = "/resources"
PROXY_SERVICE_WEBSERVICES = {"http://192.168.1.187:8181": "/scan"}

# Limiter service
LIMITER_SERVICE_STORAGE_URI = "redis://localhost:6379/0"
LIMITER_SERVICE_STRATEGY = "fixed-window"


# Redis service
REDIS_SERVICE_URI = "redis://localhost:6379/0"


# Cache service
CACHE_SERVICE_CACHE_TYPE = "RedisCache"
CACHE_SERVICE_REDIS_URI = (
    # NOTE: Do not use the same redis DB as other services
    "redis://localhost:6379/1"
)
