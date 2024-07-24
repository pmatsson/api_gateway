from os import environ

# General
DEBUG = True

# Mail
MAIL_DEFAULT_SENDER = "no-reply@adslabs.org"
VERIFY_URL = "https://ui.adsabs.harvard.edu/#user/account/verify"

# Feeback
FEEDBACK_FORMS_ORIGIN = "user_submission"
BBB_FEEDBACK_ORIGIN = "bbb_feedback"
FEEDBACK_ALLOWED_ORIGINS = [FEEDBACK_FORMS_ORIGIN, BBB_FEEDBACK_ORIGIN]

FEEDBACK_TEMPLATES = {
    "Missing References": {"file": "missing_references.txt"},
    "Associated Articles": {"file": "associated_articles.txt"},
    "Updated Record": {"file": "updated_record.txt", "update": True},
    "New Record": {"file": "new_record.txt", "new": True},
    "Bumblebee Feedback": {"file": "bumblebee_feedback.txt"},
}


FEEDBACK_EMAIL = "adshelp@cfa.harvard.edu"
FEEDBACK_EMAIL_SUBJECT_OVERRIDE = {
    "Missing References": "adsabs@cfa.harvard.edu",
}

FEEDBACK_SLACK_END_POINT = "https://hooks.slack.com/services/TOKEN/TOKEN"
FEEDBACK_SLACK_EMOJI = ":interrobang:"
FORM_SLACK_EMOJI = ":inbox_tray:"

# CORS
CORS_HEADERS = [
    "Content-Type",
    "X-BB-Api-Client-Version",
    "Authorization",
    "Accept",
]

CORS_DOMAINS = [
    "http://localhost:8000",
    "http://localhost:5000",
    "http://adslabs.org",
]

CORS_METHODS = ["GET", "OPTIONS", "POST"]


# Logging
LOGGING_LEVEL = "DEBUG"
LOG_STDOUT = False

# Database
SQLALCHEMY_DATABASE_URI = "postgresql://user:password@db:5432/gateway"
SQLALCHEMY_TRACK_MODIFICATIONS = False
SECRET_KEY = environ.get("PROXY_SECRET_KEY", "736563726574")

# Auth
OAUTH2_CLIENT_ID_SALT_LEN = 40
OAUTH2_CLIENT_SECRET_SALT_LEN = 40
GOOGLE_RECAPTCHA_ENDPOINT = "https://www.google.com/recaptcha/api/siteverify"
GOOGLE_RECAPTCHA_PRIVATE_KEY = "MY_PRIVATE_KEY"

# Session
PERMANENT_SESSION_LIFETIME = 3600 * 24 * 365.25  # 1 year in seconds
SESSION_REFRESH_EACH_REQUEST = True
ANONYMOUS_BOOTSTRAP_USER_EMAIL = "anonymous@ads"
BOOTSTRAP_CLIENT_NAME = "BB client"
SESSION_COOKIE_PATH = "/v1"

# Proxy service
PROXY_SERVICE_RESOURCE_ENDPOINT = "/resources"
PROXY_SERVICE_WEBSERVICES = {"http://192.168.1.187:8181": "/scan"}
PROXY_SERVICE_ALLOWED_HEADERS = ["Content-Type", "Content-Disposition"]

# Limiter service
LIMITER_SERVICE_STORAGE_URI = "redis://redis:6379/0"

LIMITER_SERVICE_STRATEGY = "fixed-window"
LIMITER_SERVICE_GROUPS = {
    "example": {
        "counts": 1,
        "per_second": 3600 * 10,
        "patterns": ["/scan/metadata/*"],
    }
}

# Redis service
REDIS_SERVICE_URL = "redis://redis:6379/0"


# Cache service
CACHE_SERVICE_CACHE_TYPE = "RedisCache"
CACHE_SERVICE_REDIS_URI = (
    # NOTE: Do not use the same redis DB as other services
    "redis://redis:6379/1"
)

# Security service
SECURITY_SERVICE_SECRET_KEY = environ.get("ADSWS_SECRET_KEY", "secret")
SECURITY_SERVICE_PASSWORD_HASH = "pbkdf2_sha512"
SECURITY_SERVICE_VERIFY_PASSWORD_SALT = environ.get(
    "ADSWS_PASSWORD_SALT", SECURITY_SERVICE_SECRET_KEY
)
SECURITY_SERVICE_VERIFY_EMAIL_SALT = environ.get(
    "ADSWS_VERIFY_EMAIL_SALT", SECURITY_SERVICE_SECRET_KEY
)

BOOTSTRAP_SCOPES = []
USER_DEFAULT_SCOPES = ["user", "api"]
USER_API_DEFAULT_SCOPES = ["api"]

# Kafka producer service
KAFKA_PRODUCER_SERVICE_BOOTSTRAP_SERVERS = ["localhost:9092"]
KAFKA_PRODUCER_SERVICE_REQUEST_TOPIC = "gatewayRequests"
KAFKA_PRODUCER_SERVICE_REQUEST_TIMEOUT_MS = 500
