from unittest.mock import MagicMock, patch

import pytest
from flask import g

from apigateway.app import create_app
from apigateway.models import base_model


@pytest.fixture(scope="module", autouse=True)
def app(request):
    app = create_app(
        **{
            "SQLALCHEMY_DATABASE_URI": "sqlite:///:memory:",
            "SQLALCHEMY_ECHO": False,
            "TESTING": True,
            "DEBUG": True,
            "PROPAGATE_EXCEPTIONS": True,
            "TRAP_BAD_REQUEST_ERRORS": True,
            "PRESERVE_CONTEXT_ON_EXCEPTION": False,
            "PROXY_SERVICE_WEBSERVICES": {},
            "BOOTSTRAP_TOKEN_EXPIRES": 3600,
            "PROXY_SERVICE_ALLOWED_HEADERS": ["test_allowed_header"],
        },
        name=request.node.name,
    )

    with app.app_context():
        yield app


@pytest.fixture(autouse=True)
def test_db(app):
    base_model.metadata.create_all(bind=app.db.engine)
    yield
    base_model.metadata.drop_all(bind=app.db.engine)


@pytest.fixture()
def mock_anon_user():
    with patch("flask_login.utils._get_user") as mock_user:
        user = MagicMock()
        user.get_id.return_value = "test_anon_user"
        user.id = 456
        user.is_anonymous_bootstrap_user = True
        user.ratelimit_quota = -1
        user.allowed_scopes = ["test_scope"]
        mock_user.return_value = user
        yield user


@pytest.fixture()
def mock_regular_user():
    with patch("flask_login.utils._get_user") as mock_user:
        user = MagicMock()
        user.get_id.return_value = "test_user"
        user.id = 123
        user.email = "test@gmail.com"
        user.is_anonymous_bootstrap_user = False
        user.ratelimit_quota = 3
        user.allowed_scopes = ["test_scope"]
        mock_user.return_value = user
        yield user


@pytest.fixture
def mock_client():
    client = MagicMock()
    client.ratelimit_multiplier = 3.0
    client.individual_ratelimit_multipliers = {}
    return client


@pytest.fixture
def mock_current_token(mock_client):
    # Store the original value
    original_token = g.get("authlib_server_oauth2_token")

    # Set the mock value
    mock_instance = MagicMock()
    mock_instance.client = mock_client
    g.authlib_server_oauth2_token = mock_instance

    yield mock_instance

    # Restore the original value
    g.authlib_server_oauth2_token = original_token


@pytest.fixture
def mock_requests(monkeypatch):
    def _mock_request(method):
        mock_method = MagicMock()
        monkeypatch.setattr(f"requests.{method}", mock_method)
        return mock_method

    return _mock_request


@pytest.fixture
def mock_cache_service(monkeypatch):
    mock_cache = MagicMock()
    monkeypatch.setattr("apigateway.extensions.cache_service", mock_cache)
    return mock_cache


@pytest.fixture
def mock_limiter_service(monkeypatch):
    mock_limiter = MagicMock()
    monkeypatch.setattr("apigateway.extensions.limiter_service", mock_limiter)
    return mock_limiter


@pytest.fixture
def mock_auth_service(monkeypatch):
    mock_auth = MagicMock()
    monkeypatch.setattr("apigateway.extensions.auth_service", mock_auth)
    return mock_auth


@pytest.fixture
def mock_proxy_service(monkeypatch):
    mock_proxy = MagicMock()
    monkeypatch.setattr("apigateway.extensions.proxy_service", mock_proxy)
    return mock_proxy


@pytest.fixture
def mock_security_service(monkeypatch):
    mock_security = MagicMock()
    monkeypatch.setattr("apigateway.extensions.security_service", mock_security)
    return mock_security


@pytest.fixture
def mock_redis_service(monkeypatch):
    mock_redis = MagicMock()
    monkeypatch.setattr("apigateway.extensions.redis_service", mock_redis)
    return mock_redis


@pytest.fixture
def mock_storage_service(monkeypatch):
    mock_storage = MagicMock()
    monkeypatch.setattr("apigateway.extensions.storage_service", mock_storage)
    return mock_storage


@pytest.fixture
def mock_csrf_extension(monkeypatch):
    mock_csrf = MagicMock()
    monkeypatch.setattr("apigateway.extensions.csrf", mock_csrf)
    return mock_csrf


@pytest.fixture
def mock_add_url_rule(app):
    with patch.object(app, "add_url_rule", new_callable=MagicMock) as mock_add_url_rule:
        yield mock_add_url_rule


@pytest.fixture
def mock_proxy_view():
    with patch("flask.views.View.as_view", return_value=MagicMock()) as mock_view:
        yield mock_view


@pytest.fixture()
def mock_add_arguments():
    with patch("argparse.ArgumentParser.parse_args") as mock_args:
        mock_args.return_value.user_email = "test@gmail.com"
        mock_args.return_value.description = "Test Description"
        mock_args.return_value.name = "Test OAuth Client"
        mock_args.return_value.create_user = False
        mock_args.return_value.scopes = ["user", "api"]
        mock_args.return_value.is_personal = False
        yield mock_args

@pytest.fixture()
def mock_simple_token(): 
    mock_token = MagicMock()
    mock_token.access_token = "access_token"
    mock_token.refresh_token = "refresh_token"
    mock_token.scopes = ["user", "api"]
    return mock_token