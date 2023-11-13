from unittest.mock import MagicMock, call, patch

import pytest
from flask import g

from apigateway.app import create_app
from apigateway.exceptions import ValidationError
from apigateway.models import OAuth2Client, OAuth2Token, User, base_model
from apigateway.services import GatewayService


@pytest.fixture(scope="module", autouse=True)
def app():
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
        }
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
def mock_cache_service(monkeypatch, app):
    mock_cache = MagicMock()
    monkeypatch.setattr(app, "cache_service", mock_cache)
    return mock_cache


@pytest.fixture
def mock_limiter_service(app, monkeypatch):
    mock_limiter = MagicMock()
    monkeypatch.setattr(app, "limiter_service", mock_limiter)
    return mock_limiter


@pytest.fixture
def mock_auth_service(app, monkeypatch):
    mock_auth = MagicMock()
    monkeypatch.setattr(app, "auth_service", mock_auth)
    return mock_auth


@pytest.fixture
def mock_proxy_service(app, monkeypatch):
    mock_proxy = MagicMock()
    monkeypatch.setattr(app, "proxy_service", mock_proxy)
    return mock_proxy


@pytest.fixture
def mock_security_service(app, monkeypatch):
    mock_proxy = MagicMock()
    monkeypatch.setattr(app, "security_service", mock_proxy)
    return mock_proxy


@pytest.fixture
def mock_csrf_extension(app, monkeypatch):
    mock_csrf = MagicMock()
    monkeypatch.setitem(app.extensions, "csrf", mock_csrf)
    return mock_csrf


@pytest.fixture
def mock_add_url_rule(app):
    with patch.object(app, "add_url_rule", new_callable=MagicMock) as mock_add_url_rule:
        yield mock_add_url_rule


@pytest.fixture
def mock_proxy_view():
    with patch("flask.views.View.as_view", return_value=MagicMock()) as mock_view:
        yield mock_view


class TestGatewayService:
    def test_init_app(self, app):
        # Arrange
        service = GatewayService("test_service")

        # Act
        service.init_app(app)

        # Assert
        assert hasattr(app, "extensions")
        assert "test_service" in app.extensions
        assert app.test_service == service

    def test_get_service_config(self, app):
        # Arrange
        app.config["test_service_test_key"] = "test_value"
        service = GatewayService("test_service", app)

        # Act
        value = service.get_service_config("test_key")

        # Assert
        assert value == "test_value"

    def test_get_service_config_default(self, app):
        # Arrange
        service = GatewayService("test_service", app)

        # Act
        value = service.get_service_config("test_key_empty", "default_value")

        # Assert
        assert value == "default_value"


class TestAuthService:
    def test_load_client(self, app, mock_anon_user):
        # Arrange
        token = OAuth2Token(user_id=mock_anon_user.get_id(), access_token="test_token")
        client = OAuth2Client(user_id=mock_anon_user.get_id(), client_id="test_client")

        app.db.session.add(token)
        app.db.session.add(client)
        app.db.session.commit()

        # Act
        client, token = app.auth_service.load_client("test_client")

        # Assert
        assert client.client_id == "test_client"
        assert token.user_id == mock_anon_user.get_id()

    def test_bootstrap_anon_user(self, app, mock_anon_user):
        # Act
        client, token = app.auth_service.bootstrap_user()

        # Assert
        assert client.user_id == mock_anon_user.get_id()
        assert token.user_id == mock_anon_user.get_id()
        assert token.expires_in == app.config.get("BOOTSTRAP_TOKEN_EXPIRES")

    def test_bootstrap_user(self, app, mock_regular_user):
        # Act
        client, token = app.auth_service.bootstrap_user()

        # Assert
        assert client.user_id == mock_regular_user.get_id()
        assert token.user_id == mock_regular_user.get_id()

    def test_bootstrap_user_no_capacity(self, app, mock_regular_user):
        with pytest.raises(ValidationError):
            _, _ = app.auth_service.bootstrap_user(ratelimit_multiplier=100)

    def test_bootstrap_invalid_scope(self, app, mock_regular_user):
        with pytest.raises(ValidationError):
            _, _ = app.auth_service.bootstrap_user(scope="invalid")

    def test_bootstrap_valid_scope(self, app, mock_regular_user):
        try:
            _, _ = app.auth_service.bootstrap_user(scope="test_scope")
        except ValidationError:
            pytest.fail("Unexpected ValidationError")


class TestProxyService:
    def test_register_services(
        self,
        app,
        mock_requests,
        mock_cache_service,
        mock_limiter_service,
        mock_auth_service,
        mock_csrf_extension,
        mock_add_url_rule,
        mock_proxy_view,
    ):
        app.config["PROXY_SERVICE_WEBSERVICES"] = {
            "http://test.com": "/test",
            "http://test2.com": "/test2",
        }

        mock_get = mock_requests("get")
        mock_response = MagicMock()
        mock_response.json.return_value = {
            "/example": {
                "description": "A description",
                "methods": ["OPTIONS", "GET", "HEAD"],
                "scopes": ["api"],
                "rate_limit": [300, 86400],
            }
        }
        mock_get.return_value = mock_response

        app.proxy_service.register_services()

        calls = [
            call("http://test.com/resources", mock_response),
            call("http://test2.com/resources", mock_response),
        ]
        mock_cache_service.set.assert_has_calls(calls, any_order=True)

        calls = [
            call("/test/example", "/test", "http://test.com"),
            call("/test2/example", "/test2", "http://test2.com"),
        ]
        mock_proxy_view.assert_has_calls(calls, any_order=True)

        # Check that the view was registered with the correct arguments
        calls = [
            call(
                "/test/example",
                endpoint="/test/example",
                view_func=mock_auth_service.require_oauth()(),
                methods=["OPTIONS", "GET", "HEAD"],
            ),
            call(
                "/test2/example",
                endpoint="/test2/example",
                view_func=mock_auth_service.require_oauth()(),
                methods=["OPTIONS", "GET", "HEAD"],
            ),
        ]
        mock_add_url_rule.assert_has_calls(calls, any_order=True)

    def test_register_services_no_auth(
        self,
        app,
        mock_requests,
        mock_cache_service,
        mock_limiter_service,
        mock_auth_service,
        mock_csrf_extension,
        mock_add_url_rule,
        mock_proxy_view,
    ):
        app.config["PROXY_SERVICE_WEBSERVICES"] = {"http://test.com": "/test"}

        mock_get = mock_requests("get")
        mock_response = MagicMock()
        mock_response.json.return_value = {
            "/example": {
                "description": "A description",
                "methods": ["OPTIONS", "GET", "HEAD"],
                "scopes": ["api"],
                "rate_limit": [300, 86400],
                "authorization": False,
            }
        }
        mock_get.return_value = mock_response

        app.proxy_service.register_services()

        mock_proxy_view.assert_called_once_with("/test/example", "/test", "http://test.com")
        mock_auth_service.require_oauth.assert_not_called()

    def test_register_services_rate_limit(
        self,
        app,
        mock_requests,
        mock_cache_service,
        mock_limiter_service,
        mock_auth_service,
        mock_csrf_extension,
        mock_add_url_rule,
        mock_proxy_view,
    ):
        app.config["PROXY_SERVICE_WEBSERVICES"] = {"http://test.com": "/test"}

        mock_get = mock_requests("get")
        mock_response = MagicMock()
        mock_response.json.return_value = {
            "/example": {
                "description": "A description",
                "methods": ["OPTIONS", "GET", "HEAD"],
                "scopes": ["api"],
                "rate_limit": [300, 86400],
            }
        }
        mock_get.return_value = mock_response

        app.proxy_service.register_services()

        # Check that the rate limit was set correctly
        mock_limiter_service.shared_limit.assert_called_once_with(counts=300, per_second=86400)


class TestLimiterService:
    def test_group_endpoint(self, app):
        # Arrange
        app.limiter_service._ratelimit_groups = {
            "group1": {
                "counts": 1,
                "per_second": 3600 * 10,
                "patterns": ["/example/.*"],
            }
        }
        app.limiter_service._symbolic_ratelimits = {}

        # Act
        app.limiter_service.group_endpoint("/example/test", 300, 86400)

        # Assert
        assert app.limiter_service._symbolic_ratelimits["group1"] == {
            "name": "group1",
            "counts": 1,
            "per_second": 3600 * 10,
        }

    def test_shared_limit_with_limit_value(self, app):
        # Arrange
        limit_value = "100/minute"

        # Act
        decorator = app.limiter_service.shared_limit(limit_value=limit_value)

        # Assert
        assert not callable(decorator.limit_value)
        assert decorator.limit_value == limit_value

    def test_shared_limit_with_counts_and_per_second(self, app, mock_current_token):
        # Arrange
        counts, per_second = 100, 60
        with app.test_request_context("/"):
            # Act
            decorator = app.limiter_service.shared_limit(counts=counts, per_second=per_second)

            # Assert
            assert callable(decorator.limit_value)

            expected_limit_value = f"{int(counts * mock_current_token.client.ratelimit_multiplier)}/{per_second} second"
            assert decorator.limit_value() == expected_limit_value


class TestSecurityService:
    def test_create_user(self, app):
        email = "test@gmail.com"
        password = "test_password"
        user = app.security_service.create_user(email, password)
        assert user.email == email
        assert user.password is not None

    def test_create_role(self, app):
        name = "test_role"
        description = "This is a test role"
        role = app.security_service.create_role(name, description)
        assert role.name == name
        assert role.description == description

    def test_add_role_to_user(self, app):
        email = "test@gmail.com"
        password = "test_password"
        user = app.security_service.create_user(email, password)
        name = "test_role"
        description = "This is a test role"
        role = app.security_service.create_role(name, description)
        result = app.security_service.add_role_to_user(user, role)
        assert result is True
        assert role in user.roles

    def test_change_password(self, app):
        email = "test@gmail.com"
        password = "test_password"
        user = app.security_service.create_user(email, password)
        new_password = "new_test_password"
        updated_user = app.security_service.change_password(user, new_password)
        assert updated_user.password != new_password
        assert updated_user.validate_password(new_password)

    def test_validate_email(self, app):
        valid_email = "test@gmail.com"
        invalid_email = "test"
        assert app.security_service.validate_email(valid_email) is True
        assert app.security_service.validate_email(invalid_email) is False

    def test_change_email(self, app):
        email = "test@gmail.com"
        password = "test_password"
        user = app.security_service.create_user(email, password)
        new_email = "new_test@gmail.com"
        updated_user = app.security_service.change_email(user, new_email)
        assert updated_user.email == new_email

    def test_generate_email_token(self, app, mock_regular_user):
        token = app.security_service.generate_email_token()
        assert isinstance(token, str)

    def test_verify_email_token(self, app, mock_regular_user):
        user = app.security_service.create_user(
            mock_regular_user.email, "test_password", id=mock_regular_user.id
        )
        token = app.security_service.generate_email_token()
        user = app.security_service.verify_email_token(token)
        assert isinstance(user, User)
