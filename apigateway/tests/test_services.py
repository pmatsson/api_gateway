from unittest.mock import MagicMock, call

import pytest
from flask import request

from apigateway.exceptions import ValidationError
from apigateway.models import OAuth2Client, OAuth2Token, User
from apigateway.services import GatewayService


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

    def test_headers_set(self, app, mock_regular_user):
        _, token = app.auth_service.bootstrap_user()

        @app.route("/test_auth_headers_set")
        def test_route():
            pass

        with app.test_request_context(
            "/test_auth_headers_set",
            headers={
                "Authorization": "Bearer " + token.access_token,
            },
        ):
            # Manually call before_request functions
            for func in app.before_request_funcs[None]:
                func()

            assert "X-api-uid" in request.headers

    def test_headers_not_set(self, app):

        @app.route("/test_auth_headers_not_set")
        def test_auth_headers_not_set():
            pass

        with app.test_request_context("/test_auth_headers_not_set"):
            # Manually call before_request functions
            for func in app.before_request_funcs[None]:
                func()

            assert "X-api-uid" not in request.headers


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
        mock_storage_service,
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
            call("http://test.com/resources", mock_response.json.return_value),
            call("http://test2.com/resources", mock_response.json.return_value),
        ]
        mock_storage_service.set.assert_has_calls(calls, any_order=True)

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
        mock_storage_service,
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
        mock_storage_service,
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
        app.limiter_service.clear_limits("*", None)

        limit_value = "5/minute"
        decorator = app.limiter_service.shared_limit(limit_value=limit_value)
        counter = 0

        @decorator
        def increment_counter():
            nonlocal counter
            counter += 1

        app.add_url_rule(
            "/test1",
            endpoint="/test1",
            view_func=increment_counter,
            methods=["GET", "POST"],
        )

        # Act
        with app.test_request_context("/test1"):
            for _ in range(10):
                try:
                    increment_counter()
                except Exception:
                    break
        # Assert
        assert counter == 5

    def test_shared_limit_with_counts_and_per_second(self, app, mock_current_token):
        # Arrange

        counts, per_second = 3, 60
        decorator = app.limiter_service.shared_limit(counts=counts, per_second=per_second)
        counter2 = 0

        @decorator
        def increment_counter2():
            nonlocal counter2
            counter2 += 1

        app.add_url_rule(
            "/test2",
            endpoint="/test2",
            view_func=increment_counter2,
            methods=["GET", "POST"],
        )

        # Act
        with app.test_request_context("/test2"):
            for _ in range(10):
                try:
                    increment_counter2()
                except Exception:
                    break
        # Assert
        assert counter2 == 9  # 9 because of rate limit multiplier of 3 for current user


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
