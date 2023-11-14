from datetime import datetime
from unittest.mock import MagicMock, patch

import pytest
import requests
from werkzeug.exceptions import Unauthorized

from apigateway.models import User
from apigateway.schemas import bootstrap_get_response_schema
from apigateway.views import Bootstrap, ProxyView, UserAuthView


class TestBootstrapView:
    @pytest.fixture
    def bootstrap(self):
        return Bootstrap()

    def test_get_authenticated_user(self, app, bootstrap, mock_regular_user):
        with app.test_request_context(json={}):
            response, status_code = bootstrap.get()

            assert status_code == 200
            assert not bootstrap_get_response_schema.validate(response)

    def test_get_authenticated_user_with_params(self, app, bootstrap, mock_regular_user):
        req_json = {
            "scope": "test_scope",
            "client_name": "test_client",
            "redirect_uri": "test_uri",
        }
        with app.test_request_context(json=req_json):
            response, status_code = bootstrap.get()
            parsed_response = bootstrap_get_response_schema.load(response)

            assert status_code == 200
            assert not bootstrap_get_response_schema.validate(response)
            assert parsed_response["scope"] == req_json["scope"]

    def test_get_anonymous_user_with_params(self, app, bootstrap, mock_anon_user):
        json = {"scope": "test_scope", "client_name": "test_client", "redirect_uri": "test_uri"}
        with app.test_request_context(json=json):
            with pytest.raises(Unauthorized):
                bootstrap.get()


class TestUserAuthView:
    @pytest.fixture
    def user_auth_view(self):
        return UserAuthView()

    @pytest.fixture
    def authenticated_user(self, app):
        with app.session_scope() as session:
            user = User()
            user.id = 123
            user.active = True
            user.confirmed_at = datetime.utcnow()
            user.email = "test@gmail.com"
            user.password = "valid_password"
            user.fs_uniquifier = "unique_id"
            session.add(user)
            session.commit()
            yield user

        with app.session_scope() as session:
            session.delete(user)
            session.commit()

    @pytest.fixture
    def unverified_user(self, app):
        with app.session_scope() as session:
            user = User()
            user.id = 123
            user.active = True
            user.email = "test_unverified@gmail.com"
            user.password = "valid_password"
            user.fs_uniquifier = "unique_id_unverified"
            app.db.session.add(user)
            app.db.session.commit()
            yield user

        with app.session_scope() as session:
            session.delete(user)
            session.commit()

    def test_post_successful_login(self, app, authenticated_user, user_auth_view):
        with app.test_request_context(
            json={"email": authenticated_user.email, "password": "valid_password"}
        ):
            _, status_code = user_auth_view.post()

            assert status_code == 200

    def test_post_invalid_password(self, app, authenticated_user, user_auth_view):
        with app.test_request_context(
            json={"email": authenticated_user.email, "password": "invalid_password"}
        ):
            with pytest.raises(Unauthorized):
                user_auth_view.post()

    def test_post_invalid_email(self, app, authenticated_user, user_auth_view):
        with app.test_request_context(
            json={"email": "invalid@gmail.com", "password": "valid_password"}
        ):
            with pytest.raises(Unauthorized):
                user_auth_view.post()

    def test_post_unverified_account(self, app, unverified_user, user_auth_view):
        with app.test_request_context(
            json={"email": unverified_user.email, "password": "valid_password"}
        ):
            with pytest.raises(Unauthorized):
                user_auth_view.post()


class TestProxyView:
    @pytest.fixture(scope="function")
    def mock_session(self):
        with patch("requests.Session", new_callable=MagicMock) as mock_session:
            mock_session.return_value.get.return_value.status_code = 200
            mock_session.return_value.get.return_value.headers = {
                "test_allowed_header": "value",
                "test_disallowed_header": "value",
            }
            yield mock_session

    @pytest.fixture(scope="module")
    def proxy_view(self):
        return ProxyView.as_view(
            "proxy_view", deploy_path="/proxy", remote_base_url="http://remote.com"
        )

    @pytest.fixture(scope="module", autouse=True)
    def register_proxy_view(self, app, proxy_view):
        app.add_url_rule("/proxy", view_func=proxy_view, methods=["GET", "POST"])

    @pytest.fixture
    def client(self, app):
        return app.test_client()

    def test_proxy_request_get(self, client, mock_session, mock_redis_service):
        response = client.get("/proxy")
        assert response.status_code == 200
        assert mock_session.return_value.get.call_count == 1

    def test_proxy_request_connection_error(self, client, mock_session, mock_redis_service):
        mock_session.return_value.get.side_effect = requests.exceptions.ConnectionError
        response = client.get("/proxy")
        assert response.data == b"504 Gateway Timeout"
        assert response.status_code == 504

    def test_proxy_request_timeout(self, client, mock_session, mock_redis_service):
        mock_session.return_value.get.side_effect = requests.exceptions.Timeout
        response = client.get("/proxy")
        assert response.data == b"504 Gateway Timeout"
        assert response.status_code == 504

    def test_allowed_headers(self, app, client, mock_session, mock_redis_service):
        response = client.get("/proxy")
        assert "test_allowed_header" in list(response.headers.keys())

    def test_disallowed_headers(self, app, client, mock_session, mock_redis_service):
        response = client.get("/proxy")
        assert "test_disallowed_header" not in list(response.headers.keys())
