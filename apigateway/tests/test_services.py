from unittest.mock import MagicMock, patch

import pytest

from apigateway.app import create_app
from apigateway.exceptions import ValidationError
from apigateway.models import OAuth2Client, OAuth2Token, base_model


@pytest.fixture(scope="module", autouse=True)
def app():
    app = create_app(
        **{
            "SQLALCHEMY_DATABASE_URI": "sqlite:///:memory:",
            "SQLALCHEMY_ECHO": False,
            "TESTING": True,
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
def moc_anon_user():
    with patch("flask_login.utils._get_user") as mock_user:
        user = MagicMock()
        user.get_id.return_value = "test_anon_user"
        user.is_anonymous_bootstrap_user = True
        user.ratelimit_quota = -1
        user.allowed_scopes = ["test_scope"]
        mock_user.return_value = user
        yield user


@pytest.fixture()
def moc_regular_user():
    with patch("flask_login.utils._get_user") as mock_user:
        user = MagicMock()
        user.get_id.return_value = "test_user"
        user.is_anonymous_bootstrap_user = False
        user.ratelimit_quota = 3
        user.allowed_scopes = ["test_scope"]
        mock_user.return_value = user
        yield user


class TestAuthService:
    def test_load_client(self, app, moc_anon_user):
        # Arrange
        token = OAuth2Token(user_id=moc_anon_user.get_id(), access_token="test_token")
        client = OAuth2Client(user_id=moc_anon_user.get_id(), client_id="test_client")

        app.db.session.add(token)
        app.db.session.add(client)
        app.db.session.commit()

        # Act
        client, token = app.auth_service.load_client("test_client")

        # Assert
        assert client.client_id == "test_client"
        assert token.user_id == moc_anon_user.get_id()

    def test_bootstrap_anon_user(self, app, moc_anon_user):
        # Act
        client, token = app.auth_service.bootstrap_user()

        # Assert
        assert client.user_id == moc_anon_user.get_id()
        assert token.user_id == moc_anon_user.get_id()
        assert token.expires_in == app.config.get("BOOTSTRAP_TOKEN_EXPIRES")

    def test_bootstrap_user(self, app, moc_regular_user):
        # Act
        client, token = app.auth_service.bootstrap_user()

        # Assert
        assert client.user_id == moc_regular_user.get_id()
        assert token.user_id == moc_regular_user.get_id()

    def test_bootstrap_user_no_capacity(self, app, moc_regular_user):
        with pytest.raises(ValidationError):
            _, _ = app.auth_service.bootstrap_user(ratelimit_multiplier=100)

    def test_bootstrap_invalid_scope(self, app, moc_regular_user):
        with pytest.raises(ValidationError):
            _, _ = app.auth_service.bootstrap_user(scope="invalid")

    def test_bootstrap_valid_scope(self, app, moc_regular_user):
        try:
            _, _ = app.auth_service.bootstrap_user(scope="test_scope")
        except ValidationError:
            pytest.fail("Unexpected ValidationError")
