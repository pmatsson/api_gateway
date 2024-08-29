import pytest
from unittest.mock import patch, MagicMock
from sqlalchemy.orm.exc import NoResultFound, MultipleResultsFound
from scripts.generate_oauth_client import get_token, DatabaseIntegrityError
from apigateway.models import OAuth2Client, OAuth2Token, User
import datetime


def test_get_token_existing_user_existing_client(mock_add_arguments, app, mock_regular_user, mock_client, mock_simple_token):
    with patch("apigateway.extensions.db.session.query") as mock_query:
        mock_query.side_effect = [
            # Mock user
            MagicMock(filter_by=MagicMock(return_value=MagicMock(one=MagicMock(return_value=mock_regular_user)))),
            # Mock client
            MagicMock(filter_by=MagicMock(return_value=MagicMock(one=MagicMock(return_value=mock_client)))),
            # Mock tokens list
            MagicMock(filter_by=MagicMock(return_value=MagicMock(all=MagicMock(return_value=[mock_simple_token])))),
        ]
        
        result = get_token()

        assert result['access_token'] == "access_token"
        assert result['refresh_token'] == "refresh_token"
        assert str(result['username']) == "test@gmail.com"

def test_get_token_no_result_found_exit(mock_add_arguments, app):
    with patch("apigateway.extensions.db.session.query") as mock_query:

        mock_query.return_value.filter_by.return_value.one.side_effect = NoResultFound
        
        with pytest.raises(SystemExit) as error:
            get_token()
        
        assert "User with email test@gmail.com not found, and --create-user was not specified. Exiting." in str(error.value)
    
def test_get_token_no_result_found_create_new_user(mock_add_arguments, app, mock_simple_token):
    mock_add_arguments.return_value.create_user = True
    with patch("apigateway.extensions.db.session.query") as mock_query, \
         patch("apigateway.extensions.db.session.add") as mock_add, \
         patch("apigateway.extensions.db.session.commit") as mock_commit:

        mock_query.return_value.filter_by.return_value.one.side_effect = NoResultFound

        mock_query.return_value.filter_by.return_value.all.return_value = [mock_simple_token]
        
        get_token()

        # Check if a new user was created
        mock_add.assert_called()
        mock_commit.assert_called()

def test_get_token_multiple_users_raises_error(mock_add_arguments, app):
    with patch("apigateway.extensions.db.session.query") as mock_query:
        mock_query.return_value.filter_by.return_value.one.side_effect = MultipleResultsFound

        with pytest.raises(DatabaseIntegrityError):
            get_token()

def test_get_token_multiple_clients_raises_error(mock_add_arguments, app, mock_regular_user):
    with patch("apigateway.extensions.db.session.query") as mock_query:

        mock_query.side_effect = [
            # Mock user
            MagicMock(filter_by=MagicMock(return_value=MagicMock(one=MagicMock(return_value=mock_regular_user)))),
            # Mock client
            MagicMock(filter_by=MagicMock(return_value=MagicMock(one=MagicMock(side_effect=MultipleResultsFound))))
        ]
        
        with pytest.raises(DatabaseIntegrityError) as error:
            get_token()

        assert ('Multiple oauthclients found for that user and name.' in str(error.value))

def test_create_client_and_metadata(mock_add_arguments, app, mock_regular_user, mock_simple_token):
   with patch("apigateway.extensions.db.session.query") as mock_query, \
         patch("apigateway.extensions.db.session.add") as mock_add,  \
         patch("apigateway.extensions.db.session.commit") as mock_commit:
        
        mock_query.side_effect = [
            # Mock user
            MagicMock(filter_by=MagicMock(return_value=MagicMock(one=MagicMock(return_value=mock_regular_user)))),
            # Mock client
            MagicMock(filter_by=MagicMock(return_value=MagicMock(one=MagicMock(side_effect=NoResultFound)))), 
            # Mock tokens list
            MagicMock(filter_by=MagicMock(return_value=MagicMock(all=MagicMock(return_value=[mock_simple_token])))),
        ]
        
        get_token()

        # Get the created client from the mock
        created_client = mock_add.call_args[0][0]
        
        # Assert that the created client's attributes correspond to the args
        assert created_client.user_id == mock_regular_user.id
        assert created_client.ratelimit_multiplier == 1.0
        assert created_client.individual_ratelimit_multipliers is None
        assert created_client.client_metadata["client_name"] == mock_add_arguments.return_value.name
        assert created_client.client_metadata["description"] == mock_add_arguments.return_value.description
        assert created_client.client_metadata["scope"] == " ".join(mock_add_arguments.return_value.scopes)
        
        # Assert that commit was called to save the client to the database
        mock_add.assert_called_once()
        mock_commit.assert_called_once()

def test_get_token_no_tokens_found(mock_add_arguments, app, mock_regular_user, mock_client, mock_simple_token):
    mock_simple_token.scopes = ["fake_scope_1", "fake_scope_2"]
    with patch("apigateway.extensions.db.session.query") as mock_query, \
         patch("apigateway.extensions.db.session.add") as mock_add,  \
         patch("apigateway.extensions.db.session.commit") as mock_commit:
        
        mock_query.side_effect = [
            # Mock user
            MagicMock(filter_by=MagicMock(return_value=MagicMock(one=MagicMock(return_value=mock_regular_user)))),
            # Mock client
            MagicMock(filter_by=MagicMock(return_value=MagicMock(one=MagicMock(return_value=mock_client)))), 
            # Mock tokens list
            MagicMock(filter_by=MagicMock(return_value=MagicMock(all=MagicMock(return_value=[mock_simple_token])))),
        ]

        get_token()

        created_token = mock_add.call_args[0][0]
        
        mock_add.assert_called()
        mock_commit.assert_called()

        assert created_token.user_id == mock_regular_user.id
        assert created_token.client_id == mock_client.client_id
        assert created_token.scope == mock_client.scope
        assert created_token.is_personal == mock_add_arguments.return_value.is_personal 
        assert created_token.is_internal == True 
