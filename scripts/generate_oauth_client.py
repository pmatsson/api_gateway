import argparse
import json
import sys, os
import datetime

from sqlalchemy.orm.exc import NoResultFound, MultipleResultsFound
from werkzeug.security import gen_salt

PROJECT_HOME=os.path.join(os.path.dirname(__file__),'..')
sys.path.append(PROJECT_HOME)

from apigateway.extensions import db
from apigateway.app import create_app

from apigateway.models import (
    OAuth2Client,
    OAuth2Token,
    User,
)

class DatabaseIntegrityError(Exception):
  
  def __init__(self,value="Multiple entries found for what should have been a unique query. This suggests that the database is not in a correct state!"):
    self.value = value

  def __str__(self):
    return repr(self.value)

def add_arguments(parser):
  
  parser.add_argument(
    '--user-email',
    required=True,
    dest='user_email',
    help='The user identifier (email) associated with this token'
    )

  parser.add_argument(
    '--description',
    required=False,
    default = '',
    dest='description',
    help='A description for this client'
    )
  
  parser.add_argument(
    '--name',
    required=True,
    dest='name',
    help='Name of the oauth client'
    )

  parser.add_argument(
    '--create-user',
    required=False,
    default=False,
    action='store_true',
    dest='create_user',
    help='Create the user if it doesn\'t exist'
    )

  parser.add_argument(
    '--scopes',
    required=True,
    nargs='*',
    dest='scopes',
    help='Space separated list of scopes'
    )

  parser.add_argument(
    '--personal',
    default=False,
    action='store_true',
    dest='is_personal',
    help='Set the token type'
    )


def get_token():
  
    parser = argparse.ArgumentParser()
    add_arguments(parser)
    args = parser.parse_args()
    app = create_app() 

    with app.app_context() as context:
        
        try:
            u = db.session.query(User).filter_by(email=args.user_email).one()
        except NoResultFound:
           
            if not args.create_user:
                sys.exit(f"User with email {args.user_email} not found, and --create-user was not specified. Exiting.")
            u = User(email=args.user_email, active=True)
            db.session.add(u)
            db.session.commit()
        except MultipleResultsFound:
        
            raise DatabaseIntegrityError
        
        
        try:
            client = db.session.query(OAuth2Client).filter_by(user_id=u.id, name=args.name).one()
        except MultipleResultsFound:
            raise DatabaseIntegrityError("Multiple oauthclients found for that user and name.")
        except NoResultFound:
            
            client = OAuth2Client(
                        user_id=u.id,
                        ratelimit_multiplier=1.0,
                        individual_ratelimit_multipliers=None,
                        last_activity=datetime.datetime.now(),
                    )
            client.set_client_metadata(
                {
                    "client_name": args.name,
                    "description": args.description,
                    "scope": " ".join(args.scopes) or " ".join(app.config.get("USER_DEFAULT_SCOPES", "")),
                }
            )

            client.gen_salt()
            db.session.add(client)
            db.session.commit()

        try:
            tokens = db.session.query(OAuth2Token).filter_by(
                client_id=client.client_id,
                user_id=u.id,
                is_personal=args.is_personal).all()
            
            # Iterate through each result and compare scopes
            matching_tokens = []
            for token in tokens:
                if set(args.scopes) == set(token.scopes):
                    matching_tokens.append(token)
            if not matching_tokens:
                raise NoResultFound
            
            print(f"Tokens with those definitions found, returning the first {len(matching_tokens)}")
            token = matching_tokens[0]

        except NoResultFound:
            salt_length = app.config.get("OAUTH2_CLIENT_ID_SALT_LEN", 40)
            expires = datetime.datetime(2050,1,1)
            token = OAuth2Token(
                token_type="Bearer",
                user_id=u.id,
                client_id=client.client_id,
                access_token=gen_salt(salt_length),
                refresh_token=gen_salt(salt_length),
                scope=client.scope,
                expires_in=(expires - datetime.datetime.now()).total_seconds(),
                is_personal=args.is_personal,
                is_internal=True,)
            
            db.session.add(token)
            db.session.commit()
        return {
            'access_token': token.access_token,
            'refresh_token': token.refresh_token,
            'username': u.email,
            'expires_in': f'{token.expires_in} seconds',
            'token_type': "Bearer"
        }


if __name__=="__main__":
  print(f'\n {json.dumps(get_token(), indent=1)}')