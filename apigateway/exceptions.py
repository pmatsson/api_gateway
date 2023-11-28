from werkzeug.exceptions import HTTPException


class ValidationError(Exception):
    """
    Exception raised when some user data are invalid
    """

    def __init__(self, value):
        self.value = value

    def __str__(self):
        return repr(self.value)


class NoClientError(Exception):
    """
    Exception raised when no oauth2client is found, but was expected
    """

    def __init__(self, value):
        self.value = value

    def __str__(self):
        return repr(self.value)


class NoTokenError(Exception):
    """
    Exception raised when no oauth2token is found, but was expected
    """

    def __init__(self, value):
        self.value = value

    def __str__(self):
        return repr(self.value)


class NotFoundError(Exception):
    """
    Exception raised when a resource is not found
    """

    def __init__(self, value):
        self.value = value

    def __str__(self):
        return repr(self.value)


class Oauth2HttpError(HTTPException):
    """
    Exception raised when an oauth2 error occurs
    """

    def __init__(self, code, description, body, headers, response=None):
        super().__init__(description, response)
        self.body = body
        self.code = code
        self.headers = headers

    def get_body(self, environ=None, scope=None) -> str:
        return self.body

    def get_headers(self, environ=None, scope=None):
        return self.headers
