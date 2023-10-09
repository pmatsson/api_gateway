from typing import Tuple
from urllib.parse import urljoin

import requests
from flask import current_app, request
from flask.views import View


class ProxyView(View):
    """A view for proxying requests to a remote webservice."""

    def __init__(self, deploy_path: str, remote_base_url: str):
        """
        Initializes a ProxyView object.

        Args:
            deploy_path (str): The path to deploy the proxy view.
            remote_base_url (str): The base URL of the remote server to proxy requests to.
        """
        super().__init__()
        self._deploy_path = deploy_path
        self._remote_base_url = remote_base_url
        self._session = requests.Session()

    def dispatch_request(self, **kwargs) -> Tuple[bytes, int]:
        """
        Dispatches the request to the proxy view.

        Returns:
            Tuple[bytes, int]: A tuple containing the content of the response and the status code.
        """
        return self._proxy_request()

    def _proxy_request(self) -> Tuple[bytes, int]:
        """
        Proxies the request to the remote server.

        Returns:
            Tuple[bytes, int]: A tuple containing the content of the response and the status code.
        """
        try:
            remote_url = self._construct_remote_url()
            http_method_func = getattr(self._session, request.method.lower())

            current_app.logger.debug(
                "Proxying %s request to %s", request.method.upper(), remote_url
            )

            response: requests.Response = http_method_func(
                remote_url, data=request.get_data(), headers=request.headers
            )
            return response.content, response.status_code
        except (
            requests.exceptions.ConnectionError,
            requests.exceptions.Timeout,
        ):
            return b"504 Gateway Timeout", 504

    def _construct_remote_url(self) -> str:
        """
        Constructs the URL of the remote server.

        Returns:
            str: The URL of the remote server.
        """
        path = request.full_path.replace(self._deploy_path, "", 1)
        path = path[1:] if path.startswith("/") else path
        return urljoin(self._remote_base_url, path)
