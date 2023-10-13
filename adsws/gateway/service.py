""" This module defines the GatewayService class. """
import os
from typing import TypedDict
from urllib.parse import urljoin

import requests

from adsws.gateway.views import ProxyView
from adsws.service import ADSWSService


class GatewayService(ADSWSService):
    """A class for registering remote webservices and resources with the Flask application."""

    def __init__(self, auth_service: ADSWSService, name: str = "GATEWAY"):
        super().__init__(name)
        self.auth_service = auth_service

    def register_services(self):
        """Registers all services specified in the configuration file."""
        services = self.get_config("WEBSERVICES", {})
        for url, deploy_path in services.items():
            self.register_service(url, deploy_path)

    def register_service(self, base_url: str, deploy_path: str):
        """Registers a single service with the Flask application

        Args:
            base_url (str): The base URL of the service.
            deploy_path (str): The deployment path of the service
        """
        self._logger.info("Registering service %s at %s", base_url, deploy_path)

        try:
            resource_json = self._fetch_resource_document(base_url)
        except requests.exceptions.RequestException as ex:
            self._logger.error("Could not fetch resource document for %s: %s", base_url, ex)
            return

        for remote_path, properties in resource_json.items():
            self._logger.debug("Registering resource %s", remote_path)

            properties.setdefault(
                "rate_limit",
                self.get_config("DEFAULT_RATE_LIMIT", [1000, 86400]),
            )
            properties.setdefault("scopes", self.get_config("DEFAULT_SCOPES", []))

            rule_name = local_path = os.path.join(deploy_path, remote_path[1:])
            self._app.add_url_rule(
                rule_name,
                endpoint=local_path,
                view_func=self.auth_service.require_oauth()(
                    ProxyView.as_view(rule_name, deploy_path, base_url)
                ),
                methods=properties["methods"],
            )

    def _fetch_resource_document(self, base_url: str) -> TypedDict:
        """
        Fetches the resource document for a given base URL.

        Args:
            base_url (str): The base URL of the service.

        Returns:
            A dictionary containing the resource document.
        """

        resource_url = urljoin(base_url, self.get_config("RESOURCE_ENDPOINT", "/"))

        try:
            response = requests.get(resource_url, timeout=self.get_config("RESOURCE_TIMEOUT", 5))
            return response.json()
        except (requests.exceptions.ConnectionError, requests.exceptions.Timeout) as ex:
            raise ex
