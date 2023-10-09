""" Module containing the base class for ADSWS services. """
import logging
from flask import Flask


class ADSWSService:
    """Base class for initializing a service, setting up logging and config."""

    def __init__(self, name: str, app: Flask = None):
        self._name = name
        if app is not None:
            self.init_app(app)

    def init_app(self, app: Flask):
        """_summary_

        Args:
            app (Flask): _description_
        """
        if app is None:
            return

        self._app = app
        self._logger = logging.getLogger(f"{app.name}.{self._name}")

        if not hasattr(app, "extensions"):
            app.extensions = {}

        app.extensions[self._name.lower()] = self

    def get_config(self, key: str, default: any = None):
        """_summary_

        Args:
            key (str): _description_
            default (any, optional): _description_. Defaults to None.

        Returns:
            _type_: _description_
        """
        return self._app.config.get(self._name + "_" + key, default)
