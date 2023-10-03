from flask import Flask
from adsmutils import ADSFlask
from adsws.extensions import gateway_service


def register_extensions(app: Flask):
    """Register extensions.

    Args:
        app (ADSFlask): Application object
    """

    gateway_service.init_app(app)


def create_app():
    """Create application and initialize dependencies.

    Returns:
        ADSFlask: Application object
    """

    app = ADSFlask(__name__, static_folder=None)    
    
    register_extensions(app)

    gateway_service.register_services()

    return app
