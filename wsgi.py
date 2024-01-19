from werkzeug.middleware.dispatcher import DispatcherMiddleware
from werkzeug.serving import run_simple
from werkzeug.wrappers import Response

from apigateway.app import create_app

if __name__ == "__main__":
    app = DispatcherMiddleware(Response("Not Found", status=404), {"/v1": create_app()})

    run_simple(
        "0.0.0.0",
        8181,
        app,
        use_reloader=True,
        use_debugger=True,
        threaded=True,
    )
