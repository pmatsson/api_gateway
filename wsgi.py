from werkzeug.serving import run_simple

from apigateway.app import create_app

if __name__ == "__main__":
    run_simple(
        "0.0.0.0",
        8181,
        create_app(),
        use_reloader=True,
        use_debugger=True,
        threaded=True,
    )
