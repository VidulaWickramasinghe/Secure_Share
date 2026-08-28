"""WSGI entrypoint for deployment and local development of Secure Share."""

from app import create_app


app = create_app()


if __name__ == "__main__":
    app.run()
