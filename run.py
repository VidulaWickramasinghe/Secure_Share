"""WSGI entrypoint for deployment and local development of Secure Share."""

from deployment import create_wsgi_application


app = create_wsgi_application()


if __name__ == "__main__":
    app.run()
