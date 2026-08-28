"""Check deployment settings without opening a server or contacting services.

Run with the intended runtime environment, e.g. VERCEL=1 python check_deployment.py.
Only setting names and fixed diagnostic messages are printed, never values.
"""

from __future__ import annotations

import sys

from flask import Flask

from app.config import Config
from app.validation import validate_application_configuration
from deployment import DeploymentConfigurationError


def main() -> int:
    application = Flask("app")
    application.config.from_object(Config)
    try:
        validate_application_configuration(application)
    except DeploymentConfigurationError as exc:
        print(str(exc), file=sys.stderr)
        return 1
    print(
        "Static configuration checks passed. Database migrations, service "
        "connectivity, persistent storage and email-worker operation still "
        "require verification."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
