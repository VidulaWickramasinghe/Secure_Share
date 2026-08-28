"""Regression coverage for the configured WSGI deployment entrypoint."""

from __future__ import annotations

import importlib.util
import tomllib
from pathlib import Path

import pytest
from packaging.specifiers import SpecifierSet

from app import create_app
from app.config import (
    _application_environment,
    _boolean_from_env,
    _nonnegative_float_from_env,
    _positive_int_from_env,
)


PROJECT_ROOT = Path(__file__).resolve().parents[1]


@pytest.mark.parametrize("empty_value", [None, "", " \t\n"])
def test_blank_optional_settings_use_their_defaults(monkeypatch, empty_value):
    name = "SECURE_SHARE_TEST_SETTING"
    if empty_value is None:
        monkeypatch.delenv(name, raising=False)
    else:
        monkeypatch.setenv(name, empty_value)

    assert _positive_int_from_env(name, 4096) == 4096
    assert _nonnegative_float_from_env(name, 0.5) == 0.5
    assert _boolean_from_env(name, True) is True
    assert _boolean_from_env(name, False) is False


@pytest.mark.parametrize(
    ("reader", "default", "invalid_value"),
    [
        (_positive_int_from_env, 4096, "not-an-integer"),
        (_positive_int_from_env, 4096, "0"),
        (_positive_int_from_env, 4096, "-1"),
        (_nonnegative_float_from_env, 0.5, "not-a-number"),
        (_nonnegative_float_from_env, 0.5, "nan"),
        (_nonnegative_float_from_env, 0.5, "-0.5"),
        (_boolean_from_env, True, "maybe"),
    ],
)
def test_invalid_nonblank_settings_are_still_rejected(
    monkeypatch, reader, default, invalid_value
):
    monkeypatch.setenv("SECURE_SHARE_TEST_SETTING", invalid_value)
    with pytest.raises(ValueError, match="SECURE_SHARE_TEST_SETTING"):
        reader("SECURE_SHARE_TEST_SETTING", default)


@pytest.mark.parametrize("empty_value", [None, "", " \t\n"])
def test_vercel_with_no_app_env_defaults_to_production(monkeypatch, empty_value):
    monkeypatch.setenv("VERCEL", "1")
    if empty_value is None:
        monkeypatch.delenv("APP_ENV", raising=False)
    else:
        monkeypatch.setenv("APP_ENV", empty_value)

    assert _application_environment() == "production"


def test_invalid_app_env_never_silently_disables_production(monkeypatch):
    monkeypatch.setenv("VERCEL", "1")
    monkeypatch.setenv("APP_ENV", "unknown")
    with pytest.raises(ValueError, match="APP_ENV"):
        _application_environment()


def test_blank_local_app_env_keeps_development_default(monkeypatch):
    monkeypatch.delenv("VERCEL", raising=False)
    monkeypatch.setenv("APP_ENV", " ")
    assert _application_environment() == "development"


def test_empty_vercel_settings_keep_production_security_defaults(monkeypatch):
    monkeypatch.setenv("VERCEL", "1")
    for name in (
        "APP_ENV",
        "SECRET_KEY",
        "ACCOUNT_TOKEN_PEPPER",
        "RATE_LIMIT_KEY_SECRET",
        "MAX_CONTENT_LENGTH",
        "BROWSER_COOKIE_SECURE",
        "SECURITY_EMAIL_INLINE_DELIVERY",
        "MAIL_BACKEND",
        "UPLOAD_FOLDER",
        "MAIL_FILE_OUTBOX",
    ):
        monkeypatch.setenv(name, "")

    # Config is evaluated on import. Load a fresh module without changing the
    # configuration already used by other tests or starting the application.
    spec = importlib.util.spec_from_file_location(
        "_secure_share_blank_config", PROJECT_ROOT / "app" / "config.py"
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    config = module.Config

    assert config.APP_ENV == "production"
    assert config.BROWSER_COOKIE_SECURE is True
    assert config.SECURITY_EMAIL_INLINE_DELIVERY is False
    assert config.MAIL_BACKEND == "smtp"
    assert config.MAX_CONTENT_LENGTH > 0
    assert config.UPLOAD_FOLDER == str(PROJECT_ROOT / "storage")
    assert config.MAIL_FILE_OUTBOX == "mail-outbox"
    # Missing production credentials must not be replaced with disposable keys.
    assert config.SECRET_KEY is None
    assert config.ACCOUNT_TOKEN_PEPPER is None
    assert config.RATE_LIMIT_KEY_SECRET is None

    with pytest.raises(RuntimeError, match="SECRET_KEY"):
        create_app(
            {name: value for name, value in vars(config).items() if name.isupper()}
        )


def test_vercel_project_declares_all_runtime_dependencies():
    with (PROJECT_ROOT / "pyproject.toml").open("rb") as configuration_file:
        project = tomllib.load(configuration_file)["project"]

    requirements = {
        line.strip()
        for line in (PROJECT_ROOT / "requirements.txt").read_text().splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    }
    # Vercel installs from pyproject.toml, while local pip/CI users still use
    # requirements.txt. Both installation paths must have the same runtime.
    assert set(project["dependencies"]) == requirements

    python_version = (PROJECT_ROOT / ".python-version").read_text().strip()
    assert python_version in SpecifierSet(project["requires-python"])


def test_vercel_entrypoint_exports_the_application_without_starting_a_server(
    app, monkeypatch
):
    with (PROJECT_ROOT / "pyproject.toml").open("rb") as configuration_file:
        configuration = tomllib.load(configuration_file)

    entrypoint = configuration["tool"]["vercel"]["entrypoint"]
    assert entrypoint == "run:app"
    module_name, variable_name = entrypoint.split(":")

    # Import the real entry module with an isolated test app, never the
    # developer's configured database, upload directory, or external services.
    monkeypatch.setattr("app.create_app", lambda: app)

    def reject_development_server(*args, **kwargs):
        raise AssertionError("Importing the WSGI entrypoint must not start a server")

    monkeypatch.setattr(app, "run", reject_development_server)
    spec = importlib.util.spec_from_file_location(
        module_name, PROJECT_ROOT / f"{module_name}.py"
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)

    application = getattr(module, variable_name)
    assert application is app
    client = application.test_client()
    assert client.get("/").status_code == 200
    assert client.get("/api/files").status_code == 401
