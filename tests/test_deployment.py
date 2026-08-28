"""Regression coverage for the configured WSGI deployment entrypoint."""

from __future__ import annotations

import importlib.util
import tomllib
from pathlib import Path

from packaging.specifiers import SpecifierSet


PROJECT_ROOT = Path(__file__).resolve().parents[1]


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
