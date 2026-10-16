"""Shared pytest fixtures for detection-engineering blueprint tests."""

from pathlib import Path

import pytest

from support import BLUEPRINT_ROOT, REPOSITORY_ROOT, load_yaml


@pytest.fixture(scope="session")
def repository_root() -> Path:
    return REPOSITORY_ROOT


@pytest.fixture(scope="session")
def blueprint_root() -> Path:
    return BLUEPRINT_ROOT


@pytest.fixture(scope="session")
def read_yaml():
    return load_yaml
