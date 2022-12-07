# pylint:disable=missing-docstring
import sys
from pathlib import Path
from unittest.mock import patch

import pytest

from poetry_codeartifact_auth import (
    CodeArtifactRepoConfig,
    parse_poetry_repo_config,
    CodeArtifactUrlParseException,
    _find_pyproject_toml_path,
    _get_repo_config_from_pyproject_toml,
    main,
)


def test__find_pyproject_toml_path():
    test_files_root = Path(__file__).parent / "files"
    expected_toml_path = test_files_root / "pyproject.toml"

    assert _find_pyproject_toml_path(str(test_files_root)) == expected_toml_path
    assert _find_pyproject_toml_path(str(test_files_root / "subdir")) == expected_toml_path
    assert (
        _find_pyproject_toml_path(str(test_files_root / "subdir" / "subsubdir"))
        == expected_toml_path
    )


def test__get_repo_config_from_pyproject_toml():
    toml_path = Path(__file__).parent / "files" / "pyproject.toml"
    expected_url = "https://banana.repo.example.com/python-repo-path"
    assert _get_repo_config_from_pyproject_toml(toml_path)["banana"]["url"] == expected_url


class TestCodeArtifactRepoConfig:
    @staticmethod
    def test_from_url_works_with_good_value():
        result = CodeArtifactRepoConfig.from_url(
            "https://example-domain-1234567.d.codeartifact.us-west-2.amazonaws.com/some-suffix"
        )
        expected = CodeArtifactRepoConfig(
            aws_account="1234567",
            domain="example-domain",
            region="us-west-2",
        )
        assert result == expected

    @staticmethod
    def test_from_url_throws_valueerror_with_bad_value():
        with pytest.raises(ValueError):
            CodeArtifactRepoConfig.from_url("garbage")
        with pytest.raises(CodeArtifactUrlParseException):
            CodeArtifactRepoConfig.from_url(
                "https://example-domain-1234567.d.INVALID.us-west-2.amazonaws.com/some-suffix"
            )


def test_parse_poetry_repo_config():
    config_output = "{'example': {'url': 'https://repo.example.com'}}"
    assert parse_poetry_repo_config(config_output)["example"]["url"] == "https://repo.example.com"


def test__cli_fails_without_subcommand():
    with patch.object(sys, "argv", ["poetry-ca-auth"]):
        with pytest.raises(SystemExit):
            main()


def test__cli_fails_with_invalid_subcommand():
    with patch.object(sys, "argv", ["poetry-ca-auth", "banana"]):
        with pytest.raises(SystemExit):
            main()
