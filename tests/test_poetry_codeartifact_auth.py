# pylint:disable=missing-docstring
import os
import sys
from pathlib import Path
from unittest.mock import patch

import pytest

import poetry_codeartifact_auth
from poetry_codeartifact_auth import (
    CodeArtifactRepoConfig,
    parse_poetry_repo_config,
    CodeArtifactUrlParseException,
    _find_pyproject_toml_path,
    _get_repo_config_from_pyproject_toml,
    main,
    CodeArtifactAuthConfigException,
    AuthConfig,
    AwsAuthMethod,
    _url_with_auth,
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


def test__url_with_auth():
    assert (
        _url_with_auth("https://example.com/foo", "a password")
        == "https://aws:a%20password@example.com/foo"
    )


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


def test__cli_fails_with_invalid_parameter_if_not_pip_install():
    with patch.object(sys, "argv", ["poetry-ca-auth", "refresh", "--banana"]):
        with pytest.raises(SystemExit):
            main()


def test__cli_passes_extra_args_to_pip_install_correctly():
    with patch.object(
        os,
        "environ",
        {
            "POETRY_CA_AUTH_METHOD": "none",
            "POETRY_CA_PIP_DEFAULT_CODEARTIFACT_REPO": "https://example.com/codeartifact",
        },
    ):
        with patch.object(sys, "argv", ["poetry-ca-auth", "pip-install", "--user", "foo"]):
            with patch.object(
                poetry_codeartifact_auth, "run_pip_install_with_auth"
            ) as pip_install_method:
                main()
                pip_install_method.assert_called_with(
                    AuthConfig(AwsAuthMethod.NONE),
                    "https://example.com/codeartifact",
                    ["--user", "foo"],
                )


class TestAuthConfig:
    @staticmethod
    def test__succeed_if_profile_provided_and_method_needs_it():
        AuthConfig(AwsAuthMethod.SSO, default_profile="something")
        AuthConfig(AwsAuthMethod.VAULT, default_profile="something")

    @staticmethod
    def test__fails_with_missing_profile_if_auth_method_needs_it():
        with pytest.raises(CodeArtifactAuthConfigException):
            AuthConfig(AwsAuthMethod.SSO)
        with pytest.raises(CodeArtifactAuthConfigException):
            AuthConfig(AwsAuthMethod.VAULT)

    @staticmethod
    def test__fails_due_to_missing_env_vars_if_auth_method_needs_it():
        with pytest.raises(CodeArtifactAuthConfigException):
            AuthConfig(AwsAuthMethod.ENV)

    @staticmethod
    def test__succeed_if_auth_env_vars_provided():
        with patch.object(
            os,
            "environ",
            {"AWS_ACCESS_KEY_ID": "a", "AWS_SECRET_ACCESS_KEY": "b", "AWS_SESSION_TOKEN": "c"},
        ):
            AuthConfig(AwsAuthMethod.ENV)
