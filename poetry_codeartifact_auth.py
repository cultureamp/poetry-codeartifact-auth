#!/usr/bin/env python
"""Tools for saving a CodeArtifact authentication token locally and easily refreshing it as needed"""

import argparse
import ast
import logging
import os
import re
import subprocess
from dataclasses import dataclass, asdict, field
from enum import Enum
from io import StringIO
from typing import Dict, TypedDict, cast, Tuple, Iterable
from urllib.parse import urlparse

import boto3
import dotenv.parser
import pkg_resources

LOG = logging.getLogger(__name__)


_CODEARTIFACT_URL_RE = re.compile(
    r"^(?P<domain>[\w-]+)-(?P<aws_account>\d+)\.d\.codeartifact\.(?P<region>[\w-]+)\.amazonaws\.com$"
)
_DEFAULT_DURATION = 12 * 60 * 60


class CodeArtifactUrlParseException(Exception):
    """Could not parse CodeArtifact URL"""


@dataclass(frozen=True)
class CodeArtifactRepoConfig:
    """Configuration for access to a CodeArtifact repo"""

    aws_account: str
    domain: str
    region: str

    @staticmethod
    def from_url(repository_url: str):
        """Parse a CodeArtifact repository URL to extract relevant attributes"""
        # https://cultureamp-python-ci-12346789012.d.codeartifact.us-west-2.amazonaws.com/pypi/cultureamp-private-python-repo/simple'
        host = urlparse(repository_url).hostname
        if not host:
            raise ValueError("Unparseable repository URL")
        match = _CODEARTIFACT_URL_RE.match(host)
        if not match:
            raise CodeArtifactUrlParseException("Could not parse repository URL hostname")
        attributes = match.groupdict()
        return CodeArtifactRepoConfig(**attributes)


@dataclass(frozen=True)
class AwsAuthParameters:
    """Resolved authentication parameters which allow access to make AWS calls"""

    aws_access_key_id: str
    aws_secret_access_key: str
    aws_session_token: str

    @staticmethod
    def from_env_auth_vars(auth_vars: Dict[str, str]):
        """Extract authentication parameters from environment variables"""
        return AwsAuthParameters(
            auth_vars["AWS_ACCESS_KEY_ID"],
            auth_vars["AWS_SECRET_ACCESS_KEY"],
            auth_vars["AWS_SESSION_TOKEN"],
        )


def get_ca_auth_token_for_params(
    repo_config: CodeArtifactRepoConfig,
    auth_params: AwsAuthParameters,
    duration_seconds: int = None,
) -> str:
    """Fetch a CodeArtifact token enabling repository access"""
    boto3_session = boto3.Session(**asdict(auth_params), region_name=repo_config.region)
    client = boto3_session.client("codeartifact")
    response = client.get_authorization_token(
        domain=repo_config.domain,
        domainOwner=repo_config.aws_account,
        durationSeconds=(duration_seconds or _DEFAULT_DURATION),
    )
    token = response["authorizationToken"]
    LOG.info(
        f"fetched_codeartifact_token expiry='{response['expiration']}' token=({len(token)} chars)"
    )
    return token


class MissingAuthVarsException(Exception):
    """Exception when authentication variables are not found in the environment"""


def _get_auth_params_using_env() -> AwsAuthParameters:
    """Get AWS auth parameters from environment variables"""
    try:
        return AwsAuthParameters.from_env_auth_vars(dict(os.environ))
    except KeyError as exc:
        raise MissingAuthVarsException("One or more AWS_* auth vars was not found") from exc


def _get_auth_params_using_vault(aws_profile: str) -> AwsAuthParameters:
    """Get AWS auth parameters using aws-vault"""
    if not aws_profile:
        raise ValueError("Profile must be set to use aws-vault")
    return AwsAuthParameters.from_env_auth_vars(_aws_auth_vars_from_vault(aws_profile))


def _aws_auth_vars_from_vault(aws_profile: str) -> Dict[str, str]:
    aws_vault_env_proc = subprocess.run(
        ["aws-vault", "exec", aws_profile, "--", "env"], capture_output=True, check=True
    )
    env_var_bindings = dotenv.parser.parse_stream(StringIO(aws_vault_env_proc.stdout.decode()))
    auth_vars = {
        key: value for key, value, _, _ in env_var_bindings if key and key.startswith("AWS_")
    }
    return cast(Dict[str, str], auth_vars)


class _PoetryRepoConfig(TypedDict):
    url: str


def parse_poetry_repo_config(poetry_output: str) -> Dict[str, _PoetryRepoConfig]:
    """Parse Poetry output describing repository"""
    return ast.literal_eval(poetry_output)


def poetry_repositories() -> Dict[str, _PoetryRepoConfig]:
    """Get repositories configured in Poetry"""
    poetry_config_proc = subprocess.run(
        ["poetry", "config", "repositories"], capture_output=True, check=True
    )
    return parse_poetry_repo_config(poetry_config_proc.stdout.decode())


class AwsAuthMethod(Enum):
    """Authentication method to use for AWS call to get CodeArtifact token"""

    ENV = "environment"
    VAULT = "vault"


@dataclass(frozen=True)
class AuthConfig:
    """Configuration for authenticating against AWS"""

    method: AwsAuthMethod
    default_profile: str = ""
    profile_overrides: Dict[str, str] = field(default_factory=dict)

    def profile_for_repo(self, repo_name: str):
        """Get the profile for the provided repository name"""
        return self.profile_overrides.get(repo_name, self.default_profile)


def get_ca_auth_token(
    repo_config: CodeArtifactRepoConfig, method: AwsAuthMethod, aws_profile: str = ""
):
    """Get CodeArtifact authentication token using the requested AWS authentication method"""
    auth_params = (
        _get_auth_params_using_vault(aws_profile)
        if method == AwsAuthMethod.VAULT
        else _get_auth_params_using_env()
    )
    return get_ca_auth_token_for_params(repo_config, auth_params)


def _refresh_single_repo_auth(repo_name: str, token: str):
    subprocess.run(["poetry", "config", f"http-basic.{repo_name}", "aws", token], check=True)


def show_auth_token(config: AuthConfig):
    """Store authentication information inside Poetry for a single repository"""
    names_tokens = list(_fetch_auth_tokens(config))
    if len(names_tokens) > 1:
        raise ValueError(f"Multiple repositories are available")
    [(_, token)] = names_tokens
    print(token)


def show_auth_env_vars(config: AuthConfig):
    """Show environment variables for authentication"""
    for name, token in _fetch_auth_tokens(config):
        name_for_env_var = name.upper().replace("-", "_")
        password_env_var_name = f"POETRY_HTTP_BASIC_{name_for_env_var}_PASSWORD"
        user_env_var_name = f"POETRY_HTTP_BASIC_{name_for_env_var}_USERNAME"
        print(f"export {password_env_var_name}='{token}'")
        print(f"export {user_env_var_name}='aws'")


def _fetch_auth_tokens(config: AuthConfig) -> Iterable[Tuple[str, str]]:
    repositories = poetry_repositories()
    if not repositories:
        raise ValueError(
            "No repositories found. If you have repositories in pyproject.toml, please make"
            " sure you have poetry 1.2 or later installed"
        )
    for name, repo in repositories.items():
        LOG.debug(f"handling_poetry_repo {name=} {repo=}")
        try:
            ca_config = CodeArtifactRepoConfig.from_url(repo["url"])
        except CodeArtifactUrlParseException:
            LOG.info(f"ignoring_apparent_non_codeartifact_repo {name=} {repo=}")
            continue
        yield name, get_ca_auth_token(ca_config, config.method, config.profile_for_repo(name))


def refresh_all_auth(config: AuthConfig):
    """Store authentication information inside Poetry for a single repository"""
    for name, token in _fetch_auth_tokens(config):
        LOG.info(f"storing_poetry_auth_token {name=} token=({len(token)} chars)")
        _refresh_single_repo_auth(name, token)


def main():
    """Main command line function"""
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--verbose",
        "-v",
        action="count",
        default=0,
        dest="verbosity",
        help="Increase verbosity level (repeat for debug logging)",
    )
    parser.add_argument("--version", action="store_true", help="Print version and exit")
    parser.add_argument(
        "--auth-method",
        "-a",
        type=str,
        default=os.getenv("POETRY_CA_AUTH_METHOD", "vault"),
        choices=[v.value for v in AwsAuthMethod],
        help="Authentication method. Use `vault` (recommended) to authenticate using AWS vault. "
        "With `environment`, AWS authentication variables must be present in the environment."
        "Defaults to value in `POETRY_CA_AUTH_METHOD` environment variable.",
    )
    parser.add_argument(
        "--profile-default",
        "-p",
        type=str,
        default=os.getenv("POETRY_CA_DEFAULT_AWS_PROFILE", ""),
        help="aws-vault profile to us if auth method is 'vault'."
        "Defaults to value in `POETRY_CA_DEFAULT_AWS_PROFILE` environment variable.",
    )

    parser.add_argument(
        "--duration",
        "-d",
        type=int,
        default=_DEFAULT_DURATION,
        help="Lifetime of token. Make this as short as practical unless it is being stored securely",
    )
    subparsers = parser.add_subparsers(dest="subcommand")

    subparsers.add_parser(
        "refresh", help="refresh CodeArtifact authentication token in Poetry config"
    )
    subparsers.add_parser(
        "show-token", help="fetch CodeArtifact authentication token and display in console"
    )
    subparsers.add_parser(
        "show-auth-env-vars",
        help="fetch CodeArtifact authentication tokens as environment variables "
        "suitable for Poetry and write to stdout (recommendation: use a short `--duration` parameter"
        " here to reduce change of credentials leakage)",
    )

    parsed = parser.parse_args()

    if parsed.verbosity >= 2:
        logging.basicConfig(level=logging.DEBUG)
    elif parsed.verbosity == 1:
        logging.basicConfig(level=logging.INFO)
    else:
        logging.basicConfig(level=logging.WARN)

    if parsed.version:
        print(pkg_resources.get_distribution("poetry-codeartifact-auth").version)
    elif parsed.subcommand in ("refresh", "show-token", "show-auth-env-vars"):
        auth_method = AwsAuthMethod(parsed.auth_method)
        auth_config = AuthConfig(auth_method, parsed.profile_default)
        LOG.debug(f"parsed_auth_config {auth_config=}")
        if parsed.subcommand == "refresh":
            refresh_all_auth(auth_config)
        elif parsed.subcommand == "show-token":
            show_auth_token(auth_config)
        elif parsed.subcommand == "show-auth-env-vars":
            show_auth_env_vars(auth_config)
    else:
        raise ValueError("Unknown command")


if __name__ == "__main__":
    main()
