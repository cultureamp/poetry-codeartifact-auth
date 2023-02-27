#!/usr/bin/env python
"""Tools for saving a CodeArtifact authentication token locally and easily refreshing as needed"""

import argparse
import ast
import logging
import os
import re
import subprocess
from collections import namedtuple
from dataclasses import dataclass, asdict, field
from enum import Enum
from io import StringIO
from pathlib import Path
from typing import Dict, TypedDict, cast, Iterable, Union, List
from urllib import parse
from urllib.parse import urlparse

import boto3
import dotenv.parser
import pkg_resources
import toml

LOG = logging.getLogger(__name__)


_CODEARTIFACT_URL_RE = re.compile(
    r"^(?P<domain>[\w-]+)-(?P<aws_account>\d+)\.d\.codeartifact\.(?P<region>[\w-]+)\.amazonaws\.com$"
)
_DEFAULT_DURATION_SECONDS = 12 * 60 * 60


NameAndToken = namedtuple("NameAndToken", ["name", "token"])


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
        host = urlparse(repository_url).hostname
        if not host:
            raise ValueError("Unparseable repository URL")
        match = _CODEARTIFACT_URL_RE.match(host)
        if not match:
            raise CodeArtifactUrlParseException("Could not parse repository URL hostname")
        attributes = match.groupdict()
        return CodeArtifactRepoConfig(**attributes)


@dataclass(frozen=True)
class AwsProfileParameters:
    """Parameters which allow access to make AWS calls using only a profile name"""

    profile_name: str


@dataclass(frozen=True)
class AwsAuthParameters:
    """Resolved authentication parameters which allow access to make AWS calls"""

    aws_access_key_id: str
    aws_secret_access_key: str
    aws_session_token: str

    @staticmethod
    def from_env_auth_vars(auth_vars: Dict[str, str]):
        """Extract authentication parameters from environment variables"""
        try:
            return AwsAuthParameters(
                auth_vars["AWS_ACCESS_KEY_ID"],
                auth_vars["AWS_SECRET_ACCESS_KEY"],
                auth_vars["AWS_SESSION_TOKEN"],
            )
        except KeyError as exc:
            raise MissingAuthVarsException("One or more AWS_* auth vars was not found") from exc


AwsLoginParameters = Union[AwsProfileParameters, AwsAuthParameters, None]


def get_ca_auth_token_for_params(
    repo_config: CodeArtifactRepoConfig,
    login_params: AwsLoginParameters,
    duration_seconds: int = None,
) -> str:
    """Fetch a CodeArtifact token enabling repository access"""
    auth_args = asdict(login_params) if login_params else {}
    boto3_session = boto3.Session(**auth_args, region_name=repo_config.region)
    client = boto3_session.client("codeartifact")
    response = client.get_authorization_token(
        domain=repo_config.domain,
        domainOwner=repo_config.aws_account,
        durationSeconds=int(duration_seconds or _DEFAULT_DURATION_SECONDS),
    )
    token = response["authorizationToken"]
    LOG.info(
        f"fetched_codeartifact_token expiry='{response['expiration']}' token=({len(token)} chars)"
    )
    return token


class MissingAuthVarsException(Exception):
    """Exception when authentication variables are not found in the environment"""


class MissingPyprojectTomlFile(Exception):
    """Exception when a pyproject.toml was not found by walking up the directory tree"""


def _aws_auth_vars_from_vault(aws_profile: str) -> Dict[str, str]:
    if not aws_profile:
        raise ValueError("Profile must be set to use aws-vault")
    try:
        aws_vault_env_proc = subprocess.run(
            ["aws-vault", "exec", aws_profile, "--", "env"],
            capture_output=True,
            check=True,
        )
    except subprocess.CalledProcessError as exc:
        LOG.error(exc.stderr.decode())
        raise
    env_var_bindings = dotenv.parser.parse_stream(StringIO(aws_vault_env_proc.stdout.decode()))
    auth_vars = {
        key: value for key, value, _, _ in env_var_bindings if key and key.startswith("AWS_")
    }
    return cast(Dict[str, str], auth_vars)


def _ensure_sso_logged_in(aws_profile: str):
    if not aws_profile:
        raise ValueError("Profile must be set to use aws-vault")
    if not _is_sso_logged_in(aws_profile):
        LOG.info(f"aws_session_expired_new_login {aws_profile=}")
        subprocess.run(
            ["aws", "sso", "login", "--profile", aws_profile],
            capture_output=False,
            check=True,
        )


def _is_sso_logged_in(aws_profile: str) -> bool:
    try:
        LOG.debug(f"checking_for_existing_aws_session_with_sts profile={aws_profile!r}")
        subprocess.run(
            ["aws", "sts", "get-caller-identity", "--profile", aws_profile],
            capture_output=True,
            check=True,
        )
    except subprocess.CalledProcessError:
        return False
    LOG.debug("existing_session_exists")
    return True


class _PoetryRepoConfig(TypedDict):
    url: str


def parse_poetry_repo_config(poetry_output: str) -> Dict[str, _PoetryRepoConfig]:
    """Parse Poetry output describing repository"""
    return ast.literal_eval(poetry_output)


def _find_pyproject_toml_path(cwd: str = None):
    fs_path = Path(cwd or os.getcwd())

    def toml_path():
        return fs_path / "pyproject.toml"

    while not toml_path().exists():
        fs_path = fs_path.parent
        if fs_path == fs_path.root:
            raise MissingPyprojectTomlFile(
                "Hit root directory while attempting to find pyproject.toml"
            )
    return toml_path()


def _get_repo_config_from_pyproject_toml(toml_path: Path) -> Dict[str, _PoetryRepoConfig]:
    parsed = toml.load(toml_path)
    return {info["name"]: info for info in parsed["tool"]["poetry"].get("source", [])}


def poetry_repositories() -> Dict[str, _PoetryRepoConfig]:
    """Get repositories configured in Poetry"""
    poetry_config_proc = subprocess.run(
        ["poetry", "config", "repositories"], capture_output=True, check=True
    )
    config_from_poetry = parse_poetry_repo_config(poetry_config_proc.stdout.decode())
    if config_from_poetry:
        return config_from_poetry
    LOG.warning(
        f"No repositories found in Poetry config (possibly due to poetry < 1.2). "
        "Parsing pyproject.toml directly"
    )
    return _get_repo_config_from_pyproject_toml(_find_pyproject_toml_path())


class AwsAuthMethod(Enum):
    """Authentication method to use for AWS call to get CodeArtifact token"""

    NONE = "none"
    ENV = "environment"
    VAULT = "vault"
    SSO = "sso"


class CodeArtifactAuthConfigException(ValueError):
    """The authentication configuration is invalid"""


@dataclass(frozen=True)
class AuthConfig:
    """Configuration for authenticating against AWS"""

    method: AwsAuthMethod
    default_profile: str = ""
    duration_seconds: int = _DEFAULT_DURATION_SECONDS
    profile_overrides: Dict[str, str] = field(default_factory=dict)

    def __post_init__(self):
        if self.method in (AwsAuthMethod.VAULT, AwsAuthMethod.SSO):
            if not self.default_profile:
                raise CodeArtifactAuthConfigException(
                    f"AWS default profile must be set for authentication method {self.method}"
                )
        elif self.method == AwsAuthMethod.ENV:
            try:
                AwsAuthParameters.from_env_auth_vars(dict(os.environ))
            except MissingAuthVarsException as exc:
                raise CodeArtifactAuthConfigException(
                    "AWS_* authentication vars must be set"
                ) from exc

    def profile_for_repo(self, repo_name: str):
        """Get the profile for the provided repository name"""
        return self.profile_overrides.get(repo_name, self.default_profile)


def auth_config_from_env() -> AuthConfig:
    """Determine AuthConfig from the environment"""
    return AuthConfig(
        method=AwsAuthMethod(_auth_method_from_env()), default_profile=_aws_profile_from_env()
    )


def auth_params_from_config(config: AuthConfig, repo_name: str) -> AwsLoginParameters:
    """Get AWS authentication parameters"""
    if config.method in (AwsAuthMethod.VAULT, AwsAuthMethod.ENV):
        if config.method == AwsAuthMethod.VAULT:
            profile = config.profile_for_repo(repo_name)
            LOG.info(f"authenticating_using_vault profile={profile!r}")
            env_auth_vars = _aws_auth_vars_from_vault(profile)
        elif config.method == AwsAuthMethod.ENV:
            env_auth_vars = dict(os.environ)
        else:
            raise ValueError("Invalid authentication method")
        return AwsAuthParameters.from_env_auth_vars(env_auth_vars)
    if config.method == AwsAuthMethod.SSO:
        profile = config.profile_for_repo(repo_name)
        LOG.info(f"authenticating_using_sso profile={profile!r}")
        _ensure_sso_logged_in(profile)
        return AwsProfileParameters(config.profile_for_repo(repo_name))
    if config.method == AwsAuthMethod.NONE:
        return None
    raise ValueError("Invalid authentication method")


def _refresh_single_repo_auth(repo_name: str, token: str):
    subprocess.run(["poetry", "config", f"http-basic.{repo_name}", "aws", token], check=True)


def show_auth_token(config: AuthConfig):
    """Store authentication information inside Poetry for a single repository"""
    names_tokens = list(_fetch_auth_tokens(config))
    if len(names_tokens) > 1:
        raise ValueError(f"Multiple repositories are available")
    [(_, token)] = names_tokens
    print(token)


def _get_auth_env_vars(config: AuthConfig) -> Dict[str, str]:
    tokens = _fetch_auth_tokens(config)
    return _vars_for_auth_tokens(tokens)


def _vars_for_auth_tokens(tokens: Iterable[NameAndToken]) -> Dict[str, str]:
    result = {}
    for name, token in tokens:
        name_for_env_var = name.upper().replace("-", "_")
        password_env_var_name = f"POETRY_HTTP_BASIC_{name_for_env_var}_PASSWORD"
        user_env_var_name = f"POETRY_HTTP_BASIC_{name_for_env_var}_USERNAME"
        result[password_env_var_name] = token
        result[user_env_var_name] = "aws"
    return result


def show_auth_env_vars(config: AuthConfig):
    """Show environment variables for authentication"""
    for var_name, value in _get_auth_env_vars(config).items():
        print(f"export {var_name}='{value}'")


def _touch(filepath: Union[str, os.PathLike]):
    with open(filepath, "w+", encoding="UTF-8") as _:
        pass


def write_auth_to_dotenv(
    config: AuthConfig,
    env_path: Union[str, os.PathLike],
    create: bool = False,
    export: bool = False,
):
    """Write authentication variables to a dotenv"""
    if create:
        _touch(env_path)
        LOG.debug(f"creating_file {env_path=}")
    for var_name, value in _get_auth_env_vars(config).items():
        dotenv.set_key(env_path, var_name, value, export=export)
        LOG.debug(f"set_env_var {env_path=} {var_name=} {value=}")
    LOG.info(f"wrote_env_vars {env_path=}")


class NoCodeArtifactRepositoriesError(ValueError):
    """No Codeartifact repositories configured in pyproject.toml in current directory"""


def _fetch_auth_tokens(config: AuthConfig) -> Iterable[NameAndToken]:
    repositories = poetry_repositories()
    if not repositories:
        raise NoCodeArtifactRepositoriesError(
            "No repositories found. Make sure a valid pyproject.toml which defines "
            "extra sources is available in a current or parent directory"
        )
    for name, repo in repositories.items():
        LOG.debug(f"handling_poetry_repo {name=} {repo=}")
        try:
            ca_config = CodeArtifactRepoConfig.from_url(repo["url"])
        except CodeArtifactUrlParseException:
            LOG.info(f"ignoring_apparent_non_codeartifact_repo {name=} {repo=}")
            continue

        token = get_ca_auth_token_for_params(
            ca_config, auth_params_from_config(config, name), config.duration_seconds
        )
        yield NameAndToken(name, token)


def refresh_all_auth(config: AuthConfig):
    """Store authentication information inside Poetry for a single repository"""
    for name, token in _fetch_auth_tokens(config):
        LOG.info(f"storing_poetry_auth_token {name=} token=({len(token)} chars)")
        _refresh_single_repo_auth(name, token)


def _url_with_auth(repository: str, token: str):
    parsed = parse.urlparse(repository)
    return f"{parsed.scheme}://aws:{parse.quote(token, '')}@{parsed.netloc}{parsed.path}"


def run_pip_install_with_auth(config: AuthConfig, repository: str, pip_args: List[str]):
    """Runs pip install with authentication"""
    ca_config = CodeArtifactRepoConfig.from_url(repository)
    token = get_ca_auth_token_for_params(ca_config, auth_params_from_config(config, ""), 3600)
    subprocess.run(
        ["pip", "install", "--extra-index-url", _url_with_auth(repository, token), *pip_args],
        check=True,
    )


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
        default=_auth_method_from_env(),
        choices=[v.value for v in AwsAuthMethod],
        help="Authentication method. Use `sso` (recommended) to authenticate using `aws sso` command ."
        "(requires CLI v2 – `vault`, which uses aws-vault, still works with v1) "
        "With `environment`, AWS authentication variables must be present in the environment."
        "Defaults to value in `POETRY_CA_AUTH_METHOD` environment variable.",
    )
    parser.add_argument(
        "--profile-default",
        "-p",
        type=str,
        default=_aws_profile_from_env(),
        help="aws-vault/SSO profile to us if auth method is 'vault'."
        "Defaults to value in `POETRY_CA_DEFAULT_AWS_PROFILE` environment variable.",
    )

    parser.add_argument(
        "--duration-minutes",
        "-m",
        type=int,
        default=_DEFAULT_DURATION_SECONDS / 60,
        help="Lifetime of token. Make this as short as practical unless it is being stored securely",
    )
    subparsers = parser.add_subparsers(dest="subcommand", required=False)

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

    write_dotenv = subparsers.add_parser(
        "write-to-dotenv",
        help="write auth vars to a .env file (recommendation: use a short `--duration` parameter"
        " here to reduce change of credentials leakage). Useful for eg docker-compose",
    )

    write_dotenv.add_argument(
        "-e",
        "--export",
        action="store_true",
        help="prefix variable with `export ` to create a sourceable .env instead of one for docker-compose",
    )
    write_dotenv.add_argument("-f", "--file", default=".env", help="name of .env file to write to")
    write_dotenv.add_argument(
        "-c",
        "--create",
        action="store_true",
        help="create dotenv file if it does not already exist",
    )

    pip_run = subparsers.add_parser(
        "pip-install",
        help="run pip with a codeartifact repository added along with auth credentials",
    )
    pip_run.add_argument(
        "-r",
        "--repository",
        default=os.getenv("POETRY_CA_PIP_DEFAULT_CODEARTIFACT_REPO", ""),
        help="repository URL to use. Defaults to value stored in POETRY_CA_PIP_DEFAULT_CODEARTIFACT_REPO"
        " env var. The token expiry is set to one hour for this command",
    )
    pip_run.add_argument("pip_args", nargs="+", help="Arguments for pip")

    parsed = parser.parse_args()

    if parsed.verbosity >= 2:
        logging.basicConfig(level=logging.DEBUG)
    elif parsed.verbosity == 1:
        logging.basicConfig(level=logging.INFO)
    else:
        logging.basicConfig(level=logging.WARN)

    if parsed.version:
        print(pkg_resources.get_distribution("poetry-codeartifact-auth").version)
        return
    auth_method = AwsAuthMethod(parsed.auth_method)
    auth_config = AuthConfig(
        auth_method, parsed.profile_default, duration_seconds=parsed.duration_minutes * 60
    )
    LOG.debug(f"parsed_auth_config {auth_config=}")
    if parsed.subcommand == "refresh":
        refresh_all_auth(auth_config)
    elif parsed.subcommand == "show-token":
        show_auth_token(auth_config)
    elif parsed.subcommand == "show-auth-env-vars":
        show_auth_env_vars(auth_config)
    elif parsed.subcommand == "write-to-dotenv":
        write_auth_to_dotenv(auth_config, parsed.file, create=parsed.create, export=parsed.export)
    elif parsed.subcommand == "pip-install":
        run_pip_install_with_auth(auth_config, parsed.repository, parsed.pip_args)
    else:
        raise ValueError("You must specify a valid subcommand")


def _aws_profile_from_env() -> str:
    return os.getenv("POETRY_CA_DEFAULT_AWS_PROFILE", "")


def _auth_method_from_env() -> str:
    return os.getenv("POETRY_CA_AUTH_METHOD", "sso")


if __name__ == "__main__":
    main()
