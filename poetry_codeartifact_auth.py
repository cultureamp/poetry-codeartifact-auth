#!/usr/bin/env python

import argparse
import ast
import logging
import os
import re
import subprocess
from dataclasses import dataclass, asdict
from enum import Enum
from io import StringIO
from typing import Dict, TypedDict
from urllib.parse import urlparse

import boto3
import dotenv.parser

logging.basicConfig()
LOG = logging.getLogger(__name__)


_CODEARTIFACT_URL_RE = re.compile(
    r'^(?P<domain>[\w-]+)-(?P<aws_account>\d+)\.d\.codeartifact\.(?P<region>[\w-]+)\.amazonaws\.com$'
)


@dataclass(frozen=True)
class CodeArtifactRepoConfig:
    aws_account: str
    domain: str
    region: str

    @staticmethod
    def from_url(repository_url: str):
        # https://cultureamp-python-ci-12346789012.d.codeartifact.us-west-2.amazonaws.com/pypi/cultureamp-private-python-repo/simple'
        host = urlparse(repository_url).hostname
        if not host:
            raise ValueError("Unparseable repository URL")
        match = _CODEARTIFACT_URL_RE.match(host)
        if not match:
            raise ValueError("Could not parse repository URL hostname")
        attributes = match.groupdict()
        return CodeArtifactRepoConfig(**attributes)


@dataclass(frozen=True)
class AwsAuthParameters:
    aws_access_key_id: str
    aws_secret_access_key: str
    aws_session_token: str

    @staticmethod
    def from_env_auth_vars(auth_vars: Dict[str, str]):
        return AwsAuthParameters(
            auth_vars["AWS_ACCESS_KEY_ID"],
            auth_vars["AWS_SECRET_ACCESS_KEY"],
            auth_vars["AWS_SESSION_TOKEN"]
        )


def get_auth_token_for_params(repo_config: CodeArtifactRepoConfig, auth_params: AwsAuthParameters):
    boto3_session = boto3.Session(**asdict(auth_params), region_name=repo_config.region)
    client = boto3_session.client("codeartifact")
    return client.get_authorization_token(domain=repo_config.domain, domainOwner=repo_config.aws_account)


def get_auth_token_using_env(repo_config: CodeArtifactRepoConfig):
    auth_params = AwsAuthParameters.from_env_auth_vars(os.environ)
    return get_auth_token_for_params(repo_config, auth_params)


def get_auth_token_using_vault(repo_config: CodeArtifactRepoConfig, aws_profile: str):
    if not aws_profile:
        raise ValueError("Profile must be set to use aws-vault")
    auth_params = AwsAuthParameters.from_env_auth_vars(aws_auth_vars_from_vault(aws_profile))
    return get_auth_token_for_params(repo_config, auth_params)


def aws_auth_vars_from_vault(aws_profile: str) -> Dict[str, str]:
    aws_vault_env_proc = subprocess.run(["aws-vault", "exec", aws_profile, "--", "env"], capture_output=True)
    env_var_bindings = dotenv.parser.parse_stream(StringIO(aws_vault_env_proc.stdout.decode()))
    return {key: value for key, value, _, _ in env_var_bindings if key.startswith("AWS_")}


class PoetryRepoConfig(TypedDict):
    url: str


def parse_poetry_repo_config(poetry_output: str) -> Dict[str, PoetryRepoConfig]:
    return ast.literal_eval(poetry_output)


def poetry_repositories() -> Dict[str, PoetryRepoConfig]:
    poetry_config_proc = subprocess.run(["poetry", "config", "repositories"], capture_output=True)
    return parse_poetry_repo_config(poetry_config_proc.stdout.decode())


class AuthMethod(Enum):
    ENV = "environment"
    VAULT = "vault"


class AuthConfig:
    def __init__(self, method: AuthMethod, default_profile: str = "", profile_overrides = None):
        self.method = method
        self._default_profile = default_profile
        self._profile_overrides = profile_overrides or {}

    def aws_profile(self, repo_name: str):
        return self._profile_overrides.get(repo_name, self._default_profile)


def get_auth_token(repo_config: CodeArtifactRepoConfig, method: AuthMethod, aws_profile: str = ""):
    if method == AuthMethod.ENV:
        return get_auth_token_using_env(repo_config)
    elif method == AuthMethod.VAULT:
        return get_auth_token_using_vault(repo_config, aws_profile)


def refresh_single_repo_auth(repo_name: str, token: str):
    subprocess.run(["poetry", "config", f"http-basic.{repo_name}", "aws", token])


def refresh_all_auth(config: AuthConfig):
    for name, repo in poetry_repositories().items():
        ca_config = CodeArtifactRepoConfig.from_url(repo['url'])
        token = get_auth_token(ca_config, config.method)
        refresh_single_repo_auth(name, token)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("-a", "--auth-method", type=str, default=os.getenv("POETRY_CA_AUTH_METHOD", "vault"))
    parser.add_argument("-p", "--profile-default", type=str, default=os.getenv("POETRY_CA_DEFAULT_AWS_PROFILE", ""))
    parsed = parser.parse_args()
    auth_method = AuthMethod(parsed.auth_method)
    config = AuthConfig(auth_method, parsed.profile_default)
    refresh_all_auth(config)


if __name__ == "__main__":
    main()