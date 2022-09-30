import os
import re
import subprocess
from dataclasses import dataclass, asdict
from io import StringIO
from typing import Dict
import logging
from urllib.parse import urlparse

import boto3
import dotenv.parser
from cleo.events.console_command_event import ConsoleCommandEvent
from cleo.events.console_events import COMMAND
from cleo.events.event_dispatcher import EventDispatcher
from poetry.console.application import Application
from poetry.console.commands.lock import LockCommand
from poetry.console.commands.update import UpdateCommand
from poetry.plugins.application_plugin import ApplicationPlugin

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


def get_auth_token(repo_config: CodeArtifactRepoConfig, auth_params: AwsAuthParameters):
    boto3_session = boto3.Session(**asdict(auth_params), region_name=repo_config.region)
    client = boto3_session.client("codeartifact")
    return client.get_authorization_token(domain=repo_config.domain, domainOwner=repo_config.aws_account)


def get_auth_token_using_env(repo_config: CodeArtifactRepoConfig):
    auth_params = AwsAuthParameters.from_env_auth_vars(os.environ)
    return get_auth_token(repo_config, auth_params)


def get_auth_token_using_vault(repo_config: CodeArtifactRepoConfig, aws_profile: str):
    auth_params = AwsAuthParameters.from_env_auth_vars(aws_auth_vars_from_vault(aws_profile))
    return get_auth_token(repo_config, auth_params)


def aws_auth_vars_from_vault(aws_profile: str) -> Dict[str, str]:
    aws_vault_env_proc = subprocess.run(["aws-vault", "exec", aws_profile, "--", "env"], capture_output=True)
    env_var_bindings = dotenv.parser.parse_stream(StringIO(aws_vault_env_proc.stdout.decode("UTF-8")))
    return {key: value for key, value, _, _ in env_var_bindings if key.startswith("AWS_")}



class CodeArtifactAuthPlugin(ApplicationPlugin):
    def __init__(self):
        self._aws_profile = None
        self._auth_method = None
        self._source_name = None
        self._profile = None
        self._code_artifact_repo_config = None
        self._app_config = None

    def activate(self, application: Application):
        application.event_dispatcher.add_listener(
            COMMAND, self.authenticate
        )
        self._app_config = application.poetry.config
        aws_account = self._app_config.get("codeartifact-auth.aws-account")
        domain = self._app_config.get("codeartifact-auth.domain")
        region = self._app_config.get("codeartifact-auth.region")
        self._code_artifact_repo_config = CodeArtifactRepoConfig(aws_account, domain, region)

        self._auth_method = self._app_config.get("codeartifact-auth.auth_method", "aws-vault")
        if self._auth_method not in ("environment", "aws-vault"):
            raise ValueError(f"Invalid auth method {self._auth_method}. Should be one of 'environment' or 'aws-vault'")
        self._aws_profile = self._app_config.get("codeartifact-auth.aws-profile")
        if self._auth_method == "aws-vault":
            if self._aws_profile is None:
                raise ValueError("Profile must be set if auth_method is 'aws-vault'")
        self._source_name = self._app_config.get("codeartifact-auth.source", "codeartifact")

    def authenticate(
        self,
        event: ConsoleCommandEvent,
        event_name: str,
        dispatcher: EventDispatcher
    ) -> None:
        command = event.command
        if not (isinstance(command, UpdateCommand) or isinstance(command, LockCommand)):
            return

        if self._auth_method == "aws-vault":
            auth_token = get_auth_token_using_vault(
                self._code_artifact_repo_config, self._profile
            )
        else:
            auth_token = get_auth_token_using_env(self._code_artifact_repo_config)

        self._app_config.merge(f"http-basic.{self._source_name}", f"aws {auth_token}")

