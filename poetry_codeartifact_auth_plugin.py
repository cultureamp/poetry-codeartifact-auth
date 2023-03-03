"""Poetry plugin code"""

from cleo.events.console_command_event import ConsoleCommandEvent
from cleo.events.console_events import COMMAND
from cleo.events.event_dispatcher import EventDispatcher
from poetry.console.application import Application
from poetry.console.commands.installer_command import InstallerCommand
from poetry.console.commands.self.self_command import SelfCommand
from poetry.plugins.application_plugin import ApplicationPlugin

from poetry_codeartifact_auth import (
    poetry_repositories,
    auth_config_from_env,
    refresh_all_auth,
    CodeArtifactAuthConfigException,
)


class CAAuthPlugin(ApplicationPlugin):
    """
    Plugin so you can install in Poetry and set-and-forget

    This plugin will activate for installation-related-commands
    """

    def activate(self, application: Application) -> None:
        """Activate the plugin and create hooks for installation events"""
        application.event_dispatcher.add_listener(COMMAND, self.refresh_auth)

    # pylint:disable=unused-argument
    def refresh_auth(
        self, event: ConsoleCommandEvent, event_name: str, dispatcher: EventDispatcher
    ) -> None:
        """Refresh the authentication token if it is an install-type event"""
        command = event.command
        if not isinstance(command, InstallerCommand):
            return
        if isinstance(command, SelfCommand):
            # self commands should work w/o TOML file and don't need this unless you want
            # to install private plugins
            return
        if not poetry_repositories():
            event.io.write_line(
                "No codeartifact repositories are configured. "
                "If you are not using private packages this is fine"
            )
            return

        try:
            auth_config = auth_config_from_env()
        except CodeArtifactAuthConfigException as exc:
            event.io.write_error(
                f"{exc!r}. AWS profile must be configured using `POETRY_CA_DEFAULT_AWS_PROFILE` or "
                f"`POETRY_CA_AUTH_METHOD` env var must be set to `none` or `environment`. "
                f"CodeArtifact auth plugin will not function"
            )
            return
        refresh_all_auth(auth_config)
