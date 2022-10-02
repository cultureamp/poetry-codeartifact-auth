# pylint:disable=missing-docstring
import pytest

from poetry_codeartifact_auth import (
    CodeArtifactRepoConfig,
    parse_poetry_repo_config,
    CodeArtifactUrlParseException,
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
