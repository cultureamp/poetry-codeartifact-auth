**Note**: Culture Amp has built this tool for internal use but has limited capacity to support this product.
It is provided on an as-is basis. Bugfix PRs may get looked at, but feature development is likely to be very limited
and driven by internal needs.

# Poetry CodeArtifact Auth Plugin

Do you use [CodeArtifact](https://aws.amazon.com/codeartifact/) to store private Python packages? Do you get annoyed by the fiddliness of needing to re-authenticate so you can fetch packages? Then this could be the utility you need!

It supports AWS SSO login (via `aws-vault`) to fetch the CodeArtifact authentication token. The token is saved to your machine (but note that it will only last for a limited time). It can be installed as a Poetry plugin as well, so that authentication is triggered automatically for Poetry operations which are likely to need it (for codebases which use private CodeArtifact repositories).

It can also be used to automatically fetch authentication tokens to run `pip install`.

## Requirements

* [Poetry](https://python-poetry.org) (recommended: 1.2 or later). To use  the tool the `poetry` command must be available – it doesn't need to be installed in the same virtualenv.
* [AWS CLI](https://aws.amazon.com/cli/) – v2+ if you wish to use `sso` login method.
* (optional; may be deprecated) [aws-vault](https://github.com/99designs/aws-vault) to handle authenticating using a pre-configured profile in a standlone session

## Usage

1. Install core package somewhere on your system using

```
    pip3 install git+https://github.com/cultureamp/poetry-codeartifact-auth.git
```
  See notes below about package publication status. The intent is to install this globally (but if you have global dependency conflicts you could create a custom virtual environment and set up a command alias to run in the virtual environment. This is likely not needed though).

2. (recommended) also, or instead, add as a Poetry plugin to make the authentication token refresh automatically (only provides an equivalent to the `poetry-ca-auth refresh` subcommand at this time). This will not help if you are using `pip` only.

```
   poetry self add git+https://github.com/cultureamp/poetry-codeartifact-auth.git#main -E plugin
```

3. If not already added, add the CodeArtifact repository URL to your `pyproject.toml`. The URL will look something like `https://yourorg-python-ci-12346789012.d.codeartifact.us-west-2.amazonaws.com/pypi/some-named-private-python-repo/simple`. Follow Poetry's [instructions](https://python-poetry.org/docs/repositories/#secondary-package-sources) for adding this. The CodeArtifact `domain`, `domainOwner` (AWS account ID) and `region` are inferred from the repository URL when fetching auth credentials.

3. Set up AWS authentication as described below

4. Refresh the CodeArtifact repo credentials for your use case

### Use cases

#### Installing apps locally

If you have installed as a Poetry plugin, then as long as you have configured your system as specified above, you should be able to use the normal Poetry commands, and those which interact with package repositories will automatically authenticate against CodeArtifact as needed.

If you just want to be able to run `poetry install` on your own machine (maybe the most common case) and you **haven't installed as a Poetry plugin**, run

```
poetry-ca-auth refresh
```

This will trigger the authentication procedure, regardless of whether the token is expired. If you are using AWS SSO there will be a seemingly endless series of redirects but it seems to work effectively. The credentials will be saved used Poetry's credential saving mechanism which should work for any local builds on your machine. Poetry stores the credentials in a secure location (usually, possibly not on headless environments like servers).

If you want to use `pip` instead to install more private dependencies in an adhoc fashion, you can do so using

```
poetry-ca-auth pip-install
```

Arguments will be passed through to `pip install` but it will automatically populate `--extra-index-url` with a URL with authentication tokens included. You will need to pass the CodeArtifact repository URL in, either with `--repository` or by setting the `POETRY_CA_PIP_DEFAULT_CODEARTIFACT_REPO` environment variable.

#### Building docker containers

If you have other use cases (eg Docker builds), you may want to use other subcommands, such as `write-to-dotenv`.

This works most simply using `docker-compose`.  Run `poetry-ca-auth write-to-dotenv` to write the env vars to `.env` in the working directory.
Then, if you have a `docker-compose.yaml` file such as this:

```
services:
  yourapp:
    build:
      context: .
      dockerfile: Dockerfile
      args:
        - POETRY_HTTP_BASIC_<UPPERCASE_SOURCE_NAME>_PASSWORD
        - POETRY_HTTP_BASIC_<UPPERCASE_SOURCE_NAME>_USERNAME
```

and a Dockerfile which has the following lines before `poetry install`

```
ARG POETRY_HTTP_BASIC_<UPPERCASE_SOURCE_NAME>_PASSWORD
ARG POETRY_HTTP_BASIC_<UPPERCASE_SOURCE_NAME>_USERNAME
```

where `<UPPERCASE_SOURCE_NAME>` is created by taking the name of your Codeartifact Source, converting `-` to `_` and converting to upper case.

you can simply run `docker compose build yourapp` and it will automatically pick up the values in the `.env` file, and supply them as args to the build. You can also do this with raw `docker build` but it requires more effort to get the build args to work.


### Authentication methods

The authentication method can be passed using `--auth-method` argument or configured using the environment variable `POETRY_CA_AUTH_METHOD`. The environment variable is the only option when running as a plugin.

#### `sso` (recommended)

If you use `sso`, you need to have an AWS profile set up on your system (eg using `aws configure sso`) which has permissions to fetch CodeArtifact authentication tokens. You can select the profile to use with an environment variable `POETRY_CA_DEFAULT_AWS_PROFILE` (probably in your login shell profile – eg `.bashrc`) or pass to the `refresh` subcommand using the `--profile-default` argument.

#### `vault`

Uses `aws-vault` command. Has the same requirements as `sso` in terms of pre-configured profiles you can choose.

### `environment`

Pulls AWS credentials from the environment before fetching the CodeArtifact token.

### `none`

If you already have AWS authentication due to, for example, a role you have (eg in Sagemaker Studio), you may be able to fetch the token without any extra work, you use this method to fetch the token directly (in which case the library is doing less for you but is likely still handy).

## Limitations

* Currently only supports a single AWS profile configured via environment. If you have multiple CodeArtifact repositories with different authentication, the code would need a patch to handle this
* Not currently tested for authentication flows which require user interaction at the CLI console – eg if you are not using AWS SSO but are using MFA. But it may work fine.


## Developing

Make sure to install development dependencies, eg using `poetry install` (which installs them by default).

Make sure you have [pre-commit](https://pre-commit.com) installed on your machine. Then, as a one-off, run:

    pre-commit install --install-hooks

This will then make sure various checks are run on files when you commit.

Tests can be run with `pytest`.


## Availability on Public Repositories

This package would likely be suitable to release publicly and publish on PyPI, however we have not yet set up the publication pipeline for this. As it is a standalone tool, and not something that third party code should depend on directly, it should not be a problem to install directly from a Github URL.

