**Note**: Culture Amp has built this tool for internal use but has limited capacity to support this product.
It is provided on an as-is basis. Bugfix PRs may get looked at, but feature development is likely to be very limited
and driven by internal needs.

# Poetry CodeArtifact Auth Plugin

Do you use [CodeArtifact](https://aws.amazon.com/codeartifact/) to store private Python packages? Do you get annoyed by the fiddliness of needing to re-authenticate so you can fetch packages? Then this could be the utility you need!

It supports AWS SSO login (via `aws-vault`) to fetch the CodeArtifact authentication token. The token is saved to your machine (but note that it will only last for a limited time)

## Requirements

* [Poetry](https://python-poetry.org) (recommended: 1.2 or later). To use  the tool the `poetry` command must be available – it doesn't need to be installed in the same virtualenv.
* (recommended) [aws-vault](https://github.com/99designs/aws-vault) to handle authenticating using a pre-configured   profile

## Usage

1. Install somewhere on your system using
```
    pip3 install git+ssh://git@github.com/cultureamp/poetry-codeartifact-auth.git
```

(you will need [Github SSH Authentication](https://docs.github.com/en/authentication/connecting-to-github-with-ssh) set up already. Alternatively you can probably set up HTTPS authentication use the `https` URL). See notes below about package publication status. 

[*For venv users*] The intent is to install this globally (but if you have global dependency conflicts you could create a custom virtual environment and set up a command alias to run in the virtual environment. This is likely not needed though). 

[*For conda users*] Install in base (or any other clean) env.  Create new virtual environments off of base (or your clean env with `poetry-ca-auth` installed) by running `conda create --clone base --name my-virtual-env-name` , then activate your virtual  env `conda activate my-virtual-env-name`.  

2. If not already added, add the CodeArtifact repository URL to your `pyproject.toml`. The URL will look something like `https://yourorg-python-ci-12346789012.d.codeartifact.us-west-2.amazonaws.com/pypi/some-named-private-python-repo/simple`. Follow Poetry's [instructions](https://python-poetry.org/docs/repositories/#secondary-package-sources) for adding this. The CodeArtifact `domain`, `domainOwner` (AWS account ID) and `region` are inferred from the repository URL when fetching auth credentials.

3. Set up AWS authentication as described below

4. Refresh the CodeArtifact repo credentials for your use case

### Use cases

#### Building locally
If you just want to be able to run `poetry install` on your own machine (maybe the most common case), run

```
poetry-ca-auth refresh
```

This will trigger the authentication procedure, regardless of whether the token is expired. If you are using AWS SSO there will be a seemingly endless series of redirects but it seems to work effectively. The credentials will be saved used Poetry's credential saving mechanism which should work for any local builds on your machine. Poetry stores the credentials in a secure location (usually, possibly not on headless environments like servers).

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

#### `aws-vault` (recommended)

If using `aws-vault`, ensure that you have a profile available which has permissions to fetch CodeArtifact authentication tokens (e.g. assume the `CiUserRole` in the `cultureamp-continuous-integration` account). You can configure the profile using an environment variable `POETRY_CA_DEFAULT_AWS_PROFILE` (probably in your login shell profile – eg `.bashrc` or `.zshrc`) or pass to the `refresh` subcommand using the `--profile-default` argument. More info on profile configuation for AWS vault [here](https://cultureamp.atlassian.net/wiki/spaces/SEC/pages/2744649490/AWS+SSO+Okta+-+User+Guides#Generating-a-CultureAmp-configuration-file)
e.g. usage `aws-vault --debug login $POETRY_CA_DEFAULT_AWS_PROFILE` 

### AWS credentials from the environment

If `aws-vault` doesn't fit your needs, you can also just pull the AWS credentials from the environment. You can either set environment variable `POETRY_CA_AUTH_METHOD` to `environment` to use this method, or pass via the `--auth-method` argument.

### AWS already authenticated

If you are running somewhere where you are already have sufficient AWS permissions to fetch the token (eg Sagemaker studio, if that is configured), you can set `POETRY_CA_AUTH_METHOD` to `none` and it will simply fetch the token directly.

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

This package would likely be suitable to release publicly and publish on PyPI, however we have not yet set up the publication pipeline for this. As it is a standalone tool, and not something that third party code should depend on directly, it should not be a problem to install directly from a Git SSH URL.

