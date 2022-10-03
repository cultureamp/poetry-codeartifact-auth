[//]: # (**Note**: Culture Amp has built this tool for internal use but has limited capacity to support this product.)

[//]: # (It is provided on an as-is basis. Bugfix PRs may get looked at, but feature development is likely to be very limited)

[//]: # (and driven by internal needs.)

# Poetry CodeArtifact Auth Plugin

Do you use [CodeArtifact](https://aws.amazon.com/codeartifact/) to store private Python packages? Do you get annoyed by the fiddliness of needing to re-authenticate so you can fetch packages? Then this could be the utility you need!

It supports AWS SSO login (via `aws-vault`) to fetch the CodeArtifact authentication token. The token is saved to your machine (but note that it will only last for a limited time)

## Requirements

* [Poetry](https://python-poetry.org) (currently 1.2 or later is needed – we may backport to 1.1 though). To use  the tool the `poetry` command must be available – it doesn't need to be installed in the same virtualenv.
* (recommended) [aws-vault](https://github.com/99designs/aws-vault) to handle authenticating using an pre-configured   profile

## Usage

1. Install somewhere on your system using
```
    pip3 install git+ssh://git@github.com/cultureamp/poetry-codeartifact-auth.git
```

(you will need [Github SSH Authentication](https://docs.github.com/en/authentication/connecting-to-github-with-ssh) set up already. Alternatively you can probably set up HTTPS authentication use the `https` URL). See notes below about package publication status. The intent is to install this globally (but if you have global dependency conflicts you could create a custom virtual environment and set up a command alias to run in the virtual environment. This is likely not needed though).

2. If not already added, add the CodeArtifact repository URL to your `pyproject.toml`. The URL will look something like `https://yourorg-python-ci-12346789012.d.codeartifact.us-west-2.amazonaws.com/pypi/some-named-private-python-repo/simple`. Follow Poetry's [instructions](https://python-poetry.org/docs/repositories/#secondary-package-sources) for adding this. The CodeArtifact `domain`, `domainOwner` (AWS account ID) and `region` are inferred from the repository URL when fetching auth credentials.

3. Set up AWS authentication as described below

4. To refresh your auth credentials when needed run:
```
    poetry-ca-auth refresh
```

This will trigger the authentication procedure, regardless of whether the token is expired. If you are using AWS SSO there will be a seemingly endless series of redirects but it seems to work effectively.

### Using `aws-vault` (recommended)

If using `aws-vault`, ensure that you have a profile available which has permissions to fetch CodeArtifact authentication tokens. You can configure the profile using an environment variable `POETRY_CA_DEFAULT_AWS_PROFILE` (probably in your login shell profile – eg `.bashrc`) or pass to the `refresh` subcommand using the `--profile-default` argument.

### Using AWS credentials from the environment

If `aws-vault` doesn't fit your needs, you can also just pull the AWS credentials from the environment. You can either set environment variable `POETRY_CA_AUTH_METHOD` to `environment` to use this method, or pass via the `--auth-method` argument.


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

## Specifics for Culture Amp

If following the recommended `aws-vault` route, you probably want to check out the [wiki instructions](https://cultureamp.atlassian.net/wiki/spaces/SEC/pages/2744649490/AWS+SSO+Okta+-+User+Guides#Generating-a-CultureAmp-configuration-file) and then set

```
    POETRY_CA_DEFAULT_AWS_PROFILE=cultureamp-continuous-integration:CiUserRole
```

in your shell's persistent config (eg `.bashrc`).

If you want to follow the higher friction route you can copy in AWS credentials from the [SSO landing page]("https://d-92677b0242.awsapps.com/start#/) each time you need to refresh authentication, and pass `--auth-mode environment` to `poetry-ca-auth refresh`.