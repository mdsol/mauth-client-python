# Contributing

GitHub Actions runs the automated checks for pull requests and publishes releases to PyPI.

For local development, install the dependencies with Poetry and run the unit tests with pytest. The test suite runs against all supported Python versions in CI.

## Installation

To setup your environment:
1. Install Python
1. Install Pyenv
  ```bash
  brew update
  brew install pyenv
  ```
1. Install your favorite Python version (>= 3.10 please!)
  ```bash
  pyenv install <YOUR_FAVORITE_VERSION>
  ```
1. Install Poetry, see: https://python-poetry.org/docs/#installation
1. Install Dependencies
  ```bash
  poetry install -v
  ```


## Cloning the Repo

This repo contains the submodule `mauth-protocol-test-suite` so requires a flag when initially cloning in order to clone and init submodules:
```sh
git clone --recurse-submodules git@github.com:mdsol/mauth-client-python.git
```

If you have already cloned before the submodule was introduced, then run:
```sh
cd tests/mauth-protocol-test-suite
git submodule update --init
```

to init the submodule.


## Unit Tests

1. Make any changes, update the tests and then run tests with `poetry run pytest`.
1. Coverage report can be viewed using `open htmlcov/index.html`.
1. To run a specific test file, use `poetry run pytest <SOME_FILE>`.
