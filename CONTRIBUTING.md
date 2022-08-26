# Contributing

We use [travis](https://travis-ci.org) for automated CI of the code (and status checks are required to pass prior to PR merges being accepted).
We use travis to deploy updated versions to PyPI (only from `master`)

For local development (cross version) we use [tox](http://tox.readthedocs.io/en/latest/) with [pyenv](https://github.com/pyenv/pyenv) to automate the running of unit tests against different python versions in virtualised python environments.

## Installation

To setup your environment:
1. Install Python
1. Install Pyenv
  ```bash
  brew update
  brew install pyenv
  ```
1. Install Pyenv versions for the Tox Suite
  ```bash
  pyenv install 3.6.10
  pyenv install 3.7.7
  pyenv install 3.8.2
  pyenv install pypy3.6-7.3.1
  ```
1. Install Poetry
  ```bash
  pip install poetry
  ```
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

1. Make any changes, update the tests and then run tests with `poetry run tox`
1. Coverage report can be viewed using `open htmlcov/index.html`
