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
  pyenv install 3.5.7
  pyenv install 3.6.9
  pyenv install 3.7.4
  pyenv install pypy3.6-7.1.1
  ```
1. Install Tox
  ```bash
  pip install tox tox-pyenv
  ```
1. Setup the local project versions (one for each env in the `envlist`)
  ```bash
  pyenv local 3.5.7 3.6.9 3.7.4 pypy3.6-7.1.1
  ```

## Unit Tests

1. Make any changes, update the tests and then run tests with `tox`
1. Coverage report can be viewed using `open htmlcov/index.html`
