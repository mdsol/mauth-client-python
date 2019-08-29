# Contributing

## Installation

- Install pyenv (`curl -L https://raw.githubusercontent.com/yyuu/pyenv-installer/master/bin/pyenv-installer | bash`)
- Install Python 3.6.1 (`pyenv install 3.6.1`)
- Clone the repo
- Run `cd mauth-client-python`
- Create a [virtual environment](https://amaral.northwestern.edu/resources/guides/pyenv-tutorial#VirtualEnvironments):
  - `mkdir virtualenv`
  - `pyenv virtualenv 3.6.1 venv`
  - `pyenv activate venv`
- Run `python setup.py install`.

## Unit Tests

To run unit tests for the lambdas, execute `python setup.py test`

## Branches & pull requests

We use the git-flow branch strategy. Features should be based off the `develop` branch and merged using GitHub pull requests.
