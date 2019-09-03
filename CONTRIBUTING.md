# Contributing

We use [travis](https://travis-ci.org) for automated CI of the code (and status checks are required to pass prior to PR merges being accepted).
We use travis to deploy updated versions to PyPI (only from `master`)

For local development (cross version) we use [tox](http://tox.readthedocs.io/en/latest/) with [pyenv](https://github.com/pyenv/pyenv) to automate the running of unit tests against different python versions in virtualised python environments.

## Installation

To setup your environment:
1. Install Python
1. Install Pyenv
   ```bash
   $ brew update
   $ brew install pyenv
   ```
1. Install Pyenv versions for the Tox Suite
   ```bash
   $ pyenv install 3.5.7
   $ pyenv install 3.6.9
   $ pyenv install 3.7.4
   ```
1. Install Tox
   ```bash
   $ pip install tox tox-pyenv
   ```
1. Setup the local project versions (one for each env in the `envlist`)
   ```bash
    $ pyenv local 3.5.7 3.6.9 3.7.4
   ```


## Unit Tests

1. Make any changes, update the tests and then run tests with `tox`
   ```bash
Name                                                      Stmts   Miss  Cover
-----------------------------------------------------------------------------
mauth_client/__init__.py                                      1      0   100%
mauth_client/mauth_authenticator/__init__.py                  2      0   100%
mauth_client/mauth_authenticator/exceptions.py                8      0   100%
mauth_client/mauth_authenticator/key_holder.py               43      2    95%
mauth_client/mauth_authenticator/lambda_helper.py            22     12    45%
mauth_client/mauth_authenticator/mauth_authenticator.py      90      3    97%
mauth_client/mauth_authenticator/rsa_decrypt.py              12      0   100%
mauth_client/requests_mauth/__init__.py                       1      0   100%
mauth_client/requests_mauth/client.py                        30      2    93%
mauth_client/requests_mauth/rsa_sign.py                      27      0   100%
-----------------------------------------------------------------------------
TOTAL                                                       236     19    92%
stats run-test: commands[1] | coverage html
_______________________________________________________________________________________ summary ________________________________________________________________________________________
  clean: commands succeeded
  py35: commands succeeded
  py36: commands succeeded
  py37: commands succeeded
  stats: commands succeeded
  congratulations :)
   ```
1. Coverage report can be viewed using `open htmlcov/index.html`


## Branches & pull requests

1. Push your changes and create a PR to `master`
1. Once the PR is complete, tag the branch and push it to github, this will trigger Travis to deploy to PyPI (make sure the version is consistent)
   ```bash
   $ git checkout master
   $ git pull
   $ git tag -a 0.1.0 -m "MAuth Client 0.1.0"
   $ git push --tags
   ```
