# MAuth Client Python
[![Build
Status](https://travis-ci.com/mdsol/mauth-client-python.svg?token=YCqgqZjJBpwz6GCprYaV&branch=develop)](https://travis-ci.com/mdsol/mauth-client-python)

MAuth Client Python is an authentication library to manage the information needed to both sign and authenticate requests and responses for Medidata's MAuth authentication system.


## Pre-requisites

To use MAuth Authenticator you will need:

* An MAuth app ID
* An MAuth private key (with the public key registered with Medidata's MAuth server)


## Installation

To resolve packages using pip, add the following to ~/.pip/pip.conf:
```
[global]
index-url = https://<username>:<password>@mdsol.jfrog.io/mdsol/api/pypi/pypi-packages/simple/
```

Install using pip:
```
$ pip install mauth-client
```

Or directly from GitHub:
```
$ pip install git+https://github.com/mdsol/mauth-client-python.git
```

This will also install the dependencies.

To resolve using a requirements file, the index URL can be specified in the first line of the file:
```
--index-url https://<username>:<password>@mdsol.jfrog.io/mdsol/api/pypi/pypi-packages/simple/
mauth-client==<latest version>
```

## Usage

### Signing Outgoing Requests

```python
import requests
from mauth_client.requests_mauth import MAuth

# MAuth configuration
APP_UUID = "<MAUTH_APP_UUID>"
private_key = open("private.key", "r").read()
mauth = MAuth(APP_UUID, private_key)

# Call an MAuth protected resource, in this case an iMedidata API
# listing the studies for a particular user
user_uuid = "10ac3b0e-9fe2-11df-a531-12313900d531"
url = "https://innovate.imedidata.com/api/v2/users/{}/studies.json".format(user_uuid)

# Make the requests call, passing the auth client
result = requests.get(url, auth=mauth)

# Print results
if result.status_code == 200:
    print([r["uuid"] for r in result.json()["studies"]])
print(result.text)
```

The `mauth_sign_versions` option can be set as an environment variable to specify protocol versions to sign outgoing requests:

| Key                   | Value                                                                                |
| --------------------- | ------------------------------------------------------------------------------------ |
| `MAUTH_SIGN_VERSIONS` | **(optional)** Comma-separated protocol versions to sign requests. Defaults to `v1`. |

This option can also be passed to the constructor:

```python
mauth_sign_versions = "v1,v2"
mauth = MAuth(APP_UUID, private_key, mauth_sign_versions)
```


### Authenticating Incoming Requests

MAuth Client Python supports AWS Lambda functions and Flask applications to authenticate MAuth signed requests.

The following variables are **required** to be configured in the environment variables:

| Key            | Value                                                         |
| -------------- | ------------------------------------------------------------- |
| `APP_UUID`     | APP_UUID for the AWS Lambda function                          |
| `PRIVATE_KEY`  | Encrypted private key for the APP_UUID                        |
| `MAUTH_URL`    | MAuth service URL (e.g. https://mauth-innovate.imedidata.com) |


The following variables can optionally be set in the environment variables:

| Key                    | Value                                                                                     |
| ---------------------- | ----------------------------------------------------------------------------------------- |
| `MAUTH_API_VERSION`    | **(optional)** MAuth API version. Only `v1` exists as of this writing. Defaults to `v1`.  |
| `MAUTH_MODE`           | **(optional)** Method to authenticate requests. `local` or `remote`. Defaults to `local`. |
| `V2_ONLY_AUTHENTICATE` | **(optional)** Authenticate requests with only V2. Defaults to `False`.                   |


#### AWS Lambda functions

```python
from mauth_client.lambda_authenticator import LambdaAuthenticator

authenticator = LambdaAuthenticator(method, url, headers, body)
authentic, status_code, message = authenticator.is_authentic()
app_uuid = authenticator.get_app_uuid()
```

#### Flask applications

You will need to create an application instance and initialize it with FlaskAuthenticator.
To specify routes that need to be authenticated use the `requires_authentication` decorator.

```python
from flask import Flask
from mauth_client.flask_authenticator import FlaskAuthenticator, requires_authentication

app = Flask("Some Sample App")
authenticator = FlaskAuthenticator()
authenticator.init_app(app)

@app.route("/some/private/route", methods=["GET"])
@requires_authentication
def private_route():
    return "Wibble"

@app.route("/app_status", methods=["GET"])
def app_status():
    return "OK"
```

#### FastAPI applications

You will need to create an application instance and initialize it with FastAPIAuthenticator.
To specify routes that need to be authenticated use the `requires_authentication` dependency.

```python
from fastapi import FastAPI, Depends
from mauth_client.fastapi_authenticator import FastAPIAuthenticator

app = FastAPI()
authenticator = FastAPIAuthenticator()
authenticator.init_app(app)

@app.get("/some/private/route", dependencies=[Depends(requires_authentication)])
def private_route():
    return {"msg": "top secret"}

@app.get("/app_status")
def app_status():
    return {"msg": "OK"}
```

## Contributing

See [CONTRIBUTING](CONTRIBUTING.md)
