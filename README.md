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
mauth-authenticator==<latest version>
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
url = "https://innovate.imedidata.com/api/v2/users/%s/studies.json" % user_uuid

# Make the requests call, passing the auth client
result = requests.get(url, auth=mauth)

# Print results
if result.status_code == 200:
    print([r["uuid"] for r in result.json()["studies"]])
print(result.text)
```


### Authenticating Incoming Requests in AWS Lambda

The following variables are **required** to be configured in the AWS Lambda environment variables setting:

| Key            | Value                                                         |
| -------------- | ------------------------------------------------------------- |
| `APP_UUID`     | APP_UUID for the AWS Lambda function                          |
| `PRIVATE_KEY`  | Encrypted private key for the APP_UUID                        |
| `MAUTH_URL`    | MAuth service URL (e.g. https://mauth-innovate.imedidata.com) |

```python
from mauth_client.mauth_authenticator import MAuthAuthenticator

mauth_authenticator = MAuthAuthenticator(method, url, headers, body)
authentic, status_code, message = mauth_authenticator.is_authentic()
app_uuid = mauth_authenticator.get_app_uuid()
```


## Contributing

See [CONTRIBUTING](CONTRIBUTING.md)
