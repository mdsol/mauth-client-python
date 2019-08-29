# MAuth Client Python
[![Build
Status](https://travis-ci.com/mdsol/mauth-client-python.svg?token=YCqgqZjJBpwz6GCprYaV&branch=develop)](https://travis-ci.com/mdsol/mauth-client-python)

MAuth Client Python is an authentication library to manage the information needed to both sign and authenticate requests and responses for Medidata's MAuth authentication system.


## Pre-requisites

To use MAuth Authenticator you will need:

* An MAuth app ID
* An MAuth private key (with the public key registered with Medidata's MAuth server)


## Environment Variables

The following variables are **required** to be configured in the AWS Lambda environment variables setting:

| Key            | Value                                                        |
| -------------- | ------------------------------------------------------------ |
| `APP_UUID`     | APP_UUID for the AWS Lambda function                         |
| `PRIVATE_KEY`  | Encrypted private key for the APP_UUID                       |
| `MAUTH_URL`    | MAuth service URL (e.g. https://mauth-sandbox.imedidata.net) |


## Use as a library

### Installation

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


### Usage

```python
from mauth_client.mauth_authenticator import generate_trace_id
from mauth_client.mauth_authenticator import MAuthAuthenticator

trace_id = generate_trace_id()

mauth_authenticator = MAuthAuthenticator(trace_id, method, url, headers, body)
authentic, status_code, message = mauth_authenticator.is_authentic()
app_uuid = mauth_authenticator.get_app_uuid()
```


## Contributing

See [CONTRIBUTING](CONTRIBUTING.md)


## Contact

Developed and maintained by the Æ (Architecture Enablement) team
- [Slack channel](https://mdsol.slack.com/messages/ae)
- [ae@mdsol.com](mailto:ae@mdsol.com)
- [JIRA board](https://jira.mdsol.com/secure/RapidBoard.jspa?rapidView=1403)
