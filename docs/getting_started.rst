Getting Started
***************

Below you can find some information and examples on getting started using the framework.

Installation
------------
Install using `pip` in the usual way

Install with pip::

    $ pip install mauth-client

Or directly from github with::

    $ pip install git+https://github.com/mdsol/mauth-client-python.git


Simple signing of Requests
--------------------------

In order to be able to utilise this you will need to have setup your MAuth Credentials. To do so:

1. Generate and register an Application (see :doc:`mauth_setup` for instructions)

2. Create a `MAuth` instance using the `mauth_client.requests_mauth.MAuth` class::

    from mauth_client.requests_mauth import MAuth

    mauth = MAuth(app_uuid='your_app_uuid', private_key_data='your_private_key_data')
3. Add the `MAuth` instance to your request; this can be done inline with the `requests.verb` action or by using a `requests.Session`::

    # Using the request authentication request signer inline
    response = requests.get('/some/url.json', auth=mauth)

    # Using a requests.Session
    client = requests.Session()
    client.auth = mauth
    response = client.get('/some/url.json')

See :doc:`examples` for more examples.

Configuration
-------------
The module expects to have the following variables passed (both as strings)
  *  Application UUID - `app_uuid`
  *  Private Key Data - `private_key_data`

These are supplied as 12-factor environment variables.


Authenticating Incoming Requests in AWS Lambda
----------------------------------------------

1. Configure the following AWS Lambda environment variables:

==============  ===============================================================
Key             Value
==============  ===============================================================
APP_UUID        APP_UUID for the AWS Lambda function
PRIVATE_KEY     Encrypted private key for the APP_UUID
MAUTH_URL       MAuth service URL (e.g. https://mauth-sandbox.imedidata.net)
==============  ===============================================================

2. Create a `LambdaAuthenticator` instance using the `mauth_client.lambda_authenticator.LambdaAuthenticator` class::

    from mauth_client.lambda_authenticator import LambdaAuthenticator

    lambda_authenticator = LambdaAuthenticator(method, url, headers, body)

3. Authenticate incoming request by calling the `is_authentic` method::

    authentic, status_code, message = lambda_authenticator.is_authentic()


Authenticating Incoming Requests in Flask applications
------------------------------------------------------

1. Configure the following environment variables:

==============  ===============================================================
Key             Value
==============  ===============================================================
APP_UUID        APP_UUID for the Flask application
PRIVATE_KEY     Encrypted private key for the APP_UUID
MAUTH_URL       MAuth service URL (e.g. https://mauth-sandbox.imedidata.net)
==============  ===============================================================

2. Create an application instance and initialize it with the flask authenticator::

    from flask import Flask
    from mauth_client.flask_authenticator import FlaskAuthenticator

    app = Flask("Some Sample App")
    authenticator = MAuthAuthenticator()
    authenticator.init_app(app)

3. Specify routes that need to be authenticated using the `requires_authentication` decorator::

    from flask import Flask
    from mauth_client.flask_authenticator import requires_authentication

    @app.route("/some/private/route", methods=["GET"])
    @requires_authentication
    def private_route():
        return 'Wibble'

    @app.route("/app_status", methods=["GET"])
    def app_status():
        return 'OK'
