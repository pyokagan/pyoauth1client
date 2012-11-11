==================================================
pyoauth1client - The convenient oAuth 1.0 client
==================================================

The problem with current oAuth1 client libraries
==================================================
Many oauth1 client libraries(citations coming soon) assume that the user
is developing a web application and thus requires complete
control over every step of the oAuth authorization process.

Thus, in order for an ordinary user who just wants to extract some
data from a web service (e.g. twitter), he has to do the following:

1. Read up on how the oAuth 1.0 protocol flow works 
2. Look through the service provider's documentation to find the URL endpoints.
3. Learn how the different functions

To add insult to the injury, the user's python code will end up looking
like this (python-oauth2, Python 2 code)::

    import urlparse
    import oauth2 as oauth
    consumer = oauth.Consumer('bZiXcNWAgekCfCKluqi6eQ', 'ggdwDXVjewLYmUZnDM9f767YmNieR3gRSu07E')
    client = oauth.Client(consumer)
    resp, content = client.request("https://twitter.com/oauth/request_token", "POST")
    if resp["status"] != "200":
        raise Exception("Invalid response {0}".format(resp["status"]))
    request_token = dict(urlparse.parse_qsl(content))
    print "URL:", "http://twitter.com/oauth/authorize?oauth_token={0}".format(request_token["oauth_token"])
    oauth_verifier = raw_input("PIN: ")
    token = oauth.Token(request_token["oauth_token"], request_token["oauth_token_secret"])
    token.set_verifier(oauth_verifier)
    client = oauth.Client(consumer, token)
    resp, content = client.request("http://twitter.com/oauth/access_token", "POST")
    access_token = dict(urlparse.parse_qsl(content))
    client = oauth.Client(consumer, oauth.Token(access_token["oauth_token"], access_token["oauth_token_secret"]))
    resp, content = client.request("https://api.twitter.com/1.1/account/verify_credentials.json")


oAuth does not need to be this complicated.

Meet pyoauth1client
============================
Note that you must first create your `~/.config/oauth1.json` file with your
client credentials.

With requests::

    >>> from oauth1client import load_config
    >>> token = load_config().server("twitter").basic_flow()
    >>> from oauth1client.requests import OAuth1Auth
    >>> import requests
    >>> requests.get("https://api.twitter.com/1.1/account/verify_credentials.json", 
    ...     auth = OAuth1Auth(token))
    <Response [200]>
    >>> token.dump_profile() #Save the token so that you can use it with oauth1curl

With curl. `oauth1client.curl.CurlWrapper` implements some functions of 
the `subprocess` module. When these functions are called, CurlWrapper
will modify the process arguments to use oAuth before sending
the arguments to subprocess::

    >>> from oauth1client import load_config
    >>> token = load_config().server("twitter").basic_flow()
    >>> from oauth1client.curl import CurlWrapper
    >>> x = CurlWrapper(token)
    >>> x.call(["curl", "https://api.twitter.com/1.1/account/verify_credentials.json"])

With oauth1curl. Note that currently you must first perform
the basic flow in Python and call `Token.dump_profile()` to save
the token in order for oauth1curl to be able to load it::

    $ oauth1curl 'https://api.twitter.com/1.1/account/verify_credentials.json'

The ~/.config/oauth1.json file
================================
::

    {
        "twitter": {
            "client_id": "CLIENT ID",
            "client_secret": "CLIENT SECRET",
            "callback": "http://127.0.0.1"
        },
        "tumblr": {
            "client_id": "CLIENT ID",
            "client_secret": "CLIENT SECRET",
            "callback": "http://localhost:8080"
        },
        "bitbucket": {
            "client_id": "CLIENT ID",
            "client_secret": "CLIENT SECRET"
        },
        "flickr": {
            "client_id": "CLIENT ID",
            "client_secret": "CLIENT SECRET"
        }
    }

Supported oAuth providers 
==========================

* Twitter
* Tumblr
* Bitbucket
* Flickr

pyoauth1client strives to support all of the oAuth1 providers in the internet.
If your provider is not listed here, please create an issue in the bitbucket
repository.

Supported HTTP Client Libraries
=================================

* requests
* urllib (being worked on)

pyoauth1client aims to support the *popular* python HTTP Client libraries
like urllib and requests. If a popular python HTTP Client library is
not listed here, please create an issue in the bitbucket repository.

Supported HTTP Client command line applications
================================================

* curl
* wget (being worked on)

pyoauth1client aims to support the *popular* command line applications like
curl and wget. If a popular HTTP client command line application is not
listed here, please create an issue in the bitbucket repository.
