from collections import namedtuple as _namedtuple
from abc import ABCMeta as _ABCMeta, abstractproperty as _abstractproperty, abstractmethod as _abstractmethod
from functools import partial as _partial
from urllib.parse import quote

class Response(metaclass = _ABCMeta):
    text = _abstractproperty(doc = "Content of the response, in unicode")
    status_code = _abstractproperty(doc = "Integer code of the responded HTTP Status")

_Request = _namedtuple("_Request", ("method", "url", "data", "headers", "cookies"))

class Request(_Request):
    def __new__(cls, method, url, data = {}, headers = {}, cookies = {}):
        return super().__new__(cls, method, url, data, headers, cookies)

def apply_query_to_url(p, url):
    """Applies a key-value query string to URL. """
    from urllib.parse import urlsplit, urlunsplit, urlencode
    x = urlsplit(url)
    if x.query == '':
        query = urlencode(p)
    else:
        query = '{}&{}'.format(x.query, urlencode(p))
    return urlunsplit((x[0], x[1], x[2], query, x[4]))

def apply_headers_to_req(headers, req):
    try:
        h = dict(req.headers)
    except:
        h = dict()
    h.update(headers)
    return req._replace(headers = h)

def apply_url_query_to_req(query, req):
    from urllib.parse import urlsplit, urlunsplit, urlencode
    try:
        url = str(req.url)
    except:
        url = ""
    x = urlsplit(url)
    if x.query == '':
        q = urlencode(query)
    else:
        q = '{}&{}'.format(x.query, urlencode(query))
    return req._replace(url = urlunsplit((x[0], x[1], x[2], q, x[4])))

def apply_data_to_req(data, req):
    try:
        d = dict(req.data)
    except:
        d = dict()
    d.update(data)
    return req._replace(method = "POST", data = d)

def nonce(length=8):
    """Generate pseudorandom number."""
    import random
    return ''.join([str(random.randint(0, 9)) for i in range(length)])

def timestamp():
    """Get seconds since epoch (UTC)."""
    import time
    return int(time.time())

quote = _partial(quote, safe = '')

TemporaryCredentials = _namedtuple("TemporaryCredentials",
        ("token", "secret"))

TokenCredentials = _namedtuple("TokenCredentials", ("token", "secret"))

#Applying oauth parameters to request
def apply_oauth_to_req_header(data, req):
    x = ",".join(['{0}="{1}"'.format(quote(str(k)), quote(str(v))) for k, v in data.items()])
    return apply_headers_to_req({"Authorization": "OAuth {0}".format(x)}, req)

def apply_oauth_to_req_data(data, req):
    return apply_data_to_req(data, req)

def apply_oauth_to_req_query(data, req):
    return apply_url_query_to_req(data, req)

# Signature base string

def base_string_uri(uri):
    from urllib.parse import urlsplit, urlunsplit
    x = urlsplit(uri)
    scheme = x.scheme.lower() #Scheme must be lowercase
    host, _, port = x.netloc.partition(':')
    host = host.lower() #Host must be lowercase
    if port: port = int(port)
    if (scheme == "http" and port == 80) or (scheme == "https" and port == 443) or not port:
        netloc = host
    else:
        netloc = "{0}:{1}".format(host, port)
    path = x.path if x.path else "/"
    return urlunsplit((scheme, netloc, path, "", ""))

def base_string_request_params(uri, oauth_params = None, data = None):
    from urllib.parse import urlsplit, parse_qs, urlencode 
    query = dict((k, v[0]) for k, v in parse_qs(urlsplit(uri).query))
    if oauth_params: query.update(oauth_params)
    if data: query.update(data)
    if "oauth_signature" in query: del query["oauth_signature"]
    #Parameter normalization
    params = [(quote(str(k)), quote(str(v))) for k, v in query.items()]
    params.sort()
    return '&'.join(['{0}={1}'.format(k, v) for k, v in params])

def signature_base_string(method, uri, oauth_params = None, data = None):
    return '{0}&{1}&{2}'.format(quote(method.upper()), quote(base_string_uri(uri)),
            quote(base_string_request_params(uri, oauth_params, data)))

#TODO: Different  signing methods (Authorization, POST Data, GEt query)

class SignatureMethod:
    def __call__(self, req, oauth_params, token_secret = ""):
        pass

class PLAINTEXTSignatureMethod:
    name = "PLAINTEXT"
    def __init__(self, client_secret):
        self.client_secret = client_secret
    def __call__(self, req, oauth_params, token_secret = ""):
        return "{0}&{1}".format(quote(self.client_secret), quote(token_secret))

class HMACSHA1SignatureMethod:
    name = "HMAC-SHA1"
    def __init__(self, client_secret):
        self.client_secret = client_secret
    def __call__(self, req, oauth_params, token_secret = ""):
        import hmac
        from hashlib import sha1
        from binascii import b2a_base64
        #digest = HMAC-SHA1(key, text)
        text = signature_base_string(req.method, req.url, oauth_params, req.data)
        key = "{0}&{1}".format(quote(self.client_secret), quote(token_secret))
        x = hmac.new(key.encode('ascii'), text.encode('ascii'), sha1)
        return b2a_base64(x.digest())[:-1].decode('ascii')

class RSASHA1SignatureMethod:
    #TODO
    name = "RSA-SHA1"


class OAuth1Server:
    temp_cred_endpoint = None
    token_endpoint = None
    auth_endpoint = None
    apply_oauth_to_req = staticmethod(apply_oauth_to_req_header)

    def __init__(self, client_id, signature_method):
        self.client_id = client_id
        self.signature_method = signature_method

    def oauth_params(self, token = None):
        p = {"oauth_consumer_key": self.client_id,
                "oauth_signature_method": self.signature_method.name,
                "oauth_timestamp": timestamp(),
                "oauth_nonce": nonce(),
                "oauth_version": "1.0"}
        if token: p["oauth_token"] = token
        return p

    def apply_req(self, r, cred):
        p = self.oauth_params(cred.token)
        p["oauth_signature"] = self.signature_method(r, p, cred.secret)
        return self.apply_oauth_to_req(p, r)

    def temp_cred_req(self, oauth_callback = "oob", **kwargs):
        """Generate Request for requesting temporary credentials"""
        p = self.oauth_params()
        p["oauth_callback"] = oauth_callback
        p.update(kwargs)
        r = Request("POST", self.temp_cred_endpoint)
        p["oauth_signature"] = self.signature_method(r, p)
        return self.apply_oauth_to_req(p, r)

    def temp_cred_parse_resp(self, resp):
        from urllib.parse import parse_qs
        x = dict((k, v[0]) for k, v in parse_qs(resp.text).items())
        return TemporaryCredentials(x["oauth_token"], x["oauth_token_secret"])

    def temp_cred(self, oauth_callback = "oob", **kwargs):
        import requests
        req = self.temp_cred_req(oauth_callback, **kwargs)
        r = requests.request(**(req._asdict()))
        r.raise_for_status()
        return self.temp_cred_parse_resp(r)

    def auth_userreq(self, temp_cred):
        p = {"oauth_token": temp_cred.token}
        return apply_query_to_url(p, self.auth_endpoint)

    def token_req(self, temp_cred, oauth_verifier):
        p = self.oauth_params(temp_cred.token)
        p["oauth_verifier"] = oauth_verifier
        r = Request("POST", self.token_endpoint)
        p["oauth_signature"] = self.signature_method(r, p, temp_cred.secret)
        return self.apply_oauth_to_req(p, r)

    def token_parse_resp(self, resp):
        from urllib.parse import parse_qs
        x = dict((k, v[0]) for k, v in parse_qs(resp.text).items())
        return TokenCredentials(x["oauth_token"], x["oauth_token_secret"])

    def token(self, temp_cred, oauth_verifier):
        import requests
        req = self.token_req(temp_cred, oauth_verifier)
        r = requests.request(**(req._asdict()))
        r.raise_for_status()
        return self.token_parse_resp(r)

    def basic_flow(self, oauth_callback = "oob"):
        from subprocess import call
        temp_cred = self.temp_cred(oauth_callback = oauth_callback)
        url = self.auth_userreq(temp_cred)
        call(["sensible-browser", url])
        code = input("Code: ")
        return TokenStore(self, self.token(temp_cred, code.strip()))

class TwitterOAuth1(OAuth1Server):
    temp_cred_endpoint = "https://api.twitter.com/oauth/request_token"
    token_endpoint = "https://api.twitter.com/oauth/access_token"
    auth_endpoint = "https://api.twitter.com/oauth/authorize"

class TumblrOAuth1(OAuth1Server):
    temp_cred_endpoint = "http://www.tumblr.com/oauth/request_token"
    auth_endpoint = "http://www.tumblr.com/oauth/authorize"
    token_endpoint = "http://www.tumblr.com/oauth/access_token"

class BitbucketOAuth1(OAuth1Server):
    temp_cred_endpoint = "https://bitbucket.org/!api/1.0/oauth/request_token"
    auth_endpoint = "https://bitbucket.org/!api/1.0/oauth/authenticate"
    token_endpoint = "https://bitbucket.org/!api/1.0/oauth/access_token"

class TokenStore:
    def __init__(self, server, token_credentials = None, path = None):
        self.server = server
        self.token_credentials = token_credentials
        self.path = path
        self.modified = True
    def apply_req(self, r):
        return self.server.apply_req(r, self.token_credentials)
    def loads(self, input):
        import pickle
        self.token_credentials = pickle.loads(input)
        self.modified = False
    def load(self, file = None):
        import pickle
        if file is None:
            if self.path is not None:
                file = self.path
            else:
                raise ValueError("file must be provided if self.path is None")
        if isinstance(file, str):
            self.path = file 
            file = open(file, "rb")
        self.token_credentials = pickle.load(file)
        self.modified = False

    def dumps(self):
        import pickle
        return pickle.dumps(self.token_credentials)
    
    def dump(self, file = None):
        import pickle
        if file is None:
            if self.path is not None:
                file = self.path
            else:
                raise ValueError("file must be provided if self.path is None")
        if self.modified:
            if isinstance(file, str):
                self.path = file
                file = open(file, "wb")
            pickle.dump(self.token_credentials, file)
            return True
        else:
            return False

import requests.auth

class RequestsOAuth2(requests.auth.AuthBase):
    def __init__(self, token_store):
        self.token_store = token_store
    def __call__(self, x):
        if x.files:
            data = {}
            replace_data = False 
        else:
            replace_data = True
            data = x.data
        y = Request(x.method, x.url, data, x.headers, x.cookies)
        y = self.token_store.apply_req(y)
        x.method = y.method
        x.url = y.url
        if replace_data: x.data = y.data
        x.headers = y.headers
        x.cookies = y.cookies
        return x

class CurlWrapper:
    def __init__(self, token_store):
        self.token_store = token_store

    @staticmethod
    def req_to_curl_args(req):
        from urllib.parse import urlencode
        #Reconstruct CURL Request
        args = []
        #Headers
        if req.headers:
            for x, y in req.headers.items():
                args.append("-H")
                args.append("{}: {}".format(x, y))
        #Data
        if req.data:
            for x, y in req.data.items():
                args.append("-d")
                args.append(urlencode({x: y}))
        #Finally, URL
        args.append(req.url)
        return args

    def call_curl(self, req, args, refresh = True):
        from subprocess import call
        import sys
        if self.token_store:
            r = self.token_store.apply_req(req)
        else:
            r = req
        return_code = call(["curl"] + args +  self.req_to_curl_args(r))
        return return_code

    def main(self, args = None):
        from . import Request
        from argparse import ArgumentParser
        import sys
        p = ArgumentParser()
        p.add_argument("-d", "--data-urlencode", dest = "data", action = "append", default = [])
        args, rest = p.parse_known_args(args)
        if not rest:
            p.error("URL not specified")
        url = rest[-1]
        del rest[-1]
        #Generate data
        data = dict()
        for x in args.data:
            if x.startswith("@"):
                key, _, value = open(x[1:]).read().partition("=")
            else:
                key, _, value = x.partition("=")
            data[key] = value
        if data or next(filter(lambda x: x.startswith("-F") or x == "--form", rest), None):
            method = "POST"
        else:
            method = "GET"
        req = Request(method = method, url = url, data = data, headers = {}, cookies = {})
        return self.call_curl(req, rest)

