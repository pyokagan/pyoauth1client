"""
TODO: Write some documentation here
"""
from collections import namedtuple as _namedtuple, UserDict, Mapping, MutableMapping
from abc import (ABCMeta as _ABCMeta, abstractproperty as _abstractproperty,
        abstractmethod as _abstractmethod)
from functools import partial as _partial
from urllib.parse import (quote as urlquote, urlsplit, urlunsplit, urlencode,
        parse_qs)
from time import time
from random import randint
import hmac
import hashlib
from binascii import b2a_base64
from copy import deepcopy, copy
from os import walk, makedirs
from os.path import join as joinpath, relpath, isfile, isdir, expanduser, dirname
from itertools import chain
from functools import reduce
import json
import sys
import requests
from http.server import BaseHTTPRequestHandler, HTTPServer


class Response(metaclass=_ABCMeta):
    text = _abstractproperty(doc="Content of the response, in unicode")
    status_code = _abstractproperty(doc="Integer code of the responded HTTP "
            "Status")

_Request = _namedtuple("_Request", ("method", "url", "data",
                        "headers", "cookies"))


class Request(_Request):
    def __new__(cls, method, url, data={}, headers={}, cookies={}):
        return super().__new__(cls, method, url, data, headers, cookies)


def apply_query_to_url(url, p):
    """Applies a key-value query string to URL. """
    x = urlsplit(url)
    if x.query == '':
        query = urlencode(p)
    else:
        query = '{0}&{1}'.format(x.query, urlencode(p))
    return urlunsplit((x[0], x[1], x[2], query, x[4]))


def apply_headers_to_req(req, headers):
    if isinstance(req.headers, Mapping):
        if isinstance(req.headers, MutableMapping):
            h = copy(req.headers)
        else:
            h = dict(req.headers)
    else:
        h = dict()
    h.update(headers)
    return req._replace(headers=h)


def apply_url_query_to_req(req, query):
    try:
        url = str(req.url)
    except:
        url = ""
    x = urlsplit(url)
    if x.query == '':
        q = urlencode(query)
    else:
        q = '{}&{}'.format(x.query, urlencode(query))
    return req._replace(url=urlunsplit((x[0], x[1], x[2], q, x[4])))


def apply_data_to_req(req, data):
    if isinstance(req.data, Mapping):
        if isinstance(req.data, MutableMapping):
            d = copy(req.data)
        else:
            d = dict(req.data)
    else:
        d = dict()
    d.update(data)
    return req._replace(method="POST", data=d)


def nonce(length=8):
    """Generate pseudorandom number."""
    return ''.join([str(randint(0, 9)) for i in range(length)])


def timestamp():
    """Get seconds since epoch (UTC)."""
    return int(time())


urlquote = _partial(urlquote, safe='')

TemporaryCredentials = _namedtuple("TemporaryCredentials",
        ("token", "secret"))

TokenCredentials = _namedtuple("TokenCredentials", ("token", "secret"))


#Applying oauth parameters to request
def req_apply_oauth_header(req: Request, oauth_params) -> Request:
    x = ",".join(['{0}="{1}"'.format(urlquote(str(k)), urlquote(str(v)))
            for k, v in oauth_params.items()])
    return apply_headers_to_req(req, {"Authorization": "OAuth {0}".format(x)})


def req_apply_oauth_data(req: Request, oauth_params) -> Request:
    return apply_data_to_req(req, oauth_params)


def req_apply_oauth_urlquery(req: Request, oauth_params) -> Request:
    return apply_url_query_to_req(req, oauth_params)


""" Signature Base String Functions (For Signature Methods) """


def base_string_uri(uri):
    x = urlsplit(uri)
    scheme = x.scheme.lower()  # Scheme must be lowercase
    host, _, port = x.netloc.partition(':')
    host = host.lower()  # Host must be lowercase
    if port:
        port = int(port)
    if (scheme == "http" and port == 80) or (scheme == "https" and port == 443) or not port:
        netloc = host
    else:
        netloc = "{0}:{1}".format(host, port)
    path = x.path if x.path else "/"
    return urlunsplit((scheme, netloc, path, "", ""))


def base_string_request_params(uri, oauth_params = None, data = None):
    from urllib.parse import urlsplit, parse_qs, urlencode 
    from collections import Mapping
    query = dict((k, v[0]) for k, v in parse_qs(urlsplit(uri).query).items())
    if oauth_params: 
        query.update(oauth_params)
    if data and isinstance(data, Mapping):
        query.update(data)
    if "oauth_signature" in query: 
        del query["oauth_signature"]
    #Parameter normalization
    params = [(urlquote(str(k)), urlquote(str(v))) for k, v in query.items()]
    params.sort()
    return '&'.join(['{0}={1}'.format(k, v) for k, v in params])


def signature_base_string(method, uri, oauth_params = None, data = None):
    return '{0}&{1}&{2}'.format(urlquote(method.upper()), urlquote(base_string_uri(uri)),
            urlquote(base_string_request_params(uri, oauth_params, data)))


""" Signature Methods """


class PLAINTEXTSignatureMethod:
    name = "PLAINTEXT"
    def __init__(self, client_secret: str):
        self.client_secret = client_secret
    def __call__(self, req: Request, oauth_params:dict, token_secret:str = "") -> str:
        return "{0}&{1}".format(urlquote(self.client_secret), urlquote(token_secret))

class HMACSHA1SignatureMethod:
    name = "HMAC-SHA1"
    def __init__(self, client_secret: str):
        self.client_secret = client_secret
    def __call__(self, req: Request, oauth_params:dict, token_secret:str = "") -> str:
        #digest = HMAC-SHA1(key, text)
        text = signature_base_string(req.method, req.url, oauth_params, req.data)
        key = "{0}&{1}".format(urlquote(self.client_secret), urlquote(token_secret))
        x = hmac.new(key.encode('ascii'), text.encode('ascii'), hashlib.sha1)
        return b2a_base64(x.digest())[:-1].decode('ascii')

#TODO: RSASHA1SignatureMethod: Use the RSA module?


def oauth(req: Request, client_id:str,
        signature_method, credentials = None, params = {},
        req_oauth = req_apply_oauth_header):
    """Adds oauth parameters to a Request and signs the Request, returning the
    signed Request."""
    #Applies oauth_params to the req, and signs it.
    p = {"oauth_consumer_key": client_id,
            "oauth_timestamp": timestamp(),
            "oauth_nonce": nonce(),
            "oauth_signature_method": signature_method.name,
            "oauth_version": "1.0"}
    if credentials: p["oauth_token"] = credentials.token
    p.update(params)
    signature = signature_method(req, p, credentials.secret if credentials else "")
    p["oauth_signature"] = signature
    x = req_oauth(req, p)
    return x


""" Token Storage """

def _token_store_path_posix(name, profile = "default"):
    return joinpath(expanduser("~/.local/share/oauth1/profiles"), profile, name)

def _token_store_path(name, profile = "default"):
    return _token_store_path_posix(name, profile)

def token_store_open(name, profile = "default", mode = "rb"):
    path = _token_store_path(name, profile)
    makedirs(dirname(path), exist_ok = True)
    return open(path, mode)

class Token:
    def __init__(self, server, token_credentials = None):
        self.server = server
        self.token_credentials = token_credentials
        self.modified = True

    def apply_req(self, r):
        return self.server.oauth(r, self.token_credentials)

    def loads(self, input):
        import pickle
        self.token_credentials = pickle.loads(input)
        self.modified = False

    def load(self, file):
        import pickle
        if isinstance(file, str):
            file = open(file, "rb")
        self.token_credentials = pickle.load(file)
        self.modified = False

    def load_profile(self, profile = "default", *, name = None):
        if name is None:
            name = self.server.name
        return self.load(token_store_open(name, profile, "rb"))

    def dumps(self):
        import pickle
        return pickle.dumps(self.token_credentials)
    
    def dump(self, file):
        import pickle
        if self.modified:
            if isinstance(file, str):
                makedirs(dirname(file), exist_ok = True)
                file = open(file, "wb")
            pickle.dump(self.token_credentials, file)
            return True
        else:
            return False

    def dump_profile(self, profile = "default", *, name = None):
        """Dump the token into the global store"""
        if name is None:
            name = self.server.name
        return self.dump(token_store_open(name, profile, "wb"))


""" Server """

class OAuth1Server:
    callback = "http://localhost"
    req_oauth = staticmethod(req_apply_oauth_header)

    def __init__(self, client_id, signature_method, *, 
            temp_cred_endpoint = None, 
            temp_cred_endpoint_method = "POST",
            token_cred_endpoint = None, 
            token_cred_endpoint_method = "POST",
            auth_endpoint = None, callback = "http://localhost"):
        self.client_id = client_id
        self.signature_method = signature_method
        self.temp_cred_endpoint = temp_cred_endpoint
        self.temp_cred_endpoint_method = temp_cred_endpoint_method
        self.token_cred_endpoint = token_cred_endpoint
        self.token_cred_endpoint_method = token_cred_endpoint_method
        self.auth_endpoint = auth_endpoint
        self.callback = callback

    def oauth(self, req, credentials = None, params = {}):
        """Adds oauth parameters and signs a Request"""
        return oauth(req, self.client_id, self.signature_method, 
                credentials, params, self.req_oauth)

    """ Temporary Credentials Endpoint """

    def temp_cred_req(self, oauth_callback = None, **kwargs):
        """Generate Request for requesting temporary credentials"""
        if oauth_callback is None: oauth_callback = self.callback
        p = dict(kwargs)
        p["oauth_callback"] = oauth_callback
        r = Request(self.temp_cred_endpoint_method, self.temp_cred_endpoint)
        return self.oauth(r, params = p)

    def temp_cred_parse_resp(self, resp):
        x = dict((k, v[0]) for k, v in parse_qs(resp.text).items())
        return TemporaryCredentials(x["oauth_token"], x["oauth_token_secret"])

    def temp_cred(self, oauth_callback = None, **kwargs):
        if oauth_callback is None: 
            oauth_callback = self.callback
        req = self.temp_cred_req(oauth_callback, **kwargs)
        r = requests.request(**(req._asdict()))
        r.raise_for_status()
        return self.temp_cred_parse_resp(r)

    """ Authorization Endpoint """

    def auth_userreq(self, temp_cred, *, oauth_callback = None, 
            extra_params = {}):
        p = extra_params.copy()
        p.update({"oauth_token": temp_cred.token})
        return apply_query_to_url(self.auth_endpoint, p)
    
    def auth_parse_userresp(self, redirect_url):
        p = dict((k, v[0]) for k, v in parse_qs(urlsplit(redirect_url).query).items())
        return p["oauth_verifier"]

    """ Token Credentials Endpoint """

    def token_cred_req(self, temp_cred, oauth_verifier):
        r = Request(self.token_cred_endpoint_method, self.token_cred_endpoint)
        return self.oauth(r, temp_cred, params = {"oauth_verifier": oauth_verifier})

    def token_cred_parse_resp(self, resp):
        x = dict((k, v[0]) for k, v in parse_qs(resp.text).items())
        return TokenCredentials(x["oauth_token"], x["oauth_token_secret"])

    def token_cred(self, temp_cred, oauth_verifier):
        req = self.token_cred_req(temp_cred, oauth_verifier)
        r = requests.request(**(req._asdict()))
        r.raise_for_status()
        return self.token_cred_parse_resp(r)

    def basic_flow(self, oauth_callback = None, *, token_class = Token):
        from subprocess import call
        if oauth_callback is None:
            oauth_callback = self.callback
        def blah(redirect_url):
            temp_cred = self.temp_cred(oauth_callback = redirect_url)
            url = self.auth_userreq(temp_cred, oauth_callback = redirect_url)
            return url, temp_cred
        url, temp_cred = ua_handle_http(blah, oauth_callback)
        code = self.auth_parse_userresp(url)
        return token_class(self, self.token_cred(temp_cred, code))

    def load_profile(self, profile = "default", *, token_class = Token):
        """Load a Token from a profile."""
        x = token_class(self)
        x.load_profile(profile)
        return x

class LegacyOAuth1Server(OAuth1Server):
    def auth_userreq(self, temp_cred, *, oauth_callback = None, 
            extra_params = {}):
        if oauth_callback is None:
            oauth_callback = self.callback
        p = extra_params.copy()
        p.update({"oauth_callback": oauth_callback})
        return super().auth_userreq(temp_cred, extra_params = p)

    def auth_parse_userresp(self, redirect_url):
        p = dict((k, v[0]) for k, v in parse_qs(urlsplit(redirect_url).query).items())
        return p["oauth_token"]

    def token_cred_req(self, temp_cred, oauth_verifier):
        r = Request(self.token_cred_endpoint_method, self.token_cred_endpoint)
        temp_cred = temp_cred._replace(token = oauth_verifier)
        return self.oauth(r, temp_cred)


def get_all_file_paths_in_path(path: str):
    """Return a list of all paths in the directory `path`"""
    def join_paths(dir_path, filenames):
        return (joinpath(path, dir_path, filename) for \
                filename in filenames)
    files_iter = (join_paths(dir_path, filenames) for \
            dir_path, _, filenames in walk(path))
    return chain.from_iterable(files_iter)


def get_all_file_paths_in_paths(paths: [str]):
    """Return a list of all paths in the list of paths"""
    """path: TypedIteratore(Path). Returns: TypedIterator(Path)"""
    def handle(x):
        if isdir(x):
            return get_all_file_paths_in_path(x)
        elif isfile(x):
            return [x]
        else:
            return None
    paths_iter = (handle(x) for x in paths)
    paths_iter2 = filter(None, paths_iter)
    return chain.from_iterable(paths_iter2)

def _config_search_paths_posix():
    return ["/usr/share/oauth1/db.d",
            "/usr/share/oauth1/db.json",
            "/usr/local/share/oauth1/db.d",
            "/usr/local/share/oauth1/db.json",
            "/etc/oauth1.json",
            expanduser("~/.local/share/oauth1/oauth1.d"),
            expanduser("~/.local/share/oauth1/oauth1.json"),
            expanduser("~/.config/oauth1.json")
            ]

config_search_paths = _config_search_paths_posix()

def merge(x, y):
    from copy import deepcopy
    for key in x:
        if key in y:
            x[key].update(y[key])
    return x

bundled_config = {
        "twitter": {
            "temp_cred_endpoint": "https://api.twitter.com/oauth/request_token",
            "token_cred_endpoint": "https://api.twitter.com/oauth/access_token",
            "auth_endpoint": "https://api.twitter.com/oauth/authorize",
            "resources": "https://api.twitter.com|https://userstream.twitter.com|https://stream.twitter.com"
            },
        "tumblr": {
            "temp_cred_endpoint": "https://www.tumblr.com/oauth/request_token",
            "auth_endpoint": "https://www.tumblr.com/oauth/authorize",
            "token_cred_endpoint": "https://www.tumblr.com/oauth/access_token",
            "resources": "https://api.tumblr.com"
            },
        "bitbucket": {
            "temp_cred_endpoint": "https://bitbucket.org/!api/1.0/oauth/request_token",
            "auth_endpoint": "https://bitbucket.org/!api/1.0/oauth/authenticate",
            "token_cred_endpoint": "https://bitbucket.org/!api/1.0/oauth/access_token",
            "resources": "https://api.bitbucket.org"
            },
        "flickr": {
            "temp_cred_endpoint": "https://www.flickr.com/services/oauth/request_token",
            "temp_cred_endpoint_method": "GET",
            "auth_endpoint": "https://www.flickr.com/services/oauth/authorize",
            "token_cred_endpoint": "https://www.flickr.com/services/oauth/access_token",
            "token_cred_endpoint_method": "GET",
            "resources": "https://api.flickr.com|http://api.flickr.com|https://www.flickr.com|http://www.flickr.com",
            "_pyoauth1client_class": "oauth1client.FlickrOAuth1"
            },
        "trello": {
            "temp_cred_endpoint": "https://trello.com/1/OAuthGetRequestToken",
            "auth_endpoint": "https://trello.com/1/OAuthAuthorizeToken",
            "token_cred_endpoint": "https://trello.com/1/OAuthGetAccessToken",
            "resources": "https://trello.com",
            "_pyoauth1client_class": "oauth1client.TrelloOAuth1"
            },
        "dropbox": {
            "temp_cred_endpoint": "https://api.dropbox.com/1/oauth/request_token",
            "auth_endpoint": "https://www.dropbox.com/1/oauth/authorize",
            "token_cred_endpoint": "https://api.dropbox.com/1/oauth/access_token",
            "resources": "https://api-content.dropbox.com|https://api.dropbox.com",
            "version": "1.0"
            },
        "vimeo": {
            "temp_cred_endpoint": "https://vimeo.com/oauth/request_token",
            "auth_endpoint": "https://vimeo.com/oauth/authorize",
            "token_cred_endpoint": "https://vimeo.com/oauth/access_token",
            "resources": "https://vimeo.com/api/rest/v2",
            "_pyoauth1client_class": "oauth1client.VimeoOAuth1"
            },
        "yahoo": {
            "temp_cred_endpoint": "https://api.login.yahoo.com/oauth/v2/get_request_token",
            "auth_endpoint": "https://api.login.yahoo.com/oauth/v2/request_auth",
            "token_cred_endpoint": "https://api.login.yahoo.com/oauth/v2/get_token",
            "resources": "http://social.yahooapis.com"
            }
        }

class Config(UserDict):
    def server(self, name, **kwargs):
        """Returns the server with name"""
        x = self[name].copy()
        if "signature_method" in x:
            signature_method = x["signature_method"]
        else:
            signature_method = "HMAC-SHA1"
        if signature_method == "HMAC-SHA1":
            signature_method = HMACSHA1SignatureMethod(x["client_secret"])
        elif signature_method == "PLAINTEXT":
            signature_method = PLAINTEXTSignatureMethod(x["client_secret"])
        else:
            raise ValueError("Unknown signature method {0!r}".format(signature_method))
        x["signature_method"] = signature_method
        if "version" in x:
            version = x["version"]
        else:
            version = "rfc"
        if "_pyoauth1client_class" in x:
            module, _, cls = x["_pyoauth1client_class"].rpartition(".")
            module = __import__(module, fromlist = [cls])
            cls = getattr(module, cls)
        elif version == "rfc" or version == "1.0a":
            cls = OAuth1Server
        elif version == "1.0":
            cls = LegacyOAuth1Server
        else:
            raise ValueError("Unknown oAuth version {!r}".format(version))
        x = dict((k, v) for k, v in x.items() if not (k.startswith("_") or 
            k in ["client_secret", "resources", "version"]))
        x.update(kwargs)
        y = cls(**x)
        y.name = name
        return y

    def url(self, url, **kwargs):
        """Returns the server which has a resource under URL"""
        def check(x, url):
            if "resources" in x:
                y = x["resources"].split("|")
                return any(url.startswith(x) for x in y)
            else:
                return False
        z = next((x for x in self if check(self[x], url)), None)
        if z:
            return self.server(z)
        else:
            raise KeyError(url)

def load_config(paths = config_search_paths):
    z = get_all_file_paths_in_paths(paths)
    def load_file(x):
        f = open(x, "r", encoding = 'utf-8')
        y = json.load(f)
        f.close()
        return y
    configs = (load_file(x) for x in z)
    return Config(reduce(lambda x, y: merge(x, y), chain([bundled_config], configs)))

""" User Interface Support """

class StoppableHttpServer(HTTPServer):
    """http server that reacts to self.stop flag"""
    def serve_forever(self):
        """Handle one request at a time until stopped."""
        self.stop = False
        self.response_url = None
        while not self.stop:
            self.handle_request()
        return self.response_url

class HttpResponseHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        from copy import copy
        #Send a Nice response back to client
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.end_headers()
        self.wfile.write(self.path.encode('ascii'))
        self.server.response_url = copy(self.path)
        #Stop the server
        self.server.stop = True
    def log_request(code = '-', size = '-'):
        pass


def _run_http_server(port_pipe, pipe, port_range):
    import socket
    port = port_range[0]
    while port <= port_range[1]:
        try:
            httpd = StoppableHttpServer(('127.0.0.1', port), HttpResponseHandler)
            break
        except socket.error as e:
            if e.errno == 98 or e.errno == 13: #Address already in use or permission denied
                httpd = None
        port += 1
    if httpd is None:
        #Could not find a port
        port_pipe.send(0)
        port_pipe.close()
        return
    port_pipe.send(port)
    port_pipe.close()
    x = httpd.serve_forever()
    pipe.send(x)
    pipe.close()


def run_http_server(redirect_uri = None, port_range = (10000, 10010) ):
    """Returns (modified) redirect_uri"""
    from multiprocessing import Process, Pipe
    from urllib.parse import urlsplit, urlunsplit
    if redirect_uri is None:
        redirect_uri = "http://localhost"
    p = urlsplit(redirect_uri)
    #Ensure hostname is localhost or 127.0.0.1
    if p.hostname != "127.0.0.1" and p.hostname != "localhost":
        raise ValueError("url must have host of 127.0.0.1 or localhost! Got: {}".format(p.hostname))
    if p.port is not None:
        port_range = (int(p.port), int(p.port))
    parent_port_pipe, child_port_pipe = Pipe()
    parent_pipe, child_pipe = Pipe()
    httpd_p = Process(target = _run_http_server, args = (child_port_pipe, child_pipe, port_range))
    httpd_p.start()
    if parent_port_pipe.poll(3000):
        final_port = parent_port_pipe.recv()
    else:
        raise Exception("Timeout waiting for HTTP server process to start")
    if final_port == 0:
        #Could not find a port
        raise Exception("Could not find open port")
    netloc = "{0}:{1}".format(p.hostname, final_port)
    if p.path:
        path = p.path
    else:
        path = '/'
    p = p._replace(netloc = netloc, path = path)
    return (urlunsplit(p), parent_pipe, httpd_p)


def stop_http_server(redirect_uri, httpd_p):
    import requests
    requests.get(redirect_uri)
    httpd_p.join()

def ua_win_tk(url, pipe = None):
    from tkinter import Tk, Frame, Label, Entry, StringVar, BOTH, Button, RIGHT
    import sys
    sys.stdout.flush()
    instructions = "Visit the following URL to authorize the application:"
    response = {"x": False}
    root = Tk()
    root.title("oAuth1 Authorization Required")
    webbox = Frame(root)
    instructions = Label(webbox, text = instructions)
    instructions.pack(padx = 5, pady = 5)
    urlstr = StringVar(value = url)
    urlbox = Entry(webbox, textvariable = urlstr, state = "readonly")
    urlbox.pack(padx = 5, pady = 5)
    def open_browser():
        from subprocess import Popen
        p = Popen(["sensible-browser", url])
    browserbutton = Button(webbox, text = "Open in web browser", command = open_browser)
    browserbutton.pack(padx = 5, pady = 5)
    webbox.pack(fill = BOTH, expand = 1)
    if pipe:
        def poll():
            if pipe.poll():
                root.destroy()
                #Mutability ftw... wat
                response["x"] = True
            else:
                root.after(300, poll)
        root.after(300, poll)
    cancelbutton = Button(root, text = "Cancel", command = root.destroy)
    cancelbutton.pack(side = RIGHT, padx = 5, pady = 5)
    root.mainloop()
    return response["x"]


def ua_handle_http(gen_userreq, redirect_uri):
    import requests
    redirect_uri, pipe, p = run_http_server(redirect_uri)
    #Step 3: If all fails, fall back to tty
    #Step 4: If that fails, Fail noisily
    try:
        url, context = gen_userreq(redirect_uri)
        gui_handlers = [(ua_win_tk, lambda: True)]
        #Step 1: Load handler based on what modules are already loaded
        result = None
        for x, y in gui_handlers:
            if y():
                result = x(url, pipe)
                break
        if result:
            url = pipe.recv()
            p.join()
            pipe.close()
            return url, context
        else:
            raise Exception("No result")
    except:
        #Clean up server properly
        stop_http_server(redirect_uri, p)
        raise


""" Workarounds """
class FlickrOAuth1(OAuth1Server):
    def oauth(self, req, credentials = None, params = {}):
        #NOTE: While flickr supports HTTPS in its oauth endpoints, flickr
        #thinks that the HTTPS endpoints are being accessed via HTTP, and thus
        #constructs the signature base string accordingly, which
        #will hence not match the signature base string generated by
        #pyoauth1client. We solve this by replacing HTTPS with HTTP
        #when generating the signature base string, and then revert the change
        #after the base string is generated. This way the signature
        #base string will match the one generated by flickr even though
        #we are accessing the endpoints via HTTPS for ADDED SECURITY!!!111one
        x = urlsplit(req.url)
        if x.scheme == "https":
            #Remove the HTTPS Scheme
            https = True
            x = x._replace(scheme = "http")
            req = req._replace(url = urlunsplit(x))
        else:
            https = False
        y = super().oauth(req, credentials, params)
        if https:
            #Add back the HTTPS scheme
            x = urlsplit(y.url)
            x = x._replace(scheme = "https")
            y = y._replace(url = urlunsplit(x))
        return y

    def auth_userreq(self, temp_cred, *,
            oauth_callback = None, perms = "delete", extra_params = {}):
        #NOTE: Flickr REQUIRES the perms URL parameter. It will error out
        #with "unknown permissions" or something if the parameter is not provided.
        p = extra_params.copy()
        p.update({"perms": perms})
        return super().auth_userreq(temp_cred, extra_params = p)

class TrelloOAuth1(OAuth1Server):
    def auth_userreq(self, temp_cred, *,
            oauth_callback = None,
            scope="read,write,account",
            expiration="never", name=None, extra_params = {}):
        #NOTE: Trello just had to invent the scope parameter
        p = extra_params.copy()
        p.update({"scope": scope, "expiration": expiration})
        if name:
            p.update({"name": name})
        return super().auth_userreq(temp_cred, extra_params = p)

class VimeoOAuth1(OAuth1Server):
    def auth_userreq(self, temp_cred, *, oauth_callback = None,
            permission = "delete", 
            extra_params = {}):
        #permission: one of read, write, delete
        p = extra_params.copy()
        p.update({"permission": permission})
        return super().auth_userreq(temp_cred, oauth_callback = oauth_callback,
                extra_params = p)
