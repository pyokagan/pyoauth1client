from argparse import ArgumentParser
from oauth1client import Request
import sys
import subprocess
from urllib.parse import unquote

class FriendlyArgumentParser(ArgumentParser):
    """An ArgumentParser that does not call sys.exit
    but raises an exception instead on error"""
    def error(message):
        raise ValueError(message)

class SubprocessWrapper:
    def Popen(self, args, *popenargs, **kwargs):
        return subprocess.Popen(args[0:1] + self.transform_args(args[1:]),
                *popenargs, **kwargs)

    def call(self, args, *popenargs, **kwargs):
        return subprocess.call(args[0:1] + self.transform_args(args[1:]),
                *popenargs, **kwargs)

    def check_call(self, args, *popenargs, **kwargs):
        return subprocess.check_call(args[0:1] + self.transform_args(args[1:]),
                *popenargs, **kwargs)

    def check_output(self, args, *popenargs, **kwargs):
        return subprocess.check_output(args[0:1] + self.transform_args(args[1:]),
                *popenargs, **kwargs)
        

class CurlWrapper(SubprocessWrapper):
    def __init__(self, token):
        self.token = token

    @staticmethod
    def req_to_curl_args(req):
        from urllib.parse import urlencode
        #Reconstruct CURL Request
        args = []
        args.append("-X")
        args.append(req.method)
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

    def transform_args(self, args = None, *, parser_class = FriendlyArgumentParser):
        p = parser_class()
        #TODO: --data-binary????
        p.add_argument("-d", dest = "data", action = "append", default = [])
        p.add_argument("--data-urlencode", dest = "data_urlencode", action = "append",
                default = [])
        p.add_argument("-H", "--header", dest = "headers", action = "append", default = [])
        p.add_argument("-X", "--request", dest = "method", action = "append", default = [])
        args, rest = p.parse_known_args(args)
        if not rest:
            p.error("URL not specified")
        url = rest[-1]
        del rest[-1]
        before_rest = []
        #Check headers for content-type
        headers = dict()
        for x in args.headers:
            key, _, value = x.partition(":")
            key = key.lower().strip()
            value = value.strip()
            if not value and not key.endswith(";") and key in headers:
                del headers[key]
            if key.endswith(";"):
                key = key[:-1]
            headers[key] = value
            before_rest.append("-H")
            before_rest.append(x)
        data = {}
        if "content-type" in headers and headers["content-type"] != "application/x-www-form-urlencoded":
            #No data required since it is not needed in oauth signature.
            #However, we need to add back the arguments later
            for x in args.data:
                before_rest.append("-d")
                before_rest.append(x)
            for x in args.data_urlencode:
                before_rest.append("--data-urlencode")
                before_rest.append(x)
        else:
            #Convert data to a dict
            for x in args.data:
                if x.startswith("@"):
                    key, _, value = open(x[1:]).read().partition("=")
                else:
                    key, _, value = x.partition("=")
                data[key] = unquote(value) #Expected to be urlencoded already
            for x in args.data_urlencode:
                if x.find("=") != -1:
                    key, _, value = x.partition("=")
                    if key:
                        data[key] = value #Will urlencode later
                    else:
                        raise ValueError("--data-urlencode {} not supported".format(x))
        if args.method:
            method = args.method[-1].upper()
        elif (args.data or args.data_urlencode or 
                next(filter(lambda x: x.startswith("-F") or 
                    x in ["--form","--data-binary"], rest), None)):
            method = "POST"
        else:
            method = "GET"
        req = Request(method = method, url = url, data = data, headers = {}, cookies = {})
        if self.token:
            req = self.token.apply_req(req)
        return before_rest + rest + self.req_to_curl_args(req)

    def main(self, args = None):
        x = self.transform_args(args, parser_class = ArgumentParser)
        sys.exit(subprocess.call(["curl"] + x))

