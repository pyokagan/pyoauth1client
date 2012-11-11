from argparse import ArgumentParser
from oauth1client import Request
import sys
import subprocess

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
        if self.token:
            req = self.token.apply_req(req)
        return rest + self.req_to_curl_args(req)

    def main(self, args = None):
        x = self.transform_args(args, parser_class = ArgumentParser)
        sys.exit(subprocess.call(["curl"] + x))

