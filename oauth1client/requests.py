import requests.auth
from oauth1client import Request

class OAuth1Auth(requests.auth.AuthBase):
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
        if replace_data: 
            x.data = y.data
        x.headers = y.headers
        x.cookies = y.cookies
        return x
