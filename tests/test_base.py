# -*- coding: utf-8 -*-
import flask
import pytest
import hmac
import md5
from base64 import b64encode
from hashlib import sha256
from collections import namedtuple
import datetime

def test_case():
    app = flask.Flask(__name__)
    app.testing = True
#    app.config['TESTING'] = True

    @app.route('/json', methods=['POST'])
    def return_json():
        data = flask.request.get_json()
        return flask.jsonify(data)

    data = dict(name="Jesse")
    with app.test_client() as client:
        response = client.post('/json', data=flask.json.dumps(data), content_type='application/json')

        assert response.status_code == 200

        assert response.headers['Content-Type'] == 'application/json'
        assert response.mimetype, 'application/json'

        response_data = flask.json.loads(response.data)
        assert response_data['name'] == "Jesse"


# HttpHeader = namedtuple('HttpHeader', 'name, value')

def sort_dict(adict):
    keys = adict.keys()
    keys.sort()
    return map(adict.get, keys)

def canonicalize_headers(headers):
    return sorted(map(lambda (k,v):(canonicalize_header_name(k), v), headers.items()))

def canonicalize_header_name(name):
    return '-'.join(x.capitalize() or '_' for x in name.split('-'))

def sign(data, secret_key = 'AKIAI44QH8DHBEXAMPLE'):
    return b64encode(hmac.new(secret_key, data, sha256).digest())

def test_canonicalize_header_name():
    assert canonicalize_header_name('content-type') == 'Content-Type'
    assert canonicalize_header_name('x-bla-header') == 'X-Bla-Header'
    assert canonicalize_header_name('x-BLA-header') == 'X-Bla-Header'

def test_canonicalize_headers():
    headers = { 'content-type': 1 }
    canheaders = canonicalize_headers(headers)
    header = canheaders.pop()
    assert header[0] == 'Content-Type'

def test_hmac():
    def make_request(method, url, body='', headers=dict()):
        content_type = headers.get('Content-Type', 'text/html')
        expires = headers.get('Date', datetime.datetime.now().isoformat())

        content_md5 = md5.new(body).digest()
        headers['Content-Md5'] = content_md5

        r = []
        r.append(method)
        r.append(content_md5)
        r.append(content_type)
        r.append(expires)
#        r.append(CanonicalizedAmzHeaders)
        r.append(url)
        signature = sign("\n".join(r))

        headers['Authorization'] = "%s:%s" % ('KEY', signature)

        return canonicalize_headers(headers)

    headers = make_request('GET', '/hello/world', '<h1>Hello World</h1>', {'Content-Type':'text/html','Date':'Thu, 17 Nov 2005 18:49:58 GMT'})

    # http://stackoverflow.com/questions/9542738/python-find-in-list
    to_test = next(h for h in headers if h[0] == 'Authorization')
    assert to_test[0] == 'Authorization'
    assert to_test[1] == 'KEY:tqeR0wILSlzQp8beXeA5otz+086+Uuk3sUdVY9GuadI='
