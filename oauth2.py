"""
oauth2.py

This module implements OAuth 2.0, as used by the Foursquare v2 API.

First, create a client:

    c = oauth2.Client(clientID, clientSecret, 
	callbackURL, authURL, accessURL, apiURL)

Then call requestAuth() to get an OAuth login URL:

    url = c.requestAuth()

Send the user to that url. Once the user has logged in, Foursquare will
load the callbackURL.

The callback will have a 'code' parameter. Pass that to requestSession()
to get an access token:

    c.requestSession(code)
    token = c.getAccessToken()

Once you have an access token, you can make API calls:

    c.setAccessToken(token)
    result = c.post(path, params)
    result = c.get(path, params)
"""


import urllib
import urllib2
from django.utils import simplejson
import sys
import uuid

class Client:
    POST = "POST"
    GET = "GET"

    def __init__(self, client_id, client_secret, callback_url,
	    auth_url, access_url, api_url):
	self.client_id = client_id
	self.client_secret = client_secret
	self.callback_url = callback_url
	self.auth_url = auth_url
	self.access_url = access_url
	self.api_url = api_url

    def requestAuth(self):
	"""
	Return authentication URL to which users must be redirected to
	do an OAuth login.
	"""
	return "%s?%s" % (self.auth_url, urllib.urlencode({
	    'client_id' : self.client_id,
	    'response_type' : 'code',
	    'redirect_uri' : self.callback_url }))

    def setAccessToken(self, access_token):
	self.access_token = access_token

    def getAccessToken(self):
	return self.access_token

    def requestSession(self, auth_code):
	"""
	Swap an authentication code for an access token.
	"""
	url = "%s?%s" % (self.access_url, urllib.urlencode({
	    'client_id' : self.client_id,
	    'client_secret' : self.client_secret,
	    'redirect_uri' : self.callback_url,
	    'grant_type' : 'authorization_code',
	    'code' : auth_code}))
	
	req = urllib2.Request(url)
	resp = urllib2.urlopen(req)

	jsn = simplejson.loads(resp.read())

	self.setAccessToken(jsn['access_token'])
	return jsn

    def to_str(self, s):
	return s.encode('utf-8') if type(s) == unicode else str(s)

    def multipart_encode(self, params):
	"""
	Generate multipart/form-data headers and data for uploading photos.
	The photo must have the key 'photo' to be recognized as such.
	"""
        boundary = uuid.uuid4().hex
	headers = { 'Content-Type' : "multipart/form-data; boundary=%s" % boundary }
	data = ''
	for k, v in params.iteritems():
	    data += '--%s\r\n' % boundary
	    if k == 'photo':
		data += 'Content-Disposition: form-data; name="%s"; filename="%s.jpg"\r\n' % (k, k)
		data += 'Content-Type: image/jpeg\r\n'
	    else:
		data += 'Content-Disposition: form-data; name="%s"\r\n' % k
	    data += '\r\n%s\r\n' % self.to_str(v)
        data += '--%s--\r\n\r\n' % boundary

	return data, headers

    def encodeParams(self, params):
	"""
	UTF-8 encode all parameters.
	"""
	_params = {}
	for k, v in params.iteritems():
	    _params[str(k)] = self.to_str(v)
	return _params

    def makeRequest(self, method, path, params):
	"""
	Perform an API call with the access token.
	If params has a 'photo' key, do a multipart form-data upload.
	"""
	if params is None:
	    params = {}
	params['oauth_token'] = self.getAccessToken()

	if 'photo' in params:
	    data, headers = self.multipart_encode(params)
	    req = urllib2.Request('%s/%s' % (self.api_url, path), data, headers)
	else:
	    params = self.encodeParams(params)
	    data = urllib.urlencode(params)

	    if method == self.POST:
		req = urllib2.Request('%s/%s' % (self.api_url, path), data)
	    else:
		req = urllib2.Request("%s/%s?%s" % (self.api_url, path, data))

	resp = urllib2.urlopen(req)
	return resp.read()

    def post(self, path, params):
	return self.makeRequest(self.POST, path, params)

    def get(self, path, params):
	return self.makeRequest(self.GET, path, params)


# vim:set tw=0:
