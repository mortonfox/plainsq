import urllib
import urllib2
from django.utils import simplejson
from poster.encode import multipart_encode, MultipartParam
from poster.streaminghttp import register_openers
import sys

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

    def encodeParams(self, params):
	"""
	UTF-8 encode all parameters.
	"""
	_params = {}
	for k, v in params.iteritems():
	    if type(v) == unicode:
		v2 = v.encode('utf-8')
	    else:
		v2 = str(v)
	    _params[str(k)] = v2
	return _params

    def uploadFile(self, path, params):
	"""
	Do a file upload with the access token.
	The photo must have a key named "photo".
	"""
	if params is None:
	    params = {}
	params['oauth_token'] = self.getAccessToken()

	mparams = []
	for k, v in params.iteritems():
	    if k == 'photo':
		mparam = MultipartParam(name=k, value=v, filename='photo.jpg', filetype='image/jpeg')
	    else:
		mparam = MultipartParam(name=k, value=v)
	    mparams.append(mparam)

	datagen, headers = multipart_encode(mparams)
	req = urllib2.Request('%s/%s' % (self.api_url, path), ''.join(datagen), headers)
	resp = urllib2.urlopen(req)
	return resp.read()

    def makeRequest(self, method, path, params):
	"""
	Perform an API call with the access token.
	"""
	if params is None:
	    params = {}
	params['oauth_token'] = self.getAccessToken()

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
