import urllib
import urllib2
from django.utils import simplejson

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
	return "%s?client_id=%s&response_type=code&redirect_url=%s" % (
		self.auth_url, self.client_id, self.callback_url )

    def requestSession(self, auth_code):
	url = "%s?client_id=%s&client_secret=%s&grant_type=authorization_code&redirect_url=%s&code=%s" % (
		self.access_url, self.client_id, self.client_secret,
		self.callback_url, auth_code )

	req = urllib2.Request(url)
	resp = urllib2.urlopen(req)

	jsn = simplejson.loads(resp.read())

	self.access_token = jsn['access_token']
	return jsn

    def makeRequest(self, method, path, params):
	params['oauth_token'] = self.access_token
	data = urllib.urlencode(params)
	if method == self.POST:
	    req = urllib2.Request(url, data)
	else:
	    req = urllib2.Request("%s/%s?%s" % (self.api_url, path, data))
	resp = urllib2.urlopen(req)
	return resp.read()

    def post(self, path, params):
	return self.makeRequest(self.POST, path, params)

    def get(self, path, params):
	return self.makeRequest(self.GET, path, params)

# vim:set tw=0:
