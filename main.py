#!/usr/bin/env python

from google.appengine.ext import webapp
from google.appengine.ext.webapp import util
from google.appengine.api import memcache
from google.appengine.ext import db
from google.appengine.api.urlfetch import DownloadError 
from django.utils import simplejson

import oauth2
import uuid
import logging
import pprint
import re
import sys
import StringIO
import os
import cgi
from math import (radians, sin, cos, atan2, degrees)
from datetime import (datetime, date, timedelta)
import urllib

CLIENT_ID = 'A4JHSA3P1CL1YTMOFSERA3AESLHBCZBT4BAJQOL1NLFZYADH'
CLIENT_SECRET = 'WI1EHJFHV5L3NJGEN054W0UTA43MXC3DYNXJSNKYKBJTFWAM'

TOKEN_COOKIE = 'plainsq_token'
TOKEN_PREFIX = 'token_plainsq_'

AUTH_URL = 'https://foursquare.com/oauth2/authenticate'
ACCESS_URL = 'https://foursquare.com/oauth2/access_token'
API_URL = 'https://api.foursquare.com/v2'

USER_AGENT = 'plainsq:0.0.1 20110129'

# In development environment, use local callback.
CALLBACK_URL = 'https://plainsq.appspot.com/oauth'
if os.environ.get('SERVER_SOFTWARE','').startswith('Devel'):
    CALLBACK_URL = 'http://localhost:8081/oauth'

def escape(s):
    return cgi.escape(s, quote = True)

class AccessToken(db.Model):
    """
    Store access tokens indexed by login uuid.
    """
    uuid = db.StringProperty(required=True)
    token = db.StringProperty(required=True)
    created = db.DateTimeProperty(auto_now_add=True)

class CoordsTable(db.Model):
    """
    A table that stores coords associated with each login.
    """
    uuid = db.StringProperty(required=True)
    coords = db.StringProperty(required=True)
    created = db.DateTimeProperty(auto_now_add=True)

def pprint_to_str(obj):
    """
    Pretty print to a string buffer then return the string.
    """
    sb = StringIO.StringIO()
    pp = pprint.pprint(obj, sb, 4)
    return sb.getvalue()

def debug_json(self, jsn):
    """
    Pretty-print a JSON response.
    """
    self.response.out.write('<pre>%s</pre>' % escape(pprint_to_str(jsn)))

def no_cache(self):
    """
    Turn off web caching so that the browser will refetch the page.
    Also set the user-agent header.
    """
    self.response.headers.add_header('Cache-Control', 'no-cache') 
    self.response.headers.add_header('User-Agent', USER_AGENT) 

def newclient():
    """
    Create a new oauth2 client.
    """
    return oauth2.Client(
	    client_id = CLIENT_ID,
	    client_secret = CLIENT_SECRET,
	    callback_url = CALLBACK_URL,
	    auth_url = AUTH_URL,
	    access_url = ACCESS_URL,
	    api_url = API_URL)

def getclient(self):
    """
    Check if login cookie is available. If it is, use the access token from
    the database. Otherwise, do the OAuth handshake.
    """
    uuid = self.request.cookies.get(TOKEN_COOKIE)
    access_token = None

    if uuid is not None:
	# Retrieve the access token using the login cookie.
	result = AccessToken.gql("WHERE uuid = :1 LIMIT 1",
		TOKEN_PREFIX + uuid).get()
	# If the query fails for whatever reason, the user will just
	# have to log in again. Not such a big deal.
	if result is not None:
	    access_token = result.token

    client = newclient()

    if access_token is not None:
	# We have an access token. Use it.
	client.setAccessToken(access_token)
	return client

    self.response.out.write('Not logged in.')
    self.redirect('/login')

def htmlbegin(self, title):
    self.response.out.write(
"""<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<title>PlainSq - %s</title>
<style type="text/css">
.error { color: red; background-color: white; }
</style>
</head>

<body>
<p><a href="/"><b>PlainSq</b></a> - %s
""" % (title, title))

def htmlend(self, noabout=False, nologout=False):
    self.response.out.write("""
<hr>
<a href="/">Home</a>%s%s
</body>
</html>
""" % (
    '' if noabout else ' | <a href="/about">About</a>',
    '' if nologout else ' | <a href="/logout">Log out</a>'))

class LoginHandler(webapp.RequestHandler):
    """
    Page that we show if the user is not logged in.
    """
    def get(self):
	# This page should be cached. So omit the no_cache() call.
	htmlbegin(self, "Log in")

	self.response.out.write("""
<p>In order to use PlainSq features, you need to log in with Foursquare.
<p><a href="/login2">Log in with Foursquare</a>
""")
	htmlend(self, nologout=True)

class LoginHandler2(webapp.RequestHandler):
    """
    Second part of login handler. This does the actual login and redirection to
    Foursquare.
    """
    def get(self):
	self.response.out.write('Logging in to Foursquare...')
	client = newclient()
	self.redirect(client.requestAuth())

class MainHandler(webapp.RequestHandler):
    def get(self):
	no_cache(self)

	client = getclient(self)
	if client is None:
	    return

	htmlbegin(self, "Main")

        self.response.out.write('<p>Hello world!')

	htmlend(self)

class OAuthHandler(webapp.RequestHandler):
    """
    This handler is the callback for the OAuth handshake. It stores the access
    token and secret in cookies and redirects to the main page.
    """
    def get(self):
	no_cache(self)

	auth_code = self.request.get('code')
	client = newclient()
	client.requestSession(auth_code)

	access_token = client.getAccessToken()

	uuid_str = str(uuid.uuid1())

	# Set the login cookie.
	self.response.headers.add_header(
		'Set-Cookie', 
		'%s=%s; expires=Fri, 31-Dec-2020 23:59:59 GMT' % (
		    TOKEN_COOKIE, uuid_str))

	# Add the access token to the database.
	acc = AccessToken(uuid = TOKEN_PREFIX + uuid_str, token = access_token)
	acc.put()

	self.redirect('/')

class LogoutHandler(webapp.RequestHandler):
    """
    Handler for user logout command.
    """
    def del_cookie(self, cookie):
	""" 
	Delete cookies by setting expiration to a past date.
	"""
	self.response.headers.add_header(
		'Set-Cookie', 
		'%s=; expires=Fri, 31-Dec-1980 23:59:59 GMT' % cookie)

    def get(self):
	# This page should be cached. So omit the no_cache() call.
	self.del_cookie(TOKEN_COOKIE)

	htmlbegin(self, "Logout")
	self.response.out.write('<p>You have been logged out')
	htmlend(self, nologout=True)

def main():
    logging.getLogger().setLevel(logging.DEBUG)
    application = webapp.WSGIApplication([
	('/', MainHandler),
	('/login', LoginHandler),
	('/login2', LoginHandler2),
	('/oauth', OAuthHandler),
	('/logout', LogoutHandler),
	], debug=True)
    util.run_wsgi_app(application)


if __name__ == '__main__':
    main()
