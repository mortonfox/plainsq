#!/usr/bin/env python


from google.appengine.ext import webapp
from google.appengine.ext.webapp import util
from google.appengine.api import memcache
from google.appengine.ext import db
from google.appengine.api.urlfetch import DownloadError 
from django.utils import simplejson

import oauth2
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
    CALLBACK_URL = 'https://localhost:8081/oauth'

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

def getclient():
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


class MainHandler(webapp.RequestHandler):
    def get(self):
        self.response.out.write('Hello world!')


def main():
    application = webapp.WSGIApplication([('/', MainHandler)],
                                         debug=True)
    util.run_wsgi_app(application)


if __name__ == '__main__':
    main()
