#!/usr/bin/env python

"""
<p>PlainSquare is a lightweight Foursquare client for mobile web browsers. It is intended as a full-featured substitute for Foursquare Mobile. PlainSquare supports both geolocation (using device GPS or cellular / wi-fi positioning) and manual coordinate entry for phones without GPS.

<p>PlainSquare speeds up check-ins by making this operation single-click if you do not need to shout or change your broadcast options. PlainSquare is also designed to send you through as few screens as possible to do most common Foursquare tasks.

<p>PlainSquare uses OAuth version 2 to log in to Foursquare to avoid having to store user passwords. PlainSquare supports version 2 of the Foursquare API. It is written in Python and designed for hosting on Google App Engine. 

<pre>
Version: 0.0.11
Author: Po Shan Cheah (<a href="mailto:morton@mortonfox.com">morton@mortonfox.com</a>)
Source code: <a href="http://code.google.com/p/plainsq/">http://code.google.com/p/plainsq/</a>
Created: January 28, 2011
Last updated: May 3, 2013
</pre>
"""

USER_AGENT = 'plainsq:0.0.11 20130503'

import itertools
import json
import uuid
import logging
import pprint
import re
import sys
import StringIO
import os
import cgi
import urllib
import urllib2
import webapp2
import yaml

from google.appengine.api.urlfetch import DownloadError 
from google.appengine.api import images
from google.appengine.ext import db
from google.appengine.api import memcache
from datetime import (datetime, date, timedelta)
from webapp2_extras import sessions

import oauth2
import jinjawrap

TOKEN_COOKIE = 'plainsq_token'
TOKEN_PREFIX = 'token_plainsq_'

COORD_PREFIX = 'coord_plainsq_'

AUTH_URL = 'https://foursquare.com/oauth2/authenticate'
ACCESS_URL = 'https://foursquare.com/oauth2/access_token'
API_URL = 'https://api.foursquare.com/v2'

DEFAULT_LAT = 39.7
DEFAULT_LON = -75.6

# Send location parameters if distance is below MAX_MILES_LOC.
MAX_MILES_LOC = 1.1


def escape(s):
    return cgi.escape(s, quote = True)

class AccessToken(db.Model):
    """
    Access token entity.
    """
    token = db.StringProperty(required=True)

class User(db.Model):
    """
    User login entity.
    """
    access_token = db.ReferenceProperty(AccessToken)
    created = db.DateTimeProperty(auto_now_add=True)

def pprint_to_str(obj):
    """
    Pretty print to a string buffer then return the string.
    """
    sb = StringIO.StringIO()
    pp = pprint.pprint(obj, sb, 4)
    return sb.getvalue()

def debug_json_str(self, jsn):
    return pprint_to_str(jsn) if get_debug(self) else ''

def set_debug(self, debug):
    """
    Set the debug option in session.
    """
    self.session['debug'] = bool(debug)

def get_debug(self):
    """
    Get the debug option from session. If it is not set, then assume debugging
    is turned off.
    """
    return bool(self.session.get('debug'))

def get_map_provider(self):
    """
    Get map provider option from session. Currently, we support Google Maps and Bing Maps.
    """
    vendor = str(self.session.get('map_provider')).lower()
    if vendor == 'bing':
	return 'bing'
    else:
	return 'google'

def set_map_provider(self, vendor):
    """
    Set map provider option in session. Currently, we support Google Maps and Bing Maps.
    """
    self.session['map_provider'] = str(vendor).lower()    

def no_cache(self):
    """
    Turn off web caching so that the browser will refetch the page.
    Also set the user-agent header.
    """
    self.response.cache_expires(0)
    self.response.headers['User-Agent'] = USER_AGENT


def set_coords(self, lat, lon):
    """
    Store coordinates in session.
    """
    self.session['coords_lat'] = float(lat)
    self.session['coords_lon'] = float(lon)


def coords(self):
    """
    Get user's coordinates from coords table. If not found in table,
    use default coordinates.
    """
    lat = self.session.get('coords_lat')
    lon = self.session.get('coords_lon')

    if lat is None or lon is None:
	lat = DEFAULT_LAT
	lon = DEFAULT_LON
	set_coords(self, lat, lon)

    return (float(lat), float(lon))


def get_api_keys():
    yaml_file = os.path.dirname(__file__) + '/apikeys.yml' 
    with open(yaml_file, 'r') as fh:
	env_name = 'development' if os.environ.get('SERVER_SOFTWARE','').startswith('Devel') else 'production'
	api_keys = yaml.load(fh)

	# Do some error checking.
	if env_name not in api_keys:
	    raise Exception('No API keys for %s environment in %s' % (env_name, yaml_file))
	for field in ('client_id', 'client_secret', 'callback_url'):
	    if field not in api_keys[env_name]:
		raise Exception('No %s for %s environment in %s' % (field, env_name, yaml_file))

	return api_keys[env_name]

def newclient():
    """
    Create a new oauth2 client.
    """
    return oauth2.Client(
	    client_id = newclient.api_keys['client_id'],
	    client_secret = newclient.api_keys['client_secret'],
	    callback_url = newclient.api_keys['callback_url'],
	    auth_url = AUTH_URL,
	    access_url = ACCESS_URL,
	    api_url = API_URL)
newclient.api_keys = get_api_keys()

def getclient(self):
    """
    Check if login cookie is available. If it is, use the access token from
    the database. Otherwise, do the OAuth handshake.
    """
    uuid = self.request.cookies.get(TOKEN_COOKIE)
    access_token = None

    if uuid is not None:
	uuid_key = TOKEN_PREFIX + uuid

	# Try to get access token from memcache first.
	access_token = memcache.get(uuid_key)
	if access_token is None:

	    access = User.get_or_insert(uuid).access_token
	    if access is not None:
		access_token = access.token
		memcache.set(uuid_key, access_token)

    client = newclient()

    if access_token is not None:
	# We have an access token. Use it.
	client.setAccessToken(access_token)
	return client

    self.response.out.write('Not logged in.')
    self.redirect('/login')


def call4sq(self, client, method, path, params = {}):
    """
    Call the Foursquare API. Handle errors.
    Returns None if there was an error. Otherwise, returns the parsed JSON.
    """
    try:
	# Supply a default version.
	if 'v' not in params:
	    params['v'] = '20130214'

	if method == 'post':
	    result = client.post(path, params)
	else:
	    result = client.get(path, params)

	jsn = json.loads(result)

	meta = jsn.get('meta')
	if meta is not None:
	    errorType = meta.get('errorType', '')
	    errorDetail = meta.get('errorDetail', '')

	    if errorType == 'deprecated':
		self.response.out.write('<p><span class="error">Deprecated: %s</span>' % errorDetail)
		return jsn

	    if errorType != '' or errorDetail != '':
		errorpage(self, '%s : %s' % (errorType, errorDetail))
		return

	return jsn

    except DownloadError:
	errorpage(self,
		"Can't connect to Foursquare. #SadMayor Refresh to retry.")
	return

    except urllib2.HTTPError, e:
	jsn = json.loads(e.read())
	meta = jsn.get('meta', {})
	errormsg = meta.get('errorDetail', 'Unknown error')
	errorpage(self, 
		'Error %d from Foursquare API call to %s:<br>%s' % (e.code, e.geturl(), errormsg))
	return

    except Exception:
	cla, exc, _ = sys.exc_info()
	excName = cla.__name__
	try:
	    excArgs = exc.__dict__["args"]
	except KeyError:
	    excArgs = "<no args>"
	errorpage(self, '%s: %s' % (excName, excArgs))
	return 

def renderpage(self, template_file, params={}):
    """
    Render a page using Jinja2.
    """
    self.response.out.write(jinjawrap.renderpage(template_file, params))

def errorpage(self, msg, errcode=503):
    """
    Used for DownloadError exceptions and other errors. Generates an error
    page.
    """
    self.error(errcode)
    renderpage(self, 'error.htm', { 'msg' : msg })

def userheader(self, client):
    """ 
    Display the logged-in user's icon, name, and position.
    """
    jsn = call4sq(self, client, 'get', '/users/self')
    if jsn is None:
	return

    response = jsn.get('response')
    if response is None:
	logging.error('Missing response from /users/self:')
	logging.error(jsn)
	return jsn

    user = response.get('user')
    if user is None:
	logging.error('Missing user from /users/self:')
	logging.error(jsn)
	return jsn

    return { 'user' : user, 'jsn' : jsn }

# Add session store to RequestHandler.
# Taken from the webapp2 extra session example.
class MyHandler(webapp2.RequestHandler):              
    def dispatch(self):                                 # override dispatch
        # Get a session store for this request.
        self.session_store = sessions.get_store(request = self.request)

        try:
            # Dispatch the request.
            webapp2.RequestHandler.dispatch(self)       # dispatch the main handler
        finally:
            # Save all sessions.
            self.session_store.save_sessions(self.response)

    @webapp2.cached_property
    def session(self):
        # Returns a session using the default cookie key.
        return self.session_store.get_session()


class LoginHandler(MyHandler):
    """
    Page that we show if the user is not logged in.
    """
    def get(self):
	# This page should be cached. So omit the no_cache() call.
	renderpage(self, 'login.htm')

class LoginHandler2(MyHandler):
    """
    Second part of login handler. This does the actual login and redirection to
    Foursquare.
    """
    def get(self):
	self.response.out.write('Logging in to Foursquare...')
	client = newclient()
	self.redirect(client.requestAuth())

class MainHandler(MyHandler):
    def get(self):
	no_cache(self)
	(lat, lon) = coords(self)

	client = getclient(self)
	if client is None:
	    return

	usrhdr = userheader(self, client)
	jsn = None
	if usrhdr is not None:
	    jsn = usrhdr.get('jsn', {})

	renderpage(self, 'main.htm',
		{
		    'userheader' : usrhdr,
		    'lat' : lat,
		    'lon' : lon,
		    'debugmode' : get_debug(self),
		    'debug_json' : debug_json_str(self, jsn),
		    'map_provider' : get_map_provider(self),
		})


class SetlocHelpHandler(MyHandler):
    """
    Handler for 'Set location' help info.
    """
    def get(self):
	# This page should be cached. So omit the no_cache() call.
	renderpage(self, 'setlochelp.htm')

class OAuthHandler(MyHandler):
    """
    This handler is the callback for the OAuth handshake. It stores the access
    token and secret in cookies and redirects to the main page.
    """
    @db.transactional
    def add_access_token(self, uuid_str, access_token):
	# Add the access token to the database.
	# user = User.get_or_insert(uuid_str)
	user = User.get_by_key_name(uuid_str)
	if user is None:
	    user = User(key_name = uuid_str)
	    user.put()

	acc = AccessToken(token = access_token, parent = user)
	acc.put()

	user.access_token = acc
	user.put()

    def get(self):
	no_cache(self)

	auth_code = self.request.get('code')
	client = newclient()
	client.requestSession(auth_code)

	access_token = client.getAccessToken()

	uuid_str = str(uuid.uuid1())

	# Set the login cookie.
	self.response.set_cookie(TOKEN_COOKIE, uuid_str, max_age = 60*60*24*365)

	self.add_access_token(uuid_str, access_token)

	self.redirect('/')

class LogoutHandler(MyHandler):
    """
    Handler for user logout command.
    """
    def del_cookie(self, cookie):
	""" 
	Delete cookies by setting expiration to a past date.
	"""
	self.response.delete_cookie(cookie)

    def get(self):
	# This page should be cached. So omit the no_cache() call.
	self.del_cookie(TOKEN_COOKIE)
	renderpage(self, 'logout.htm')


class UserHandler(MyHandler):
    """
    This handler displays info on one user.
    """
    def get(self):
	no_cache(self)

	(lat, lon) = coords(self)
	client = getclient(self)
	if client is None:
	    return

	userid = self.request.get('userid')
	if userid == '':
	    self.redirect('/')
	    return

	jsn = call4sq(self, client, 'get', path='/users/%s' % userid)
	if jsn is None:
	    return

	resp = jsn.get('response')
	if resp is None:
	    logging.error('Missing response from /users:')
	    logging.error(jsn)
	    return jsn

	user = resp.get('user')
	if user is None:
	    logging.error('Missing user from /users:')
	    logging.error(jsn)
	    return jsn

	renderpage(self, 'user.htm',
		{
		    'user' : user,
		    'lat' : lat,
		    'lon' : lon,
		    'debug_json' : debug_json_str(self, jsn),
		})


class VInfoHandler(MyHandler):
    """
    This handler displays info on one venue.
    """
    def get(self):
	no_cache(self)

	(lat, lon) = coords(self)
	client = getclient(self)
	if client is None:
	    return

	vid = self.request.get('vid')
	if vid == '':
	    self.redirect('/')
	    return

	jsn = call4sq(self, client, 'get', path='/venues/%s' % vid)
	if jsn is None:
	    return

	resp = jsn.get('response')
	if resp is None:
	    logging.error('Missing response from /venues:')
	    logging.error(jsn)
	    return jsn

	venue = resp.get('venue')
	if venue is None:
	    logging.error('Missing venue from /venues:')
	    logging.error(jsn)
	    return jsn

	renderpage(self, 'vinfo.htm',
		{
		    'venue' : venue,
		    'lat' : lat,
		    'lon' : lon,
		    'debug_json' : debug_json_str(self, jsn),
		    'map_provider' : get_map_provider(self),
		})



class HistoryHandler(MyHandler):
    """
    Handler for history command.
    """
    def get(self):
	no_cache(self)

	(lat, lon) = coords(self)
	client = getclient(self)
	if client is None:
	    return

	userid = self.request.get('userid')
	if userid == '':
	    userid = 'self'

	jsn = call4sq(self, client, 'get', path='/users/%s/checkins' % userid,
		params = { 'limit' : '50' })
	if jsn is None:
	    return

	resp = jsn.get('response')
	if resp is None:
	    logging.error('Missing response from /users/checkins:')
	    logging.error(jsn)
	    return jsn

	checkins = resp.get('checkins')
	if checkins is None:
	    logging.error('Missing checkins from /users/checkins:')
	    logging.error(jsn)
	    return jsn

	renderpage(self, 'history.htm',
		{
		    'checkins' : checkins,
		    'lat' : lat,
		    'lon' : lon,
		    'debug_json' : debug_json_str(self, jsn),
		})

class DebugHandler(MyHandler):
    """
    Handler for Debug command. Toggle debug mode.
    """
    def get(self):
	set_debug(self, not get_debug(self))
	self.redirect('/')

class MapProvHandler(MyHandler):
    """
    Handler for changing map provider.
    """
    def get(self):
	vendor = get_map_provider(self)
	new_vendor = 'google' if vendor == 'bing' else 'bing'
	set_map_provider(self, new_vendor)
	self.redirect('/')

class BadgesHandler(MyHandler):
    """
    Handler for badges command.
    """
    def get(self):
	no_cache(self)

	(lat, lon) = coords(self)
	client = getclient(self)
	if client is None:
	    return

	userid = self.request.get('userid')
	if userid == '':
	    userid = 'self'

	jsn = call4sq(self, client, 'get', path='/users/%s/badges' % userid)
	if jsn is None:
	    return

	resp = jsn.get('response')
	if resp is None:
	    logging.error('Missing response from /users/badges:')
	    logging.error(jsn)
	    return jsn

	badges = resp.get('badges')
	if badges is None:
	    logging.error('Missing badges from /users/badges:')
	    logging.error(jsn)
	    return jsn

	blist = []
	if len(badges) > 0:
	    # Sort badges by reverse unlock order.
	    # Retain only unlocked badges.
	    blist = [badges[k] for k in sorted(badges.keys(), reverse=True) if badges[k].get('unlocks')]

	renderpage(self, 'badges.htm',
		{
		    'badges' : blist,
		    'debug_json' : debug_json_str(self, jsn),
		})


class NotifHandler(MyHandler):
    """
    Handler for notifications command.
    """
    def get(self):
	no_cache(self)

	client = getclient(self)
	if client is None:
	    return

	jsn = call4sq(self, client, 'get', path='/updates/notifications',
		params = { 'limit' : '50' })
	if jsn is None:
	    return

	resp = jsn.get('response')
	if resp is None:
	    logging.error('Missing response from /updates/notifications:')
	    logging.error(jsn)
	    return jsn

	notifs = resp.get('notifications')
	if notifs is None:
	    logging.error('Missing notifications from /updates/notifications:')
	    logging.error(jsn)
	    return jsn

	jsn2 = None

	hwmark = None
	items = notifs.get('items', [])

	if notifs.get('count'):
	    hwmark = 0
	    if items:
		hwmark = items[0].get('createdAt', 0)	    

	    # Mark notifications as read.
	    jsn2 = call4sq(self, client, 'post', 
		    path='/updates/marknotificationsread',
		    params = { 'highWatermark' : hwmark })

	renderpage(self, 'notifs.htm',
		{
		    'notifs' : items,
		    'hwmark' : hwmark,
		    'debugmode' : get_debug(self),
		    'debug_json' : debug_json_str(self, jsn) + debug_json_str(self, jsn2),
		})


class LeaderHandler(MyHandler):
    """
    Handler for leaderboard command.
    """
    def get(self):
	no_cache(self)

	client = getclient(self)
	if client is None:
	    return

	jsn = call4sq(self, client, 'get', path='/users/leaderboard',
		params = { 'neighbors' : '20' })
	if jsn is None:
	    return

	resp = jsn.get('response')
	if resp is None:
	    logging.error('Missing response from /users/leaderboard:')
	    logging.error(jsn)
	    return jsn

	leaderboard = resp.get('leaderboard')
	if leaderboard is None:
	    logging.error('Missing leaderboard from /users/leaderboard:')
	    logging.error(jsn)
	    return jsn

	renderpage(self, 'leaderboard.htm',
		{
		    'leaders' : leaderboard.get('items', []),
		    'debug_json' : debug_json_str(self, jsn),
		})


class MayorHandler(MyHandler):
    """
    Handler for mayor command.
    """
    def get(self):
	no_cache(self)

	(lat, lon) = coords(self)
	client = getclient(self)
	if client is None:
	    return

	userid = self.request.get('userid')
	if userid == '':
	    userid = 'self'

	jsn = call4sq(self, client, 'get', path='/users/%s/mayorships' % userid)
	if jsn is None:
	    return

	resp = jsn.get('response')
	if resp is None:
	    logging.error('Missing response from /users/mayorships:')
	    logging.error(jsn)
	    return jsn

	mayorships = resp.get('mayorships')
	if mayorships is None:
	    logging.error('Missing mayorships from /users/mayorships:')
	    logging.error(jsn)
	    return jsn

	renderpage(self, 'mayorships.htm',
		{
		    'mayoritems' : mayorships.get('items', []),
		    'lat' : lat,
		    'lon' : lon,
		    'debug_json' : debug_json_str(self, jsn),
		})


class FriendsHandler(MyHandler):
    """
    Handler for Find Friends command.
    """
    def get(self):
	no_cache(self)

	(lat, lon) = coords(self)
	client = getclient(self)
	if client is None:
	    return

	jsn = call4sq(self, client, 'get', path='/checkins/recent',
		params = { 'll':'%s,%s' % (lat,lon), 'limit':100 })
	if jsn is None:
	    return

	response = jsn.get('response')
	if response is None:
	    logging.error('Missing response from /checkins/recent:')
	    logging.error(jsn)
	    return jsn

	recent = response.get('recent')
	if recent is None:
	    logging.error('Missing recent from /checkins/recent:')
	    logging.error(jsn)
	    return jsn

	# Sort checkins by distance. If distance is missing,
	# use a very large value.
	recent.sort(key = lambda v: v.get('distance', '1000000'))

	renderpage(self, 'friends.htm',
		{
		    'friends' : recent,
		    'lat' : lat,
		    'lon' : lon,
		    'debug_json' : debug_json_str(self, jsn),
		})


def venues_list(jsn):
    """
    Get a list of venues for the venue search page.
    """

    groups = jsn.get('groups')
    if groups is None:
	venues = jsn.get('venues', [])
    else:
	# Venues may be split across groups so collect them all in one list.
	venues = itertools.chain.from_iterable([ group.get('items', []) for group in groups ])

    # Remove duplicated venue IDs.
    venues = { v.get('id') : v for v in venues }.values()

    # Sort venues ascending by distance. If distance field is missing, use a
    # very large value.
    return sorted(venues, key = lambda v: v['location'].get('distance', '1000000'))


class VenuesHandler(MyHandler):
    """
    Handler for venue search.
    """
    def post(self):
	self.get()

    def get(self):
	no_cache(self)

	(lat, lon) = coords(self)
	client = getclient(self)
	if client is None:
	    return

	# query is an optional keyword search parameter. If it is not present,
	# then just do a nearest venues search.
	query = self.request.get('query')

	parms = { "ll" : '%s,%s' % (lat, lon), "limit" : 50 }
	if query != '':
	    parms['query'] = query

	jsn = call4sq(self, client, 'get', path='/venues/search',
		params = parms)
	if jsn is None:
	    return

	response = jsn.get('response')
	if response is None:
	    logging.error('Missing response from /venues/search:')
	    logging.error(jsn)
	    return jsn

	renderpage(self, 'venues.htm',
		{
		    'venues' : venues_list(response),
		    'lat' : lat,
		    'lon' : lon,
		    'debug_json' : debug_json_str(self, jsn),
		})


def deg_min(st):
    deg = st[:2]
    min = st[2:]
    if min == '':
	min = '0'
    if len(min) > 2:
	min = min[:2] + '.' + min[2:]
    return (deg, min)

def parse_coord_digits(coordstr):
    """
    Parse user-entered coordinates.
    This function handles the case where coordinates are entered as digits
    only. The string is split into two halves. The first half fills in dd
    mm.mmm in the latitude and the second half fills in dd mm.mmm in the
    longitude. These coordinates are assumed to be in the N/W quadrant.
    """
    mid = int((len(coordstr) + 1) / 2)
    latstr = coordstr[:mid]
    lonstr = coordstr[mid:]

    (d, m) = deg_min(latstr)
    lat = "%.6f" % (int(d) + float(m) / 60)

    (d, m) = deg_min(lonstr)
    lon = "%.6f" % -(int(d) + float(m) / 60)

    return (lat, lon)


def parse_coord_nsew(matchObj):
    """
    Parse user-entered coordinates.
    This function is the same as parse_coord_digits but also allows the user to
    enter N or S and E or W. For example, the user can enter something like
    NddddddEdddddd for coordinates in the N/E quadrant.
    """
    sign = 1
    if matchObj.group(1).upper() == 'S':
	sign = -1
    (d, m) = deg_min(matchObj.group(2))
    lat = "%.6f" % (sign * (int(d) + float(m) / 60))

    sign = 1
    if matchObj.group(3).upper() == 'W':
	sign = -1
    (d, m) = deg_min(matchObj.group(4))
    lon = "%.6f" % (sign * (int(d) + float(m) / 60))

    return (lat, lon)


def parse_coord(coordstr):
    """
    Parse user-entered coordinates.
    """
    if re.match('^\d{6,}$', coordstr):
	return parse_coord_digits(coordstr)

    matchObj = re.match('^([NnSs])(\d{3,})([EeWw])(\d{3,})$', coordstr)
    if matchObj:
	return parse_coord_nsew(matchObj)

    return None


def isFloat(s):
    try:
	float(s)
	return True
    except ValueError:
	return False

class SetlocJSHandler(MyHandler):
    """
    Client-side version of SetlocHandler. If Javascript is enabled, use this to
    avoid hitting Geocoding API quotas.
    """
    def get(self):
	self.post()

    def post(self):
	# This page should be cached. So omit the no_cache() call.

	newloc = self.request.get('newloc').strip()

	coords = parse_coord(newloc)
	if coords:
	    (lat, lon) = coords
	    set_coords(self, lat, lon)
	    self.redirect('/venues')
	    return

	renderpage(self, 'setlocjs.htm', 
		{ 
		    'newloc' : newloc,
		    'map_provider' : get_map_provider(self),
		})

class SetlocHandler(MyHandler):
    """
    This handles the 'set location' input box if Javascript is disabled. If the
    locations string is six or more digits, it will be parsed as user-input
    coordinates. Otherwise, it will be fed to the Google Geocoding API.
    """
    def get(self):
	self.post()

    def post(self):
	no_cache(self)

	newloc = self.request.get('newloc').strip()

	coords = parse_coord(newloc)
	if coords:
	    (lat, lon) = coords
	    set_coords(self, lat, lon)
	    self.redirect('/venues')
	    return

	try:
	    args = urllib.urlencode({
		"sensor" : "false",
		"address" : newloc,
		})
	    req = urllib2.Request('http://maps.googleapis.com/maps/api/geocode/json?%s' % args)
	    resp = urllib2.urlopen(req)

	except DownloadError:
	    errorpage(self,
		    "Can't connect to Google Geocoding API. Refresh to retry.")
	    return

	except urllib2.HTTPError, e:
	    output = e.read()
	    errorpage(self, 
		    'Error %d from Google Geocoding API call to %s:<br>%s' % (e.code, e.geturl(), output))
	    return

	output = resp.read()
	jsn = json.loads(output)

	status = jsn.get('status')
	if not status:
	    status = 'Unknown Error'
	if status != 'OK' and status != 'ZERO_RESULTS':
	    errorpage(self,
		    'Error from Google Geocoding API: %s' % status)
	    return

	renderpage(self, 'setloc.htm',
		{
		    'results' : jsn.get('results'),
		    'debug_json' : debug_json_str(self, jsn),
		    'map_provider' : get_map_provider(self),
		})


class CoordsHandler(MyHandler):
    """
    This handles user-input coordinates. Sets the location to 
    those coordinates and brings up the venue search page.
    """
    def get(self):
	self.post()

    def post(self):
	no_cache(self)

	geolat = self.request.get('geolat')
	geolong = self.request.get('geolong')

	# geolat/geolong are float parameters. Move to those coordinates.
	if isFloat(geolat) and isFloat(geolong):
	    set_coords(self, geolat, geolong)
	    self.redirect('/venues')
	else:
	    self.redirect('/')



def do_checkin(self, client, vid, useloc = False, broadcast = 'public', shout = None):
    (lat, lon) = coords(self)

    params = {
	"venueId" : vid,
	"broadcast" : broadcast,
	}
    if shout is not None:
	params['shout'] = shout
    if useloc:
	params['ll'] = '%s,%s' % (lat, lon)
    jsn = call4sq(self, client, 'post', path='/checkins/add', params=params)
    if jsn is None:
	return

    usrhdr = userheader(self, client)

    response = jsn.get('response')
    if response is None:
	logging.error('Missing response from /checkins/add:')
	logging.error(jsn)
	return jsn

    checkin = response.get('checkin')
    if checkin is None:
	logging.error('Missing checkin from /checkins/add:')
	logging.error(jsn)
	return jsn

    notif = response.get('notifications')
    if notif is None:
	logging.error('Missing notifications from /checkins/add:')
	logging.error(jsn)
	return jsn

    renderpage(self, 'checkin.htm', 
	    { 
		'checkin' : checkin,
		'notif' : notif,
		'userheader' : usrhdr,
		'lat' : lat,
		'lon' : lon,
		'debug_json' : debug_json_str(self, jsn),
		'map_provider' : get_map_provider(self),
	    })


class CheckinTestHandler(MyHandler):
    """
    Test harness for processing a checkin response.
    """
    def get(self):
	no_cache(self)

	client = getclient(self)
	if client is None:
	    return

	(lat, lon) = coords(self)

	jsn = { }

	response = jsn.get('response')
	if response is None:
	    logging.error('Missing response from /checkins/add:')
	    logging.error(jsn)
	    return jsn

	checkin = response.get('checkin')
	if checkin is None:
	    logging.error('Missing checkin from /checkins/add:')
	    logging.error(jsn)
	    return jsn

	notif = response.get('notifications')
	if notif is None:
	    logging.error('Missing notifications from /checkins/add:')
	    logging.error(jsn)
	    return jsn

	renderpage(self, 'checkin.htm', 
		{ 
		    'checkin' : checkin,
		    'notif' : notif,
		    'lat' : lat,
		    'lon' : lon,
		    'debug_json' : debug_json_str(self, jsn),
		    'map_provider' : get_map_provider(self),
		})



class CheckinHandler(MyHandler):
    """
    This handles user checkins by venue ID.
    """
    def get(self):
	self.post()

    def post(self):
	no_cache(self)

	client = getclient(self)
	if client is None:
	    return

	vid = self.request.get('vid')
	if vid == '':
	    self.redirect('/')
	    return

	dist = self.request.get('dist')
	# logging.debug('checkin: dist = %s' % dist)
	useloc = isFloat(dist) and float(dist) < MAX_MILES_LOC

	do_checkin(self, client, vid, useloc)

class AddVenueHandler(MyHandler):
    """
    Add a venue at the current coordinates with no address information.
    """
    # This is technically not idempotent but allow both methods anyway.
    def get(self):
	self.post()

    def post(self):
	no_cache(self)

	(lat, lon) = coords(self)
	client = getclient(self)
	if client is None:
	    return

	vname = self.request.get('vname')
	if vname == '':
	    self.redirect('/')
	    return

	jsn = call4sq(self, client, 'post', path='/venues/add',
		params = {"name" : vname, "ll" : '%s,%s' % (lat, lon)})
	if jsn is None:
	    return

	response = jsn.get('response')
	if response is None:
	    logging.error('Missing response from /venues/add:')
	    logging.error(jsn)
	    return jsn

	venue = response.get('venue')
	if venue is None:
	    logging.error('Missing venue from /venues/add:')
	    logging.error(jsn)
	    return jsn

	do_checkin(self, client, venue['id'], True)

class AboutHandler(MyHandler):
    """
    Handler for About command.
    """
    def get(self):
	# This page should be cached. So omit the no_cache() call.
	renderpage(self, 'about.htm', { 'about' : __doc__ })

class GeoLocHandler(MyHandler):
    """
    Geolocation Handler with GPS monitoring and refresh.
    Uses HTML5 Geolocation API.
    """
    def get(self):
	# This page should be cached. So omit the no_cache() call.
	renderpage(self, 'geoloc.htm',
		{
		    'map_provider' : get_map_provider(self),
		})

class PurgeHandler(MyHandler):
    """
    Purge old database entries from AuthToken.
    """
    @db.transactional
    def purge_user(self, user):
	for tmp in AccessToken.all().ancestor(user):
	    tmp.delete()

	user.delete()


    def get(self):
	no_cache(self)

	cutoffdate = (date.today() - timedelta(days=30)).isoformat()
	creatclause = "WHERE created < DATE('%s')" % cutoffdate

	query = User.gql(creatclause)
	count = 0
	for user in query:
	    self.purge_user(user)
	    count += 1

	memcache.flush_all()

	renderpage(self, 'purge.htm', { 'count' : count })


class CheckinLong2Handler(MyHandler):
    """
    Continuation of CheckinLongHandler after the user submits the
    checkin form with options.
    """
    def post(self):
	self.get()

    def get(self):
	no_cache(self)

	client = getclient(self)
	if client is None:
	    return

	vid = self.request.get('vid')
	if vid == '':
	    self.redirect('/')
	    return

	dist = self.request.get('dist')
	# logging.debug('checkin_long2: dist = %s' % dist)
	useloc = isFloat(dist) and float(dist) < MAX_MILES_LOC

	shout = self.request.get('shout')
	private = int(self.request.get('private'))
	twitter = int(self.request.get('twitter'))
	facebook = int(self.request.get('facebook'))

	broadstrs = []
	if private:
	    broadstrs.append('private')
	else:
	    broadstrs.append('public')
	if twitter:
	    broadstrs.append('twitter')
	if facebook:
	    broadstrs.append('facebook')

	do_checkin(self, client, vid, useloc, ','.join(broadstrs), shout)


class CheckinLongHandler(MyHandler):
    """
    This handles user checkin with options.
    """
    def get(self):
	no_cache(self)

	(lat, lon) = coords(self)
	client = getclient(self)
	if client is None:
	    return

	vid = self.request.get('vid')
	vname = self.request.get('vname')
	dist = self.request.get('dist')

	jsn = call4sq(self, client, 'get', '/settings/all')
	if jsn is None:
	    return

	usrhdr = userheader(self, client)

	response = jsn.get('response')
	if response is None:
	    logging.error('Missing response from /settings/all:')
	    logging.error(jsn)
	    return jsn

	settings = response.get('settings')
	if settings is None:
	    logging.error('Missing settings from /settings/all:')
	    logging.error(jsn)
	    return jsn

	private = 0
	twitter = 0
	facebook = 0

	if settings['sendToTwitter']:
	    twitter = 1
	if settings['sendToFacebook']:
	    facebook = 1

	renderpage(self, 'checkin_long.htm',
		{
		    'userheader' : usrhdr,
		    'lat' : lat,
		    'lon' : lon,
		    'debug_json' : debug_json_str(self, jsn),
		    'vname' : vname,
		    'vid' : vid,
		    'dist' : dist,
		    'private' : private,
		    'twitter' : twitter,
		    'facebook' : facebook,
		})


class SpecialsHandler(MyHandler):
    """
    Retrieves a list of nearby specials.
    """
    def get(self):
	no_cache(self)

	(lat, lon) = coords(self)
	client = getclient(self)
	if client is None:
	    return

	jsn = call4sq(self, client, 'get', '/specials/search',
		params = { 
		    'll' : '%s,%s' % (lat, lon),
		    'limit' : 50
		    })
	if jsn is None:
	    return

	response = jsn.get('response')
	if response is None:
	    logging.error('Missing response from /specials/search:')
	    logging.error(jsn)
	    return jsn

	specials = response.get('specials')
	if specials is None:
	    logging.error('Missing specials from /specials/search:')
	    logging.error(jsn)
	    return jsn

	renderpage(self, 'specials.htm', 
		{ 
		    'specials_jsn' : specials,
		    'debug_json' : debug_json_str(self, jsn),
		})


class DelCommentHandler(MyHandler):
    """
    Delete a comment from a check-in.
    """
    def get(self):
	self.post()

    def post(self):
	no_cache(self)

	(lat, lon) = coords(self)
	client = getclient(self)
	if client is None:
	    return

	checkin_id = self.request.get('chkid')
	comment_id = self.request.get('commid')
	if checkin_id == '' or comment_id == '':
	    self.redirect('/')
	    return

	jsn = call4sq(self, client, 'post', 
		'/checkins/%s/deletecomment' % escape(checkin_id),
		params = { 'commentId' : comment_id }
		)
	if jsn is None:
	    return

	self.redirect('/comments?chkid=%s' % escape(checkin_id))

class AddCommentHandler(MyHandler):
    """
    Add a comment to a check-in.
    """
    def get(self):
	self.post()

    def post(self):
	no_cache(self)

	(lat, lon) = coords(self)
	client = getclient(self)
	if client is None:
	    return

	checkin_id = self.request.get('chkid')
	text = self.request.get('text')
	if checkin_id == '':
	    self.redirect('/')
	    return

	if text:
	    jsn = call4sq(self, client, 'post', 
		    '/checkins/%s/addcomment' % escape(checkin_id),
		    params = { 'text' : text }
		    )
	    if jsn is None:
		return

	self.redirect('/comments?chkid=%s' % escape(checkin_id))

class AddPhotoHandler(MyHandler):
    """
    Add a photo to a check-in.
    """
    def get(self):
	self.post()

    def post(self):
	no_cache(self)

	(lat, lon) = coords(self)
	client = getclient(self)
	if client is None:
	    return

	checkin_id = self.request.get('chkid')
	venue_id = self.request.get('venid')
	photo = self.request.get('photo')

	if checkin_id == '' and venue_id == '':
	    self.redirect('/')
	    return

	if photo:
	    # Resize photo and convert to JPEG.
	    photo = images.resize(photo, 800, 800, images.JPEG)

	    params = { 'photo' : photo }
	    if venue_id:
		params['venueId'] = venue_id
	    else:
		params['checkinId'] = checkin_id

	    jsn = call4sq(self, client, 'post', '/photos/add', params)
	    if jsn is None:
		return

	if venue_id:
	    self.redirect('/venue?vid=%s' % escape(venue_id))
	else:
	    self.redirect('/comments?chkid=%s' % escape(checkin_id))

	    
class PhotoHandler(MyHandler):
    """
    View full-size version of a photo.
    """
    def get(self):
	no_cache(self)

	(lat, lon) = coords(self)
	client = getclient(self)
	if client is None:
	    return

	checkin_id = self.request.get('chkid')
	venue_id = self.request.get('venid')
	user_id = self.request.get('userid')
	photo_id = self.request.get('photoid')
	if photo_id == '':
	    self.redirect('/')
	    return

	jsn = call4sq(self, client, 'get', '/photos/%s' % escape(photo_id))
	if jsn is None:
	    return

	response = jsn.get('response')
	if response is None:
	    logging.error('Missing response from /photos:')
	    logging.error(jsn)
	    return jsn

	photo = response.get('photo')
	if photo is None:
	    logging.error('Missing photo from /photos:')
	    logging.error(jsn)
	    return jsn

	renderpage(self, 'photo.htm',
		{
		    'venue_id' : venue_id,
		    'user_id' : user_id,
		    'checkin_id' : checkin_id,
		    'photo' : photo,
		    'debug_json' : debug_json_str(self, jsn),
		})


class CommentsHandler(MyHandler):
    """
    View comments on a check-in.
    """
    def get(self):
	no_cache(self)

	(lat, lon) = coords(self)
	client = getclient(self)
	if client is None:
	    return

	checkin_id = self.request.get('chkid')
	if checkin_id == '':
	    self.redirect('/')
	    return

	jsn = call4sq(self, client, 'get', '/checkins/%s' % escape(checkin_id))
	if jsn is None:
	    return

	response = jsn.get('response')
	if response is None:
	    logging.error('Missing response from /checkins:')
	    logging.error(jsn)
	    return jsn

	checkin = response.get('checkin')
	if checkin is None:
	    logging.error('Missing checkin from /checkins:')
	    logging.error(jsn)
	    return jsn

	renderpage(self, 'comments.htm', 
		{
		    'lat' : lat,
		    'lon' : lon,
		    'checkin' : checkin,
		    'debug_json' : debug_json_str(self, jsn),
		})

class TimeTestHandler(MyHandler):
    """
    Display current time.
    """
    def get(self):
	dt_now = datetime.utcnow()
	self.response.out.write("""<!DOCTYPE html>
<html>
<body>
Current time: %s (%.2f)
</body>
</html>""" % (str(dt_now), (dt_now - datetime(1970, 1, 1)).total_seconds()))

class UnknownHandler(MyHandler):
    """
    Handle bad URLs.
    """
    def get(self, unknown_path):
	errorpage(self, 'Unknown URL: /%s' % escape(unknown_path), 404)

config = {}
config['webapp2_extras.sessions'] = {
    'secret_key': 'sekrit-key',
}

# logging.getLogger().setLevel(logging.DEBUG)
app = webapp2.WSGIApplication([
    ('/', MainHandler),
    ('/setlochelp', SetlocHelpHandler),
    ('/login', LoginHandler),
    ('/login2', LoginHandler2),
    ('/oauth', OAuthHandler),
    ('/logout', LogoutHandler),
    ('/venue', VInfoHandler),
    ('/user', UserHandler),
    ('/history', HistoryHandler),
    ('/debug', DebugHandler),
    ('/mapprov', MapProvHandler),
    ('/notif', NotifHandler),
    ('/leader', LeaderHandler),
    ('/badges', BadgesHandler),
    ('/mayor', MayorHandler),
    ('/friends', FriendsHandler),
    ('/venues', VenuesHandler),
    ('/coords', CoordsHandler),
    ('/setloc', SetlocHandler),
    ('/setlocjs', SetlocJSHandler),
    ('/checkin', CheckinHandler),
    ('/checkintest', CheckinTestHandler),
    ('/timetest', TimeTestHandler),
    ('/addvenue', AddVenueHandler),
    ('/about', AboutHandler),
    ('/geoloc', GeoLocHandler),
    ('/purge', PurgeHandler),
    ('/checkin_long', CheckinLongHandler),
    ('/checkin_long2', CheckinLong2Handler),
    ('/specials', SpecialsHandler),
    ('/comments', CommentsHandler),
    ('/addcomment', AddCommentHandler),
    ('/delcomment', DelCommentHandler),
    ('/addphoto', AddPhotoHandler),
    ('/photo', PhotoHandler),
    ('/(.*)', UnknownHandler),
    ], debug = True, config = config)


# vim:set tw=0:
