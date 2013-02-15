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
Last updated: February 14, 2013
</pre>
"""

USER_AGENT = 'plainsq:0.0.11 20130214'


from google.appengine.ext import webapp
from google.appengine.ext.webapp import util
from google.appengine.api.urlfetch import DownloadError 
from google.appengine.api import images
from google.appengine.ext import db
from google.appengine.datastore import entity_pb
from google.appengine.api import memcache

import itertools
import json
import oauth2
import uuid
import logging
import pprint
import re
import sys
import StringIO
import os
import cgi
from math import (radians, sin, cos, atan2, degrees, sqrt)
from datetime import (datetime, date, timedelta)
import urllib
import urllib2
import jinja2
from markupsafe import Markup

jinja_environment = jinja2.Environment(
    extensions = ['jinja2.ext.do'],
    loader = jinja2.FileSystemLoader(os.path.dirname(__file__) + '/templates')
)

def encode_any(s):
    try:
	return str(s)
    except UnicodeEncodeError:
	return unicode(s).encode('utf8')

def urlencode_filter(s):
    if isinstance(s, Markup):
        s = s.unescape()
    s = urllib.quote_plus(encode_any(s))
    return Markup(s)

jinja_environment.filters['urlencode'] = urlencode_filter

def urlparms_filter(parms):
    return urllib.urlencode( { k : encode_any(v) for k, v in parms.items() } )

jinja_environment.filters['urlparms'] = urlparms_filter

def convcoords_filter(coords):
    return convcoords(coords[0], coords[1])

jinja_environment.filters['convcoords'] = convcoords_filter

def wordchars_filter(s):
    return re.sub(r'[^a-zA-Z0-9_]', '', encode_any(s))

jinja_environment.filters['wordchars'] = wordchars_filter

def datefmt_filter(s):
    return datetime.fromtimestamp(s).ctime()

jinja_environment.filters['datefmt'] = datefmt_filter

dt_now = datetime.utcnow()
def fuzzydelta_filter(s):
    d1 = datetime.fromtimestamp(s)
    return fuzzy_delta(dt_now - d1)

jinja_environment.filters['fuzzydelta'] = fuzzydelta_filter

def phonefmt_filter(phone):
    phoneStr = ''
    phone = encode_any(phone)
    if len(phone) > 6:
	phoneStr = '(%s)%s-%s' % (phone[0:3], phone[3:6], phone[6:])
    return phoneStr

jinja_environment.filters['phonefmt'] = phonefmt_filter

def distcompass_filter(vcoords, lat, lon):
    dist = None
    compass = None
    vlat = vcoords.get('lat')
    vlon = vcoords.get('lon')
    if vlat is not None and vlon is not None:
	dist = distance(lat, lon, vlat, vlon)
	compass = bearing(lat, lon, vlat, vlon)
    return { 'dist' : dist, 'compass' : compass }

jinja_environment.filters['distcompass'] = distcompass_filter

def photourl_filter(photo):
    imgurl = photo['url']

    # If multiple sizes are available, then pick the largest photo that is not
    # greater than 150 pixels in width. If none fit, pick the smallest photo.
    if photo['sizes']['count'] > 0:
	_photos = filter(lambda p:p['width'] <= 150, photo['sizes']['items'])
	if _photos:
	    imgurl = max(_photos, key = lambda p:p['width'])['url']
	else:
	    imgurl = min(photo['sizes']['items'], key = lambda p:p['width'])['url']

    return imgurl

jinja_environment.filters['photourl'] = photourl_filter


TOKEN_COOKIE = 'plainsq_token'
TOKEN_PREFIX = 'token_plainsq_'

COORD_PREFIX = 'coord_plainsq_'

AUTH_URL = 'https://foursquare.com/oauth2/authenticate'
ACCESS_URL = 'https://foursquare.com/oauth2/access_token'
API_URL = 'https://api.foursquare.com/v2'

DEFAULT_LAT = '39.7'
DEFAULT_LON = '-75.6'
DEBUG_COOKIE = 'plainsq_debug'

METERS_PER_MILE = 1609.344

# Send location parameters if distance is below MAX_MILES_LOC.
MAX_MILES_LOC = 1.1

if os.environ.get('SERVER_SOFTWARE','').startswith('Devel'):
    # In development environment, use local callback.
    # Also need to use a different consumer because Foursquare
    # checks the callback URL.
    CALLBACK_URL = 'http://localhost:8081/oauth'
    CLIENT_ID = '313XKCMSSWSWHW2PRZX231LBRIGB4OFCESREW5T1E2Z5MBPR'
    CLIENT_SECRET = 'P4AFGZNDXIU5MCBWMOUTZLHCHYWDC5RFOEYP3I2EZAP3SNIO'
else:
    # Production environment.
    CALLBACK_URL = 'https://plainsq.appspot.com/oauth'
    CLIENT_ID = 'A4JHSA3P1CL1YTMOFSERA3AESLHBCZBT4BAJQOL1NLFZYADH'
    CLIENT_SECRET = 'WI1EHJFHV5L3NJGEN054W0UTA43MXC3DYNXJSNKYKBJTFWAM'

def escape(s):
    return cgi.escape(s, quote = True)

class AccessToken(db.Model):
    """
    Access token entity.
    """
    token = db.StringProperty(required=True)

class Coords(db.Model):
    """
    Coordinates entity.
    """
    coords = db.StringProperty(required=True)

class User(db.Model):
    """
    User login entity.
    """
    access_token = db.ReferenceProperty(AccessToken)
    coords = db.ReferenceProperty(Coords)
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
    Set the debug option cookie.
    """
    self.response.set_cookie(DEBUG_COOKIE, str(debug), max_age = 60*60*24*365)

def get_debug(self):
    """
    Get the debug setting from cookie. If cookie is not found,
    assume we are not in debug mode.
    """
    debug = self.request.cookies.get(DEBUG_COOKIE)
    if debug is None:
	return 0
    return int(debug)

def no_cache(self):
    """
    Turn off web caching so that the browser will refetch the page.
    Also set the user-agent header.
    """
    self.response.cache_expires(0)
    self.response.headers['User-Agent'] = USER_AGENT


@db.transactional
def _set_coords(uuid_str, coord_str):
    user = User.get_by_key_name(uuid_str)
    if user is None:
	user = User(key_name = uuid_str)
	user.put()

    coords = user.coords
    if coords is None:
	coords = Coords(coords = coord_str, parent = user)
	coords.put()
	user.coords = coords
	user.put()
    else:
	coords.coords = coord_str
	coords.put()

def set_coords(self, lat, lon):
    """
    Store the coordinates in our table.
    """
    coord_str = "%s,%s" % (lat, lon)

    uuid = self.request.cookies.get(TOKEN_COOKIE)
    if uuid is not None:
	_set_coords(uuid, coord_str)

	# Update memcache.
	memcache.set(COORD_PREFIX + uuid, coord_str)


def get_coord_str(self):
    """
    Given the token cookie, get coordinates either from
    memcache or datastore.
    """

    # Try to get coordinates from memcache first.
    uuid = self.request.cookies.get(TOKEN_COOKIE)
    if uuid is not None:
	coord_key = COORD_PREFIX + uuid

	coord_str = memcache.get(coord_key)
	if coord_str is not None:
	    return coord_str

	# If not in memcache, try the datastore.
	result = User.get_or_insert(uuid).coords
	if result is not None:
	    coord_str = result.coords
	    memcache.set(coord_key, coord_str)
	    return coord_str

    return None

def coords(self):
    """
    Get user's coordinates from coords table. If not found in table,
    use default coordinates.
    """
    lat = None
    lon = None

    coord_str = get_coord_str(self)

    if coord_str is not None:
	try:
	    (lat, lon) = coord_str.split(',')
	except ValueError:
	    pass

    if lat is None or lon is None:
	lat = DEFAULT_LAT
	lon = DEFAULT_LON
	set_coords(self, lat, lon)

    return (lat, lon)

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


def conv_a_coord(coord, nsew):
    coord = float(coord)

    d = nsew[0]
    if coord < 0:
	d = nsew[1]
	coord = -coord

    return '%s%02d %06.3f' % (d, int(coord), 60 * (coord - int(coord)))

def convcoords(lat, lon):
    """
    Convert coordinates from decimal degrees to dd mm.mmm.
    Returns the result as a string.
    """
    return conv_a_coord(lat, 'NS') + ' ' + conv_a_coord(lon, 'EW')

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
    t = jinja_environment.get_template(template_file)
    self.response.out.write(t.render(params))

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


class LoginHandler(webapp.RequestHandler):
    """
    Page that we show if the user is not logged in.
    """
    def get(self):
	# This page should be cached. So omit the no_cache() call.
	renderpage(self, 'login.htm')

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
		})


class SetlocHelpHandler(webapp.RequestHandler):
    """
    Handler for 'Set location' help info.
    """
    def get(self):
	# This page should be cached. So omit the no_cache() call.
	renderpage(self, 'setlochelp.htm')

class OAuthHandler(webapp.RequestHandler):
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

class LogoutHandler(webapp.RequestHandler):
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
	self.del_cookie(DEBUG_COOKIE)
	renderpage(self, 'logout.htm')


def fuzzy_delta(delta):
    """
    Returns a user-friendly version of timedelta.
    """
    if delta.days < 0:
	return 'in the future?'
    elif delta.days > 1:
	return '%d days ago' % delta.days
    elif delta.days == 1:
	return '1 day ago'
    else:
	hours = int(delta.seconds / 60 / 60)
	if hours > 1:
	    return '%d hours ago' % hours
	elif hours == 1:
	    return '1 hour ago'
	else:
	    minutes = int(delta.seconds / 60)
	    if minutes > 1:
		return '%d minutes ago' % minutes
	    elif minutes == 1:
		return '1 minute ago'
	    else:
		if delta.seconds > 1:
		    return '%d seconds ago' % delta.seconds
		elif delta.seconds == 1:
		    return '1 second ago'
		else:
		    return 'now'

class UserHandler(webapp.RequestHandler):
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


class VInfoHandler(webapp.RequestHandler):
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
		})



class HistoryHandler(webapp.RequestHandler):
    """
    Handler for history command.
    """
    def get(self):
	no_cache(self)

	(lat, lon) = coords(self)
	client = getclient(self)
	if client is None:
	    return

	jsn = call4sq(self, client, 'get', path='/users/self/checkins',
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

class DebugHandler(webapp.RequestHandler):
    """
    Handler for Debug command. Toggle debug mode.
    """
    def get(self):
	debug = get_debug(self)
	set_debug(self, (0 if debug else 1))
	self.redirect('/')


class BadgesHandler(webapp.RequestHandler):
    """
    Handler for badges command.
    """
    def get(self):
	no_cache(self)

	(lat, lon) = coords(self)
	client = getclient(self)
	if client is None:
	    return

	jsn = call4sq(self, client, 'get', path='/users/self/badges')
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


class NotifHandler(webapp.RequestHandler):
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


class LeaderHandler(webapp.RequestHandler):
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


class MayorHandler(webapp.RequestHandler):
    """
    Handler for mayor command.
    """
    def get(self):
	no_cache(self)

	(lat, lon) = coords(self)
	client = getclient(self)
	if client is None:
	    return

	jsn = call4sq(self, client, 'get', path='/users/self/mayorships')
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


COMPASS_DIRS = [ 'S', 'SW', 'W', 'NW', 'N', 'NE', 'E', 'SE', 'S' ]

def bearing(lat, lon, vlat, vlon):
    """
    Compute bearing from (lat, lon) to (vlat, vlon)
    Returns compass direction.

    Adapted from code by Chris Veness (scripts-geo@movable-type.co.uk) at
    http://www.movable-type.co.uk/scripts/latlong.html
    """
    dlon = radians(float(vlon) - float(lon))
    lat1 = radians(float(lat))
    lat2 = radians(float(vlat))

    y = sin(dlon) * cos(lat2)
    x = cos(lat1) * sin(lat2) - sin(lat1) * cos(lat2) * cos(dlon)
    brng = degrees(atan2(y, x))

    return COMPASS_DIRS[int((brng + 180 + 22.5) / 45)]

def distance(lat, lon, vlat, vlon):
    """
    Compute distance from (lat, lon) to (vlat, vlon) using haversine formula.
    Returns distance in miles.

    Adapted from code by Chris Veness (scripts-geo@movable-type.co.uk) at
    http://www.movable-type.co.uk/scripts/latlong.html
    """
    earth_radius = 6371 * 1000.0 / METERS_PER_MILE
    dLat = radians(float(vlat) - float(lat))
    dLon = radians(float(vlon) - float(lon))
    lat1 = radians(float(lat))
    lat2 = radians(float(vlat))

    a = sin(dLat/2) * sin(dLat/2) + sin(dLon/2) * sin(dLon/2) * cos(lat1) * cos(lat2) 
    c = 2 * atan2(sqrt(a), sqrt(1-a)) 
    d = earth_radius * c

    return d


class FriendsHandler(webapp.RequestHandler):
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


class VenuesHandler(webapp.RequestHandler):
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

class SetlocJSHandler(webapp.RequestHandler):
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

	renderpage(self, 'setlocjs.htm', { 'newloc' : newloc })

class SetlocHandler(webapp.RequestHandler):
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
		})


class CoordsHandler(webapp.RequestHandler):
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

    notif = jsn.get('notifications')
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
	    })


class CheckinHandler(webapp.RequestHandler):
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

class AddVenueHandler(webapp.RequestHandler):
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

class AboutHandler(webapp.RequestHandler):
    """
    Handler for About command.
    """
    def get(self):
	# This page should be cached. So omit the no_cache() call.
	renderpage(self, 'about.htm', { 'about' : __doc__ })

class GeoLocHandler(webapp.RequestHandler):
    """
    Geolocation Handler with GPS monitoring and refresh.
    Uses HTML5 Geolocation API.
    """
    def get(self):
	# This page should be cached. So omit the no_cache() call.
	renderpage(self, 'geoloc.htm')

class PurgeHandler(webapp.RequestHandler):
    """
    Purge old database entries from CoordsTable and AuthToken.
    """
    @db.transactional
    def purge_user(self, user):
	for tmp in AccessToken.all().ancestor(user):
	    tmp.delete()

	for tmp in Coords.all().ancestor(user):
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


class CheckinLong2Handler(webapp.RequestHandler):
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


class CheckinLongHandler(webapp.RequestHandler):
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


class SpecialsHandler(webapp.RequestHandler):
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


class DelCommentHandler(webapp.RequestHandler):
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

class AddCommentHandler(webapp.RequestHandler):
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

class AddPhotoHandler(webapp.RequestHandler):
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

	    
class PhotoHandler(webapp.RequestHandler):
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
		    'checkin_id' : checkin_id,
		    'photo' : photo,
		    'debug_json' : debug_json_str(self, jsn),
		})


class CommentsHandler(webapp.RequestHandler):
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


class UnknownHandler(webapp.RequestHandler):
    """
    Handle bad URLs.
    """
    def get(self, unknown_path):
	errorpage(self, 'Unknown URL: /%s' % escape(unknown_path), 404)

# logging.getLogger().setLevel(logging.DEBUG)
app = webapp.WSGIApplication([
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
    ], debug=True)


# vim:set tw=0:
