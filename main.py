#!/usr/bin/env python

"""
<p>PlainSquare is a lightweight Foursquare client for mobile web browsers. It is intended as a full-featured substitute for Foursquare Mobile. PlainSquare supports both geolocation (using device GPS or cellular / wi-fi positioning) and manual coordinate entry for phones without GPS.

<p>PlainSquare speeds up check-ins by making this operation single-click if you do not need to shout or change your broadcast options. PlainSquare is also designed to send you through as few screens as possible to do most common Foursquare tasks.

<p>PlainSquare uses OAuth version 2 to log in to Foursquare to avoid having to store user passwords. PlainSquare supports version 2 of the Foursquare API. It is written in Python and designed for hosting on Google App Engine. 

<pre>
Version: 0.0.6
Author: Po Shan Cheah (morton@mortonfox.com)
Source code: <a href="http://code.google.com/p/plainsq/">http://code.google.com/p/plainsq/</a>
Created: January 28, 2011
Last updated: September 2, 2011
</pre>
"""


from google.appengine.ext import webapp
from google.appengine.ext.webapp import util
from google.appengine.api.urlfetch import DownloadError 
from google.appengine.api import images
from django.utils import simplejson
from google.appengine.ext import db
from google.appengine.datastore import entity_pb
from google.appengine.api import memcache

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
import urllib2

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

USER_AGENT = 'plainsq:0.0.6 20110902'

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
    if get_debug(self):
	self.response.out.write('<pre>%s</pre>' % escape(pprint_to_str(jsn)))

def set_debug(self, debug):
    """
    Set the debug option cookie.
    """
    self.response.headers.add_header(
	    'Set-Cookie',
	    '%s=%s; expires=Fri, 31-Dec-2020 23:59:59 GMT'
	    % (DEBUG_COOKIE, debug))

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
    self.response.headers.add_header('Cache-Control', 'no-cache') 
    self.response.headers.add_header('User-Agent', USER_AGENT) 


def query_coords(self, uuid = None):
    """
    Run a GQL query to get the coordinates, if available.
    """
    if uuid is None:
	uuid = self.request.cookies.get(TOKEN_COOKIE)
    if uuid is not None:
	return CoordsTable.gql('WHERE uuid=:1 LIMIT 1', uuid).get()

def set_coords(self, lat, lon):
    """
    Store the coordinates in our table.
    """
    result = query_coords(self)
    if result is None:
	uuid = self.request.cookies.get(TOKEN_COOKIE)
	if uuid is not None:
	    coord_str = "%s,%s" % (lat, lon)
	    CoordsTable(uuid = uuid, coords = coord_str).put()
	    # Update memcache.
	    memcache.set(COORD_PREFIX + uuid, coord_str)
    else:
	# Update existing record.
	result.coords = "%s,%s" % (lat, lon)
	db.put(result)
	# Update memcache.
	memcache.set(COORD_PREFIX + result.uuid, result.coords)

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
	result = query_coords(self, uuid)
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
	
	    # Retrieve the access token using the login cookie.
	    result = AccessToken.gql("WHERE uuid = :1 LIMIT 1",
		    uuid_key).get()
	    # If the query fails for whatever reason, the user will just
	    # have to log in again. Not such a big deal.
	    if result is not None:
		access_token = result.token
		memcache.set(uuid_key, access_token)

    client = newclient()

    if access_token is not None:
	# We have an access token. Use it.
	client.setAccessToken(access_token)
	return client

    self.response.out.write('Not logged in.')
    self.redirect('/login')

def htmlbegin(self, title, nolocate = False):
    self.response.out.write(
"""<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<title>PlainSq - %s</title>

<meta name="HandheldFriendly" content="true" />
<meta name="viewport" content="width=device-width, height=device-height, user-scalable=yes" />

<link rel="stylesheet" href="/screen.css" media="all" type="text/css">
<link rel="stylesheet" href="/handheld.css" media="handheld, only screen and (max-device-width:480px)" type="text/css">

</head>

<body>
<p><a class="button" href="/"><b>PlainSq</b></a>%s - %s
""" % (
    title,
    '' if nolocate else '<span class="linksep"> | </span><a class="button" href="/geoloc">Locate</a>',
    title))

def htmlend(self, noabout=False, nologout=False):
    self.response.out.write("""
<hr>
<a class="button" href="/">Home</a>%s%s
</body>
</html>
""" % (
    '' if noabout else '<span class="linksep"> | </span><a class="button" href="/about">About</a>',
    '' if nologout else '<span class="linksep"> | </span><a class="button" href="/logout">Log out</a>'))

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

def call4sq(self, client, method, path, params = None):
    """
    Call the Foursquare API. Handle errors.
    Returns None if there was an error. Otherwise, returns the parsed JSON.
    """
    try:
	if method == 'post':
	    result = client.post(path, params)
	else:
	    result = client.get(path, params)

	jsn = simplejson.loads(result)

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
	jsn = simplejson.loads(e.read())
	meta = jsn.get('meta', {})
	errormsg = meta.get('errorDetail', 'Unknown error')
	errorpage(self, 
		'Error %d from Foursquare API call to %s:<br>%s' % (e.code, e.geturl(), errormsg))
	return


def errorpage(self, msg, errcode=503):
    """
    Used for DownloadError exceptions and other errors. Generates an error
    page.
    """
    self.error(errcode)

    htmlbegin(self, "Error")
    self.response.out.write('<p><span class="error">Error: %s</span>' % msg)
    htmlend(self)

def userheader(self, client, lat, lon):
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

    firstname = user.get('firstName', '')
    photo = user.get('photo', '')

    venueName = ''
    checkins = user.get('checkins')
    if checkins is not None:
	items = checkins.get('items')
	if items is not None and len(items) > 0:
	    venue = items[0].get('venue')
	    if venue is not None:
		venueName = venue.get('name', '')

    self.response.out.write(
	    '<p><img src="%s" style="float:left"> %s @ %s<br>Loc: %s'
	    '<br style="clear:both">' 
	    % (photo, escape(firstname), escape(venueName),
		convcoords(lat, lon)))

    return jsn

class LoginHandler(webapp.RequestHandler):
    """
    Page that we show if the user is not logged in.
    """
    def get(self):
	# This page should be cached. So omit the no_cache() call.
	htmlbegin(self, "Log in", nolocate = True)

	self.response.out.write("""
<p>In order to use PlainSq features, you need to log in with Foursquare.
<p><a class="button" href="/login2">Log in with Foursquare</a>
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
	(lat, lon) = coords(self)

	client = getclient(self)
	if client is None:
	    return

	htmlbegin(self, "Main")

	# Unread notifications count should be in the notification tray in
	# the user query.
	unreadcount = -1
	jsn = userheader(self, client, lat, lon)
	if jsn:
	    notifs = jsn.get('notifications', [])
	    for notif in notifs:
		if notif.get('type', '') == 'notificationTray':
		    unreadcount = notif.get('item', {}).get('unreadCount', {})

        self.response.out.write("""
<script type="text/javascript" src="geocode.js"></script>
<ol class="menulist">

<li><a class="widebutton" href="/geoloc" accesskey="1">Detect location</a></li>

<li><form class="formbox" action="/setloc" onSubmit="box_onsubmit(); return false;" method="get">
Set location: <input class="inputbox" type="text" name="newloc" id="newloc" size="16"
accesskey="2"><input class="submitbutton" type="submit" value="Go"></form></li>

<li><a class="widebutton" href="/venues" accesskey="3">Nearest Venues</a></li>

<li><form class="formbox" action="/venues" method="get">
Search Venues: <input class="inputbox" type="text" name="query" size="8"
accesskey="4"><input class="submitbutton" type="submit" value="Search"></form></li>

<li><a class="widebutton" href="/history" accesskey="5">History</a></li>

<li><a class="widebutton" href="/friends" accesskey="6">Find friends</a></li>

<li><form class="formbox" action="/shout" method="post">
Shout: <input class="inputbox" type="text" name="message" size="16" accesskey="7">
<input class="submitbutton" type="submit" value="Shout"></form></li>

<li><a class="widebutton" href="/leader" accesskey="8">Leaderboard</a></li>

<li><a class="widebutton" href="/specials" accesskey="9">Specials</a></li>

<li><a class="widebutton" href="/notif" accesskey="0">Notifications (%d)</a></li>

<li><a class="widebutton" href="/badges">Badges</a></li>

<li><a class="widebutton" href="/mayor">Mayorships</a></li>

<li><a class="widebutton" href="/debug">Turn debugging %s</a></li>

</ol>

<hr>
<p>'Set location' input can be either a place name / zip code or coordinates.
<br>
<br>Enter coordinates as a series of 6 or more digits, e.g.:
<br>
<br>39123457512345 means N 39&deg; 12.345' W 75&deg; 12.345'
<br>391234751234 means N 39&deg; 12.340' W 75&deg; 12.340'
<br>3912375123 means N 39&deg; 12.300' W 75&deg; 12.300'
<br>
<br>Any other input format will be passed to a geocoder for interpretation.
""" % (unreadcount, "off" if get_debug(self) else "on"))

	debug_json(self, jsn)
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
	self.del_cookie(DEBUG_COOKIE)

	htmlbegin(self, "Logout", nolocate = True)
	self.response.out.write('<p>You have been logged out')
	htmlend(self, nologout=True)

def venue_cmds(venue, checkin_long=False):
    """
    Show checkin/moveto links in venue header.
    """
    s = ''
    # s = '<a class="vbutton" href="/checkin?vid=%s">checkin</a>' % venue['id']
    if checkin_long:
	s += ' <a class="vbutton" href="/checkin_long?%s">checkin with options</a>' % \
		escape(urllib.urlencode( { 
		    'vid' : venue['id'], 
		    'vname' : venue['name'].encode('utf-8')
		    } ))

    location = venue.get('location')
    if location is not None:
	lat = location.get('lat')
	lng = location.get('lng')
	if lat is not None and lng is not None:
	    s += ' <a class="vbutton" href="/coords?%s">move to</a>' % \
		    escape(urllib.urlencode( {
			'geolat' : lat,
			'geolong' : lng,
			} ))

    # Link to venue page on Foursquare regular website.
    s += ' <a class="vbutton" href="http://foursquare.com/venue/%s">web</a>' % venue['id']

    s += """<form style="margin:0; padding:0;" action="/checkin" method="post">
<input type="hidden" name="vid" value="%s">
<input class="formbutton" type="submit" value="checkin">
</form>""" % venue['id']

    return '<span class="buttonbox">%s</span>' % s

def addr_fmt(venue):
    """
    Format the address block of a venue.
    """
    location = venue.get('location', {})
    contact = venue.get('contact', {})
    return addr_fmt_2(location, contact)

def addr_fmt_2(location, contact):
    """
    Format an address block from location and contact records.
    """
    s = ''

    if location is not None:
	addr = location.get('address', '')
	if addr != '':
	    s += escape(addr) + '<br>'

	cross = location.get('crossStreet', '')
	if cross != '':
	    s += '(%s)<br>' % escape(cross)

	city = location.get('city', '')
	state = location.get('state', '')
	zip = location.get('postalCode', '')
	country = location.get('country', '')
	if city != '' or state != '' or zip != '' or country != '':
	    s += '%s, %s %s %s<br>' % (
		    escape(city), escape(state), escape(zip), escape(country))

    if contact is not None:
	phone = contact.get('phone', '')
	if len(phone) > 6:
	    s += '(%s)%s-%s<br>' % (phone[0:3], phone[3:6], phone[6:])

	twitter = contact.get('twitter', '')

	# Discard invalid characters.
	twitter = re.sub(r'[^a-zA-Z0-9_]', '', twitter)

	if len(twitter) > 0:
	    s += '<a href="http://mobile.twitter.com/%s">@%s</a><br>' % (
		    urllib.quote(twitter), escape(twitter))

    return s

def category_fmt(cat):
    path = ' / '.join(cat['parents'] + [ cat['name'] ])
    return """
<p><img src="%s" style="float:left">%s
<br style="clear:both">
""" % (cat['icon'], path)

def google_map(lat, lon):
    """
    Static Google Map.
    """
    return """
<p><img width="250" height="250" alt="[Google Map]"
src="http://maps.google.com/maps/api/staticmap?%s">
""" % escape(urllib.urlencode( {
    'size' : '250x250', 
    'format' : 'gif',
    'sensor' : 'false',
    'zoom' : '14',
    'markers' : 'size:mid|color:blue|%s,%s' % (lat, lon),
    } ))

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

def name_fmt(user):
    if user is None:
	return ''
    return escape('%s %s' % (
	    user.get('firstName', ''),
	    user.get('lastName', ''))
	    )

def venue_checkin_fmt(checkin, dnow):
    """
    Format the info about a user checked in at this venue.
    """
    s = ''
    s += '<p><img src="%s" style="float:left">%s from %s' % (
	    checkin['user']['photo'],
	    name_fmt(checkin['user']),
	    escape(checkin['user'].get('homeCity', '')))

    shout = checkin.get('shout')
    if shout is not None:
	s += '<br>"%s"' % escape(shout)

    d1 = datetime.fromtimestamp(checkin['createdAt'])
    s += '<br>%s' % fuzzy_delta(dnow - d1)

    s += '<br style="clear:both">'
    return s

def vinfo_fmt(venue):
    """
    Format info on a venue.
    """
    s = ''

    s += '<p>%s %s<br>%s' % (
	    escape(venue['name']),
	    venue_cmds(venue, checkin_long=True),
	    addr_fmt(venue))

    url = venue.get('url')
    if url:
	s += '<br><a href="%s">%s</a>' % (url, url)

    location = venue.get('location', {})
    if location is not None:
	lat = location.get('lat')
	lng = location.get('lng')
	if lat is not None and lng is not None:
	    # Add static Google Map to the page.
	    s += google_map(lat, lng)

    cats = venue.get('categories', [])
    s += ''.join([category_fmt(c) for c in cats])

    tags = venue.get('tags', [])
    if len(tags) > 0:
	s += '<p>Tags: %s' % escape(', '.join(tags))

    stats = venue.get('stats')
    if stats is not None:
	s += """
<p>Checkins: %s <br>Users: %s
""" % (stats['checkinsCount'], stats['usersCount'])

    beenhere = venue.get('beenHere')
    if beenhere is not None:
	s += """
<br>Your checkins: %s
""" % beenhere['count']

    herenow = venue.get('hereNow')
    if herenow is not None:
	s += """
<br>Here now: %s
""" % herenow['count']

    mayor = venue.get('mayor')
    if mayor is not None:
	user = mayor.get('user')

    if user is None:
	s += '<p>No mayor'
    else:
	s += """
<p><img src="%s" style="float:left">%s (%sx) 
from %s is the mayor<br style="clear:both"> 
""" % (user['photo'], 
	name_fmt(user),
	mayor['count'], 
	escape(user.get('homeCity', '')))

    if herenow is not None:
	if herenow['count'] > 0:
	    s += '<p><b>Checked in here:</b>'
	hngroups = herenow.get('groups', [])
	dnow = datetime.utcnow()
	for g in hngroups:
	    items = g.get('items', [])
	    s += ''.join(
		    [venue_checkin_fmt(c, dnow) for c in items])

    s += tips_fmt(venue.get('tips', []))
    s += specials_fmt(venue.get('specials', []))
    s += specials_fmt(venue.get('specialsNearby', []), nearby=True)

    photos = venue.get('photos')
    if photos is None:
	count = 0
    else:
	count = photos.get('count', 0)

    if count == 0:
	s += '<p>-- No photos --'
    else:
	for group in photos['groups']:
	    s += '<p>-- %s: %d --' % (group['name'], group['count'])
	    s += ''.join([photo_fmt(p, dnow, venue_id = venue['id']) 
		for p in group['items']])

    s += """
<p>
<form style="margin:0; padding:0;" enctype="multipart/form-data" action="/addphoto" method="post">
<input type="file" name="photo"><br>
<input type="hidden" value="%s" name="venid">
<input type="submit" value="Add JPEG photo"><br>
</form>
""" % venue['id']

    return s

def get_prim_category(cats):
    if cats is not None:
	for c in cats:
	    if c.get('primary', False):
		return c
    return None

def special_fmt(special):
    """
    Format a venue special.
    """
    s = ''
    venue = special.get('venue', {})

    s += '<p><img src="http://foursquare.com/img/specials/%s.png" style="float:left"> %s<br style="clear:both">' % (
	    special.get('icon', 'check-in'), special.get('title', 'Special Offer'))

    if venue:
	s += '<p><a class="button" href="/venue?vid=%s"><b>%s</b></a><br>%s' % (
		escape(venue.get('id', '')),
		escape(venue.get('name', '')), 
		addr_fmt(venue))

    message = special.get('message')
    if message:
	s += '<br>Message: %s' % escape(message)

    desc = special.get('description')
    if desc:
	s += '<br>Description: %s' % escape(desc)

    fineprint = special.get('finePrint')
    if fineprint:
	s += '<br>Fine print: %s' % escape(fineprint)

    unlocked = special.get('unlocked')
    if unlocked:
	s += '<br>Unlocked: %s' % unlocked

    state = special.get('state')
    if state:
	s += '<br>State: %s' % escape(state)

    progress = special.get('progress')
    if progress:
	s += '<br>Progress: %d %s of %d' % (
		progress,
		special.get('progressDescription', ''),
		special.get('target', 0))

    detail = special.get('detail')
    if detail:
	s += '<br>Detail: %d' % detail

    return s


def specials_fmt(specials, nearby=False):
    """
    Format venue specials.
    """
    return '' if len(specials) == 0 else '<p><b>Specials%s:</b>' % (
	    ' nearby' if nearby else ''
	    ) + '<ul class="seplist">%s</ul>' % ''.join(
		    ['<li>%s</li>' % special_fmt(x) for x in specials])

def tip_fmt(tip):
    """
    Format a tip on the venue page.
    """
    return """
<p><img src="%s" style="float:left">%s from %s says: 
%s (Posted: %s)<br style="clear:both">
""" % (tip['user']['photo'],
	name_fmt(tip['user']),
	escape(tip['user'].get('homeCity', '')),
	escape(tip['text']),
	datetime.fromtimestamp(tip['createdAt']).ctime())

def tips_fmt(tips):
    """
    Format a list of tips on the venue page.
    """
    s = ''
    if tips['count'] > 0:
	s += '<p><b>Tips:</b>'
    for grp in tips['groups']:
	s += ''.join([tip_fmt(t) for t in grp['items']])
    return s

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

	htmlbegin(self, "Venue info")
	userheader(self, client, lat, lon)

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

	self.response.out.write(vinfo_fmt(venue))

	debug_json(self, jsn)
	htmlend(self)

def pluralize(count, what):
    if count == 0:
	s = 'no %ss' % what
    elif count == 1:
	s = '1 %s' % what
    else:
	s = '%d %ss' % (count, what)
    return s

def comments_cmd(checkin):
    comments = checkin.get('comments')
    if comments is None:
	count = 0
    else:
	count = comments.get('count', 0)

    cstr = pluralize(count, 'comment')

    photos = checkin.get('photos')
    if photos is None:
	count = 0
    else:
	count = photos.get('count', 0)

    pstr = pluralize(count, 'photo')

    return '<span class="buttonbox"><a class="vbutton" href="/comments?chkid=%s">%s, %s</a></span>' % (
	    checkin['id'], cstr, pstr)

def history_checkin_fmt(checkin, dnow):
    """
    Format an item from the check-in history.
    """
    s = ''

    venue = checkin.get('venue')
    if venue is not None:
	id = venue.get('id')
	# Orphaned venues will be missing the id field.
	if id is None:
	    s += '<b>%s</b><br>' % escape(venue['name'])
	else:
	    s += '<a class="button" href="/venue?vid=%s"><b>%s</b></a> %s<br>%s' % (
		    id, escape(venue['name']), venue_cmds(venue),
		    addr_fmt(venue)
		    )
    else:
	location = checkin.get('location')
	if location is not None:
	    s += '<p>%s (venueless)<br>' % location.get('name', '')

    shout = checkin.get('shout')
    if shout is not None:
	s += '"%s"<br>' % escape(shout)

    s += '%s<br>' % comments_cmd(checkin)

    d1 = datetime.fromtimestamp(checkin['createdAt'])
    s += fuzzy_delta(dnow - d1)

    return s

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

	htmlbegin(self, "History")
	userheader(self, client, lat, lon)

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

	if checkins['count'] == 0:
	    self.response.out.write('<p>No check-ins?')
	else:
	    dnow = datetime.utcnow()
	    self.response.out.write("""
<ul class="vlist">
%s
</ul>
""" % ''.join(
    ['<li>%s</li>' % history_checkin_fmt(c, dnow)
	for c in checkins['items']]))

	debug_json(self, jsn)
	htmlend(self)

class DebugHandler(webapp.RequestHandler):
    """
    Handler for Debug command. Toggle debug mode.
    """
    def get(self):
	debug = get_debug(self)
	set_debug(self, (0 if debug else 1))
	self.redirect('/')

def badge_fmt(badge):
    iconurl = ""
    img = badge.get('image')
    if img is not None:
	iconurl = img['prefix'] + str(img['sizes'][0]) + img['name']

    unlockstr = ''
    unlocks = badge.get('unlocks')
    if unlocks:
	checkins = unlocks[0]['checkins']
	if len(checkins) > 0:
	    venue = checkins[0].get('venue')
	    if venue is not None:
		location = venue['location']
		city = location.get('city', '')
		state = location.get('state', '')
		locstr = ''
		if city != '' or state != '':
		    locstr = ' in %s %s' % (city, state)
		unlockstr = """
Unlocked at <a href="/venue?vid=%s">%s</a>%s on %s.
""" % (
	escape(venue['id']), escape(venue['name']), locstr, 
	datetime.fromtimestamp(checkins[0]['createdAt']).ctime())

    desc = badge.get('description')
    if desc is None:
	desc = badge.get('hint', '')

    text = '<b>%s</b><br>%s<br>%s<br style="clear:both">' % (badge.get('name', ''), desc, unlockstr)

    return """
<img src="%s" style="float:right; padding:3px;">%s
""" % (iconurl, text)

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

	htmlbegin(self, "Badges")

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

	if len(badges) == 0:
	    self.response.out.write('<p>No badges yet.')
	else:
	    # Sort badges by reverse unlock order.
	    # Retain only unlocked badges.
	    keys = filter(lambda k: badges[k].get('unlocks'), sorted(badges.keys(), reverse=True))
	    self.response.out.write(
		    '<ol class="numseplist">%s</ol>' % 
		    ''.join([
			'<li>%s</li>' % badge_fmt(badges[k]) for k in keys]))

	debug_json(self, jsn)
	htmlend(self)

def leader_fmt(leader):
    """
    Format a user on the leaderboard page.
    """
    user = leader.get('user', {})
    scores = leader.get('scores', {})
    return '<img src="%s" style="float:right"><b>%d: %s from %s</b><br>Recent: %d<br>Max: %d<br>Checkins:%d<br style="clear:both">' % (
	    user.get('photo', ''),
	    leader.get('rank', 0),
	    name_fmt(user),
	    escape(user.get('homeCity', '')),
	    scores.get('recent', 0),
	    scores.get('max', 0),
	    scores.get('checkinsCount', 0))

def notif_fmt(notif):
    s = ''
    target = notif.get('target', {})
    targetType = target.get('type', '')
    venue = None

    if targetType == 'checkin' or targetType == 'tip':
	venue = target.get('object', {}).get('venue', {})
    elif targetType == 'venue':
	venue = target.get('object', {})

    if venue:
	s = '<a class="vbutton" href="http://foursquare.com/venue/%s">%s</a>' % (
		venue.get('id', ''), escape(venue.get('name', '')))

    return '<li><img src="%s" style="float:right"><i>%s</i><br>%s<br>%s<br style="clear:both"></li>' % (
	    notif.get('image', {}).get('fullPath', ''),
	    datetime.fromtimestamp(notif.get('createdAt', 0)).ctime(),
	    escape(notif.get('text', '')),
	    s,
	    )

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

	htmlbegin(self, 'Notifications')

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

	if notifs.get('count'):
	    items = notifs.get('items', [])

	    self.response.out.write(
		'<ol class="numseplist">%s</ol>' % 
		''.join([notif_fmt(n) for n in items]))

	    hwmark = 0
	    if items:
		hwmark = items[0].get('createdAt', 0)	    

	    if get_debug(self):
		self.response.out.write('<br>Setting highwater mark to %d' % hwmark)

	    # Mark notifications as read.
	    jsn2 = call4sq(self, client, 'post', 
		    path='/updates/marknotificationsread',
		    params = { 'highWatermark' : hwmark })
	else:
	    self.response.out.write('<p>No notifications yet.')

	debug_json(self, jsn)
	debug_json(self, jsn2)
	htmlend(self)


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

	htmlbegin(self, 'Leaderboard')

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

	if leaderboard.get('count'):
	    self.response.out.write(
		    '<ul class="seplist">%s</ul>' % ''.join(
			['<li>%s</li>' % leader_fmt(x) 
			    for x in leaderboard.get('items', [])]))
	else:
	    self.response.out.write('<p>Empty leaderboard?')

	debug_json(self, jsn)
	htmlend(self)


def mayor_venue_fmt(venue):
    return '<li><a class="button" href="/venue?vid=%s"><b>%s</b></a> %s<br>%s</li>' % (
	    venue['id'], escape(venue['name']), venue_cmds(venue),
	    addr_fmt(venue))

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

	htmlbegin(self, "Mayorships")

	jsn = userheader(self, client, lat, lon)
	if jsn is None:
	    return

	user = jsn.get('response', {}).get('user', {})
	mayorships = user.get('mayorships', {})
	count = mayorships.get('count', 0)
	if count == 0:
	    self.response.out.write('<p>No mayorships yet.')
	else:
	    self.response.out.write(
		'<ol class="numseplist">%s</ol>' % 
		''.join([mayor_venue_fmt(v) for v in mayorships['items']]))

	debug_json(self, jsn)
	htmlend(self)

COMPASS_DIRS = [ 'S', 'SW', 'W', 'NW', 'N', 'NE', 'E', 'SE', 'S' ]

def bearing(lat, lon, vlat, vlon):
    """
    Compute compass direction from (lat, lon) to (vlat, vlon)
    """
    dlon = radians(float(vlon) - float(lon))
    lat1 = radians(float(lat))
    lat2 = radians(float(vlat))

    y = sin(dlon) * cos(lat2)
    x = cos(lat1) * sin(lat2) - sin(lat1) * cos(lat2) * cos(dlon)
    brng = degrees(atan2(y, x))

    return COMPASS_DIRS[int((brng + 180 + 22.5) / 45)]

def friend_checkin_fmt(checkin, lat, lon, dnow):
    """
    Format checkin record from one friend.
    """
    s = ''

    venue = checkin.get('venue')
    user = checkin.get('user')

    user_shown = False

    if venue is not None:
	s += '<a class="button" href="/venue?vid=%s"><b>%s</b> @ %s</a><br>' % (
		venue.get('id'),
		name_fmt(user),
		venue.get('name', ''),
		)
	user_shown = True
    else:
	location = checkin.get('location', {})
	name = location.get('name')
	if name is not None:
	    s += '<b>%s</b> @ %s<br>' % (name_fmt(user), name)
	    user_shown = True

    shout = checkin.get('shout')
    if shout is not None:
	if not user_shown:
	    s += '<b>' + name_fmt(user) + '</b> '
	s += '"%s"<br>' % escape(shout)

    s += '%s<br>' % comments_cmd(checkin)

    if user:
	photo = user.get('photo')
	if photo:
	    s += '<img src="%s" style="float:right; padding:3px;">' % photo

    dist = checkin.get('distance')
    if dist is not None:
	dist = float(dist) / METERS_PER_MILE

    if venue is not None:
	s += addr_fmt(venue)
	location = venue.get('location', {})
    else:
	location = checkin.get('location', {})

    geolat = location.get('lat')
    geolong = location.get('lng')
	
    if geolat is None or geolong is None:
	compass = ''
    else:
	compass = ' ' + bearing(lat, lon, geolat, geolong)

    if dist is not None:
	s += '(%.1f mi%s)<br>' % (dist, compass)

    d1 = datetime.fromtimestamp(checkin['createdAt'])
    s += fuzzy_delta(dnow - d1)

    source = checkin.get('source')
    if source:
	s += '<br>via <a href="%s">%s</a>' % (
		source.get('url', ''), 
		source.get('name', ''))
    
    s += '<br style="clear:both">'

    return s

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

	htmlbegin(self, "Find Friends")
	userheader(self, client, lat, lon)

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

	dnow = datetime.utcnow()

	# Sort checkins by distance. If distance is missing,
	# use a very large value.
	recent.sort(key = lambda v: v.get('distance', '1000000'))

	if len(recent) == 0:
	    self.response.out.write('<p>No friends?')
	else:
	    self.response.out.write("""
<ul class="vlist">
%s
</ul>
""" % ''.join(
    ['<li>%s</li>' % friend_checkin_fmt(c, lat, lon, dnow)
	for c in recent]))

	debug_json(self, jsn)
	htmlend(self)

class ShoutHandler(webapp.RequestHandler):
    """
    This handles user shouts.
    """
    def post(self):
	self.get()

    def get(self):
	no_cache(self)
	(lat, lon) = coords(self)

	client = getclient(self)
	if client is None:
	    return

	message = self.request.get('message')
	if message == '':
	    self.redirect('/')
	    return

	jsn = call4sq(self, client, 'post', path='/checkins/add',
		params = {
		    "shout" : message,
		    "ll" : '%s,%s' % (lat, lon),
		    "broadcast" : "public",
		    })
	if jsn is None:
	    return

	htmlbegin(self, "Shout")
	userheader(self, client, lat, lon)

	notif = jsn.get('notifications')
	if notif is None:
	    logging.error('Missing notifications from /checkins/add:')
	    logging.error(jsn)
	    return jsn

	msgs = find_notifs(notif, 'message')
	if len(msgs) > 0:
	    self.response.out.write('<p>%s' % escape(msgs[0]['message']))

	debug_json(self, jsn)
	htmlend(self)

def venue_fmt(venue, lat, lon):
    """
    Format a venue in the venue search page.
    """
    s = ''

    s += '<a class="button" href="/venue?vid=%s"><b>%s</b></a> %s<br>%s' % (
	    escape(venue['id']), escape(venue['name']), 
	    venue_cmds(venue), addr_fmt(venue))

    location = venue.get('location')
    if location is not None:
	# Show distance and bearing from current coordinates.
	dist = location.get('distance')
	if dist is not None:
	    dist = float(dist) / METERS_PER_MILE
	    vlat = location.get('lat')
	    vlng = location.get('lng')
	    compass = ''
	    if vlat is not None and vlng is not None:
		compass = bearing(lat, lon, vlat, vlng)
	    s += '(%.1f mi %s)<br>' % (dist, compass)

    return s

def venues_fmt(jsn, lat, lon):
    """
    Format a list of venues in the venue search page.
    """

    groups = jsn.get('groups')
    if groups is None:
	venues = jsn.get('venues', [])
    else:
	# Venues may be split across groups so collect them all in one list.
	venues = []
	for group in groups:
	    venues.extend(group['items'])

    venues = remove_dup_vids(venues)

    # Sort venues ascending by distance. If distance field is missing,
    # use a very large value.
    venues.sort(key = lambda v: v['location'].get('distance', '1000000'))

    return """
<ul class="vlist">
%s
</ul>
""" % ''.join(['<li>%s</li>' % venue_fmt(v, lat, lon) for v in venues])

def remove_dup_vids(venues):
    """
    Return a new list of venues with all duplicate entries removed.
    """
    vids = []
    newvenues = []
    for v in venues:
	id = v['id']
	if id not in vids:
	    vids.append(id)
	    newvenues.append(v)
    return newvenues

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

	parms = { "ll" : '%s,%s' % (lat, lon), "limit" : 50, 'v' : '20110615' }
	if query != '':
	    parms['query'] = query

	jsn = call4sq(self, client, 'get', path='/venues/search',
		params = parms)
	if jsn is None:
	    return

	htmlbegin(self, "Venue search")
	userheader(self, client, lat, lon)

	response = jsn.get('response')
	if response is None:
	    logging.error('Missing response from /venues/search:')
	    logging.error(jsn)
	    return jsn

	self.response.out.write("""
<form class="formbox" action="/venues" method="get">
Search Venues: <input class="inputbox" type="text" name="query" size="8"><input class="submitbutton" type="submit" value="Search"></form>
""")

	self.response.out.write('<p>' + venues_fmt(response, lat, lon))

	self.response.out.write("""
<form class="formbox" action="/addvenue" method="post">
Not found? Add a venue here and check in:<br><input class="inputbox" type="text" name="vname" size="16"><input class="submitbutton" type="submit" value="Add Venue"></form>
""")

	debug_json(self, jsn)
	htmlend(self)

def deg_min(st):
    deg = st[:2]
    min = st[2:]
    if min == '':
	min = '0'
    if len(min) > 2:
	min = min[:2] + '.' + min[2:]
    return (deg, min)

def parse_coord(coordstr):
    """
    Parse user-entered coordinates.
    These coordinates are entered as digits only. The string is split into
    two halves. The first half fills in dd mm.mmm in the latitude and 
    the second half fills in dd mm.mmm in the longitude.
    """
    mid = int((len(coordstr) + 1) / 2)
    latstr = coordstr[:mid]
    lonstr = coordstr[mid:]

    (d, m) = deg_min(latstr)
    lat = "%.6f" % (int(d) + float(m) / 60)

    (d, m) = deg_min(lonstr)
    lon = "%.6f" % -(int(d) + float(m) / 60)

    return (lat, lon)

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
	htmlbegin(self, 'Set location')
	self.response.out.write("""
<noscript>
<p><span class="error">No Javascript support or Javascript disabled.</span> Can't set location.
</noscript>
<p><span id="error"></span><span id="output"></span>
<form class="formbox" action="/setloc" onSubmit="box_onsubmit(); return false;" method="get">
Search again? <input class="inputbox" type="text" name="newloc" id="newloc"
size="16"><input class="submitbutton" type="submit" value="Go"></form>
<script type="text/javascript" src="http://maps.googleapis.com/maps/api/js?sensor=false"></script>
<script type="text/javascript" src="lib.js"></script>
<script type="text/javascript" src="geocode.js"></script>
""")

	newloc = self.request.get('newloc').strip()

	if re.match('^\d{6,}$', newloc):
	    (lat, lon) = parse_coord(newloc)
	    set_coords(self, lat, lon)
	    self.redirect('/venues')
	    return

	self.response.out.write("""
<script>
window.onload = do_geocode('%s');
</script>
""" % newloc);
	htmlend(self)

class SetlocHandler(webapp.RequestHandler):
    """
    This handles the 'set location' input box. If the locations string is six
    or more digits, it will be parsed as user-input coordinates. Otherwise, it
    will be fed to the Google Geocoding API.
    """
    def get(self):
	self.post()

    def post(self):
	no_cache(self)

	htmlbegin(self, 'Set location')

	newloc = self.request.get('newloc').strip()

	if re.match('^\d{6,}$', newloc):
	    (lat, lon) = parse_coord(newloc)
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
	jsn = simplejson.loads(output)

	status = jsn.get('status')
	if not status:
	    status = 'Unknown Error'
	if status != 'OK' and status != 'ZERO_RESULTS':
	    errorpage(self,
		    'Error from Google Geocoding API: %s' % status)
	    return

	results = jsn.get('results')
	if results:
	    self.response.out.write("""
<p>Did you mean?
<ul class="vlist">
%s
</ul>
""" % ''.join(
    ['<li>%s</li>' % geocode_result_fmt(res) 
	for res in results]))
	else:
	    self.response.out.write('<p>No search results.')

	self.response.out.write("""
<form class="formbox" action="/setloc" method="get">
Search again? <input class="inputbox" type="text" name="newloc" size="16"><input class="submitbutton" type="submit" value="Go"></form>
""")

	htmlend(self)

def geocode_result_fmt(result):
    addr = result.get('formatted_address', '')
    geometry = result.get('geometry', {})
    location = geometry.get('location', {})
    lat = location.get('lat', 0)
    lng = location.get('lng', 0)

    s = '<a class="button" href="/coords?%s">%s</a>' % (
	    escape(urllib.urlencode({
		'geolat' : lat,
		'geolong' : lng,
		})),
	    escape(addr))
    s += '<br>%s' % convcoords(lat, lng)
    s +=  google_map(lat, lng)
    return s

class CoordsHandler(webapp.RequestHandler):
    """
    This handles user-input coordinates. Sets the location to 
    those coordinates and brings up the venue search page.
    """
    def get(self):
	self.post()

    def post(self):
	no_cache(self)

	htmlbegin(self, "Change location")

	geolat = self.request.get('geolat')
	geolong = self.request.get('geolong')

	# geolat/geolong are float parameters. Move to those coordinates.
	if isFloat(geolat) and isFloat(geolong):
	    set_coords(self, geolat, geolong)
	    self.redirect('/venues')
	else:
	    self.redirect('/')

	htmlend(self)

def checkin_badge_fmt(badge):
    iconurl = ""
    img = badge.get('image')
    if img is not None:
	iconurl = img['prefix'] + str(img['sizes'][0]) + img['name']

    return """
<p><img src="%s" style="float:left">
You've unlocked the %s badge: 
%s<br style="clear:both">
""" % (iconurl, badge.get('name', ''), badge.get('description', ''))

def checkin_score_fmt(score):
    return """
<p><img src="%s" style="float:left">
%s points: %s<br style="clear:both">
""" % (score['icon'], score['points'], score['message'])

def find_notifs(notif, ntype):
    return [n['item'] for n in notif if n['type'] == ntype]

def checkin_fmt(checkin, notif):
    """
    Format checkin messages.
    """
    msgs = find_notifs(notif, 'message')
    if len(msgs) > 0:
	s = '<p>%s' % escape(msgs[0]['message'])

    venue = checkin.get('venue')
    if venue is not None:
	s += '<p><a class="button" href="/venue?vid=%s">%s</a><br>%s' % ( 
		venue['id'], escape(venue['name']), addr_fmt(venue))

	location = venue.get('location')
	if location is not None:
	    lat = location.get('lat')
	    lng = location.get('lng')
	    if lat is not None and lng is not None:
		# Add static Google Map to the page.
		s += google_map(lat, lng)

	pcat = get_prim_category(venue.get('categories'))
	if pcat is not None:
	    s += category_fmt(pcat)

    mayor = None
    mayors = find_notifs(notif, 'mayorship')
    if len(mayors) > 0:
	mayor = mayors[0]

    if mayor is not None:
	user = mayor.get('user')
	msg = escape(mayor['message'])
	s += '<p>%s' % msg if user is None else """
<p><img src="%s" style="float:left">%s<br style="clear:both">
""" % (user['photo'], msg)
    
    badges = find_notifs(notif, 'badge')
    if len(badges) > 0:
	s += ''.join([checkin_badge_fmt(b) for b in badges[0].values()])

    scores = find_notifs(notif, 'score')
    if len(scores) > 0:
	s += ''.join([checkin_score_fmt(score) 
	    for score in scores[0]['scores']])

    specials = find_notifs(notif, 'special')
    if len(specials) > 0:
	s += ''.join([special_fmt(item.get('special', {}))
	    for item in specials])

    leaderboard = find_notifs(notif, 'leaderboard')
    if len(leaderboard) > 0:
	s += checkin_ldr_fmt(leaderboard[0])
    
    return s

def checkin_ldr_row_fmt(leader):
    user = leader.get('user', {})
    scores = leader.get('scores', {})
    return """
<p><img src="%s" style="float:left"> #%d: %s %s from %s<br>
%d points, %d checkins, %d max<br style="clear:both">
""" % (user.get('photo', ''),
	leader.get('rank', 0),
	user.get('firstName', ''),
	user.get('lastName', ''),
	user.get('homeCity', ''),
	scores.get('recent', 0),
	scores.get('checkinsCount', 0),
	scores.get('max', 0))

def checkin_ldr_fmt(leaderboard):
    s = ''

    leaders = leaderboard.get('leaderboard', [])
    s += ''.join([checkin_ldr_row_fmt(l) for l in leaders])

    s += '<p>%s' % leaderboard.get('message', '')
    return s

def do_checkin(self, client, vid):
    (lat, lon) = coords(self)

    jsn = call4sq(self, client, 'post', path='/checkins/add',
	    params = {
		"venueId" : vid,
		"broadcast" : "public",
		})
    if jsn is None:
	return

    htmlbegin(self, "Check in")
    userheader(self, client, lat, lon)

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

    self.response.out.write(checkin_fmt(checkin, notif))

    debug_json(self, jsn)
    htmlend(self)

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

	do_checkin(self, client, vid)

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

	do_checkin(self, client, venue['id'])

class AboutHandler(webapp.RequestHandler):
    """
    Handler for About command.
    """
    def get(self):
	# This page should be cached. So omit the no_cache() call.
	htmlbegin(self, "About", nolocate = True)
	self.response.out.write(__doc__)
	htmlend(self, noabout=True, nologout=True)

class GeoLocHandler(webapp.RequestHandler):
    """
    Geolocation Handler with GPS monitoring and refresh.
    Uses HTML5 Geolocation API.
    """
    def get(self):
	# This page should be cached. So omit the no_cache() call.
	htmlbegin(self, "Detect Location")
	self.response.out.write("""
<noscript>
<p><span class="error">No Javascript support or Javascript disabled.</span> Can't detect location.
</noscript>
<p><span id="error">&nbsp;</span><span id="output">&nbsp;</span>
<p><span id="map">&nbsp;</span>
<script type="text/javascript" src="lib.js"></script>
<script type="text/javascript" src="geoloc.js"></script>
""")
	htmlend(self)

class PurgeHandler(webapp.RequestHandler):
    """
    Purge old database entries from CoordsTable and AuthToken.
    """
    def get(self):
	no_cache(self)

	cutoffdate = (date.today() - timedelta(days=30)).isoformat()
	creatclause = "WHERE created < DATE('%s')" % cutoffdate

	htmlbegin(self, 'Purge old database entries')

	query = AccessToken.gql(creatclause)
	count = 0
	for result in query:
	    result.delete()
	    count += 1
	self.response.out.write('<p>Deleted %d old entries from AccessToken table' % count)

	query = CoordsTable.gql(creatclause)
	count = 0
	for result in query:
	    result.delete()
	    count += 1
	self.response.out.write('<p>Deleted %d old entries from CoordsTable table' % count)

	memcache.flush_all()
	self.response.out.write('<p>Flushed memcache')

	htmlend(self)

class CheckinLong2Handler(webapp.RequestHandler):
    """
    Continuation of CheckinLongHandler after the user submits the
    checkin form with options.
    """
    def post(self):
	self.get()

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

	shout = self.request.get('shout')
	private = int(self.request.get('private'))
	twitter = int(self.request.get('twitter'))
	facebook = int(self.request.get('facebook'))

	broadstrs = []
	if private:
	    broadstrs += 'private'
	else:
	    broadstrs += 'public'
	if twitter:
	    broadstrs += 'twitter'
	if facebook:
	    broadstrs += 'facebook'

	jsn = call4sq(self, client, 'post', path='/checkins/add',
		params = {
		    'venueId' : vid,
		    'shout' : shout,
		    'broadcast' : ','.join(broadstrs),
		    })
	if jsn is None:
	    return

	htmlbegin(self, "Check in")
	userheader(self, client, lat, lon)

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

	self.response.out.write(checkin_fmt(checkin, notif))

	debug_json(self, jsn)
	htmlend(self)

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

	jsn = call4sq(self, client, 'get', '/settings/all')
	if jsn is None:
	    return

	htmlbegin(self, "Check in")
	userheader(self, client, lat, lon)

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

	self.response.out.write('<p>Check in @ %s' % escape(vname))

	sel = 'selected="selected"'

	self.response.out.write("""
<form action="/checkin_long2" method="post">
Shout (optional): <input class="inputbox" type="text" name="shout" size="15"><br>
<input type="hidden" value="%s" name="vid">
<input class="formbutton" type="submit" value="check-in"><br>
<select name="private">
<option value="1" %s>Don't show your friends</option>
<option value="0" %s>Show your friends</option>
</select><br>
<select name="twitter">
<option value="0" %s>Don't send to Twitter</option>
<option value="1" %s>Send to Twitter</option>
</select><br>
<select name="facebook">
<option value="0" %s>Don't send to Facebook</option>
<option value="1" %s>Send to Facebook</option>
</select><br>
</form>
"""
	    % ( escape(vid), private and sel, private or sel,
		twitter or sel, twitter and sel,
		facebook or sel, facebook and sel ))

	debug_json(self, jsn)
	htmlend(self)

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

	htmlbegin(self, "Specials")
	userheader(self, client, lat, lon)

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

	if specials['count'] == 0:
	    self.response.out.write('<p>No specials nearby')
	else:
	    self.response.out.write(specials_fmt(specials['items']))

	debug_json(self, jsn)
	htmlend(self)

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

def photo_full_fmt(photo, venue_id = None, checkin_id = None):
    if venue_id:
	backurl = '/venue?vid=%s' % escape(venue_id)
    else:
	backurl = '/comments?chkid=%s' % escape(checkin_id)
    return '<p><a href="%s"><img src="%s"></a><br>' % (
	    backurl, photo['url'])
	    
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

	htmlbegin(self, "Photo")
	userheader(self, client, lat, lon)

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

	self.response.out.write(photo_full_fmt(photo, 
	    checkin_id = checkin_id, venue_id = venue_id))

	debug_json(self, jsn)
	htmlend(self)


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

	htmlbegin(self, "Checkin Comments")
	userheader(self, client, lat, lon)

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

	self.response.out.write(checkin_comments_fmt(checkin))

	self.response.out.write("""
<p>
<form style="margin:0; padding:0;" action="/addcomment" method="post">
<input class="inputbox" type="text" name="text" size="15"><br>
<input type="hidden" value="%s" name="chkid">
<input class="formbutton" type="submit" value="Add comment"><br>
</form>
""" % escape(checkin_id))

	self.response.out.write("""
<p>
<form style="margin:0; padding:0;" enctype="multipart/form-data" action="/addphoto" method="post">
<input class="inputbox" type="file" name="photo"><br>
<input type="hidden" value="%s" name="chkid">
<input class="formbutton" type="submit" value="Add JPEG photo"><br>
</form>
""" % escape(checkin_id))

	debug_json(self, jsn)
	htmlend(self)

def comment_fmt(comment, checkin, dnow):
    return '<p>%s: %s (%s)<br>%s<br>' % (
	    name_fmt(comment['user']),
	    comment['text'],
	    fuzzy_delta(dnow - datetime.fromtimestamp(comment['createdAt'])),
	    del_comment_cmd(checkin, comment),
	    )

def photo_fmt(photo, dnow, venue_id = None, checkin_id = None):
    imgurl = photo['url']

    # If multiple sizes are available, then pick the largest photo that is not
    # greater than 150 pixels in width. If none fit, pick the smallest photo.
    if photo['sizes']['count'] > 0:
	_photos = filter(lambda p:p['width'] <= 150, photo['sizes']['items'])
	if _photos:
	    imgurl = max(_photos, key = lambda p:p['width'])['url']
	else:
	    imgurl = min(photo['sizes']['items'], key = lambda p:p['width'])['url']

    photoparms = { 'photoid' : photo['id'] }
    if venue_id is not None:
	photoparms['venid'] = venue_id
    else:
	photoparms['chkid'] = checkin_id
    photourl = '/photo?%s' % escape(urllib.urlencode(photoparms))

    return '<p>%s:<br><a href="%s"><img src="%s"></a><br>(%s)<br>' % (
	    name_fmt(photo['user']),
	    photourl,
	    imgurl,
	    fuzzy_delta(dnow - datetime.fromtimestamp(photo['createdAt'])),
	    )

def del_comment_cmd(checkin, comment):
    return '<a class="vbutton" href="/delcomment?chkid=%s&commid=%s">delete</a>' % (
	    checkin['id'], comment['id'])

def checkin_comments_fmt(checkin):
    s = ''
    dnow = datetime.utcnow()
    s += '<p></p>' + history_checkin_fmt(checkin, dnow)
    
    s += '<p>-- %s --' % pluralize(checkin['comments']['count'], 'comment')
    if checkin['comments']['count'] > 0:
	s += ''.join([comment_fmt(c, checkin, dnow) for c in checkin['comments']['items']])

    s += '<p>-- %s --' % pluralize(checkin['photos']['count'], 'photo')
    if checkin['photos']['count'] > 0:
	s += ''.join([photo_fmt(c, dnow, checkin_id = checkin['id']) 
	    for c in checkin['photos']['items']])

    return s

class UnknownHandler(webapp.RequestHandler):
    """
    Handle bad URLs.
    """
    def get(self, unknown_path):
	errorpage(self, 'Unknown URL: /%s' % escape(unknown_path), 404)

def main():
    # logging.getLogger().setLevel(logging.DEBUG)
    application = webapp.WSGIApplication([
	('/', MainHandler),
	('/login', LoginHandler),
	('/login2', LoginHandler2),
	('/oauth', OAuthHandler),
	('/logout', LogoutHandler),
	('/venue', VInfoHandler),
	('/history', HistoryHandler),
	('/debug', DebugHandler),
	('/notif', NotifHandler),
	('/leader', LeaderHandler),
	('/badges', BadgesHandler),
	('/mayor', MayorHandler),
	('/friends', FriendsHandler),
	('/shout', ShoutHandler),
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
    util.run_wsgi_app(application)


if __name__ == '__main__':
    main()

# vim:set tw=0:
