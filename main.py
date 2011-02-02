#!/usr/bin/env python

"""
<p>PlainSquare - This webapp is similar to Foursquare's mobile website but
allows manual input of coordinates. That will allow nearest venue searches and
check-ins by phones that do not have GPS.

<p>Input is optimized for handsets without a full keyboard by allowing coordinate entry using only digits. PlainSquare streamlines the check-in process, making the default no-frills action single-click.

<p>PlainSquare uses Foursquare OAuth to log in, so it does not store user passwords. It is written in Python and is meant to be hosted on Google App Engine.

<pre>
Version: 0.0.1
Author: Po Shan Cheah (morton@mortonfox.com)
Source code: <a href="http://code.google.com/p/plainsq/">http://code.google.com/p/plainsq/</a>
Created: January 28, 2011
Last updated: February 2, 2011
</pre>
"""


from google.appengine.ext import webapp
from google.appengine.ext.webapp import util
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

DEFAULT_LAT = '39.7'
DEFAULT_LON = '-75.6'
COORDS_COOKIE = 'plainsq_coords'
DEBUG_COOKIE = 'plainsq_debug'

METERS_PER_MILE = 1609.344

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

def query_coords(self):
    """
    Run a GQL query to get the coordinates, if available.
    """
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
	    CoordsTable(uuid = uuid, coords = "%s,%s" % (lat, lon)).put()
    else:
	# Update existing record.
	result.coords = "%s,%s" % (lat, lon)
	db.put(result)

def coords(self):
    """
    Get user's coordinates from coords table. If not found in table,
    use default coordinates.
    """
    lat = None
    lon = None

    result = query_coords(self)
    if result is not None:
	try:
	    (lat, lon) = result.coords.split(',')
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
.grayed { color: #7f7f7f; background-color: white; }
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

	    if errorType != '' or errorDetail != '':
		errorpage(self, '%s : %s' % (errorType, errorDetail))
		return

	return jsn

    except DownloadError:
	errorpage(self,
		"Can't connect to Foursquare. #SadMayor Refresh to retry.")
	return

def errorpage(self, msg):
    """
    Used for DownloadError exceptions. Generates an error page.
    """
    self.error(503)

    htmlbegin(self, "Error")
    self.response.out.write('<p><span class="error">Error: %s</span>' % msg)
    htmlend(self)

def userheader(self, client, lat, lon, badges=0, mayor=0):
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

    return user

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
	(lat, lon) = coords(self)

	client = getclient(self)
	if client is None:
	    return

	htmlbegin(self, "Main")

	user = userheader(self, client, lat, lon)
	if user is None:
	    return
	leaderboard = 'http://foursquare.com/iphone/me?uid=%s' \
		% user['id']

        self.response.out.write("""
<p>

<form style="margin:0; padding:0" action="/coords" method="get">
1. Enter coordinates: <input type="text" name="coords" size="8"
accesskey="1"><input type="submit" value="Go"></form>

2. <a href="/venues" accesskey="2">Nearest Venues</a><br>

<form style="margin:0; padding:0" action="/venues" method="get">
3. Search Venues: <input type="text" name="query" size="8"
accesskey="3"><input type="submit" value="Search"></form>

4. <a href="/history" accesskey="4">History</a><br>

5. <a href="/friends" accesskey="5">Find friends</a><br>

<form style="margin:0; padding:0" action="/shout" method="get">
6. Shout: <input type="text" name="message" size="8" accesskey="6">
<input type="submit" value="Shout"></form>

7. <a href="%s" accesskey="7">Leaderboard</a><br>

8. <a href="/badges" accesskey="8">Badges</a><br>

9. <a href="/mayor" accesskey="9">Mayorships</a><br>

10. <a href="/debug" accesskey="0">Turn debugging %s</a><br>

11. <a href="/specials">Specials</a><br>

12. <a href="/geoloc">Detect location</a><br>

<p>Enter coordinates as a series of digits, e.g.:
<br>
<br>39123457512345 means N 39&deg; 12.345' W 75&deg; 12.345'
<br>391234751234 means N 39&deg; 12.340' W 75&deg; 12.340'
<br>3912375123 means N 39&deg; 12.300' W 75&deg; 12.300'
""" % (leaderboard, "off" if get_debug(self) else "on"))

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
	self.del_cookie(COORDS_COOKIE)
	self.del_cookie(DEBUG_COOKIE)

	htmlbegin(self, "Logout")
	self.response.out.write('<p>You have been logged out')
	htmlend(self, nologout=True)

def venue_cmds(venue, checkin_long=False):
    """
    Show checkin/moveto links in venue header.
    """
    s = '<a href="/checkin?vid=%s">[checkin]</a>' % venue['id']
    if checkin_long:
	s += ' <a href="/checkin_long?%s">[checkin with options]</a>' % \
		escape(urllib.urlencode( { 
		    'vid' : venue['id'], 
		    'vname' : venue['name']
		    } ))

    location = venue.get('location')
    if location is not None:
	s += ' <a href="/coords?%s">[move to]</a>' % \
		escape(urllib.urlencode( {
		    'geolat' : location['lat'],
		    'geolong' : location['lng'],
		    } ))

    # Link to venue page on Foursquare regular website.
    s += ' <a href="http://foursquare.com/venue/%s">[web]</a>' % venue['id']
    return s

def addr_fmt(venue):
    """
    Format the address block of a venue.
    """
    s = ''

    location = venue.get('location', {})

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

    contact = venue.get('contact', {})

    phone = contact.get('phone', '')
    if len(phone) > 6:
	s += '(%s)%s-%s<br>' % (phone[0:3], phone[3:6], phone[6:])

    twitter = contact.get('twitter', '')
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
<p><img width="150" height="150" alt="[Google Map]"
src="http://maps.google.com/maps/api/staticmap?%s">
""" % escape(urllib.urlencode( {
    'size' : '150x150', 
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

def venue_checkin_fmt(checkin, dnow):
    """
    Format the info about a user checked in at this venue.
    """
    s = ''
    s += '<p><img src="%s" style="float:left">%s %s from %s' % (
	    checkin['user']['photo'],
	    escape(checkin['user'].get('firstName', '')),
	    escape(checkin['user'].get('lastName', '')),
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

    location = venue.get('location', {})
    # Add static Google Map to the page.
    s += google_map(location['lat'], location['lng'])

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
<p><img src="%s" style="float:left">%s %s (%sx) 
from %s is the mayor<br style="clear:both"> 
""" % (user['photo'], 
	escape(user.get('firstName', '')), 
	escape(user.get('lastName', '')), 
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

    pcat = get_prim_category(venue['categories'])
    if pcat is not None:
	s += category_fmt(pcat)

    s += '<p>%s (%s): %s / %s' % (
	    escape(venue.get('name', '')), special['type'],
	    escape(special.get('message', '')),
	    escape(special.get('description', '')),
	    )
    return s


def specials_fmt(specials, nearby=False):
    """
    Format venue specials.
    """
    return '' if len(specials) == 0 else '<p><b>Specials%s:</b>' % (
	    ' nearby' if nearby else ''
	    ) + ''.join(
		    [special_fmt(x) for x in specials])

def tip_fmt(tip):
    """
    Format a tip on the venue page.
    """
    return """
<p><img src="%s" style="float:left">%s %s from %s says: 
%s (Posted: %s)<br style="clear:both">
""" % (tip['user']['photo'],
	escape(tip['user'].get('firstName', '')),
	escape(tip['user'].get('lastName', '')),
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

def comments_cmd(checkin):
    comments = checkin.get('comments')
    if comments is None:
	count = 0
    else:
	count = comments.get('count', 0)

    if count == 0:
	cstr = 'No comments'
    elif count == 1:
	cstr = '1 comment'
    else:
	cstr = '%s comments' % count

    return '<a href="/comments?chkid=%s">[%s]</a>' % (checkin['id'], cstr)

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
	    s += '<p>%s<br>' % escape(venue['name'])
	else:
	    s += '<p><a href="/venue?vid=%s">%s</a> %s<br>%s' % (
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
	    self.response.out.write(''.join(
		[history_checkin_fmt(c, dnow) for c in checkins['items']]))

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
    img = badge['image']
    iconurl = img['prefix'] + str(img['sizes'][0]) + img['name']

    unlockstr = ''
    unlocks = badge['unlocks']
    if len(unlocks) > 0:
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
	venue['id'], venue['name'], locstr, 
	datetime.fromtimestamp(checkins[0]['createdAt']).ctime())

    desc = badge.get('description')
    if desc is None:
	desc = badge.get('hint', '')

    if unlockstr == '':
	text = '<span class="grayed">%s<br>%s</span>' % (badge['name'], desc)
    else:
	text = '%s<br>%s<br>%s' % (badge['name'], desc, unlockstr)

    return """
<p><img src="%s" style="float:left"> %s<br style="clear:both">
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
	userheader(self, client, lat, lon, badges=1)

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
	    self.response.out.write(''.join([
		badge_fmt(b) for b in badges.values()]))

	debug_json(self, jsn)
	htmlend(self)

def mayor_venue_fmt(venue):
    return '<li><a href="/venue?vid=%s">%s</a> %s<br>%s' % (
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

	user = userheader(self, client, lat, lon, mayor=1)
	if user is None:
	    return

	mayorships = user.get('mayorships', {})
	count = mayorships.get('count', 0)
	if count == 0:
	    self.response.out.write('<p>No mayorships yet.')
	else:
	    self.response.out.write(
		'<ol style="padding: 0 0 0 1.5em">%s</ol>' % 
		''.join([mayor_venue_fmt(v) for v in mayorships['items']]))

	debug_json(self, user)
	htmlend(self)

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

    compass = [ 'S', 'SW', 'W', 'NW', 'N', 'NE', 'E', 'SE', 'S' ]
    return compass[int((brng + 180 + 22.5) / 45)]

def friend_checkin_fmt(checkin, lat, lon, dnow):
    """
    Format checkin record from one friend.
    """
    s = '<p>'

    venue = checkin.get('venue')
    user = checkin.get('user')

    if venue is not None:
	s += '<a href="/venue?vid=%s">%s %s @ %s</a><br>' % (
		venue.get('id'),
		user.get('firstName', ''),
		user.get('lastName', ''),
		venue.get('name', ''),
		)

    shout = checkin.get('shout')
    if shout is not None:
	if venue is None:
	    s += '%s %s: ' % (
		user.get('firstName', ''),
		user.get('lastName', ''))
	s += '"%s"<br>' % escape(shout)

    s += '%s<br>' % comments_cmd(checkin)

    dist = checkin.get('distance')
    if dist is not None:
	dist = float(dist) / METERS_PER_MILE

    if venue is not None:
	s += addr_fmt(venue)

	location = venue.get('location')
	if location is not None:
	    geolat = location.get('lat')
	    geolong = location.get('lng')
	
	if geolat is None or geolong is None:
	    compass = ''
	else:
	    compass = bearing(lat, lon, geolat, geolong)

	if dist is not None:
	    s += '(%.1f mi %s)<br>' % (dist, compass)
    else:
	if dist is not None:
	    s += '(%.1f mi)<br>' % dist

    d1 = datetime.fromtimestamp(checkin['createdAt'])
    s += fuzzy_delta(dnow - d1)

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
	    self.response.out.write(
		''.join(
		    [friend_checkin_fmt(c, lat, lon, dnow) for c in recent]))

	debug_json(self, jsn)
	htmlend(self)

class ShoutHandler(webapp.RequestHandler):
    """
    This handles user shouts.
    """
    def put(self):
	self.get()

    def get(self):
	no_cache(self)
	(lat, lon) = coords(self)

	client = getclient(self)
	if client is None:
	    return

	message = self.request.get('message')

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

	self.response.out.write('<p>%s' % escape(notif[0]['item']['message']))

	debug_json(self, jsn)
	htmlend(self)

def venue_fmt(venue, lat, lon):
    """
    Format a venue in the venue search page.
    """
    s = ''

    s += '<p><a href="/venue?vid=%s">%s</a> %s<br>%s' % (
	    venue['id'], escape(venue['name']), 
	    venue_cmds(venue), addr_fmt(venue))

    # Show distance and bearing from current coordinates.
    dist = venue['location'].get('distance')
    if dist is not None:
	dist = float(dist) / METERS_PER_MILE
	compass = bearing(lat, lon, 
		venue['location']['lat'], venue['location']['lng'])
	s += '(%.1f mi %s)<br>' % (dist, compass)

    return s

def venues_fmt(jsn, lat, lon):
    """
    Format a list of venues in the venue search page.
    """

    groups = jsn.get('groups')
    if groups is None:
	return 'No matching venues found.'

    # Venues may be split across groups so collect them all in one list.
    venues = []
    for group in groups:
	venues.extend(group['items'])

    venues = remove_dup_vids(venues)

    # Sort venues ascending by distance. If distance field is missing,
    # use a very large value.
    venues.sort(key = lambda v: v['location'].get('distance', '1000000'))

    return ''.join([venue_fmt(v, lat, lon) for v in venues])

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

	parms = { "ll" : '%s,%s' % (lat, lon), "limit" : 50 }
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
<form style="margin:0; padding:0" action="/addvenue" method="get"><p>
Add venue here and check in: <input type="text" name="vname" size="15"><input type="submit" value="Add Venue"></p></form>

<p>""" + venues_fmt(response, lat, lon))

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
	    return

	coordinput = self.request.get('coords')

	# Extract digits. Ignore all other characters.
	instr = re.sub(r'[^0-9]', '', coordinput)

	if len(instr) >= 4:
	    (lat, lon) = parse_coord(instr)
	    set_coords(self, lat, lon)
	    self.redirect('/venues')
	else:
	    self.response.out.write(
		    '<p><span class="error">Bad input coords: %s</span>'
		    % escape(coordinput))

	htmlend(self)

def checkin_badge_fmt(badge):
    img = badge['image']
    iconurl = img['prefix'] + str(img['sizes'][0]) + img['name']

    return """
<p><img src="%s" style="float:left">
You've unlocked the %s badge: 
%s<br style="clear:both">
""" % (iconurl, badge['name'], badge['description'])

def checkin_score_fmt(score):
    return """
<p><img src="http://foursquare.com%s" style="float:left">
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
	s += '<p><a href="/venue?vid=%s">%s</a><br>%s' % ( 
		venue['id'], escape(venue['name']), addr_fmt(venue))

	# Add static Google Map to the page.
	s += google_map(venue['location']['lat'], venue['location']['lng'])

	pcat = get_prim_category(venue['categories'])
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
    s += ''.join([checkin_badge_fmt(b) for b in badges])

    scores = find_notifs(notif, 'score')
    if len(scores) > 0:
	s += ''.join([checkin_score_fmt(score) 
	    for score in scores[0]['scores']])
    
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
	no_cache(self)

	client = getclient(self)
	if client is None:
	    return

	vid = self.request.get('vid')

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
	htmlbegin(self, "About")
	self.response.out.write(__doc__)
	htmlend(self, noabout=True, nologout=True)

class GeoLocHandler(webapp.RequestHandler):
    """
    Geolocation Handler. Will attempt to detect location using HTML5
    Geolocation API and set our coordinates accordingly.
    """
    def get(self):
	# This page should be cached. So omit the no_cache() call.
	htmlbegin(self, "Detect Location")
	self.response.out.write("""
<noscript>
<p><span class="error">No Javascript support or Javascript disabled.</span> Can't detect location.
</noscript>
<p><span id="output">&nbsp;</span>
<script type="text/javascript">
function show(msg) {
    var out = document.getElementById('output');
    out.innerHTML = msg;
}

function error(msg) {
    show('<span class="error">' + msg + '</span>');
}

function error_callback(err) {
    switch (err.code) {
    case err.PERMISSION_DENIED:
	error('No permission to get location: ' + err.message);
	break;
    case err.POSITION_UNAVAILABLE:
	error('Could not get location: ' + err.message);
	break;
    case err.TIMEOUT:
	error('Network timeout: ' + err.message);
	break;
    default:
	error('Unknown error: ' + err.message);
	break;
    }
}

function success_callback(pos) {
    show('Detected coordinates: ' + 
	pos.coords.latitude + ',' + pos.coords.longitude);
    // Redirect to our coordinates handler once we have the info.
    window.location = '/coords?geolat=' + pos.coords.latitude + 
	'&geolong=' + pos.coords.longitude
}

if (navigator.geolocation) {
    show('Detecting location...');
    navigator.geolocation.getCurrentPosition(
	success_callback, error_callback, { timeout: 30000 });
}
else {
    error('Geolocation API not supported in this browser.')
}
</script>
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

	htmlend(self)

class CheckinLong2Handler(webapp.RequestHandler):
    """
    Continuation of CheckinLongHandler after the user submits the
    checkin form with options.
    """
    def put(self):
	self.get()

    def get(self):
	no_cache(self)

	(lat, lon) = coords(self)
	client = getclient(self)
	if client is None:
	    return

	vid = self.request.get('vid')
	shout = self.request.get('shout')
	private = int(self.request.get('private'))
	twitter = int(self.request.get('twitter'))
	facebook = int(self.request.get('facebook'))

	broadstrs = []
	if not private:
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

	private = 1
	twitter = 0
	facebook = 0

	if settings['receivePings']:
	    private = 0
	if settings['sendToTwitter']:
	    twitter = 1
	if settings['sendToFacebook']:
	    facebook = 1

	self.response.out.write('<p>Check in @ %s' % escape(vname))

	sel = 'selected="selected"'

	self.response.out.write("""
<form action="/checkin_long2" method="get">
Shout (optional): <input type="text" name="shout" size="15"><br>
<input type="hidden" value="%s" name="vid">
<input type="submit" value="check-in"><br>
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

	jsn = call4sq(self, client, 'post', 
		'/checkins/%s/addcomment' % escape(checkin_id),
		params = { 'text' : text }
		)
	if jsn is None:
	    return

	self.redirect('/comments?chkid=%s' % escape(checkin_id))

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
<form style="margin:0 padding:0" action="/addcomment" method="get">
<input type="text" name="text" size="15"><br>
<input type="hidden" value="%s" name="chkid">
<input type="submit" value="Add comment"><br>
</form>
""" % escape(checkin_id))

	debug_json(self, jsn)
	htmlend(self)

def comment_fmt(comment, checkin, dnow):
    return '<p><img src="%s" style="float:left"> %s %s: %s (%s)<br>%s<br style="clear:both">' % (
	    comment['user'].get('photo', ''),
	    comment['user']['firstName'],
	    comment['user']['lastName'],
	    comment['text'],
	    fuzzy_delta(dnow - datetime.fromtimestamp(comment['createdAt'])),
	    del_comment_cmd(checkin, comment),
	    )

def del_comment_cmd(checkin, comment):
    return '<a href="/delcomment?chkid=%s&commid=%s">[delete]</a>' % (
	    checkin['id'], comment['id'])

def checkin_comments_fmt(checkin):
    s = ''
    dnow = datetime.utcnow()
    s += history_checkin_fmt(checkin, dnow)
    if checkin['comments']['count'] == 0:
	s += '<p>No comments.'
    else:
	s += ''.join([comment_fmt(c, checkin, dnow) for c in checkin['comments']['items']])
    return s

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
	('/badges', BadgesHandler),
	('/mayor', MayorHandler),
	('/friends', FriendsHandler),
	('/shout', ShoutHandler),
	('/venues', VenuesHandler),
	('/coords', CoordsHandler),
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
	], debug=True)
    util.run_wsgi_app(application)


if __name__ == '__main__':
    main()

# vim:set tw=0:
