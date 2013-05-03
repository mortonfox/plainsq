"""
jinjawrap.py

Wrap our Jinja2 code into a separate module.
"""

import os
import urllib
import jinja2
import re
from markupsafe import Markup
from datetime import datetime
from math import (radians, sin, cos, atan2, degrees, sqrt)

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

def convcoords_filter(coords):
    return convcoords(coords[0], coords[1])

jinja_environment.filters['convcoords'] = convcoords_filter

def wordchars_filter(s):
    return re.sub(r'[^a-zA-Z0-9_]', '', encode_any(s))

jinja_environment.filters['wordchars'] = wordchars_filter

def datefmt_filter(s):
    return datetime.fromtimestamp(s).ctime()

jinja_environment.filters['datefmt'] = datefmt_filter

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

def fuzzydelta_filter(s):
    d1 = datetime.fromtimestamp(s)
    dt_now = datetime.utcnow()
    return fuzzy_delta(dt_now - d1)

jinja_environment.filters['fuzzydelta'] = fuzzydelta_filter

def phonefmt_filter(phone):
    phoneStr = ''
    phone = encode_any(phone)
    if len(phone) > 6:
	phoneStr = '(%s)%s-%s' % (phone[0:3], phone[3:6], phone[6:])
    return phoneStr

jinja_environment.filters['phonefmt'] = phonefmt_filter


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

METERS_PER_MILE = 1609.344

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

def renderpage(template_file, params={}):
    """
    Render a page using Jinja2.
    """
    t = jinja_environment.get_template(template_file)
    return t.render(params)

# vim:set tw=0:
