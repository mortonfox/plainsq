// Javascript for geocoding handler page.

function show(msg) {
    var out = document.getElementById('output');
    out.innerHTML = msg;
}

function error(msg) {
    var err = document.getElementById('error');
    err.innerHTML = '<span class="error">' + msg + '</span><br>';
}

function conv_coord(coord, nsew) {
    var d, degs, mins;
    d = nsew[0];
    if (coord < 0) {
	d = nsew[1];
	coord = -coord;
    }
    degs = Math.floor(coord);
    mins = (coord - degs) * 60;
    return d + degs + ' ' + mins.toFixed(3);
}

function fmt_result(result) {
    var addr, s, lat, lng, loc;
    addr = result.formatted_address;
    loc = result.geometry.location;
    lat = loc.lat();
    lng = loc.lng();

    s = '<a class="button" href="/coords?geolat=' + encodeURIComponent(lat) +
	'&geolong=' + encodeURIComponent(lng) + '">' + addr + '</a><br>' +
	conv_coords(lat, lng) + '<p>' + map_image(lat, lng);
    return s;
}

function fmt_results(results) {
    var s, i, len;
    s = 'Did you mean?<ul class="vlist">';
    for (i = 0, len = results.length; i < len; ++i) {
	s += '<li>' + fmt_result(results[i]) + '</li>';
    }
    s += '</ul>';
    return s;
}

function geocode_callback(results, status) {
    switch (status) {
    case google.maps.GeocoderStatus.ZERO_RESULTS:
	show('No results.');
	break;
    case google.maps.GeocoderStatus.OVER_QUERY_LIMIT:
	error('Quota exceeded.');
	break;
    case google.maps.GeocoderStatus.REQUEST_DENIED:
	error('Request denied.');
	break;
    case google.maps.GeocoderStatus.INVALID_REQUEST:
	error('Invalid request.');
	break;
    case google.maps.GeocoderStatus.OK:
	show(fmt_results(results));
	break;
    default:
	error('Unknown error: ' + status);
	break;
    }
}

function do_geocode(name) {
    var geocoder;
    geocoder = new google.maps.Geocoder();
    geocoder.geocode({'address':name}, geocode_callback);
}

function box_onsubmit() {
    var newloc;
    newloc = document.getElementById('newloc').value;
    window.location = '/setlocjs?newloc=' + encodeURIComponent(newloc);
}

// vim:set tw=0:
