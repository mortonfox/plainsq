// Javascript for Geolocation handler page.

var itercount, watchid, lastupdate;

function show(msg) {
    var out = document.getElementById('output');
    out.innerHTML = msg;

    var err = document.getElementById('error');
    err.innerHTML = '';
}

function error(msg) {
    var err = document.getElementById('error');
    err.innerHTML = '<span class="error">' + msg + '</span><br>';
}

function map(lat, lon) {
    var mapelem = document.getElementById('map');
    mapelem.innerHTML = '<img width="250" height="250" alt="[Google Map]" '+
	'src="http://maps.google.com/maps/api/staticmap?' +
	'size=250x250&format=gif&sensor=true&zoom=14&' +
	'markers=size:mid|color:blue|' + lat + ',' + lon + '">';
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

function success_callback(pos) {
    var lat, lon, now;

    // Don't update too frequently.
    now = (new Date()).getTime();
    if (now - lastupdate < 2000) {
	return;
    }
    lastupdate = now;

    itercount += 1;
    lat = pos.coords.latitude;
    lon = pos.coords.longitude;
    show(conv_coord(lat, 'NS') + ' ' + conv_coord(lon, 'EW') + 
	' (' + itercount + 
	') <a class="button" href="/coords?geolat=' + lat + 
	'&geolong=' + lon + '">Go</a>');
    map(lat, lon);
}

function start() {
    itercount = 0;
    lastupdate = 0;
    watchid = null;

    if (navigator.geolocation) {
	show('Detecting location...');
	watchid = navigator.geolocation.watchPosition(
	    success_callback, 
	    error_callback, 
	    { 
		enableHighAccuracy: true, 
		maximumAge: 0
	    }
	);
    }
    else {
	error('Geolocation API not supported in this browser.');
    }
}

function stop() {
    if (watchid !== null) {
	navigator.geolocation.clearWatch(watchid);
	watchid = null;
    }
}

window.onload = start;
window.onunload = stop;

// -- End --
