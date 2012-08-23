// Javascript for Geolocation handler page.

var itercount, watchid, lastupdate;

function show(msg) {
    var out, err;

    out = document.getElementById('output');
    out.innerHTML = msg;

    err = document.getElementById('error');
    err.innerHTML = '';
}

function error(msg) {
    var err = document.getElementById('error');
    err.innerHTML = '<span class="error">' + msg + '</span><br>';
}

function map(lat, lon) {
    var mapelem = document.getElementById('map');
    mapelem.innerHTML = map_image(lat, lon);
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

// Check if Google Map image has been loaded.
function check_gmap_loaded() {
    var gmap = document.getElementById('gmap');
    if (gmap === null) {
	// If Google Map image is not present at all, then this test is
	// irrelevant anyway.
	return true;
    }

    if (!gmap.complete) {
	return false;
    }

    if (typeof gmap.naturalWidth !== "undefined" && gmap.naturalWidth === 0) {
	return false;
    }

    return true;
}

function success_callback(pos) {
    var lat, lon, now;

    // Don't update too frequently.
    now = (new Date()).getTime();
    if (now - lastupdate < 2000) {
	return;
    }
    if (!check_gmap_loaded() && (now - lastupdate < 10000)) {
	// Allow up to 10 seconds for Google Map to finish loading.
	return;
    }
    lastupdate = now;

    itercount += 1;
    lat = pos.coords.latitude;
    lon = pos.coords.longitude;
    show('<a class="button" href="/coords?geolat=' + encodeURIComponent(lat) + 
	'&geolong=' + encodeURIComponent(lon) + '">' + 
	conv_coords(lat, lon) + ' (' + itercount + ')</a>');
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
