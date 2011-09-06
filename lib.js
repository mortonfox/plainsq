// Shared javascript functions.

function google_map(lat, lon) {
    return '<img id="gmap" width="250" height="250" alt="[Google Map]" '+
	'src="http://maps.google.com/maps/api/staticmap?' +
	'size=250x250&format=gif&sensor=true&zoom=14&' +
	'markers=size:mid|color:blue|' + encodeURIComponent(lat) + ',' +
	encodeURIComponent(lon) + '">';
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

function conv_coords(lat, lon) {
    return conv_coord(lat, 'NS') + ' ' + conv_coord(lon, 'EW')
}


// vim:set tw=0:
