// Shared javascript functions.

function map_image(lat, lon) {
    var coords;
    coords = encodeURIComponent(lat) + ',' + encodeURIComponent(lon);
    return '<img id="gmap" width="250" height="250" alt="[Bing Map]" '+
	'src="http://dev.virtualearth.net/REST/v1/Imagery/Map/Road/' + 
	coords + '/14?ms=250,250&pp=' + coords + 
	';0&key=Aha1lOg_Dx1TU7quU-wNTgDN3K3fI9d4MYRgNGIIX1rQI7SBHs4iLB6LRnbKFN5c">';

    /*
    return '<img id="gmap" width="250" height="250" alt="[Google Map]" '+
	'src="http://maps.google.com/maps/api/staticmap?' +
	'size=250x250&format=gif&sensor=true&zoom=14&' +
	'markers=size:mid|color:blue|' + encodeURIComponent(lat) + ',' +
	encodeURIComponent(lon) + '">';
	*/
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
