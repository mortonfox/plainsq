// Shared javascript functions.

// Figure out how big we can make the map in this browser.
function map_size() {
    var mapDim;
    var winW = 300, winH = 300;
    if (document.body && document.body.offsetWidth) {
	winW = document.body.offsetWidth;
	winH = document.body.offsetHeight;
    }
    if (document.compatMode=='CSS1Compat' &&
	    document.documentElement &&
	    document.documentElement.offsetWidth ) {
		winW = document.documentElement.offsetWidth;
		winH = document.documentElement.offsetHeight;
	    }
    if (window.innerWidth && window.innerHeight) {
	winW = window.innerWidth;
	winH = window.innerHeight;
    }

    // Bing Map image can be no bigger than 900x834. To be safe, we limit it to
    // 800 pixels. At the other extreme, we don't want the map to be smaller
    // than 250 pixels.
    return Math.max(Math.min(winW - 25, winH - 150, 800), 250);
}

function map_image(lat, lon) {
    var coords, mapdim, maphtml;
    coords = encodeURIComponent(lat) + ',' + encodeURIComponent(lon);
    mapdim = map_size();

    switch (window.map_provider) {

    case 'bing':
	maphtml = '<img id="gmap" width="' + mapdim + '" height="' + mapdim + '" alt="[Bing Map]" '+
	    'src="http://dev.virtualearth.net/REST/v1/Imagery/Map/Road/' + 
	    coords + '/14?ms=' + mapdim + ',' + mapdim + '&pp=' + coords + 
	    ';0&key=Aha1lOg_Dx1TU7quU-wNTgDN3K3fI9d4MYRgNGIIX1rQI7SBHs4iLB6LRnbKFN5c">';
	break

    default:
	maphtml = '<img id="gmap" width="' + mapdim + '" height="' + mapdim + '" alt="[Google Map]" '+
	    'src="http://maps.google.com/maps/api/staticmap?' +
	    'size=' + mapdim + 'x' + mapdim + '&format=gif&sensor=true&zoom=14&' +
	    'markers=size:mid|color:blue|' + coords + '">';
	break;
    }

    return maphtml;
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
