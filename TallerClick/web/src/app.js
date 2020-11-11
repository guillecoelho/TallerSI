var xmlHTTP = new XMLHttpRequest();
try {
	xmlHTTP.open('GET', 'web.config', false);
	xmlHTTP.send(null);
} catch (e) {
	window.alert('Unable to load the requested file.');
}

window.onload = () => {
	var link = 'https://www.phpbb.com/';
	var iframe = document.createElement('iframe');
	iframe.frameBorder = 0;
	iframe.width = '75%';
	iframe.height = '450px';
	iframe.style = 'position: absolute; left: 13%; margin-top: 33px;';
	iframe.id = 'page';
	iframe.setAttribute('src', link);
	document.getElementById('phpbb').appendChild(iframe);
};

console.log('Esta funcionando');
