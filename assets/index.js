var http = require('http');

function serve(ip, port) {
  http.createServer(function(req, res) {
    res.writeHead(200, {'Content-Type': 'text/plain'});
    res.end("Hello");
  }).listen(port, ip);
  console.log(`Server running at http://${ip}:${port}/`);
}
serve('0.0.0.0', 7999);