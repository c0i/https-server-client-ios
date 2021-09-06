
# python3
# https://gist.github.com/dergachev/7028596#gistcomment-3708957

from http.server import HTTPServer, SimpleHTTPRequestHandler
import ssl, os
# os.system("openssl req -nodes -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365 -subj '/CN=localhost'")
port = 443

httpd = HTTPServer(('0.0.0.0', port), SimpleHTTPRequestHandler)
httpd.socket = ssl.wrap_socket(httpd.socket, keyfile='private.key', certfile="certificate.pem", server_side=True)
print(f"Server running on https://0.0.0.0:{port}")
httpd.serve_forever()