"""The "outside" for the egress end-to-end tests: a static file server on
127.0.0.1, over TLS or plain HTTP. Prints "PORT <n>" once it listens.

usage: serve.py ROOT [--tls CERT KEY]
"""
import functools
import http.server
import ssl
import sys


class Quiet(http.server.SimpleHTTPRequestHandler):
    def log_message(self, fmt, *args):
        sys.stderr.write("serve: " + (fmt % args) + "\n")


def main():
    root = sys.argv[1]
    handler = functools.partial(Quiet, directory=root)
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), handler)
    if len(sys.argv) > 2 and sys.argv[2] == "--tls":
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(sys.argv[3], sys.argv[4])
        server.socket = ctx.wrap_socket(server.socket, server_side=True)
    print("PORT", server.server_address[1], flush=True)
    server.serve_forever()


main()
