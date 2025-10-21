#!/usr/bin/env python3
"""
Simple HTTP proxy server for demonstrating BPFHook transparent proxy redirection.
Logs all proxied connections and forwards them to the target server.
"""

import http.server
import socketserver
import urllib.request
import urllib.parse
import json
from datetime import datetime
import sys
import os

PROXY_PORT = int(os.environ.get('PROXY_PORT', 8888))
TARGET_HOST = os.environ.get('TARGET_HOST', 'bpf-target-server')
TARGET_PORT = int(os.environ.get('TARGET_PORT', 8080))

class ProxyHTTPRequestHandler(http.server.BaseHTTPRequestHandler):
    """HTTP proxy request handler that forwards requests and logs them."""

    def proxy_request(self, method):
        """Forward the request to the target server."""
        # Log the incoming request
        timestamp = datetime.now().isoformat()
        client_addr = self.client_address[0]

        print(f"[{timestamp}] PROXY: {method} {self.path} from {client_addr}")
        print(f"  Original destination was intercepted and redirected here")
        print(f"  Forwarding to: {TARGET_HOST}:{TARGET_PORT}{self.path}")

        # Build the target URL
        target_url = f"http://{TARGET_HOST}:{TARGET_PORT}{self.path}"

        # Copy headers
        headers = {}
        for header, value in self.headers.items():
            if header.lower() not in ['host', 'connection']:
                headers[header] = value

        # Add proxy identification
        headers['X-Forwarded-For'] = client_addr
        headers['X-Proxied-By'] = 'BPFHook-Proxy'

        # Read request body if present
        content_length = int(self.headers.get('Content-Length', 0))
        body = self.rfile.read(content_length) if content_length > 0 else None

        try:
            # Create request
            req = urllib.request.Request(target_url, data=body, headers=headers, method=method)

            # Send request to target
            with urllib.request.urlopen(req) as response:
                # Send response status
                self.send_response(response.getcode())

                # Copy response headers
                for header, value in response.headers.items():
                    if header.lower() not in ['connection', 'transfer-encoding']:
                        self.send_header(header, value)

                # Add proxy header
                self.send_header('X-Proxy-Response', 'true')
                self.end_headers()

                # Copy response body
                self.wfile.write(response.read())

                print(f"  Response: {response.getcode()} forwarded back to client")

        except urllib.error.HTTPError as e:
            # Forward HTTP errors
            self.send_response(e.code)
            self.send_header('Content-Type', 'text/plain')
            self.end_headers()
            self.wfile.write(f"Proxy error: {e}".encode())
            print(f"  Error: {e}")

        except Exception as e:
            # Handle other errors
            self.send_response(502)
            self.send_header('Content-Type', 'text/plain')
            self.end_headers()
            self.wfile.write(f"Proxy error: {e}".encode())
            print(f"  Error: {e}")

        print("-" * 60)
        sys.stdout.flush()

    def do_GET(self):
        """Handle GET requests."""
        self.proxy_request('GET')

    def do_POST(self):
        """Handle POST requests."""
        self.proxy_request('POST')

    def do_PUT(self):
        """Handle PUT requests."""
        self.proxy_request('PUT')

    def do_DELETE(self):
        """Handle DELETE requests."""
        self.proxy_request('DELETE')

    def do_HEAD(self):
        """Handle HEAD requests."""
        self.proxy_request('HEAD')

    def do_OPTIONS(self):
        """Handle OPTIONS requests."""
        self.proxy_request('OPTIONS')

    def do_PATCH(self):
        """Handle PATCH requests."""
        self.proxy_request('PATCH')

    def log_message(self, format, *args):
        """Override to suppress default logging."""
        pass


class ReuseAddrTCPServer(socketserver.TCPServer):
    """TCP server that allows address reuse."""
    allow_reuse_address = True


def run_proxy():
    """Run the proxy server."""
    try:
        with ReuseAddrTCPServer(("", PROXY_PORT), ProxyHTTPRequestHandler) as httpd:
            print(f"=" * 60)
            print(f"BPFHook Transparent Proxy Server")
            print(f"=" * 60)
            print(f"Proxy listening on port: {PROXY_PORT}")
            print(f"Forwarding to: {TARGET_HOST}:{TARGET_PORT}")
            print(f"Started at: {datetime.now().isoformat()}")
            print(f"=" * 60)
            print(f"Waiting for intercepted connections...")
            print()
            sys.stdout.flush()
            httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nProxy server stopped")
    except Exception as e:
        print(f"Proxy server error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    run_proxy()