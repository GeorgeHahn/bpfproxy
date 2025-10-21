#!/usr/bin/env python3
"""
Custom HTTP server that supports all HTTP methods for testing BPF hook.
"""

import http.server
import socketserver
import json
from datetime import datetime
import sys

PORT = 8080

class AllMethodsHTTPRequestHandler(http.server.BaseHTTPRequestHandler):
    """HTTP request handler that supports all HTTP methods."""

    def send_json_response(self, status_code, data):
        """Send a JSON response."""
        self.send_response(status_code)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS, HEAD, PATCH, TRACE, CONNECT')
        self.send_header('Access-Control-Allow-Headers', 'Content-Type')
        self.end_headers()
        response = json.dumps(data)
        self.wfile.write(response.encode())

    def send_text_response(self, status_code, message):
        """Send a text response."""
        self.send_response(status_code)
        self.send_header('Content-Type', 'text/plain')
        self.send_header('Access-Control-Allow-Origin', '*')
        self.end_headers()
        self.wfile.write(message.encode())

    def log_request_info(self):
        """Log information about the request."""
        timestamp = datetime.now().isoformat()
        print(f"[{timestamp}] {self.command} {self.path} from {self.client_address[0]}")

    def do_GET(self):
        """Handle GET requests."""
        self.log_request_info()
        response = {
            "method": "GET",
            "path": self.path,
            "message": "GET request successful",
            "timestamp": datetime.now().isoformat()
        }
        self.send_json_response(200, response)

    def do_POST(self):
        """Handle POST requests."""
        self.log_request_info()
        content_length = int(self.headers.get('Content-Length', 0))
        post_data = self.rfile.read(content_length).decode('utf-8') if content_length > 0 else ""

        response = {
            "method": "POST",
            "path": self.path,
            "message": "POST request successful",
            "data_received": post_data,
            "timestamp": datetime.now().isoformat()
        }
        self.send_json_response(200, response)

    def do_PUT(self):
        """Handle PUT requests."""
        self.log_request_info()
        content_length = int(self.headers.get('Content-Length', 0))
        put_data = self.rfile.read(content_length).decode('utf-8') if content_length > 0 else ""

        response = {
            "method": "PUT",
            "path": self.path,
            "message": "PUT request successful",
            "data_received": put_data,
            "timestamp": datetime.now().isoformat()
        }
        self.send_json_response(200, response)

    def do_DELETE(self):
        """Handle DELETE requests."""
        self.log_request_info()
        response = {
            "method": "DELETE",
            "path": self.path,
            "message": "DELETE request successful",
            "timestamp": datetime.now().isoformat()
        }
        self.send_json_response(200, response)

    def do_HEAD(self):
        """Handle HEAD requests."""
        self.log_request_info()
        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.send_header('X-Custom-Header', 'HEAD request successful')
        self.end_headers()

    def do_OPTIONS(self):
        """Handle OPTIONS requests (CORS preflight)."""
        self.log_request_info()
        self.send_response(200)
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS, HEAD, PATCH, TRACE, CONNECT')
        self.send_header('Access-Control-Allow-Headers', 'Content-Type, Authorization')
        self.send_header('Access-Control-Max-Age', '3600')
        self.send_header('Allow', 'GET, POST, PUT, DELETE, OPTIONS, HEAD, PATCH, TRACE, CONNECT')
        self.end_headers()

    def do_PATCH(self):
        """Handle PATCH requests."""
        self.log_request_info()
        content_length = int(self.headers.get('Content-Length', 0))
        patch_data = self.rfile.read(content_length).decode('utf-8') if content_length > 0 else ""

        response = {
            "method": "PATCH",
            "path": self.path,
            "message": "PATCH request successful",
            "data_received": patch_data,
            "timestamp": datetime.now().isoformat()
        }
        self.send_json_response(200, response)

    def do_TRACE(self):
        """Handle TRACE requests."""
        self.log_request_info()
        # TRACE should echo back the request
        message = f"TRACE {self.path} HTTP/1.1\r\n"
        for header, value in self.headers.items():
            message += f"{header}: {value}\r\n"

        self.send_text_response(200, message)

    def do_CONNECT(self):
        """Handle CONNECT requests (typically used for HTTPS tunneling)."""
        self.log_request_info()
        # For testing purposes, we'll just acknowledge the CONNECT request
        response = {
            "method": "CONNECT",
            "path": self.path,
            "message": "CONNECT request acknowledged (test mode)",
            "timestamp": datetime.now().isoformat()
        }
        self.send_json_response(200, response)

    def log_message(self, format, *args):
        """Override to customize logging."""
        # Suppress default logging to reduce noise
        pass


class ReuseAddrTCPServer(socketserver.TCPServer):
    """TCP server that allows address reuse."""
    allow_reuse_address = True


def run_server():
    """Run the HTTP server."""
    try:
        with ReuseAddrTCPServer(("", PORT), AllMethodsHTTPRequestHandler) as httpd:
            print(f"HTTP server listening on port {PORT}")
            print(f"Supports: GET, POST, PUT, DELETE, HEAD, OPTIONS, PATCH, TRACE, CONNECT")
            print(f"Server started at {datetime.now().isoformat()}")
            print("-" * 50)
            sys.stdout.flush()
            httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nServer stopped by user")
    except Exception as e:
        print(f"Server error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    run_server()