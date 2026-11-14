"""A stand-in for a llama.cpp reranker on its own Unix socket (L9-15 tests).

Usage: python3 stub_rerank_uds.py <socket> <request log>

Serves HTTP/1.0 on the Unix socket <socket>. GET /health answers ok; POST
/v1/rerank scores each document by how many of the query's words it holds,
and names the request's model, or "stub-reranker" when it names none; any
other request answers 404. Each request is appended to <request log> as one
JSON line: its method, path and JSON body. Standard library only; it serves
until it is signalled.
"""
import json
import os
import socketserver
import sys
from http.server import BaseHTTPRequestHandler

LOG = None


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        """A Unix socket peer has no address to print."""

    def address_string(self):
        return "unix"

    def record(self, body):
        with open(LOG, "a", encoding="utf-8") as log:
            line = {"method": self.command, "path": self.path, "body": body}
            log.write(json.dumps(line) + "\n")

    def answer(self, status, payload):
        data = json.dumps(payload).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        self.record(None)
        if self.path == "/health":
            self.answer(200, {"status": "ok"})
        else:
            self.answer(404, {"error": "not found"})

    def do_POST(self):
        length = int(self.headers.get("Content-Length", "0"))
        body = json.loads(self.rfile.read(length) or b"null")
        self.record(body)
        if self.path != "/v1/rerank":
            self.answer(404, {"error": "not found"})
            return
        words = set(body["query"].lower().split())
        results = [
            {"index": index, "relevance_score": float(len(words & set(document.lower().split())))}
            for index, document in enumerate(body["documents"])
        ]
        self.answer(200, {
            "model": body.get("model", "stub-reranker"),
            "object": "list",
            "usage": {"prompt_tokens": 1, "total_tokens": 1},
            "results": results,
        })


class Server(socketserver.ThreadingMixIn, socketserver.UnixStreamServer):
    daemon_threads = True


def main():
    global LOG
    socket_path, LOG = sys.argv[1], sys.argv[2]
    if os.path.exists(socket_path):
        os.unlink(socket_path)
    with Server(socket_path, Handler) as server:
        server.serve_forever()


if __name__ == "__main__":
    main()
