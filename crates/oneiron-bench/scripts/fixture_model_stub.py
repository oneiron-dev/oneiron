"""Retrieval-sensitive fixture answerer and exact-match scorer, not a model benchmark."""
import json
import re
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

UPDATE = re.compile(r"\bcontract launch code was updated from [a-z]+ to ([a-z]+)\b", re.I)


def complete(body):
    model = body["model"]
    system = body["messages"][0]["content"]
    user = json.loads(body["messages"][1]["content"])
    if model.startswith("gpt-4.1-mini"):
        # Judge sees the gold only after an answer is fixed by the caller.
        candidate = user["candidate_answer"].strip().casefold()
        gold = user["gold_answer"].strip().casefold()
        return "1" if candidate and candidate == gold else "0"
    if "search query" in system:
        return "contract launch code"
    # Answering only inspects the question and retrieved context; no gold or labels.
    if "contract launch code" not in user["question"].lower():
        return "unknown"
    match = UPDATE.search(user["context"])
    return match.group(1).lower() if match else "unknown"


class Handler(BaseHTTPRequestHandler):
    def do_POST(self):
        body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
        model = body["model"]
        answer = complete(body)
        payload = {
            "id": "retrieval-fixture", "object": "chat.completion", "model": model,
            "choices": [{"index": 0, "message": {"role": "assistant", "content": answer},
                         "finish_reason": "stop"}],
            "usage": {"prompt_tokens": 100, "completion_tokens": 3, "total_tokens": 103},
        }
        data = json.dumps(payload).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)


if __name__ == "__main__":
    ThreadingHTTPServer(("127.0.0.1", 8080), Handler).serve_forever()
