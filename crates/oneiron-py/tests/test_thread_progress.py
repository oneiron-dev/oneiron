"""Backend dispatch must let Python threads run and preserve DTOs and errors.

Each probe runs in a separate interpreter. If an SDK call keeps the GIL, its
Python HTTP peer cannot answer. The parent timeout fails promptly instead of
waiting for the SDK's 120-second network timeout.
"""

from http.server import BaseHTTPRequestHandler, HTTPServer
import json
from pathlib import Path
import subprocess
import sys
import threading

import pytest

from oneiron import Oneiron, OneironError


SUCCESS = {
    "witness": {
        "turn_short_id": "turn-probe",
        "message_short_ids": ["message-probe"],
        "receipt_ref": "witness:probe",
    },
    "claim_upsert": {
        "claim_short_id": "claim-probe",
        "approval": "auto",
        "superseded_short_id": None,
        "receipt_ref": "gate:probe",
    },
    "recall": {
        "items": [],
        "scope_honesty": {"out_of_scope_worlds": []},
        "retrieval_meta": {
            "sparse": True, "total_candidates": 0,
            "claims_returned": 0, "deep_pending": None,
        },
        "pack_version": 1,
        "rendered": None,
    },
    "receipts": [],
}
REFUSAL = {
    "code": "THREAD_PROGRESS_REFUSAL",
    "message": "the peer refused after another Python thread ran",
    "suggestions": ["Keep this typed refusal unchanged."],
}


def call(memory, verb):
    if verb == "witness":
        return memory.witness({
            "conversation_ref": "11111111111111111111111111111111",
            "messages": [{
                "author": "user", "message_type": "dialogue",
                "content": "thread progress", "order": 0,
            }],
        })
    if verb == "claim_upsert":
        return memory.claim_upsert({
            "predicate": "preference.travel.seat",
            "subject_ref": "11111111111111111111111111111111",
            "value": {"seat": "window"}, "confidence": 1.0, "source": "user_stated",
        })
    if verb == "recall":
        return memory.recall("thread progress")
    return memory.receipts()


def probe(verb, outcome):
    request_arrived = threading.Event()
    progressed = threading.Event()
    handler_errors = []

    class Handler(BaseHTTPRequestHandler):
        def do_POST(self):
            try:
                assert self.path == f"/v1/core/facade/{verb}"
                self.rfile.read(int(self.headers["Content-Length"]))
                request_arrived.set()
                # No response until a SECOND Python thread runs after ingress.
                assert progressed.wait(5), "Python worker made no progress"
                payload = SUCCESS[verb] if outcome == "success" else {"error": REFUSAL}
                encoded = json.dumps(payload).encode()
                self.send_response(200 if outcome == "success" else 409)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(encoded)))
                self.end_headers()
                self.wfile.write(encoded)
            except Exception as error:
                handler_errors.append(error)

        def log_message(self, *_args):
            pass

    def worker():
        if request_arrived.wait(5):
            progressed.set()

    with HTTPServer(("127.0.0.1", 0), Handler) as server:
        server.timeout = 5
        peer = threading.Thread(target=server.handle_request, daemon=True)
        progress_thread = threading.Thread(target=worker, daemon=True)
        memory = Oneiron.connect(f"http://127.0.0.1:{server.server_port}", "thread-probe")
        peer.start()
        progress_thread.start()
        if outcome == "success":
            assert call(memory, verb) == SUCCESS[verb]
        else:
            with pytest.raises(OneironError) as caught:
                call(memory, verb)
            error = caught.value
            assert error.code == REFUSAL["code"]
            assert error.message == REFUSAL["message"]
            assert error.suggestions == tuple(REFUSAL["suggestions"])
        peer.join(timeout=5)
        progress_thread.join(timeout=5)
        assert not peer.is_alive()
        assert not progress_thread.is_alive()
        assert not handler_errors, handler_errors
        assert request_arrived.is_set() and progressed.is_set()


@pytest.mark.parametrize("verb", list(SUCCESS))
@pytest.mark.parametrize("outcome", ["success", "refusal"])
def test_backend_dispatch_allows_python_thread_progress(verb, outcome):
    result = subprocess.run(
        [sys.executable, str(Path(__file__).resolve()), verb, outcome],
        capture_output=True,
        text=True,
        timeout=20,
        check=False,
    )
    assert result.returncode == 0, result.stdout + result.stderr


@pytest.mark.parametrize("verb", ["witness", "claim_upsert"])
def test_python_input_conversion_stays_typed(verb):
    # Construction is local; malformed input must fail before a network call.
    memory = Oneiron.connect("http://127.0.0.1:9", "conversion-probe")
    with pytest.raises(OneironError) as caught:
        getattr(memory, verb)({})
    assert caught.value.code == "BAD_REQUEST"
    assert caught.value.suggestions


if __name__ == "__main__":
    probe(sys.argv[1], sys.argv[2])
