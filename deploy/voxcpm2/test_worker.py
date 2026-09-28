"""CPU-only protocol harness; it never claims a GPU-rendered voice."""
import http.client
import json
import struct
import tempfile
import threading
import unittest
import socket
from pathlib import Path

import numpy as np

from worker import Worker, BoundedHTTPServer, handler_for, pack, unpack, load_policy


class FakeModel:
    class tts_model:
        sample_rate = 48000

    def __init__(self):
        self.calls = []

    def generate(self, **kwargs):
        self.calls.append(kwargs)
        return np.array([0.5, -0.5], dtype=np.float32)


class WorkerTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.model = FakeModel()
        self.limits = load_policy(Path(__file__).with_name("serving-policy.default.json"))
        self.worker = Worker(self.model, "pinned-checkpoint", self.tmp.name, "t" * 32, self.limits)
        self.server = BoundedHTTPServer(("127.0.0.1", 0), handler_for(self.worker),
                                        self.limits["upload_read_deadline_ms"])
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.conn = http.client.HTTPConnection("127.0.0.1", self.server.server_port, timeout=2)

    def tearDown(self):
        self.conn.close()
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2)
        self.tmp.cleanup()

    def request(self, method, path, body=None, authorized=True):
        headers = {"Authorization": "Bearer " + ("t" * 32 if authorized else "bad")}
        self.conn.request(method, path, body=body, headers=headers)
        response = self.conn.getresponse()
        return response.status, response.read()

    def test_banked_ref_render_returns_pcm_and_exact_target_metadata(self):
        target = {"voice_id": "owner-voice", "owner": "5e" * 16,
                  "register": "neutral", "reference_revision": "a" * 32,
                  "limits": self.limits, "warm": self.worker.target()}
        wav = b"RIFF0000WAVEfmt "
        status, ready = self.request("GET", "/ready")
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(ready), target["warm"])
        self.assertEqual(self.model.calls, [])
        body = pack({"target": target, "text": "hello", "transcript": "reference words"}, wav)
        status, received = self.request("POST", "/render", body)
        self.assertEqual(status, 200)
        meta, pcm = unpack(received)
        self.assertEqual(meta, {"target": target, "sample_rate": 48000, "channels": 1})
        self.assertEqual(struct.unpack("<hh", pcm), (16383, -16383))
        self.assertEqual(len(self.model.calls), 1)
        call = self.model.calls[0]
        self.assertEqual(call["text"], "hello")
        self.assertEqual(call["prompt_text"], "reference words")
        self.assertEqual(call["reference_wav_path"], call["prompt_wav_path"])
        self.assertFalse(__import__("pathlib").Path(call["reference_wav_path"]).exists())

    def target(self):
        return {"voice_id": "owner-voice", "owner": "5e" * 16,
                "register": "neutral", "reference_revision": "a" * 32,
                "limits": self.limits, "warm": self.worker.target()}

    def replace_worker(self, model, limits):
        self.conn.close()
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2)
        self.limits = limits
        self.model = model
        self.worker = Worker(model, "pinned-checkpoint", self.tmp.name, "t" * 32, limits)
        self.server = BoundedHTTPServer(("127.0.0.1", 0), handler_for(self.worker),
                                        limits["upload_read_deadline_ms"])
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.conn = http.client.HTTPConnection("127.0.0.1", self.server.server_port, timeout=2)

    def test_refuses_unauthorized_and_stale_targets(self):
        status, _ = self.request("GET", "/ready", authorized=False)
        self.assertEqual(status, 401)
        target = {"voice_id": "owner-voice", "owner": "5e" * 16,
                  "register": "neutral", "warm": {**self.worker.target(), "boot_id": "stale"}}
        status, _ = self.request("POST", "/render",
                                 pack({"target": target, "text": "hi", "transcript": "ref"},
                                      b"RIFF0000WAVEfmt "))
        self.assertEqual(status, 400)
        self.assertEqual(self.model.calls, [])

    def test_changed_policy_narrows_render_and_worker_rejects_widening(self):
        narrower = {**self.limits, "max_text_bytes": 4}
        target = {**self.target(), "limits": narrower}
        body = pack({"target": target, "text": "hello", "transcript": "ref"},
                    b"RIFF0000WAVEfmt ")
        self.assertEqual(self.request("POST", "/render", body)[0], 400)
        target["limits"] = {**self.limits, "max_text_bytes": 65536}
        self.assertEqual(self.request("POST", "/render", pack(
            {"target": target, "text": "hi", "transcript": "ref"},
            b"RIFF0000WAVEfmt "))[0], 400)

    @staticmethod
    def _metadata_straddles(target, limit):
        target["limits"] = {**target["limits"], "max_header_bytes": limit}
        request = {"target": target, "text": "a", "transcript": "a"}
        response = {"target": target, "sample_rate": 48000, "channels": 1}
        return (len(json.dumps(request, separators=(",", ":")).encode()) <= limit <
                len(json.dumps(response, separators=(",", ":")).encode()))

    def test_large_manifest_deadline_and_narrowed_request_metadata(self):
        from worker import validate_limits
        parent = {**self.limits, "http_deadline_ms": 120001}
        self.assertEqual(validate_limits(parent)["http_deadline_ms"], 120001)
        self.replace_worker(FakeModel(), parent)
        self.assertEqual(self.request("GET", "/ready")[0], 200)
        self.assertEqual(self.request("POST", "/render", pack(
            {"target": self.target(), "text": "hi", "transcript": "ref"},
            b"RIFF0000WAVEfmt "))[0], 200)
        self.model.calls.clear()
        # A narrower request is authoritative even though deployment permits
        # more metadata; this previously rendered despite its 1024-byte row.
        target = {**self.target(), "limits": {**self.limits, "max_header_bytes": 1024}}
        body = pack({"target": target, "text": "hi", "transcript": "r" * 1400},
                    b"RIFF0000WAVEfmt ")
        self.assertGreater(int.from_bytes(body[:4], "big"), 1024)
        self.assertEqual(self.request("POST", "/render", body)[0], 400)
        self.assertEqual(self.model.calls, [])
        # A caller can also narrow below the response metadata footprint.
        target = self.target()
        request = {"target": target, "text": "a", "transcript": "a"}
        response = {"target": target, "sample_rate": 48000, "channels": 1}
        req_size = len(json.dumps(request, separators=(",", ":")).encode())
        resp_size = len(json.dumps(response, separators=(",", ":")).encode())
        narrow = next((limit for limit in range(req_size - 16, resp_size + 16)
                       if self._metadata_straddles(target, limit)), None)
        self.assertIsNotNone(narrow, "fixture must straddle response header size")
        target["limits"]["max_header_bytes"] = narrow
        self.assertEqual(self.request("POST", "/render", pack(
            {"target": target, "text": "a", "transcript": "a"},
            b"RIFF0000WAVEfmt "))[0], 400)
        self.assertEqual(self.model.calls, [])

    def test_continuous_upload_and_incomplete_headers_obey_elapsed_deadline(self):
        limits = {**self.limits, "upload_read_deadline_ms": 250}
        self.replace_worker(FakeModel(), limits)
        body = pack({"target": self.target(), "text": "hi", "transcript": "ref"},
                    b"RIFF0000WAVEfmt ")
        sock = socket.create_connection(("127.0.0.1", self.server.server_port), 2)
        sock.settimeout(2)
        sock.sendall(("POST /render HTTP/1.1\r\nHost: localhost\r\n"
                      "Authorization: Bearer " + "t" * 32 +
                      f"\r\nContent-Length: {len(body)}\r\n\r\n").encode())
        # Finish later than the absolute deadline without ever being idle for
        # a full 250 ms. Buffered `read()` used to accept this as HTTP 200.
        for offset in range(0, len(body), 50):
            try:
                sock.sendall(body[offset:offset + 50])
            except (BrokenPipeError, ConnectionResetError):
                break
            threading.Event().wait(0.075)
        self.assertIn(b"408", sock.recv(4096))
        sock.close()
        self.assertEqual(self.worker.model.calls, [])
        # Absolute cutoff also applies while headers have not completed.
        sock = socket.create_connection(("127.0.0.1", self.server.server_port), 2)
        sock.settimeout(2)
        sock.sendall(("POST /render HTTP/1.1\r\nHost: localhost\r\n"
                      "Authorization: Bearer " + "t" * 32 +
                      f"\r\nContent-Length: {len(body)}\r\nX-Partial: ").encode())
        threading.Event().wait(0.35)
        try:
            sock.sendall(b"done\r\n\r\n" + body)
            self.assertNotIn(b"HTTP/1.0 200", sock.recv(4096))
        except (BrokenPipeError, ConnectionResetError):
            pass
        finally:
            sock.close()
        self.assertEqual(self.worker.model.calls, [])
        self.assertEqual(self.request("GET", "/ready")[0], 200)
        self.assertEqual(self.request("POST", "/render", body)[0], 200)

    def test_overload_and_incomplete_upload_release_admission(self):
        class BlockingModel(FakeModel):
            def __init__(self):
                super().__init__()
                self.started = threading.Event()
                self.release = threading.Event()
            def generate(self, **kwargs):
                self.started.set()
                if not self.release.wait(3):
                    raise TimeoutError("test inference timeout")
                return super().generate(**kwargs)
        model = BlockingModel()
        limits = {**self.limits, "max_inflight_uploads": 2,
                  "upload_read_deadline_ms": 250}
        self.replace_worker(model, limits)
        target = self.target()
        body = pack({"target": target, "text": "hi", "transcript": "ref"},
                    b"RIFF0000WAVEfmt ")
        outcomes = []
        observed = threading.Condition()
        def post():
            conn = http.client.HTTPConnection("127.0.0.1", self.server.server_port, timeout=3)
            conn.request("POST", "/render", body=body,
                         headers={"Authorization": "Bearer " + "t" * 32})
            response = conn.getresponse()
            with observed:
                outcomes.append(response.status)
                observed.notify_all()
            response.read()
            conn.close()
        threads = [threading.Thread(target=post) for _ in range(12)]
        threads[0].start()
        self.assertTrue(model.started.wait(2))
        for thread in threads[1:]:
            thread.start()
        # Readiness remains usable even while inference holds a slot.
        self.assertEqual(self.request("GET", "/ready")[0], 200)
        with observed:
            self.assertTrue(observed.wait_for(lambda: outcomes.count(429) >= 10, timeout=3))
        model.release.set()
        for thread in threads:
            thread.join(timeout=4)
            self.assertFalse(thread.is_alive())
        self.assertLessEqual(outcomes.count(200), 2)
        self.assertGreaterEqual(outcomes.count(429), 10)
        # One partial body times out; its slot is freed for the next request.
        sock = socket.create_connection(("127.0.0.1", self.server.server_port), 2)
        sock.sendall(("POST /render HTTP/1.1\r\nHost: localhost\r\n"
                      "Authorization: Bearer " + "t" * 32 +
                      "\r\nContent-Length: 100\r\n\r\npart").encode())
        sock.settimeout(2)
        self.assertIn(b"408", sock.recv(4096))
        sock.close()
        self.assertEqual(self.request("POST", "/render", body)[0], 200)


if __name__ == "__main__":
    unittest.main()
