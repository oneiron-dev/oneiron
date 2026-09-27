"""CPU-only protocol harness; it never claims a GPU-rendered voice."""
import http.client
import json
import struct
import tempfile
import threading
import unittest
from http.server import ThreadingHTTPServer

import numpy as np

from worker import Worker, handler_for, pack, unpack


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
        self.worker = Worker(self.model, "pinned-checkpoint", self.tmp.name, "t" * 32)
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), handler_for(self.worker))
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
        target = {"source_pack": "banked-owner", "owner": "5e" * 16,
                  "register": "neutral", "warm": self.worker.target()}
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

    def test_refuses_unauthorized_and_stale_targets(self):
        status, _ = self.request("GET", "/ready", authorized=False)
        self.assertEqual(status, 401)
        target = {"source_pack": "banked-owner", "owner": "5e" * 16,
                  "register": "neutral", "warm": {**self.worker.target(), "boot_id": "stale"}}
        status, _ = self.request("POST", "/render",
                                 pack({"target": target, "text": "hi", "transcript": "ref"},
                                      b"RIFF0000WAVEfmt "))
        self.assertEqual(status, 400)
        self.assertEqual(self.model.calls, [])


if __name__ == "__main__":
    unittest.main()
