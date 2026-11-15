"""CPU-only protocol harness; it never claims a GPU-rendered voice."""
import base64
import hashlib
import http.client
import json
import os
import socket
import struct
import tempfile
import threading
import unittest
from pathlib import Path

import numpy as np

from worker import Worker, BoundedHTTPServer, handler_for, pack, load_policy


class FakeModel:
    class tts_model:
        sample_rate = 48000

    def __init__(self):
        self.calls = []

    def generate(self, **kwargs):
        self.calls.append(kwargs)
        return np.array([0.5, -0.5], dtype=np.float32)


class VoiceSocket:
    """A minimal masked client for GET /v1/voice: handshake, frames, reader."""

    def __init__(self, port):
        self.sock = socket.create_connection(("127.0.0.1", port), 2)
        self.sock.settimeout(2)
        self._extra = b""

    def handshake(self, bearer="t" * 32):
        key = base64.b64encode(os.urandom(16)).decode("ascii")
        self.key = key
        request = ("GET /v1/voice HTTP/1.1\r\nHost: 127.0.0.1\r\n"
                   "Upgrade: websocket\r\nConnection: Upgrade\r\n"
                   "Sec-WebSocket-Version: 13\r\n"
                   f"Sec-WebSocket-Key: {key}\r\n")
        if bearer is not None:
            request += f"Authorization: Bearer {bearer}\r\n"
        request += "\r\n"
        self.sock.sendall(request.encode())
        data = self._extra
        while b"\r\n\r\n" not in data:
            chunk = self.sock.recv(4096)
            if not chunk:
                break
            data += chunk
        head, _, rest = data.partition(b"\r\n\r\n")
        self._extra = rest
        return int(head.split(b" ", 2)[1]), head

    def send_frame(self, opcode, payload, fin=True):
        mask = os.urandom(4)
        head = bytes([(0x80 if fin else 0x00) | opcode])
        count = len(payload)
        if count <= 125:
            head += bytes([0x80 | count])
        elif count <= 0xFFFF:
            head += bytes([0x80 | 126]) + struct.pack("!H", count)
        else:
            head += bytes([0x80 | 127]) + struct.pack("!Q", count)
        self.sock.sendall(head + mask + bytes(
            byte ^ mask[i & 3] for i, byte in enumerate(payload)))

    def send_text(self, obj):
        if isinstance(obj, dict):
            payload = json.dumps(obj, separators=(",", ":")).encode()
        elif isinstance(obj, bytes):
            payload = obj
        else:
            payload = str(obj).encode()
        self.send_frame(0x1, payload)

    def send_binary(self, data):
        self.send_frame(0x2, data)

    def send_close(self, code=1000):
        self.send_frame(0x8, struct.pack("!H", code))

    def _recv_exactly(self, count):
        while len(self._extra) < count:
            chunk = self.sock.recv(4096)
            if not chunk:
                raise ConnectionError("eof")
            self._extra += chunk
        out, self._extra = self._extra[:count], self._extra[count:]
        return out

    def recv_frame(self):
        head = self._recv_exactly(2)
        byte0, byte1 = head[0], head[1]
        op = byte0 & 0x0F
        masked = byte1 & 0x80
        length = byte1 & 0x7F
        if length == 126:
            (length,) = struct.unpack("!H", self._recv_exactly(2))
        elif length == 127:
            (length,) = struct.unpack("!Q", self._recv_exactly(8))
        mask = self._recv_exactly(4) if masked else None
        payload = self._recv_exactly(length) if length else b""
        if mask is not None:
            payload = bytes(byte ^ mask[i & 3] for i, byte in enumerate(payload))
        return op, payload

    def recv_json(self):
        op, payload = self.recv_frame()
        if op != 0x1:
            raise AssertionError(f"expected text, got opcode {op}")
        return json.loads(payload.decode("utf-8"))

    def close(self):
        try:
            self.sock.close()
        except OSError:
            pass


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

    def test_voice_socket_refuses_without_bearer(self):
        for bearer in (None, "bad"):
            ws = VoiceSocket(self.server.server_port)
            try:
                status, _ = ws.handshake(bearer=bearer)
            finally:
                ws.close()
            self.assertEqual(status, 401)

    def test_voice_socket_renders_and_ends(self):
        ws = VoiceSocket(self.server.server_port)
        try:
            status, head = ws.handshake()
            self.assertEqual(status, 101)
            self.assertTrue(head.startswith(b"HTTP/1.1 101 "), head)
            accept = base64.b64encode(hashlib.sha1(
                (ws.key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11").encode()).digest())
            self.assertIn(b"\r\nSec-WebSocket-Accept: " + accept + b"\r\n", head + b"\r\n")
            ready = ws.recv_json()
            self.assertEqual(ready["type"], "ready")
            self.assertEqual(ready["version"], 1)
            self.assertEqual(ready["target"], {**self.worker.target(), "transcript_frame": True})
            generation = 1
            target = self.target()
            transcript = "ref"
            wav = b"RIFF0000WAVEfmt "
            ws.send_text({"type": "start", "generation": generation, "target": target,
                          "transcript_bytes": len(transcript.encode()),
                          "reference_bytes": len(wav)})
            ws.send_binary(transcript.encode())
            ws.send_binary(wav)
            started = ws.recv_json()
            self.assertEqual(started["type"], "started")
            self.assertEqual(started["generation"], generation)
            self.assertEqual(started["target"], target)
            self.assertEqual(started["sample_rate"], self.worker.sample_rate)
            self.assertEqual(started["channels"], 1)
            text = "hi \u2713"
            ws.send_text({"type": "text", "generation": generation, "text": text})
            pcm_parts = []
            chunk_index = 0
            while True:
                message = ws.recv_json()
                if message["type"] == "audio":
                    self.assertEqual(message["generation"], generation)
                    self.assertEqual(message["chunk_index"], chunk_index)
                    chunk_index += 1
                    op, payload = ws.recv_frame()
                    self.assertEqual(op, 0x2)
                    self.assertEqual(len(payload), message["bytes"])
                    pcm_parts.append(payload)
                elif message["type"] == "usage":
                    self.assertEqual(message["generation"], generation)
                    self.assertEqual(message["characters"], len(text))
                    break
                else:
                    self.fail(f"unexpected {message}")
            pcm = b"".join(pcm_parts)
            self.assertGreater(len(pcm_parts), 0)
            status, body = self.request("POST", "/render", pack(
                {"target": target, "text": text, "transcript": transcript}, wav))
            self.assertEqual(status, 200)
            header_len = int.from_bytes(body[:4], "big")
            self.assertEqual(pcm, body[4 + header_len:])
            ws.send_text({"type": "end", "generation": generation})
            done = ws.recv_json()
            self.assertEqual(done, {"type": "done", "generation": generation})
            ws.send_close()
            op, _ = ws.recv_frame()
            self.assertEqual(op, 0x8)
        finally:
            ws.close()
        self.assertEqual(list(Path(self.tmp.name).glob("ref-*")), [])

    def test_voice_socket_cancel_erases_the_reference(self):
        ws = VoiceSocket(self.server.server_port)
        try:
            self.assertEqual(ws.handshake()[0], 101)
            ws.recv_json()
            generation = 1
            target = self.target()
            transcript = "ref"
            wav = b"RIFF0000WAVEfmt "
            ws.send_text({"type": "start", "generation": generation, "target": target,
                          "transcript_bytes": len(transcript.encode()),
                          "reference_bytes": len(wav)})
            ws.send_binary(transcript.encode())
            ws.send_binary(wav)
            started = ws.recv_json()
            self.assertEqual(started["type"], "started")
            self.assertEqual(len(list(Path(self.tmp.name).glob("ref-*"))), 1)
            ws.send_text({"type": "cancel", "generation": generation})
            for _ in range(40):
                if not list(Path(self.tmp.name).glob("ref-*")):
                    break
                threading.Event().wait(0.05)
            self.assertEqual(list(Path(self.tmp.name).glob("ref-*")), [])
            ws.send_text({"type": "text", "generation": generation, "text": "hi"})
            error = ws.recv_json()
            self.assertEqual(error["type"], "error")
            self.assertEqual(error["generation"], generation)
            self.assertEqual(error["code"], "not_started")
            ws.send_close()
            op, _ = ws.recv_frame()
            self.assertEqual(op, 0x8)
        finally:
            ws.close()
        self.assertEqual(list(Path(self.tmp.name).glob("ref-*")), [])

    def test_voice_socket_splits_pcm_into_bounded_frames(self):
        class LongModel(FakeModel):
            def generate(self, **kwargs):
                self.calls.append(kwargs)
                return np.full(70000, 0.5, dtype=np.float32)

        self.replace_worker(LongModel(), self.limits)
        ws = VoiceSocket(self.server.server_port)
        try:
            self.assertEqual(ws.handshake()[0], 101)
            ws.recv_json()
            generation = 1
            target = self.target()
            transcript = "ref"
            wav = b"RIFF0000WAVEfmt "
            ws.send_text({"type": "start", "generation": generation, "target": target,
                          "transcript_bytes": len(transcript.encode()),
                          "reference_bytes": len(wav)})
            ws.send_binary(transcript.encode())
            ws.send_binary(wav)
            self.assertEqual(ws.recv_json()["type"], "started")
            ws.send_text({"type": "text", "generation": generation, "text": "hi"})
            parts = []
            index = 0
            while True:
                message = ws.recv_json()
                if message["type"] == "audio":
                    self.assertEqual(message["generation"], generation)
                    self.assertEqual(message["chunk_index"], index)
                    index += 1
                    self.assertLessEqual(message["bytes"], 65536)
                    op, payload = ws.recv_frame()
                    self.assertEqual(op, 0x2)
                    self.assertEqual(len(payload), message["bytes"])
                    parts.append(payload)
                elif message["type"] == "usage":
                    break
                else:
                    self.fail(f"unexpected {message}")
            self.assertGreater(len(parts), 1)
            pcm = b"".join(parts)
            self.assertGreater(len(pcm), 65536)
            status, body = self.request("POST", "/render", pack(
                {"target": target, "text": "hi", "transcript": transcript}, wav))
            self.assertEqual(status, 200)
            header_len = int.from_bytes(body[:4], "big")
            self.assertEqual(pcm, body[4 + header_len:])
            ws.send_text({"type": "end", "generation": generation})
            self.assertEqual(ws.recv_json()["type"], "done")
            ws.send_close()
            self.assertEqual(ws.recv_frame()[0], 0x8)
        finally:
            ws.close()
        self.assertEqual(list(Path(self.tmp.name).glob("ref-*")), [])

    def test_voice_socket_takes_a_reference_past_max_ref_bytes(self):
        # Rule 5: a reference is never refused by size; `POST /render` takes
        # it whole, and the socket takes the length its `start` announced.
        self.replace_worker(FakeModel(), {**self.limits, "max_ref_bytes": 12})
        ws = VoiceSocket(self.server.server_port)
        try:
            self.assertEqual(ws.handshake()[0], 101)
            ws.recv_json()
            generation = 1
            target = self.target()
            transcript = "ref"
            wav = b"RIFF0000WAVEfmt " + b"\0" * 64
            self.assertGreater(len(wav), self.limits["max_ref_bytes"])
            ws.send_text({"type": "start", "generation": generation, "target": target,
                          "transcript_bytes": len(transcript.encode()),
                          "reference_bytes": len(wav)})
            ws.send_binary(transcript.encode())
            ws.send_binary(wav)
            started = ws.recv_json()
            self.assertEqual(started["type"], "started")
            self.assertEqual(started["generation"], generation)
            ws.send_text({"type": "text", "generation": generation, "text": "hi"})
            parts = []
            while True:
                message = ws.recv_json()
                if message["type"] == "audio":
                    op, payload = ws.recv_frame()
                    self.assertEqual(op, 0x2)
                    parts.append(payload)
                elif message["type"] == "usage":
                    break
                else:
                    self.fail(f"unexpected {message}")
            status, body = self.request("POST", "/render", pack(
                {"target": target, "text": "hi", "transcript": transcript}, wav))
            self.assertEqual(status, 200)
            header_len = int.from_bytes(body[:4], "big")
            self.assertEqual(b"".join(parts), body[4 + header_len:])
            ws.send_text({"type": "end", "generation": generation})
            self.assertEqual(ws.recv_json()["type"], "done")
            ws.send_close()
            self.assertEqual(ws.recv_frame()[0], 0x8)
        finally:
            ws.close()
        self.assertEqual(list(Path(self.tmp.name).glob("ref-*")), [])

    def test_voice_socket_refuses_an_oversized_frame(self):
        ws = VoiceSocket(self.server.server_port)
        try:
            self.assertEqual(ws.handshake()[0], 101)
            ws.recv_json()
            over = self.limits["max_header_bytes"] + 1024
            ws.send_text({"type": "text", "generation": 1, "text": "x" * over})
            op, payload = ws.recv_frame()
            self.assertEqual(op, 0x8)
            self.assertEqual(int.from_bytes(payload[:2], "big"), 1009)
        finally:
            ws.close()


if __name__ == "__main__":
    unittest.main()
