"""Request-body decoding for our own model servers (OF-604, ARCH-0081 §6).

The engine sends a request body of 16 KiB or more in zstd (level 3) or gzip
when the provider entry names the codec (`request_compression = "zstd"`),
and sends it once more, plain, when a compressed body is answered 400 or 415.
A server that decodes takes the encoded body; one that cannot answers 415.

- `decode_body` serves a stdlib `http.server` handler (exl3_server.py).
- `DecodeContentEncoding` is an ASGI middleware for vLLM:
  `PYTHONPATH=/opt/oneiron/deploy/house-model vllm serve <model>
  --middleware body_codec.DecodeContentEncoding`.

zstd needs Python 3.14 (`compression.zstd`) or the `zstandard` package;
without either, a zstd body is answered 415 and the engine sends plain.
"""
import json
import zlib

try:
    from compression import zstd as _zstd
except ImportError:
    _zstd = None
try:
    import zstandard as _zstandard
except ImportError:
    _zstandard = None

# The most a decoded body may hold: far above any chat request.
MAX_DECODED_BYTES = 64 * 1024 * 1024


class UnsupportedEncoding(ValueError):
    """A Content-Encoding this server cannot read: answer 415."""


def _gzip(raw, limit):
    decoder = zlib.decompressobj(wbits=31)
    try:
        body = decoder.decompress(raw, limit + 1)
    except zlib.error as e:
        raise ValueError(f"the gzip body does not decode: {e}") from None
    if len(body) > limit:
        raise ValueError("the decoded body is too large")
    if not decoder.eof:
        raise ValueError("the gzip body is cut short")
    return body


def _zstd_decode(raw, limit):
    if _zstd is not None:
        decoder = _zstd.ZstdDecompressor()
        try:
            body = decoder.decompress(raw, max_length=limit + 1)
        except _zstd.ZstdError as e:
            raise ValueError(f"the zstd body does not decode: {e}") from None
        if len(body) > limit:
            raise ValueError("the decoded body is too large")
        if not decoder.eof:
            raise ValueError("the zstd body is cut short")
        return body
    if _zstandard is not None:
        parts, total = [], 0
        try:
            with _zstandard.ZstdDecompressor().stream_reader(raw) as reader:
                while chunk := reader.read(65536):
                    total += len(chunk)
                    if total > limit:
                        raise ValueError("the decoded body is too large")
                    parts.append(chunk)
        except _zstandard.ZstdError as e:
            raise ValueError(f"the zstd body does not decode: {e}") from None
        return b"".join(parts)
    raise UnsupportedEncoding("zstd")


def decode_body(encoding, raw, limit=MAX_DECODED_BYTES):
    """`raw` decoded by its Content-Encoding header value, at most `limit`
    bytes. Raises UnsupportedEncoding for a codec this server cannot read,
    and ValueError for a body that does not decode within `limit`."""
    token = (encoding or "identity").strip().lower()
    if token == "identity":
        return raw
    if token in ("gzip", "x-gzip"):
        return _gzip(raw, limit)
    if token == "zstd":
        return _zstd_decode(raw, limit)
    raise UnsupportedEncoding(token)


async def _refuse(send, status, message):
    payload = json.dumps({"error": {"message": message, "type": "invalid_request_error"}}).encode()
    await send({"type": "http.response.start", "status": status,
                "headers": [(b"content-type", b"application/json"),
                            (b"content-length", str(len(payload)).encode("ascii"))]})
    await send({"type": "http.response.body", "body": payload})


class DecodeContentEncoding:
    """ASGI middleware: an HTTP request body sent with Content-Encoding gzip
    or zstd reaches the app decoded, with the header dropped and its
    Content-Length the decoded one. A codec it cannot read is answered 415,
    a body that does not decode 400, one past `limit` 413."""

    def __init__(self, app, limit=MAX_DECODED_BYTES):
        self.app = app
        self.limit = limit

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            return await self.app(scope, receive, send)
        headers = scope.get("headers") or []
        encoding = next((value.decode("latin-1") for name, value in headers
                         if name == b"content-encoding"), None)
        if encoding is None or encoding.strip().lower() == "identity":
            return await self.app(scope, receive, send)
        raw = bytearray()
        while True:
            message = await receive()
            if message["type"] == "http.disconnect":
                return None
            raw += message.get("body", b"")
            if len(raw) > self.limit:
                return await _refuse(send, 413, "the request body is too large")
            if not message.get("more_body", False):
                break
        try:
            body = decode_body(encoding, bytes(raw), self.limit)
        except UnsupportedEncoding:
            return await _refuse(send, 415, f"Content-Encoding {encoding} is not supported")
        except ValueError as e:
            return await _refuse(send, 400, str(e))
        headers = [(name, value) for name, value in headers
                   if name not in (b"content-encoding", b"content-length")]
        headers.append((b"content-length", str(len(body)).encode("ascii")))
        delivered = False

        async def replay():
            nonlocal delivered
            if delivered:
                return await receive()
            delivered = True
            return {"type": "http.request", "body": body, "more_body": False}

        return await self.app(dict(scope, headers=headers), replay, send)
