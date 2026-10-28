"""Portable snapshots of a canonical checkpoint (DESIGN-V2 R3, worker half):
the bytes `session.export` writes and `session.import` reads.

Format `snapshot_v1`, schema 1:

    b"OIRS" | u32 little-endian schema | u64 little-endian header length |
    header | payload

The header is canonical JSON: UTF-8, keys sorted, no whitespace, no float
anywhere. It names what the snapshot holds: `compatibility` (the worker's
identity less its epoch, the KV layout and the recurrent state kind),
`checkpoint` (its ref, exactly), `token_count`, `kv` (the pages it spans and
the valid tokens of the last), `state` (the recurrent state's position and,
for SWA, its window start and ring spans), and `tensors`, each
`{name, dtype, shape, offset, length}`, sorted by name. The payload is
those tensors' bytes, little-endian, back to back in that order from offset
0 with no padding, so the ranges cover it exactly. A reader refuses
anything else: another magic or schema, a header that is not canonical, a
duplicate name, a gap, an overlap, a trailing byte, a length that is not
its shape's, a dtype outside the whitelist.

Nothing in it is a pointer, a physical page index, a pickle or a JSON
tensor. KV is the target cache's quantized pages in logical sequence order
(the draft's is never carried: it is rebuilt from the committed frontier
on); tokens are i64, and the checkpoint's digest is their BLAKE2b-256
(`anchor.token_digest`). The region's SHA-256 names the whole snapshot on
the wire; it is never the token digest.

A snapshot this worker writes lives in a memfd sealed against write, grow,
shrink and further seals (`Region`), passed to the host on its op's answer
and kept only for that op's replay.
"""
import fcntl
import hashlib
import json
import os
import struct
import sys
import threading

import torch
from exllamav3 import CacheLayer_quant
from exllamav3.constants import PAGE_SIZE

from .registry import SNAPSHOT_INCOMPATIBLE, Refused

MAGIC = b"OIRS"
SCHEMA = 1
ENCODING = "snapshot_v1"
HASH = "sha256"
# Magic, schema, header length.
PREFIX = struct.Struct("<4sIQ")
# The dtypes a tensor may have, by the name the header gives them.
DTYPES = {"bfloat16": torch.bfloat16, "float16": torch.float16, "float32": torch.float32, "int32": torch.int32,
          "int64": torch.int64}
DTYPE_NAMES = {dtype: name for name, dtype in DTYPES.items()}
TENSOR_FIELDS = frozenset(("name", "dtype", "shape", "offset", "length"))
# A quantized KV layer's tensors: keys, values and their scales.
KV_FIELDS = ("qk", "qv", "sk", "sv")
# Linux's memfd seal ABI (fcntl.h: F_LINUX_SPECIFIC_BASE + 9, F_SEAL_*), for
# a Python built without the names; the kernel's values never change.
F_ADD_SEALS = getattr(fcntl, "F_ADD_SEALS", 1033)
F_SEAL_SEAL = getattr(fcntl, "F_SEAL_SEAL", 0x0001)
F_SEAL_SHRINK = getattr(fcntl, "F_SEAL_SHRINK", 0x0002)
F_SEAL_GROW = getattr(fcntl, "F_SEAL_GROW", 0x0004)
F_SEAL_WRITE = getattr(fcntl, "F_SEAL_WRITE", 0x0008)
# How much one write takes: a write size, never a cap.
WRITE_CHUNK = 1 << 20


def hostable():
    """True when this process can write and pass a sealed snapshot region
    whose tensors are little-endian: Linux, with memfd."""
    return sys.platform.startswith("linux") and hasattr(os, "memfd_create") and sys.byteorder == "little"


def incompatible(message):
    return Refused(SNAPSHOT_INCOMPATIBLE, message)


def layer_name(key):
    """A cache layer's name in a snapshot: its layer index and instance."""
    return ".".join(str(part) for part in key) if isinstance(key, tuple) else str(key)


def canonical(header):
    """`header` as canonical JSON bytes; ValueError when it holds a float."""
    _no_float(header)
    return json.dumps(header, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
                      allow_nan=False).encode("utf-8")


def _no_float(value):
    if isinstance(value, float):
        raise ValueError("a snapshot header holds no float")
    if isinstance(value, dict):
        for item in value.values():
            _no_float(item)
    elif isinstance(value, list):
        for item in value:
            _no_float(item)


def _bytes_of(tensor):
    """A host tensor's bytes in place, as a flat uint8 buffer."""
    return tensor.detach().contiguous().reshape(-1).view(torch.uint8).numpy()


def encode_snapshot(fields, tensors, write):
    """Writes the snapshot of `fields` (every header field but `tensors`)
    and `tensors` ((name, host tensor) pairs) through `write(buffer)`, in
    order; returns its length and SHA-256 (64 hex)."""
    entries, views, offset = [], [], 0
    for name, tensor in sorted(tensors, key=lambda item: item[0]):
        if entries and entries[-1]["name"] == name:
            raise ValueError(f"two tensors are named {name}")
        view = _bytes_of(tensor)
        entries.append({"name": name, "dtype": DTYPE_NAMES[tensor.dtype], "shape": [int(n) for n in tensor.shape],
                        "offset": offset, "length": int(view.nbytes)})
        views.append(view)
        offset += int(view.nbytes)
    header = canonical(dict(fields, tensors=entries))
    hasher = hashlib.sha256()
    total = 0
    for piece in [PREFIX.pack(MAGIC, SCHEMA, len(header)), header] + views:
        hasher.update(piece)
        write(piece)
        total += memoryview(piece).nbytes
    return total, hasher.hexdigest()


def _strict_object(pairs):
    keys = [key for key, _ in pairs]
    if len(set(keys)) != len(keys):
        raise ValueError("a header object repeats a key")
    return dict(pairs)


def _no_number(text):
    raise ValueError(f"a snapshot header holds no float or constant: {text}")


def _header(raw):
    try:
        header = json.loads(raw.decode("utf-8"), object_pairs_hook=_strict_object, parse_float=_no_number,
                            parse_constant=_no_number)
    except (UnicodeDecodeError, ValueError) as error:
        raise incompatible(f"the snapshot's header does not read: {error}") from None
    if not isinstance(header, dict):
        raise incompatible("the snapshot's header is not an object")
    if canonical(header) != raw:
        raise incompatible("the snapshot's header is not canonical JSON")
    return header


def _count(value):
    return type(value) is int and value >= 0


def _entry(entry):
    if not isinstance(entry, dict) or set(entry) != TENSOR_FIELDS:
        raise incompatible("a tensor entry is not {name, dtype, shape, offset, length}")
    name, shape = entry["name"], entry["shape"]
    dtype = DTYPES.get(entry["dtype"]) if isinstance(entry["dtype"], str) else None
    offset, length = entry["offset"], entry["length"]
    if not isinstance(name, str) or not name:
        raise incompatible("a tensor has no name")
    if dtype is None:
        raise incompatible(f"tensor {name} has a dtype this format does not carry")
    if not isinstance(shape, list) or not all(_count(n) for n in shape):
        raise incompatible(f"tensor {name}'s shape is not a list of counts")
    if not _count(offset) or not _count(length):
        raise incompatible(f"tensor {name}'s range is not two counts")
    size = torch.empty((), dtype=dtype).element_size()
    for n in shape:
        size *= n
    if size != length:
        raise incompatible(f"tensor {name}'s length is not its shape's")
    return name, dtype, shape, offset, length


def _tensor(chunk, dtype, shape):
    """A new host tensor of `dtype` and `shape` holding `chunk`'s bytes."""
    out = torch.empty(shape, dtype=dtype)
    memoryview(out.reshape(-1).view(torch.uint8).numpy())[:] = chunk
    return out


def decode_snapshot(data):
    """The header and tensors (name -> host tensor) of the snapshot `data`,
    checked against the format. Refused `snapshot_incompatible` for anything
    this side does not read exactly."""
    view = memoryview(data).cast("B")
    if view.nbytes < PREFIX.size:
        raise incompatible("the snapshot is shorter than its prefix")
    magic, schema, header_len = PREFIX.unpack_from(view, 0)
    if magic != MAGIC:
        raise incompatible("the snapshot does not start with OIRS")
    if schema != SCHEMA:
        raise incompatible(f"the snapshot's schema is {schema}, not {SCHEMA}")
    if header_len > view.nbytes - PREFIX.size:
        raise incompatible("the snapshot's header runs past its end")
    header = _header(bytes(view[PREFIX.size:PREFIX.size + header_len]))
    payload = view[PREFIX.size + header_len:]
    entries = header.get("tensors")
    if not isinstance(entries, list):
        raise incompatible("the snapshot's header lists no tensors")
    tensors, end, previous = {}, 0, None
    for entry in entries:
        name, dtype, shape, offset, length = _entry(entry)
        if previous is not None and name <= previous:
            raise incompatible("the snapshot's tensors are not sorted by unique name")
        if offset != end:
            raise incompatible(f"tensor {name} leaves a gap or overlaps")
        if offset + length > payload.nbytes:
            raise incompatible(f"tensor {name} runs past the payload")
        tensors[name] = _tensor(payload[offset:offset + length], dtype, shape)
        end, previous = offset + length, name
    if end != payload.nbytes:
        raise incompatible("the snapshot has bytes no tensor covers")
    return header, tensors


def take(tensors, name, shape, dtype):
    """Removes and returns tensor `name`, which must have `shape` and
    `dtype`."""
    tensor = tensors.pop(name, None)
    if tensor is None:
        raise incompatible(f"the snapshot holds no {name}")
    if list(tensor.shape) != [int(n) for n in shape] or tensor.dtype != dtype:
        raise incompatible(f"the snapshot's {name} is not this worker's shape or dtype")
    return tensor


# KV adapters over the pinned exllamav3's quantized cache layer.

def kv_layout(cache):
    """`cache`'s KV layout as a snapshot names it, or None when one of its
    layers is not the one this format carries: the stock quantized layer,
    uncompanded, every layer at the same bits."""
    layers = list(cache.layers.values())
    if not layers or any(type(layer) is not CacheLayer_quant or layer.compand_a != 0 for layer in layers):
        return None
    bits = {(int(layer.k_bits), int(layer.v_bits)) for layer in layers}
    if len(bits) != 1:
        return None
    (k_bits, v_bits), = bits
    return {"layout": "quant", "k_bits": k_bits, "v_bits": v_bits, "page_tokens": PAGE_SIZE}


def kv_shapes(cache, frontier):
    """The KV tensors a snapshot of `frontier` tokens holds on `cache`: name
    -> (shape, dtype), one (frontier, width) tensor per layer field."""
    shapes = {}
    for key, layer in cache.layers.items():
        for field in KV_FIELDS:
            source = getattr(layer, field)
            shapes[f"kv.{layer_name(key)}.{field}"] = ((frontier, int(source.shape[-1])), source.dtype)
    return shapes


def gather_kv(cache, pages, frontier, start=0, stop=None):
    """The KV pages [start, stop) of `pages` hold for tokens below
    `frontier` (every page by default), in sequence order, as (name, host
    tensor) pairs; the rows of consecutive ranges, joined in order, are the
    whole range's. On the scheduler thread: it reads pages."""
    count = -(-frontier // PAGE_SIZE)
    stop = count if stop is None else min(stop, count)
    first, last = start * PAGE_SIZE, min(stop * PAGE_SIZE, frontier)
    indices = [page.page_index for page in pages[start:stop]]
    out = []
    for key, layer in cache.layers.items():
        index = torch.tensor(indices, dtype=torch.long, device=layer.qk.device)
        for field in KV_FIELDS:
            source = getattr(layer, field)
            rows = source.index_select(0, index).reshape(len(indices) * PAGE_SIZE, source.shape[-1])[:last - first]
            out.append((f"kv.{layer_name(key)}.{field}", rows.to("cpu")))
    return out


def fill_kv(cache, pages, frontier, tensors, start=0, stop=None):
    """Writes the KV rows `tensors` hold for tokens below `frontier` into
    pages [start, stop) of `pages` (every page by default), in sequence
    order. On the scheduler thread: it writes pages."""
    full, tail = divmod(frontier, PAGE_SIZE)
    stop = len(pages) if stop is None else stop
    indices = [page.page_index for page in pages]
    whole = list(range(start, min(stop, full)))
    for key, layer in cache.layers.items():
        device = layer.qk.device
        index = torch.tensor([indices[n] for n in whole], dtype=torch.long, device=device)
        for field in KV_FIELDS:
            target = getattr(layer, field)
            source = tensors[f"kv.{layer_name(key)}.{field}"]
            if whole:
                rows = source[whole[0] * PAGE_SIZE:(whole[-1] + 1) * PAGE_SIZE].to(device)
                target.index_copy_(0, index, rows.view(len(whole), PAGE_SIZE, -1))
            if tail and start <= full < stop:
                target[indices[full], :tail].copy_(source[full * PAGE_SIZE:].to(device))


class KvCopy:
    """An export's copy in progress: its header fields, the tensors it
    takes whole (tokens, recurrent state), and the KV rows gathered so far,
    a range of pages at a time in sequence order."""

    def __init__(self, fields, tensors, pages, frontier):
        self.fields = fields
        self.whole = tensors
        self.pages = pages
        self.frontier = frontier
        self.count = -(-frontier // PAGE_SIZE)
        self.next = 0
        self.parts = {}

    def add(self, pairs):
        for name, rows in pairs:
            self.parts.setdefault(name, []).append(rows)

    def tensors(self):
        """Every tensor of the snapshot, each KV field's ranges joined."""
        return self.whole + [(name, rows[0] if len(rows) == 1 else torch.cat(rows))
                             for name, rows in self.parts.items()]


def clear_pages(cache, pages):
    """Zeroes every tensor of `cache` in `pages`: an import's draft pages,
    which no snapshot carries."""
    for layer in cache.layers.values():
        for tensor in layer.get_tensors():
            if tensor is not None:
                index = torch.tensor([page.page_index for page in pages], dtype=torch.long, device=tensor.device)
                tensor.index_fill_(0, index, 0)


class Rebuilt:
    """A snapshot decoded and checked for import: its tokens, its recurrent
    snapshot (stock stash form, `state.rebuild_portable`), its KV rows by
    name, and the HEAD and parent its checkpoint names."""

    __slots__ = ("tokens", "state", "kv", "head", "parent")

    def __init__(self, tokens, state, kv, head, parent):
        self.tokens = tokens
        self.state = state
        self.kv = kv
        self.head = head
        self.parent = parent


# The region a snapshot is written into.

class Region:
    """A sealed memfd holding one snapshot this worker wrote: passed on its
    op's answer, kept for the op's replay, and closed when the answer is
    forgotten, the session is dropped or the server closes."""

    def __init__(self, fd, length, sha256):
        self.fd = fd
        self.length = length
        self.sha256 = sha256
        self.lock = threading.Lock()
        self.closed = False

    def pass_to(self, send):
        """Calls `send(fd)` while the region is open; False, and nothing
        sent, once it is closed. A close waits for a send in progress."""
        with self.lock:
            if self.closed:
                return False
            send(self.fd)
            return True

    def close(self):
        with self.lock:
            if self.closed:
                return
            self.closed = True
            os.close(self.fd)


def _write_all(fd, piece):
    view = memoryview(piece).cast("B")
    while view.nbytes:
        written = os.write(fd, view[:WRITE_CHUNK])
        view = view[written:]


def write_region(fields, tensors):
    """The snapshot of `fields` and `tensors` written into a new memfd and
    sealed against write, grow, shrink and further seals: its Region."""
    fd = os.memfd_create("oneiron-snapshot", os.MFD_CLOEXEC | os.MFD_ALLOW_SEALING)
    try:
        length, digest = encode_snapshot(fields, tensors, lambda piece: _write_all(fd, piece))
        fcntl.fcntl(fd, F_ADD_SEALS, F_SEAL_SHRINK | F_SEAL_GROW | F_SEAL_WRITE | F_SEAL_SEAL)
    except BaseException:
        os.close(fd)
        raise
    return Region(fd, length, digest)
