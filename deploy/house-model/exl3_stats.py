"""What the house EXL3 server holds, as its own counters say (FIX 9190,
DESIGN-V2 R1): the CUDA caching allocator's counters on each device the
target runs on, the Generator's cache pages and jobs, and the scheduler's
queue.

Taken on the scheduler thread, which owns the Generator, never per token. A
cheap snapshot (allocator counters, pages, queue) goes in each request's
final event and answers the supervisor's activity poll; a full one adds
exllamav3's own per-category accounting (`util.memory.vram_accounting`:
weights, cache, recurrent, statics, generator, other), which synchronizes
the device and walks the live tensors, and is taken only when asked.

`resident_mib` is the sum of this process's allocator reservations on its
devices, in MiB rounded up, and says so (`resident_source`). It is never the
device's used memory, which counts other processes, never the process RSS,
and never a sum over models: the target and its draft share one allocator
per device, counted once. A device whose counters cannot be read leaves it
None. The categories come from one walk over the target with its cache and
the Generator, which reaches the draft, so the draft's tensors may show
under `generator`; it is never walked twice.

Peaks are the allocator's own, since their reset just after the models
loaded (`peak_origin`); the load's peaks are kept apart. They are sampled
counters, not exact per-category transients. `serve_peak_mib` and
`load_peak_mib` sum the devices' peak reservations since load and during
it, as `resident_mib` sums the current ones.

Each device row names its CUDA ordinal and the device's total memory
(`capacity_bytes`, the driver's figure, read once at load); the snapshot
names when the load completed (`load_completed_at_unix_ms`). Whatever
cannot be read is left out, never guessed.
"""
import math
import time

MIB = 1 << 20
# What `resident_mib` measures.
RESIDENT_SOURCE = "cuda_allocator_reserved"
# The allocator counters read for each device, by the name they go out under.
ALLOCATOR_KEYS = (
    ("allocated", "allocated_bytes.all.current"),
    ("reserved", "reserved_bytes.all.current"),
    ("peak_allocated", "allocated_bytes.all.peak"),
    ("peak_reserved", "reserved_bytes.all.peak"),
)
# The categories `vram_accounting` reports per device, in bytes.
CATEGORY_KEYS = ("weights", "weights_arena_used", "weights_arena_tail", "weights_direct", "cache",
                 "recurrent", "statics", "generator", "other", "live_total")


def _count(value):
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        return None
    return value


def _ordinal(device):
    """The CUDA ordinal a device name `cuda:N` names; None for another."""
    kind, _, index = str(device).partition(":")
    return int(index) if kind == "cuda" and index.isdigit() else None


class Memory:
    """The target, its cache and the Generator this server runs, on the CUDA
    devices the target's modules were placed on."""

    def __init__(self, target, cache, generator, devices):
        self.target = target
        self.cache = cache
        self.generator = generator
        self.devices = list(devices)
        self.load_peaks = {}
        self.peak_origin = None
        self.capacities = {}
        self.load_completed_at_unix_ms = None

    def reset_peaks(self):
        """Keeps the load's peaks and each device's capacity, notes that the
        load has completed, then starts the allocator's peaks again: from
        here on they are serving peaks."""
        self.load_completed_at_unix_ms = int(time.time() * 1000)
        try:
            import torch
            for device in self.devices:
                stats = torch.cuda.memory_stats(device)
                self.load_peaks[device] = {
                    "peak_allocated": _count(stats.get("allocated_bytes.all.peak")),
                    "peak_reserved": _count(stats.get("reserved_bytes.all.peak")),
                }
                torch.cuda.reset_peak_memory_stats(device)
            self.peak_origin = {"reset": "after_load", "at_unix_ms": int(time.time() * 1000)}
        except Exception as error:  # counters never stop the server
            print(f"WARN ALLOCATOR_PEAKS_UNREAD {type(error).__name__}: {error}", flush=True)
        try:
            import torch
            for device in self.devices:
                self.capacities[device] = _count(int(torch.cuda.get_device_properties(device).total_memory))
        except Exception as error:  # capacity never stops the server
            print(f"WARN DEVICE_CAPACITY_UNREAD {type(error).__name__}: {error}", flush=True)

    def allocator(self):
        """Each device's allocator counters, in bytes; a counter that cannot
        be read is None."""
        rows = []
        try:
            import torch
        except Exception:
            torch = None
        for device in self.devices:
            row = {"device": device}
            ordinal = _ordinal(device)
            if ordinal is not None:
                row["ordinal"] = ordinal
            capacity = self.capacities.get(device)
            if capacity is not None:
                row["capacity_bytes"] = capacity
            stats = {}
            if torch is not None:
                try:
                    stats = torch.cuda.memory_stats(device)
                except Exception:
                    stats = {}
            for name, key in ALLOCATOR_KEYS:
                row[name] = _count(stats.get(key))
            load = self.load_peaks.get(device)
            if load:
                row["load_peaks"] = load
            rows.append(row)
        return rows

    def categories(self):
        """exllamav3's per-device accounting, by device; None when it cannot
        be taken."""
        try:
            from exllamav3.util.memory import vram_accounting
            reports = vram_accounting(self.target, cache=self.cache, generator=self.generator,
                                      devices=self.devices)
        except Exception as error:  # accounting never stops the server
            print(f"WARN VRAM_ACCOUNTING_UNREAD {type(error).__name__}: {error}", flush=True)
            return None
        out = {}
        for report in reports:
            values = report.as_dict()
            out[str(values.get("device"))] = {key: _count(values.get(key)) for key in CATEGORY_KEYS}
        return out


def resident_mib(devices, read=lambda row: row.get("reserved")):
    """The sum of the devices' allocator reservations in MiB, rounded up
    (`read` takes one row's: by default its current one); None when any is
    unknown or there is no device."""
    if not devices:
        return None
    total = 0
    for row in devices:
        reserved = read(row)
        if reserved is None:
            return None
        total += reserved
    return math.ceil(total / MIB)


def pages(generator):
    """The Generator's cache pages and jobs, from `get_cache_stats()`. The
    cached pages include pages active jobs hold: used, cached and free are
    not a partition."""
    try:
        stats = generator.get_cache_stats()
    except Exception:
        return None
    size = _count(stats.get("page_size"))
    if not size:
        return None

    def in_pages(key):
        tokens = _count(stats.get(key))
        return None if tokens is None else tokens // size

    return {
        "page_size": size,
        "total": in_pages("max_tokens"),
        "used": in_pages("used_tokens"),
        "cached": in_pages("cached_tokens"),
        "free": in_pages("free_tokens"),
        "active_jobs": _count(stats.get("active_jobs")),
        "pending_jobs": _count(stats.get("pending_jobs")),
    }


def snapshot(memory, queue, epoch, full):
    """One snapshot: the queue as the scheduler counts it, the allocator,
    the pages, and with `full` the categories."""
    devices = memory.allocator() if memory is not None else []
    out = {
        "epoch": epoch,
        "taken_at_unix_ms": int(time.time() * 1000),
        "detail": "full" if full else "cheap",
        "queue": queue,
        "devices": devices,
        "resident_source": RESIDENT_SOURCE,
        "peak_origin": memory.peak_origin if memory is not None else None,
        "load_completed_at_unix_ms": memory.load_completed_at_unix_ms if memory is not None else None,
        "pages": pages(memory.generator) if memory is not None else None,
        "resident_mib": resident_mib(devices),
        "serve_peak_mib": resident_mib(devices, lambda row: row.get("peak_reserved")),
        "load_peak_mib": resident_mib(devices, lambda row: (row.get("load_peaks") or {}).get("peak_reserved")),
    }
    if full and memory is not None:
        out["categories"] = memory.categories()
    return {key: value for key, value in out.items() if value is not None}
