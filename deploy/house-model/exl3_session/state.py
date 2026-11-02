"""Recurrent snapshots: a recurrent state at an exact token position, taken
with the stock stash API (`GDNState.stash`, the host copies the stock
checkpoint cache takes) and restored with `Cache.new_from_stashed`. Only the
recurrent state is copied; the KV pages before it are retained, never copied
(STEALS line 15, worker half).

A GDN state (the Qwen hybrid's gated delta net: its recurrent and conv
state, `GDNLayerState.get_state_tensors`) stashes whole at any position, so
its snapshot is exact at any frontier. An SWA state's stash carries its ring
positions and valid lengths (`position`, `window_beg`, the ring span), but
the stock code stashes it at page boundaries only, and this layer keeps to
that: on a target whose state is not GDN a snapshot is taken at page
boundaries only, and a frontier between two replays from the boundary below
it. That is the explicit capability limit, never an approximation.

A snapshot (`snapshot.py`, R3) carries one such recurrent snapshot portably
(`capture_portable`): the stock stash's tensors by layer, its position and,
for SWA, its window start and the ring span each layer's stash holds, the
same span the stock restore writes back. `rebuild_portable` makes it the
stock stash again on the importing worker, after checking every tensor
against that worker's own geometry, so the restore at attach is the stock
one. A checkpoint whose exact-frontier state is not held (an SWA frontier
between page boundaries) exports the snapshot below it: the import attaches
there and replays the rest exactly, and says so; it never claims the full
frontier. Any other state kind has no portable form.
"""
from exllamav3.constants import PAGE_SIZE
from exllamav3.modules.gated_delta_net import GDNLayerState, GDNState
from exllamav3.modules.sliding_attn import SWALayerState, SWAState

from .snapshot import incompatible, layer_name, take

# The recurrent states a snapshot carries, by kind: the stock state class,
# and the layer state class every recurrent layer of the cache must be.
PORTABLE = {"gdn": (GDNState, GDNLayerState), "swa": (SWAState, SWALayerState)}


class Snapshot:
    """A recurrent state at `position`, on the host: the stock stash, and its
    size as the state counts it."""

    __slots__ = ("position", "stashed", "nbytes")

    def __init__(self, position, stashed, nbytes):
        self.position = position
        self.stashed = stashed
        self.nbytes = nbytes


def exact_anywhere(cache):
    """True when `cache`'s recurrent state restores exactly at any token
    position, not only at page boundaries."""
    return cache.recurrent_state_cls is GDNState


def capture(cache, state):
    """A snapshot of `state` where it stands; None when there is none to
    take, or this target cannot restore it there exactly."""
    if state is None:
        return None
    position = int(state.position)
    if position <= 0 or (position % PAGE_SIZE and not exact_anywhere(cache)):
        return None
    return Snapshot(position, state.stash(), int(state.checkpoint_size))


def restore(cache, snapshot):
    """A new state slot holding `snapshot`, at its position."""
    return cache.new_from_stashed(snapshot.stashed, snapshot.position)


def portable_kind(cache):
    """The kind of `cache`'s recurrent state a snapshot carries (`gdn`,
    `swa`), or None when it carries none of it."""
    layers = list(cache.get_all_recurrent_layers().values())
    for kind, (state_cls, layer_cls) in PORTABLE.items():
        if cache.recurrent_state_cls is state_cls and layers and all(type(layer) is layer_cls for layer in layers):
            return kind
    return None


def ring_span(layer, position):
    """The ring rows an SWA layer's stock stash at `position` holds, and its
    stock restore writes back: [lo, hi)."""
    hi = min(int(layer.module.kv_state_size), position)
    return max(0, hi - int(layer.module.sliding_window)), hi


def capture_portable(cache, snapshot):
    """`snapshot` (a stock stash) as a snapshot's state: its header fields
    and its (name, host tensor) pairs. Refused `snapshot_incompatible` when
    `cache`'s state has no portable form."""
    kind = portable_kind(cache)
    if kind is None:
        raise incompatible("this target's recurrent state has no portable form")
    stashed = snapshot.stashed
    fields = {"kind": kind, "position": int(snapshot.position)}
    tensors, rings = [], {}
    for key, layer in cache.get_all_recurrent_layers().items():
        name = layer_name(key)
        first, second = stashed[key]
        if kind == "gdn":
            tensors += [(f"state.{name}.recurrent", first), (f"state.{name}.conv", second)]
        else:
            rings[name] = list(ring_span(layer, int(snapshot.position)))
            tensors += [(f"state.{name}.k", first), (f"state.{name}.v", second)]
    if kind == "swa":
        fields["window_beg"] = int(stashed["window_beg"])
        fields["rings"] = rings
    return fields, tensors


def rebuild_portable(cache, fields, tensors, frontier):
    """The Snapshot a snapshot's state (`fields`, and the `state.` tensors it
    takes out of `tensors`) rebuilds on `cache`: the stock stash at its
    position, each tensor the shape and dtype this cache's own stash has.
    Refused `snapshot_incompatible` for any other state."""
    kind = portable_kind(cache)
    if not isinstance(fields, dict) or kind is None or fields.get("kind") != kind:
        raise incompatible("the snapshot's recurrent state is not this target's kind")
    keys = {"kind", "position"} | ({"window_beg", "rings"} if kind == "swa" else set())
    position = fields.get("position")
    if set(fields) != keys or type(position) is not int or not 0 < position <= frontier:
        raise incompatible("the snapshot's recurrent state names no position within its frontier")
    stashed = {"position": position}
    if kind == "swa":
        window_beg, rings = fields["window_beg"], fields["rings"]
        if type(window_beg) is not int or not 0 <= window_beg <= position or window_beg % PAGE_SIZE \
                or not isinstance(rings, dict):
            raise incompatible("the snapshot's SWA window is not one this target restores")
        stashed["window_beg"] = window_beg
    layers = cache.get_all_recurrent_layers()
    for key, layer in layers.items():
        name = layer_name(key)
        if kind == "gdn":
            width = int(layer.module.conv_kernel_size)
            recurrent, conv = layer.recurrent_state[0, :1], layer.conv_state[0, :, :width]
            stashed[key] = (take(tensors, f"state.{name}.recurrent", recurrent.shape, recurrent.dtype),
                            take(tensors, f"state.{name}.conv", conv.shape, conv.dtype))
        else:
            lo, hi = ring_span(layer, position)
            if rings.get(name) != [lo, hi] or position - stashed["window_beg"] > int(layer.module.kv_state_size):
                raise incompatible(f"the snapshot's ring for layer {name} is not one this target restores")
            k, v = layer.k_state[0, lo:hi], layer.v_state[0, lo:hi]
            stashed[key] = (take(tensors, f"state.{name}.k", k.shape, k.dtype),
                            take(tensors, f"state.{name}.v", v.shape, v.dtype))
    if kind == "swa" and set(rings) != {layer_name(key) for key in layers}:
        raise incompatible("the snapshot's ring spans name other layers")
    stashed["checkpoint_size"] = sum(int(layer.get_checkpoint_size()) for layer in layers.values())
    return Snapshot(position, stashed, stashed["checkpoint_size"])
