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
"""
from exllamav3.constants import PAGE_SIZE
from exllamav3.modules.gated_delta_net import GDNState


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
