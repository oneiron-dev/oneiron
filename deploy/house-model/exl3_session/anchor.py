"""An anchor: retained state a Job can attach to. A canonical checkpoint is
one: its pages hold the canonical path's KV, no board attached. So is the
carry a thinking call's reasoning pass leaves for its answer pass: that
call's own board, which dies with the call.

`tokens` are the ids whose KV the anchor's pages hold, page `i` holding
tokens [i * PAGE, (i + 1) * PAGE). `snapshots` are recurrent snapshots at
exact positions (`state.py`). A Job attaches at position A only where its
own ids equal `tokens` up to A and a snapshot stands at A: the pages before
A's page are shared, a partial page at A is copied before the Job writes
past it (copy-on-write, `jobs.py`), and its recurrent state starts from the
snapshot. With no snapshot at the common prefix the attach point falls back
to an earlier one, or to none, and the Job replays the rest exactly.
"""
import hashlib

import torch

# The digest's personalization (blake2b takes at most 16 bytes).
DIGEST_PERSON = b"oneiron.ckpt.v1"


def common_prefix(a, b):
    """The longest common prefix of two 1-D id tensors, in tokens."""
    n = min(int(a.numel()), int(b.numel()))
    if n == 0:
        return 0
    differs = torch.nonzero(a[:n] != b[:n])
    return int(differs[0, 0]) if differs.numel() else n


def token_digest(ids):
    """The 64-hex digest of a canonical path's token ids (1-D)."""
    hasher = hashlib.blake2b(digest_size=32, person=DIGEST_PERSON)
    hasher.update(ids.to(torch.int64).contiguous().numpy().astype("<i8").tobytes())
    return hasher.hexdigest()


class Anchor:
    """Retained pages, the tokens they hold, and recurrent snapshots in
    them. `pins` count the branches and commits reading it; a `retired`
    anchor is released once nothing pins it."""

    def __init__(self, tokens, owner, snapshots):
        self.tokens = tokens
        self.owner = owner
        self.snapshots = sorted(snapshots, key=lambda snapshot: snapshot.position)
        self.pins = 0
        self.retired = False
        self.released = False

    @property
    def frontier(self):
        return int(self.tokens.numel())

    def attach_point(self, ids, cap):
        """Where a Job over `ids` (1-D) can attach, at most `cap` and short
        of its last id (which generation feeds): `(position, snapshot)`,
        `(0, None)` for nowhere."""
        limit = min(common_prefix(ids, self.tokens), cap, int(ids.numel()) - 1)
        best = None
        for snapshot in self.snapshots:
            if snapshot.position <= limit:
                best = snapshot
        return (0, None) if best is None else (best.position, best)

    def snapshot_bytes(self):
        return sum(snapshot.nbytes for snapshot in self.snapshots)
