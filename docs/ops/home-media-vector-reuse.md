# Reusing home media vectors

An opened-item device with a live own-device sync connection can reuse a
compatible text, image or audio vector already stored on its home before the
existing media backfill calls its model. The native call is
`Vault::reuse_home_media_vectors`; it asks for every kind the space fills.
The private residence RPC is `residence.media_vectors`; it is not an SDK verb.

## What this slice carries

- Text rows for CLAIMs, strictly decoded epoch SUMMARYs and TURNs in a declared
  media embedding space. A TURN uses its visible MESSAGE text in native message
  order. The space keeps its complete `model@revision@where` identity.
- Image and audio rows for ASSETs whose body names their bytes by hash
  (census L7-43). The source set is the ASSET row alone: its full-carrier
  digest pins the hash, so it pins the exact bytes the vector was made from.
  Both ends must hold those bytes. By default images and raw audio share one
  media space beside the text space.
- The row's kind, native text hash (zero for image and audio), stored vector
  bytes and optional device/runtime provenance, with the complete native
  source-ID set and full source-carrier digests. A carrier digest is not a claim about the model's runtime.
- One entity per RPC on the existing authenticated, actor-bound residence lane.
  Both ends require a currently proven own machine. Existing RPC budgets apply.

The home checks the credential, live selector grant and every source's full
selected bytes. A masked or partial source does not qualify. It rechecks after
point reads and attaches all source IDs to the existing queued-reply release.
A headed MESSAGE also passes the document export's eligibility, read and
withhold checks. If that text would leave as a masked or sealed copy, its
original vector is not reused. These checks do not export a document or change
its lineage or disclosure floor. A final native re-read must match the captured
replica, including its text hash: a document edit need not change its pointer row.
The receiver re-reads the current input (the text, or the ASSET's named bytes)
and complete source set in its write transaction. It reuses the row only when
the kind matches and its own declared space, slot, width, finite-value and
source-image checks pass. The native put retains the mark and
clears the same row's previous media refusal.

## What stays unchanged

No live home, an unproven peer, an unavailable cached row or a mismatch leaves
local backfill in place. Fresh model work keeps its existing egress gate,
refusals, counters and room/version-move work. A reused row is not reported as
fresh local model generation.

No vector map is added to canonical window documents. Logical export remains
setup-only. The media-row storage format, room MediaVector operations and
checkpoint getter are unchanged. This slice adds no setting, timeout or numeric
limit, and requires no migration.

Text ASSETs, ASSETs whose bytes a repo mark covers (the model reads their
masked copy, which the row does not pin, so each device embeds its own),
default text index vectors, other machine
directions and devices without the live opened home-query path remain outside
this slice. Matching device and home engine/server versions are needed to use
the new private RPC; existing backfill still works
when the home does not answer it. This is not runtime or full-sync proof.
