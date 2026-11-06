# Reusing home media vectors

An opened-item device with a live own-device sync connection can reuse a
compatible text, image or audio vector already stored on its home before the
existing media backfill calls its model. The native call is `Vault::reuse_home_media_vectors`.
The private residence RPC is `residence.media_vectors`; it is not an SDK verb.

## What this slice carries

- Text rows for CLAIMs, strictly decoded epoch SUMMARYs, TURNs and text ASSETs,
  and image/audio ASSET rows in a declared media embedding space. A TURN uses
  its visible MESSAGE text in native message order. A text ASSET uses its
  current native projected blob text. Image/audio reuse checks the kind and
  exact projected bytes that the native media reader would send now. An opaque
  text placeholder cannot qualify as image or audio input. The space keeps its
  complete `model@revision@where` identity and current kind-slot bindings.
- The row's kind and original input hash, stored vector bytes and optional
  device/runtime provenance, with the complete native source-ID set and full source-carrier
  digests. Every ASSET includes both its metadata row and the referenced blob's
  own row. A file-backed source is measured as its original metadata header and
  checked full body, not its storage manifest; an inline source keeps its bytes.
  A carrier digest is not release permission or a claim about the model's runtime.
- One entity per RPC on the existing authenticated, actor-bound residence lane.
  Both ends require a currently proven own machine. Existing RPC budgets apply.

The home checks the credential, live selector grant and every source's full
selected bytes. A masked or partial source does not qualify. It rechecks after
point reads and attaches all source IDs to the existing queued-reply release.
A headed MESSAGE also passes the document export's eligibility, read and
withhold checks. If that text would leave as a masked or sealed copy, its
original vector is not reused. These checks do not export a document or change
its lineage or disclosure floor. A final native re-read must match the captured
replica, including its kind and input hash: a document edit need not change its
pointer row. The receiver re-reads the current input and complete source set
in its write transaction. It reuses the row only when its own declared space, slot, width,
finite-value and source-image checks pass. The native put retains the mark and
clears the same row's previous media refusal.

## What stays unchanged

No live home, an unproven peer, an unavailable cached row or a mismatch leaves
local backfill in place. Fresh model work keeps its existing egress gate,
refusals, counters and room/version-move work. A reused row is not reported as
fresh local model generation.

No vector map is added to canonical window documents. Logical export remains
setup-only, and the checkpoint getter is unchanged. This slice adds no setting,
timeout or numeric limit, and requires no migration.

Image/audio model results now keep the hash of the exact projected bytes sent
at the native base or room landing. Room replay preserves that hash. A vector
supplied by a caller without an input binding remains unbound and still works;
its current body is never used to invent an original-input claim. This binding
alone is not enough for image/audio residence reuse: both ends must match its
kind, current input and full source image. An unbound row cannot qualify.
Neither endpoint substitutes the current body hash for a missing original hash.
Text reuse keeps its existing input eligibility and text-hash meaning. The
internal media-row codec stores an explicit hash-presence byte under storage ABI 29; no old-format reader or migration is added.

Default text index vectors, other machine directions and
devices without the live opened home-query path remain outside this slice.
Matching device and home engine/server versions are needed to use the new private
RPC; existing backfill still works when the home does not answer it. This is not
runtime or full-sync proof.
