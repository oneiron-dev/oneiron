# Authority checkpoint image size

Authority checkpoint v2 images keep complete canonical `AgentGrantAct` bodies,
including any signed acknowledgment set. The checkpoint image family no longer
applies the former 64 MiB total-image policy ceiling. Encoding, decoding,
coverage, root-policy/status/history readers, countersign staging, sync download,
and remote bundle download use the same rule. They do not cap, truncate, or
omit an acknowledgment set to make an image fit.

This changes image handling, not the signed-Revoke producer or counted-proof
rules. Those remain separate authority behavior.

## The 64 MiB optional-compaction trigger

`AUTHORITY_CHECKPOINT_V2_COMPACTION_BYTES` keeps the existing 64 MiB value.
Replay selection now measures the named MessagePack replay value alone, not
chain parents, archive manifests, unresolved rows, or other image fields:

1. Complete replay that fits keeps its original field deltas. Their anchors
   follow the signed first parent only, with the existing 32-row stride.
2. Replay above the trigger keeps the largest fitting suffix in parents-first
   order, with hash-order ties. This is topological order, not wall time. Each
   retained point is a whole state or an explicit rejection. No retained delta
   needs a dropped base. The first non-fitting or missing older point ends the
   suffix; omitted states remain unknown and request history when needed.
3. A successor of a partial image carries its actual known states through the
   same serialization normalization, then selects the suffix from all covered
   row parents. Dropped older points cannot re-enter the fitting suffix as an
   admitted tail adds points. The root still checks its own exact-byte rebuild.

Residence eligibility is unchanged: measure the image with replay replaced by
`AUTHORITY_REPLAY_OVERFLOW`, then drop residence directive and result bodies
and set `AUTHORITY_RESIDENCE_BODY_OVERFLOW` only if that baseline exceeds the
trigger. Retaining more replay does not newly drop working residence bodies.
The residence baseline's existing sensitivity to install-local image metadata
is separate from the replay selection rule.

An image at or below the trigger keeps both. An image still above it after
compaction is encoded with all remaining bodies intact. The trigger itself
does not cause a refusal. Neither compaction drops `AgentGrantAct` bodies.
Checkpoint fold schema 23 describes this replay representation. There is no
schema-22 reader or migration.

## Transport slicing and stage charge

Existing part, page, and per-RPC reply limits are unchanged. A multipart image
can span many replies:

- 2 MiB countersign parts (`AUTHORITY_CHECKPOINT_COUNTERSIGN_PART_MAX`).
- 16 MiB checkpoint serve slices (`AUTHORITY_CHECKPOINT_PART_MAX`).
- 2 MiB entry parts, 8 MiB/512-row history pages, and 32 MiB RPC replies.

The home countersign stage charges its buffer room on the existing host retained
line before allocation. Its charge stays with the staged buffer and through the
blocking countersign finish. The existing memory-floor result, idle cleanup,
socket cleanup, peer checks, ordering, and total-consistency checks remain in
place. Length checks reject arithmetic overflow and totals that do not fit
`usize`; they do not impose another image policy ceiling.

Decode, rebuild, re-encode, store, and remote-client join buffers are not charged
separately by this staging charge. This change does not establish full-heap
accounting, arbitrary end-to-end transport, or a runtime bound. In particular,
WindowSync frame limits are separate from checkpoint multipart transport. It
does not complete FIX5114.

## Cold reads across a changed authority context

A changed pinned root or peer consent set re-judges each dependent covered row
under both the image's inputs and the current inputs. A world-refolded row may
use a crossed main-log parent's state rebuilt from that parent's canonical
signed body already carried in the image. The rebuilt state uses the same
same-vault parent merge and signed-sequence bound as the original world refold.
Both judgments must still equal the image's kept state.

Missing replay states, missing carried bodies, side-row parents, and failed
reconstruction still request the whole history. The cold-context reconstruction
does not add image bodies, change the compaction trigger, or relax row validation.

## Rollout

Use matching engine/server and remote-client code in an authorized deployment.
This change needs no new configuration, migration, SDK inventory, guest image,
or worker. It does not build or deploy those components.
