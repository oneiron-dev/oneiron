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

`AUTHORITY_CHECKPOINT_V2_COMPACTION_BYTES` keeps the existing 64 MiB value and
the existing optional replay/residence compaction behavior:

1. Above the trigger, the builder drops replay evidence for
   `AUTHORITY_REPLAY_OVERFLOW` and checks the encoded size again.
2. If it is still above the trigger, it drops residence directive and result
   bodies and sets `AUTHORITY_RESIDENCE_BODY_OVERFLOW`.

An image at or below the trigger keeps both. An image still above it after both
fallbacks is encoded with all remaining bodies intact. The trigger itself does
not cause a refusal. In particular, neither fallback drops `AgentGrantAct` bodies.

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

## Rollout

Use matching engine/server and remote-client code in an authorized deployment.
This change needs no new configuration, migration, SDK inventory, guest image,
or worker. It does not build or deploy those components.
