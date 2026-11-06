# Native attribution judgment sources

The original attribution projector can record independently supplied placement for new
judgments and discovery proposals with `run_attribution_projector_with_positions`.
`AttributionJudgmentReadPosition` holds the original producer's scope, kind band,
relationship, privacy, body worlds/facets and read anchors. These fields are placement
data, not a reader grant. Ordinary projector entrypoints record explicit `None` for
judgment placement. A replay adopts both the stored row id and stored placement before
immutable comparison; it cannot restamp either stored `Some` or stored `None`.
Erasing a subject clears its judgment placement in the same existing write.

The judgment Raw codec requires an explicit `read_position` key, nil or a typed
position. There is no old-format reader or missing-key fallback. The amendment lane's
unstored synthetic judgment has explicit `None`.

Canonical judgment reads retain the physical u64 sequence, full key and BLAKE3 of
stored bytes. The eager scan records the original JUDGMENT prefix, membership and
order. It consults no judge-revision, displacement or fence table. The original Coach
request captures all decoded rows before its skill, subject and DEV filters, using
its full reader key, body pins and custody guard before the same source transaction.
Capture failure leaves ordinary values and errors unchanged and makes only the
optional witness unknown.

Typed `AttributionJudgment` and `AttributionJudgmentScan` native sources travel in the
existing `AttemptSources` carrier. Heal compares the current physical rows and scan,
then re-admits each row under the current full native predicate in that transaction.
Neither a physical u64 key nor a minted native row id grants ENTITY access.

This is a partial native family, not a complete Coach/model source declaration.
Complete Coach sources remain `None` and attempt activation remains off until the
remaining actual source families and terminal publisher compose. No runtime,
privacy, compiler or feature-completion proof is claimed by this source change.
