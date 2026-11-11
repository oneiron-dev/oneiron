# Retrieval run policy attribution (FIX 7315)

A served context-pack run records which policy manifest its two actual typed
policy reads agreed on. The Coach's producer binder reads that witness back.
This document scopes what the witness is and, explicitly, what it is not.

## The two actual typed reads

A `run_for_pack` call that reaches policy setup performs two typed policy
reads, each in its own original read transaction:

1. Claim aging profiles (`claim_aging_profiles_for_run`): always yields the
   already-created `ClaimAgingProfilesView` from that same read.
2. Retrieval weights (`retrieval_weights_for_run`): yields `Some(view)` only
   from its own original body, id, trust check and field decode. A missing row
   or a missing field stays `None`; it never borrows the owner's view, which
   would substitute host defaults for an absent field.

The two reads are independent snapshots of the same default manifest taken at
slightly different instants. They may legitimately disagree if an owner write
lands between them.

## The witness pair

The run stamps `policy_manifest_ref` / `policy_manifest_body_hash` on its
`RetrievalRunRecord` only when weights were `Some` AND both views' manifest
ref and body hash agree byte-exact. Any absence or any mismatch keeps both
fields `None`. The pair is assigned on the original `run_record` before the
original single writer/session route; scoring, results, observer, config,
validation, trace and telemetry posture are unchanged.

The writer sets both fields or neither. They witness only those two priors.

## The binder's rule

`bind_producer` keeps its existing precedence and gains one arm after the
skill arm and before the existing `links.manifests`/config fallback:

1. Skill first, unchanged: the one active skill the one linked attempt loaded.
2. Run-record witness (new): only for a nonempty run cohort where EVERY run
   recorded both witness fields and all agree on the SAME pair; the recorded
   ref must parse as a native `EntityId` (an invalid ref yields no target,
   never an error); the live raw row must be a native `POLICY_MANIFEST` whose
   current body digest equals the recorded hash. The target is the existing
   `ProducerTarget::PolicyManifest` with that same digest as its revision.
3. Existing `links.manifests`/config fallback, unchanged: the one linked live
   manifest at its stored row's digest; else the config every run recorded it
   ran under, when each recorded the same one; else `Unknown`.

The witness arm applies a current-revision gate: the target revision is the
recorded digest, selected only while the live body still hashes to it. Drift
falls through to the old config/`Unknown` path; the live current revision is
never substituted as history.

## What this is not

- Not a sole-cause claim: the pair proves only that these two priors read one
  agreed manifest body on that run, not that the manifest caused the finding.
- Not composed criticality: the separate composed-policy criticality resolver
  and its contributing manifests are not recorded by this witness.
- Not an all-source proof: VaultSearch, the configured-but-dormant pipeline,
  and any other read path are untouched by this witness.
- Not authority and not a refusal: the witness is data for binding, never an
  admission decision, a hold, or a read refusal. Mixed or absent witnesses
  keep the old path rather than preferring one read.

## Other retrieval producers

Attempt links remain independent and retain skill precedence. Bare VaultSearch,
in-room BM25 and GraphFS retrieval records do not capture these typed-policy
reads and leave the new fields unknown. No missing witness is filled by a later
manifest lookup.
