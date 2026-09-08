//! `edge.provenance` Claim module (EDGE-PROVENANCE = C, pinned decisions
//! D10/D12/D13/D15).
//!
//! Under model C the 26 B provenanced edge caches ONLY the two hot flags
//! (`confirmation_status` + `actor_class`). The FULL provenance record —
//! actor entity, source revision / body snapshot, confidence, supersession,
//! validity window — is a CLAIM with predicate [`PREDICATE_EDGE_PROVENANCE`],
//! and that Claim is the SOURCE OF TRUTH. The edge's two flags are a DERIVED
//! CACHE of the Claim (`confirmation_status` ← `supersession_status`,
//! `actor_class` ← the validated class of `actor_entity_ref`).
//!
//! Storage shape (contracts.ts `edgeProvenanceClaim`):
//!
//! * subject — the provenanced edge, addressed as a 33-byte [`EdgeRef`]
//!   `(source_id 16 B ‖ edge_kind u8 ‖ target_id 16 B)`, byte-identical to
//!   the LMDB edge key (`Store::encode_edge_key`);
//! * predicate — the literal `"edge.provenance"`;
//! * value — a MessagePack map carrying EXACTLY the ten pinned snake_case
//!   fields in [`EDGE_PROVENANCE_BODY_KEYS`] (the ONE-1138 vocabulary bump:
//!   the original seven + `substrate_ref` + `reasoning_effort` +
//!   `actor_class`, moved together as ONE sync-versioning event);
//! * stored as — a normal CLAIM entity (type byte 0, 25 B envelope +
//!   MessagePack body) written through the `pub(crate)` reserved-namespace
//!   door (D17/D18, ONE-1104);
//! * link edge — `claim_of` (u8 = 5, structural 12 B) from the Claim to the
//!   subject edge's SOURCE entity (D12); the authoritative 33-byte EdgeRef
//!   lives in the Claim body's `subj`.
//!
//! Envelope mapping (D15): the Claim entity's `occurred` interval is an
//! index-key derivation of the validity window — absent `valid_from` →
//! `occurred.start = learned_at`; absent `valid_to` → `occurred.end =
//! u64::MAX` (open intervals sort last in `temporal_occurred_end` /
//! `temporal_long_intervals`). Authoritative optionality stays in the
//! MessagePack body. The `temporal_long_intervals` migration guard
//! (`store.rs` step 7) only compares a schema-version key and never inspects
//! row timestamps, so `u64::MAX` end keys use the current `(24, 8)` row shape
//! and cannot trip it; the reopen spec test pins this. A derived envelope
//! with `start > end` (e.g. `valid_to` earlier than `learned_at` with no
//! `valid_from`) is rejected fail-closed with
//! [`Error::InvalidProvenanceBody`] — never silently reordered.
//!
//! Flag writes (D10): `restamp_edge_flags` is the ONLY 26-byte stamp
//! primitive and it stays `pub(crate)`. The single public door to provenance
//! flags is the Claim lifecycle ([`crate::Vault::put_edge_provenance`],
//! [`crate::Vault::supersede_edge_provenance`],
//! [`crate::Vault::retract_edge_provenance`]) — flags without a Claim would
//! be an unauditable cache, so no public raw-flag API exists.
//!
//! # Lifecycle (retract + supersede, contracts.ts `retractionRules` + D14)
//!
//! A provenance Claim is **LIVE** iff its wrapping Claim's `life` status is
//! `active`. Closed Claims (`superseded` / `retracted`) are never deleted —
//! they stay readable as history.
//!
//! * **SUPERSEDE** — "a newer edge.provenance Claim … takes precedence; the
//!   prior Claim gets valid_to set (closed, not deleted). Confidence breaks
//!   ties among live Claims." Per D14, "newer" is the Claim ENTITY's
//!   envelope `learned_at` (u64); `source_revision_ref` is opaque. Writing a
//!   provenance Claim for an EdgeRef therefore:
//!   - REJECTS (typed [`Error::ProvenancePrecedenceViolation`]) when the
//!     incoming `learned_at` is OLDER than the live frontier — an older
//!     Claim can never take precedence, and the engine refuses to write a
//!     dead-on-arrival assertion;
//!   - CLOSES every live Claim whose `learned_at` is strictly older than
//!     the incoming one (`life` = superseded; `valid_to` set to the incoming
//!     `learned_at` when the record had no `valid_to` of its own — an
//!     already-closed validity window is preserved, never extended);
//!   - lets equal-`learned_at` Claims COEXIST live (the contract's
//!     "confidence breaks ties among live Claims" requires a live cohort);
//!   - the explicit [`crate::Vault::supersede_edge_provenance`] form closes
//!     its named prior Claim even on a `learned_at` tie.
//!
//! * **WINNER / DERIVE** — "whenever the Claim changes, re-stamp the edge's
//!   two hot flags from it." With multiple live Claims the stamp source is
//!   the WINNER under the total D14 order: greatest `learned_at`, then
//!   greatest `confidence` ([`f32::total_cmp`]), then greatest claim-id
//!   bytes (engine-defined final tiebreak so the winner is deterministic).
//!   See `winner_index`.
//!
//! * **RETRACT** — "set supersession_status = retracted (and typically
//!   valid_to = now). The edge is KEPT with confirmation_status = retracted
//!   … the edge is not physically removed on retraction." One transaction
//!   sets the record's `supersession_status` = retracted and `valid_to` =
//!   `now`, mirrors `life` = retracted / `to` = `now` on the wrapper,
//!   re-puts the Claim with the envelope `occurred.end` refreshed per D15,
//!   and restamps the edge: from the live WINNER when other live Claims
//!   remain, else `confirmation_status` = retracted with the retracted
//!   Claim's own persisted `actor_class`.
//!
//! * **Close-instant validation** — closing can never invert a validity
//!   window: when the effective `valid_to` would precede `valid_from` (or
//!   the derived envelope start), the operation fails typed
//!   ([`Error::InvalidProvenanceBody`]) — never silently reordered.
//!
//! * **DELETE (ARCH-0038, D16)** — hard-deleting (any receipt-writing
//!   reason) or SoftErasing a provenance Claim removes/scrubs the TRUTH the
//!   edge flags cache. "The derived edge flag follows the Claim": the delete
//!   path captures the EdgeRef + sweep refs pre-purge, and post-purge
//!   refreshes the subject edge in the same transaction — restamped from the
//!   D14 winner among the REMAINING live Claims; else, when a RETRACTED
//!   `edge.provenance` Claim for the same EdgeRef still survives, the 26 B
//!   retracted dampening stamp is KEPT (the withdrawn provenance stays
//!   dampened — the retracted Claim is still readable truth, so the flag
//!   remains auditable), mirroring RETRACT's own None-branch; only when NO
//!   provenance Claim of ANY lifecycle survives is the edge downgraded
//!   26 B → 24 B bare via `downgrade_edge_to_bare` (a cached flag without
//!   any truth-Claim is unauditable). The captured `body_snapshot_ref` /
//!   `source_revision_ref` ride the queued historical-carrier sweep row's
//!   scope (executor = ONE-1091, deferred; cross-device propagation =
//!   ONE-1090, deferred).
//!
//! # Persisted `actor_class` (refresh seam + ONE-1138 relocation)
//!
//! The edge's `actor_class` flag derives from `actor_entity_ref` (contracts
//! `derivesEdgeFlags[1]`), but D13 makes the {human, agent} split for PERSON
//! actors CALLER-SUPPLIED at write time — it is not recoverable from storage
//! alone. So that a later winner-refresh (retract/supersede/D16 delete) can
//! restamp a HISTORICAL Claim's flags without defaulting, the write path
//! persists the write-time validated class ON the value record itself as the
//! `actor_class` body key (ONE-1112 C2 relocation, part of the ONE-1138
//! vocabulary bump). Validation is unchanged: caller-supplied, validated
//! against the actor entity's StructuralKind, never derived by default.
//!
//! TRANSITION SEMANTICS (ONE-1138, pinned): pre-bump claims persisted the
//! class on the wrapping Claim's `evid` field as the engine-owned map
//! `{"actor_class": u8}`. Those claims are NEVER invalidated — the decoder
//! accepts the legacy evid form when the body key is absent. Going forward,
//! writers write the BODY key ONLY and leave `evid` to evidence purity. A
//! claim carrying the class in BOTH places is ambiguous and fails closed
//! ([`Error::InvalidProvenanceBody`]); a claim carrying it in NEITHER fails
//! the same way — never a defaulted class. See
//! `resolve_persisted_actor_class`.

mod actor_substrate;
mod codec;
mod edge_ref;
mod imported;
mod lifecycle;
mod queries;
mod writes;

#[cfg(test)]
pub(crate) use self::actor_substrate::encode_actor_class_evidence;
pub(crate) use self::actor_substrate::{
    EVIDENCE_KEY_ACTOR_CLASS, decode_actor_class_evidence, decode_model_entity_body,
    encode_model_entity_body, resolve_persisted_actor_class, validate_model_substrate_field,
};
pub use self::actor_substrate::{MODEL_SUBSTRATE_FIELD_MAX_BYTES, validate_actor_class};
pub use self::codec::{
    EdgeProvenanceClaimBody, decode_edge_provenance_body, derive_confirmation_status,
};
pub(crate) use self::codec::{encode_edge_provenance_value, validate_edge_provenance_value};
pub use self::edge_ref::{
    EDGE_PROVENANCE_BODY_KEYS, EDGE_REF_LEN, EdgeRef, PREDICATE_EDGE_PROVENANCE,
    REASONING_EFFORT_MAX_BYTES, SupersessionStatus,
};
pub(crate) use self::edge_ref::{
    KEY_ACTOR_CLASS, KEY_ACTOR_ENTITY_REF, KEY_BODY_SNAPSHOT_REF, KEY_CONFIDENCE,
    KEY_REASONING_EFFORT, KEY_SOURCE_REVISION_REF, KEY_SUBSTRATE_REF, KEY_SUPERSESSION_STATUS,
    KEY_VALID_FROM, KEY_VALID_TO,
};
pub(crate) use self::lifecycle::{
    ProvenanceMaterialization, ProvenancePrecedence, StoredProvenanceClaim,
    active_cohort_winner_short_ref_in, close_record_for_supersession,
    closed_cohort_head_short_ref_in, downgrade_edge_to_bare, restamp_edge_flags, retract_record,
    winner_index,
};
pub(crate) use imported::ImportedEdgeProvenance;

use crate::Vault;
use crate::batch::EntityMetadataHeader;
use crate::claim::{ClaimBody, ClaimLifecycleStatus};
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::store::Store;
use crate::vault::parse_edge_record;
use rmpv::Value;

#[cfg(test)]
mod tests;

#[cfg(test)]
use self::lifecycle::closed_claim_put_payload;
#[cfg(test)]
use crate::claim::{ClaimApprovalStatus, ClaimSubject, encode_claim_body};
#[cfg(test)]
use crate::edge::{EdgeActorClass, EdgeConfirmationStatus, EdgeKind};
#[cfg(test)]
use crate::temporal::TimeRange;
