//! ARTL-4 (OF-368 D5/D6/D7): retained-output settle + receipts.
//!
//! An ARTL-3 [`EditProposal`] is a **retained output**: the edited bytes and
//! the edit-manifest exist, but nothing touches the artifact until the proposal
//! is *settled*. Settlement is **consume-once** (D5): exactly one of
//!
//! * **settle-select** — the proposal's bytes become a new blob-artifact
//!   version (provenance [`BlobVersionProvenance::AgentRun`](crate::blob_artifact::BlobVersionProvenance::AgentRun)), the manifest's
//!   anchor effects are replayed onto the artifact's annotation threads, and a
//!   select receipt lands; or
//! * **settle-discard** — the proposal is dropped and a discard receipt records
//!   the proposal ref
//!
//! consumes a proposal. A second settle of *any* kind on the same proposal is a
//! typed refusal ([`Error::EditProposalAlreadySettled`]). Until settled, a
//! proposal is invisible to the version chain — the retained bytes are never a
//! version, never read back.
//!
//! # Consume-once ledger + one-transaction settle
//!
//! Each proposal is keyed by `(artifact, proposal_ref)` where `proposal_ref` is
//! the agent run ref that produced it. A [`SettlementRecord`] in `vault_meta`
//! is the ledger: a select or discard writes exactly one.
//!
//! A settle-select's ledger acquisition, version append, and re-anchor sweep are
//! ONE [`Vault::with_write_txn`] — all-or-nothing. The ledger key is checked
//! FIRST, before any side effect, so a settle that finds it committed refuses
//! having written nothing. Because LMDB serializes writers, a racing second
//! settle runs its whole transaction only after the first commits, sees the
//! ledger row, and rolls back with no version appended; and a crash mid-settle
//! rolls the entire transaction back, so a retry re-appends cleanly rather than
//! rereading the new head as its base and skipping the re-anchor. The base head
//! is read inside the same transaction, so it is never stale against a
//! concurrent append. A discard is the same shape without the append/re-anchor.
//!
//! # Stale-proposal refusal (D5)
//!
//! A proposal is produced FROM a specific head ([`EditProposal::base_content_hash`]).
//! Select refuses ([`Error::EditProposalStale`]) when that base no longer equals
//! the artifact head — an intervening edit moved the head, so committing these
//! bytes would clobber it and replay a stale manifest onto newer anchors.
//!
//! # Re-anchor on select (D2/D5)
//!
//! In the same transaction as the append, select replays the manifest's anchor
//! effects ([`EditManifest::anchor_effects`]) onto the threads anchored at the
//! prior head — the [`Vault::reanchor_annotation_threads`] sweep, driven through
//! the shared write txn. The manifest's
//! [`AnchorEffect`](crate::edit_roundtrip::AnchorEffect)s lower to ARTL-2
//! [`ReanchorOp`]s through `From<&AnchorEffect>` (the reconciliation the ARTL-2
//! module doc calls for): a thread on a moved cell advances to the new version
//! with a remapped locator; a thread on a destroyed range drifts and stays
//! pinned to its origin version.
//!
//! # Receipts (D6/D7)
//!
//! Both paths land an OF-367 receipt ([`ReceiptKind::ArtifactSettle`]) projected
//! from the settlement record — a floor receipt, persisted through its own
//! substrate. A select receipt resolves `artifact@version` plus the anchor set
//! that moved (the tappable door, [`Vault::settle_receipt_door`], opens the lens
//! at those anchors); a discard receipt records the proposal ref and reason.
//! When the settle rode an assigning brief, the receipt's `job_ref` joins that
//! brief's project view (B2 RS4).
//!
//! # Standing-grant authority (D6)
//!
//! D6 lets a standing "agent may edit this workbook" grant authorize a settle
//! without a per-op consent prompt. The brief×verb-class *scope* vocabulary
//! also exists as
//! [`StandingOutboundGrantScope::BriefVerbClass`](crate::outbound_grant::StandingOutboundGrantScope),
//! but its carrier is the outbound-*send* grant family, whose capability is
//! sends-to-counterparties, not artifact writes — honoring one for a settle
//! would conflate two capabilities. Per the ARTL-4 rule "do not invent a new
//! grant family", the authority now comes from the DEC-0006 unified consent
//! contract instead: [`Vault::settle_standing_grant_authorizes`] requires a
//! live standing ACTION grant bounding the acting actor × [`SETTLE_VERB_CLASS`]
//! × the exact brief target. It fails closed — a disclosure grant, another
//! actor, a wider-target assumption, or a revoked row all authorize nothing.
//! The owner-driven select/discard ([`SettleConsent::OwnerConsent`]) remains
//! the P1 path.

mod codec;
mod keys;
mod receipts;
mod records;
mod settle;

pub use self::keys::{
    SETTLE_VERB_CLASS, SETTLED_ANCHOR_KEYS, SETTLEMENT_RECORD_KEYS, SETTLEMENT_SCHEMA_VERSION,
};
pub(crate) use self::receipts::settle_receipts;
pub use self::records::{
    SettleConsent, SettleDiscardOutcome, SettleOutcomeKind, SettleReceiptDoor, SettleSelectOutcome,
    SettledAnchor, SettlementRecord,
};

#[cfg(test)]
mod tests;

// The flat edit_settle.rs module used to provide these names to the sibling test
// module through `use super::*`: its own private crate/std import header, and
// every edit_settle-internal item the tests name bare. After the directory split
// the seam re-imports both so `tests.rs` resolves exactly as it did before.
#[cfg(test)]
use self::codec::{decode_settlement_record, encode_settlement_record};
#[cfg(test)]
use crate::Vault;
#[cfg(test)]
use crate::anchored_annotation::Locator;
#[cfg(test)]
use crate::blob_artifact::BLOB_ARTIFACT_CONTENT_HASH_LEN;
#[cfg(test)]
use crate::entity_id::EntityId;
#[cfg(test)]
use crate::error::Result;
#[cfg(test)]
use crate::temporal::TimeRange;
