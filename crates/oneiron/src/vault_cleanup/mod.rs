//! ARCH-0073 vault auto-cleanup: the Dreamer ARCHIVE cron (ONE-1931).
//!
//! # What this is
//!
//! A vault accumulates rows that carry nothing: a PERSON an extraction pass
//! minted and never learned a single fact about, a SUMMARY whose members are
//! all gone. They are not wrong, they are EMPTY, and deleting them is not
//! what anyone wants — the owner may mention that person tomorrow. So the
//! cron ARCHIVES them, and archive is reversible.
//!
//! # The archive verb is a tombstone reason, not a state machine
//!
//! There is no Archive state in this engine and this ticket does not mint one.
//! `DeleteReason::ArchivedByCleanup` (wire byte 5) is the soft-reversible twin
//! of `user_delete`: it keeps the 25 B shell, purges nothing, queues no sweep,
//! and mints no per-entity receipt — the ratified contracts row
//! (`archived_by_cleanup`: `activeStoreHardPurgeV1 = false`,
//! `historicalSweepQueued = false`, `receipt = false`) IS the spec. It is also
//! the one reason that publishes no CRDT tombstone, because an archive is
//! local hygiene rather than a deletion intent peers must obey; see
//! `DeleteReason::publishes_crdt_tombstone`.
//!
//! **Hard deletion is NEVER automatic.** Nothing in this module hard-erases,
//! purges, or enqueues a historical sweep. Its transaction-composable archive
//! door accepts only `DeleteReason::ArchivedByCleanup`, whose behavior matrix
//! is false on every destructive row.
//!
//! # The tripwire is closed-form
//!
//! [`zero_live_members`] is a TRIPWIRE, not a score. It answers from row
//! shape and edge presence alone — no thresholds, no weights, no ranking, no
//! "probably". Two arms ship, held in the const `CLEANUP_CHECKS` table so a
//! third is one line:
//!
//! * Extraction-minted `PERSON` (byte 4) with zero live claims about it.
//! * `SUMMARY` (byte 8) with zero live claims about it and no member or
//!   reference edge in either direction.
//!
//! ARC_THREAD is named by the canon but **has no entity-type byte in this
//! engine**, and this ticket does not mint one. When that kind lands, its arm
//! is one row in `CLEANUP_CHECKS`.
//!
//! ## Extraction-minted PERSON provenance
//!
//! Claim absence is not evidence of minting provenance. The trusted Core
//! extraction writer uses [`Vault::put_extraction_minted_person`] to mint a
//! PERSON with atomic, revision-bound source evidence. Only the
//! [`MACHINE_MINTED_CLAIM_SOURCES`] class is eligible. Ordinary PERSON rows,
//! replaced revisions, and missing or unreadable evidence are never candidates.
//!
//! # Posture: propose-first today, auto later
//!
//! ARCH-0066 teeth #5 (sync re-gating) and #9 (OS sandbox) are OPEN, so the
//! default posture is [`CleanupPosture::ProposeFirst`]: a run emits ONE
//! proposal carrying the impact preview (counts + ids — the preview IS the
//! proposal body) and archives nothing. Accepting RE-RUNS the tripwire per
//! entity and archives only the ones still empty; a candidate that gained a
//! live claim between proposal and accept is SKIPPED, and the skip is on the
//! run's digest receipt. Rejecting archives nothing and leaves no receipt.
//!
//! [`CleanupPosture::AutoWithDigest`] is the post-teeth path, built now and
//! reachable only by an owner flipping the `vault_meta` posture flag. It
//! archives directly and emits ONE digest receipt per run listing the ids —
//! job-level, never per-entity.
//!
//! # Not in this ticket
//!
//! * **Forgetting-window routing is OPEN/deferred** (deletion design
//!   session). This module has no interaction with forgetting windows, by
//!   decision rather than omission.
//! * **The ARCH-0024 resolver/matcher is UNBUILT.** This ticket ships the two
//!   halves that belong to the vault — an archived-aware query
//!   ([`Vault::archived_entities`]) and the restore door
//!   ([`Vault::restore_archived`]) — and records the
//!   "re-mention restores, never duplicates" contract on the door. The
//!   resolver-side hook is that program's ticket.

use rmpv::Value;

use crate::Vault;
use crate::attempt_queue::AttemptId;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};

mod cleanup_types;
mod codec_receipts;
mod person_provenance;
mod proposals_archive;
mod rollout;
mod run_record;
mod scan;
mod tripwire;
mod visibility;

pub use self::cleanup_types::{
    ArchivedEntity, CLEANUP_PHASE, CleanupAcceptOutcome, CleanupCandidate, CleanupDecision,
    CleanupDigest, CleanupImpactPreview, CleanupKind, CleanupPosture, CleanupProposal,
    CleanupRunReport, FIELD_CLEANUP_ARCHIVED_COUNT, FIELD_CLEANUP_ARCHIVED_IDS,
    FIELD_CLEANUP_DECISION, FIELD_CLEANUP_PHASE, FIELD_CLEANUP_POSTURE, FIELD_CLEANUP_PROPOSAL,
    FIELD_CLEANUP_SKIPPED_COUNT, FIELD_CLEANUP_SKIPPED_IDS, FIELD_CLEANUP_TOMBSTONE_REASON,
    VAULT_CLEANUP_ACTOR, VAULT_CLEANUP_POSTURE_KEY, VAULT_CLEANUP_RECEIPT_PREFIX,
};
pub use self::codec_receipts::{cleanup_digests, is_vault_cleanup_receipt};
pub use self::proposals_archive::{
    accept_cleanup_proposal, cleanup_proposal, cleanup_proposals, reject_cleanup_proposal,
};
pub use self::tripwire::{
    MACHINE_MINTED_CLAIM_SOURCES, claim_source_is_machine_minted, cleanup_posture,
    run_vault_cleanup, scan_cleanup_candidates, set_cleanup_posture, zero_live_members,
};

pub(crate) use self::codec_receipts::cleanup_receipts;
pub(crate) use self::tripwire::zero_live_members_in_txn;
pub(crate) use visibility::is_archived_in_txn;

use self::cleanup_types::{
    DIGEST_PREFIX, DIGEST_ROW_LABEL, DIGEST_SCHEMA_VERSION, KEY_ARCHIVED, KEY_AT, KEY_ATTEMPT,
    KEY_CANDIDATES, KEY_CREATED_AT, KEY_DECISION, KEY_ENTITY, KEY_KIND, KEY_POSTURE, KEY_PROPOSAL,
    KEY_SCHEMA_VERSION, KEY_SKIPPED, MAX_CLEANUP_SCAN_ROWS, PROPOSAL_PREFIX, PROPOSAL_ROW_LABEL,
    PROPOSAL_SCHEMA_VERSION,
};
use self::codec_receipts::{
    decode_proposal, decode_row, encode_row, field, fresh_row_id, id_list, id_value_list,
    prefixed_key, proposal_key, put_digest_in_txn, put_proposal_in_txn,
};
use self::tripwire::{
    CLEANUP_CHECKS, apply_archives_in_txn, cleanup_posture_in_txn, run_cleanup_candidates_in_txn,
};

#[cfg(test)]
mod qodo_tests;
#[cfg(test)]
mod repair_tests;
#[cfg(test)]
mod tests;

// The flat vault_cleanup.rs module provided these names to its inline test
// children through `use super::*`: the external imports the tests name bare,
// and the private helpers only the tests reach. After the directory split the
// seam re-imports them under cfg(test) so the test children resolve exactly
// as they did before.
#[cfg(test)]
use self::codec_receipts::digest_key;
#[cfg(test)]
use self::proposals_archive::accept_cleanup_proposal_in_txn;
#[cfg(test)]
use crate::claim::ClaimSource;
#[cfg(test)]
use crate::deletion::{ARCHIVE_TOMBSTONE_PREFIX, DeleteReason, TombstoneReason};
#[cfg(test)]
use crate::edge::EdgeKind;
#[cfg(test)]
use crate::receipt::{ReceiptKind, ReceiptQuery, ReceiptRecord, hex_lower};
#[cfg(test)]
use crate::registry::{ENTITY_TYPE_PERSON, ENTITY_TYPE_SUMMARY};
#[cfg(test)]
use crate::vault::LiveEntityRow;
#[cfg(test)]
use uuid::Uuid;
