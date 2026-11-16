//! The derivation transaction (untangle slice 6.7, primitive C): an agent
//! lands what it derived as ONE batch, in one write, and the engine judges
//! each item on its own.
//!
//! The caller supplies the items and nothing about who it is: the engine
//! stamps the actor, the `Generated` source, the run and its recorded
//! lineage from the caller's live run ([`DerivationStamp`]), and marks every
//! row it lands `surface = vault.derive` with the batch's id. Each item
//! stages in a savepoint of the batch's write:
//! - a claim item goes through the shared claim gate as the caller, with
//!   the derivation floors (GATE-12, GATE-13, the checker) a Dreamer run
//!   meets; a held Auto write is tried again as Proposed;
//! - a refused item rolls back its savepoint and keeps a refusal receipt,
//!   and an item that names a refused item is refused in turn;
//! - a malformed batch aborts the whole write.
//!
//! The batch record ([`record`]) lists every item's outcome and the rows it
//! landed, so the batch can be read back and, from 6.7c, reverted.
//!
//! Every item kind is one arm of [`DerivationItem`] with a stager of its
//! own: a new kind adds an arm and touches no other (S69-C-ITEMS).
//!
//! The verbs `vault.derive.commit` and `vault.derive.revert` (6.7d) carry a
//! batch and a revert on the wire ([`DeriveCommitInput`],
//! [`DeriveRevertInput`]); the host stamps who commits from the caller's
//! held live run.

mod archive;
mod artifact;
mod attachment_head;
mod batch;
mod candidate;
mod claim;
mod commit;
mod conflict;
mod conflict_resolution;
mod evidence;
mod extraction_opening;
mod extraction_set;
mod link;
mod person;
mod record;
mod revert;
mod settle;
mod sources;
mod spans;
mod supersede;
pub(crate) mod tables;
mod verified_landing;
mod wire;

pub use archive::{
    ARCHIVE_CONFIG_CHANGED, ARCHIVE_NEEDS_ATTEMPT, ARCHIVE_NO_OBSERVED_SOURCE, ARCHIVE_NOT_A_CLAIM,
    ARCHIVE_OBSERVATION_CHANGED, ARCHIVE_POLICY_CHANGED, ARCHIVE_SCORE_NOT_BELOW_POLICY,
    ARCHIVE_SOURCE_MOVED, ARCHIVE_SOURCE_WITHHELD,
};
pub use artifact::{
    PROFILE_MALFORMED, PROFILE_SOURCE_UNREAD, PROFILE_SUBJECT_UNREAD, PersonAboutFacts,
};
pub use batch::{
    DerivationBatch, DerivationItem, DerivationStamp, DerivedAboutLine, DerivedArchive,
    DerivedCandidate, DerivedClaim, DerivedConflict, DerivedConflictMember,
    DerivedConflictResolution, DerivedEvidence, DerivedEvidenceSpans, DerivedPerson,
    DerivedPersonAbout, DerivedPsychProfile, DerivedResolutionOutcome, DerivedSameAs,
    DerivedSettle, DerivedSettlement, DerivedSupersede, DerivedTopology, ItemRef, MAX_BATCH_ITEMS,
};
pub use candidate::{
    CANDIDATE_CONTESTS_HEAD, CANDIDATE_DUPLICATE, CANDIDATE_IMPORTED_EVIDENCE,
    CANDIDATE_LANDING_REFUSED, CANDIDATE_NEEDS_EXTRACTION_ATTEMPT, CANDIDATE_NOT_ATTEMPT_DREAMER,
    CANDIDATE_OPERAND_REFUSED, CANDIDATE_OWNER_DECLINED, CANDIDATE_RESTATES_HEAD,
};
pub use commit::{DerivationReceipt, ItemOutcome, ItemReceipt};
/// Shared member stamping for the build-only native resolution door.
#[cfg(oneiron_test_support)]
pub(crate) use conflict::inputs::member_candidate;
pub use conflict::{
    CONFLICT_DUPLICATE, CONFLICT_HEADS_DIFFER, CONFLICT_NEEDS_EXTRACTION_ATTEMPT,
    CONFLICT_OPERANDS_REFUSED,
};
pub use conflict_resolution::{
    CONFLICT_RESOLUTION_DUPLICATE, CONFLICT_RESOLUTION_HEADS_DIFFER,
    CONFLICT_RESOLUTION_IMPORTED_EVIDENCE, CONFLICT_RESOLUTION_LANDING_REFUSED,
    CONFLICT_RESOLUTION_MERGE_REFUSED, CONFLICT_RESOLUTION_NEEDS_EXTRACTION_ATTEMPT,
    CONFLICT_RESOLUTION_NOT_ATTEMPT_DREAMER, CONFLICT_RESOLUTION_NOTHING_TO_LAND,
    CONFLICT_RESOLUTION_OPERANDS_REFUSED, CONFLICT_RESOLUTION_OUTPUT_REFUSED,
    CONFLICT_RESOLUTION_OWNER_DECLINED, CONFLICT_RESOLUTION_RESTATES_HEAD,
    CONFLICT_RESOLUTION_SKIP_NOT_ALLOWED,
};
pub use evidence::{EVIDENCE_HEAD_NOT_A_CLAIM, EVIDENCE_SPAN_UNBOUND, EVIDENCE_UNVERIFIED};
pub use link::{SAME_AS_NOT_CLAIMS, TOPOLOGY_NEEDS_GRANT, TOPOLOGY_REJECTED, TOPOLOGY_UNREAD};
pub use person::{
    PERSON_ID_TAKEN, PERSON_NAME_UNREAD, PERSON_NEEDS_ATTEMPT, PERSON_NOT_ATTEMPT_DREAMER,
    PERSON_SOURCE_INADMISSIBLE,
};
pub use record::{DerivationBatchRecord, ItemRecord};
pub use revert::{
    DERIVE_REVERT_CONTENT_KIND, DeriveRevertReceipt, REVERT_CHANGED_SINCE, REVERT_INVERSE_REFUSED,
    REVERT_NO_INVERSE, REVERT_NOT_YOURS,
};
pub use settle::{SETTLE_OWNER_HOLD, SETTLE_REFUSED};
pub use sources::{SOURCE_MOVED, SOURCE_WITHHELD};
pub use supersede::{
    SUPERSEDE_LIFECYCLE, SUPERSEDE_PROTECTED_SOURCE, SUPERSEDE_REPLACEMENT_UNSETTLED,
};
pub use wire::{
    DeriveArchiveInput, DeriveCandidateInput, DeriveClaimInput, DeriveCommitInput,
    DeriveCommitView, DeriveConflictInput, DeriveConflictMember, DeriveConflictResolutionInput,
    DeriveConflictResolutionOutcome, DeriveEvidenceInput, DeriveEvidenceSpans, DeriveItemInput,
    DeriveItemView, DeriveLeftItemView, DerivePersonInput, DeriveRef, DeriveRevertInput,
    DeriveRevertView, DeriveSameAsInput, DeriveSettleInput, DeriveSettlementInput,
    DeriveStrengthSignals, DeriveSupersedeInput, DeriveTopologyInput,
};

/// The provenance `surface` a derivation commit stamps on every row it
/// lands. The gate reads it as a derivation-class write.
pub const DERIVE_SURFACE: &str = "vault.derive";

/// The provenance key naming the batch a row landed in.
pub const DERIVE_BATCH_KEY: &str = "batch";

/// The provenance key naming the extraction attempt whose binding committed
/// the batch, as lower hex of its attempt id. Only a binding's commit stamps
/// it; the gate groups the row with the binding's run from it.
pub const DERIVE_EXTRACTION_ATTEMPT_KEY: &str = "extraction_attempt";

/// The refusal token of an item that names a batch-local row that is not
/// there: a refused item's, or that of a candidate that attached to a head
/// and so created no row.
pub const DEPENDENCY_REFUSED: &str = "gate.deny.derive.dependency_refused";

/// The gate decision ledger's content kind for a derivation item's refusal
/// receipt.
pub const DERIVE_ITEM_CONTENT_KIND: &str = "vault.derive.item";

/// `actor`'s own scoped read: what it may derive from and cite.
fn actor_read(
    vault: &crate::Vault,
    actor: crate::write_envelope::WriteActor,
) -> crate::error::Result<crate::claim::ScopedRead<'_>> {
    let key = crate::claim::ScopedReadActorKey::for_engine_actor(actor).ok_or(
        crate::error::Error::InvalidClaimBody("a derivation actor has no read"),
    )?;
    Ok(vault.scoped_read(key))
}
