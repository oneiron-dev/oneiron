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

mod archive;
mod artifact;
mod batch;
mod claim;
mod commit;
mod evidence;
mod link;
mod record;
mod settle;
mod supersede;
pub(crate) mod tables;

pub use archive::{ARCHIVE_NEEDS_ATTEMPT, ARCHIVE_NOT_A_CLAIM, ARCHIVE_SCORE_NOT_BELOW_POLICY};
pub use artifact::{
    PROFILE_MALFORMED, PROFILE_SOURCE_UNREAD, PROFILE_SUBJECT_UNREAD, PersonAboutFacts,
};
pub use batch::{
    DerivationBatch, DerivationItem, DerivationStamp, DerivedAboutLine, DerivedArchive,
    DerivedClaim, DerivedEvidence, DerivedPersonAbout, DerivedPsychProfile, DerivedSameAs,
    DerivedSettle, DerivedSettlement, DerivedSupersede, DerivedTopology, ItemRef, MAX_BATCH_ITEMS,
};
pub use commit::{DerivationReceipt, ItemOutcome, ItemReceipt};
pub use evidence::{EVIDENCE_HEAD_NOT_A_CLAIM, EVIDENCE_UNVERIFIED};
pub use link::{SAME_AS_NOT_CLAIMS, TOPOLOGY_NEEDS_GRANT, TOPOLOGY_REJECTED, TOPOLOGY_UNREAD};
pub use record::{DerivationBatchRecord, ItemRecord};
pub use settle::{SETTLE_IMPORT_REVIEW, SETTLE_OWNER_HOLD, SETTLE_REFUSED};
pub use supersede::{SUPERSEDE_LIFECYCLE, SUPERSEDE_PROTECTED_SOURCE};

/// The provenance `surface` a derivation commit stamps on every row it
/// lands. The gate reads it as a derivation-class write.
pub const DERIVE_SURFACE: &str = "vault.derive";

/// The provenance key naming the batch a row landed in.
pub const DERIVE_BATCH_KEY: &str = "batch";

/// The refusal token of an item that names a refused item of its batch.
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
