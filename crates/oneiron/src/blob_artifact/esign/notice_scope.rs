//! FIX 6220: a world-, facet- or record-scoped credential sends its own
//! e-sign notices (`vault.esign.notices.dispatch`) for a signing document
//! its own read lane reaches, and for no other.
//!
//! An unrestricted caller (no bound credential, or one bounded by the whole
//! vault, the only caller the row admitted before) keeps the door's
//! full-vault path exactly: the same verified-actor writer and the same
//! send. A narrowed caller is judged on the signing document by the lane
//! every read verb reads under (its record allowlist, world placement, facet
//! and audience rules, the owner's facet exemption, live grants and the
//! credential's liveness): once before the door lists, recovers or claims a
//! notice, and again in each snapshot that writes. Its recoveries, claims and
//! lease returns go through the document artifact's own content writer (the
//! actor's Grant at the document's position, never a whole-vault one), and
//! its send queues the delivery only while the lane still reaches the
//! document. A document the lane does not reach answers as one that is no
//! signing document.
//!
//! The housekeeping notice worker (FIX 6219, `notice_unattended`) runs the
//! same door path with no caller: as the notices' recorded principal, its
//! recorded send act and standing judged again in each of those snapshots.
use super::model::invalid;
use super::notice_unattended::UnattendedNotices;
use crate::attempt_queue::AttemptRecord;
use crate::authority::VerifiedSlip;
use crate::claim::{ClaimReadStatus, ScopedRead};
use crate::federation::Scope;
use crate::memory::{Memory, MemoryResult};
use crate::outbound::{OutboundDispatchError, OutboundDispatchRequest, OutboundDispatchResult};
use crate::{EntityId, Result, Vault};

/// The record a narrowed credential's scope is judged on for a staged notice
/// (CALLS `FIX 6220 scoped notice dispatch`, accepted by the Engine 10-20):
/// the signing document the notice stages for. Not the notice queue as a
/// whole, and not the recipient the notice goes to.
#[derive(Clone, Copy)]
enum NoticeScopeTarget {
    SigningDocument,
}

const NOTICE_SCOPE_TARGET: NoticeScopeTarget = NoticeScopeTarget::SigningDocument;

impl NoticeScopeTarget {
    /// The record judged for the notices of `document`.
    const fn record(self, document: EntityId) -> EntityId {
        match self {
            Self::SigningDocument => document,
        }
    }
}

/// Where one call's notices are judged.
pub(super) enum NoticeScope<'a> {
    /// No bound credential, or one bounded by the whole vault: the door's
    /// full-vault path, unchanged.
    Unrestricted,
    /// A narrowed credential, judged by its own read lane.
    Credential(ScopedRead<'a>),
    /// No caller: the notice worker, as the notices' recorded principal
    /// while its send act and standing hold (FIX 6219). It writes through
    /// that principal's verified writer, as an unrestricted call does.
    Unattended(UnattendedNotices<'a>),
}

impl Memory<'_> {
    /// The scope this handle's notices are judged in. Only a narrowed
    /// credential opens its read lane here, so an unrestricted call reads
    /// nothing it did not read before.
    /// # Errors
    /// A narrowed credential whose read lane does not open, as every read
    /// verb refuses it.
    pub(super) fn notice_scope(&self) -> MemoryResult<NoticeScope<'_>> {
        match self.presented_credential() {
            Some(proof) if !bounded_by_whole_vault(proof) => Ok(NoticeScope::Credential(
                self.read_lane(ClaimReadStatus::Recorded)?,
            )),
            _ => Ok(NoticeScope::Unrestricted),
        }
    }
}

impl NoticeScope<'_> {
    /// Judges `document` in `txn`, before the door lists its notices. An
    /// unrestricted call is not judged.
    /// # Errors
    /// A document the narrowed credential's lane does not reach, as one that
    /// is no signing document, or the read's own failure.
    pub(super) fn admit_in(&self, txn: &heed::RoTxn<'_>, document: EntityId) -> Result<()> {
        match self {
            Self::Unrestricted => Ok(()),
            Self::Credential(lane) => reaches_in(lane, txn, document),
            Self::Unattended(notices) => notices.stands_in(txn),
        }
    }

    /// One recovery, claim or lease return of the door on `document`'s
    /// notices. An unrestricted call writes through the bound actor's
    /// verified writer as before; a narrowed one through the document
    /// artifact's own content writer, its lane judged again in the snapshot
    /// that writes.
    /// # Errors
    /// The writer's own refusal, a document the lane no longer reaches, or
    /// `write`'s.
    pub(super) fn write<T>(
        &self,
        memory: &Memory<'_>,
        document: EntityId,
        write: impl FnOnce(&mut heed::RwTxn<'_>) -> MemoryResult<T>,
    ) -> MemoryResult<T> {
        match self {
            Self::Unrestricted => memory.with_verified_actor_write_txn(write),
            Self::Credential(lane) => memory.with_actor_content_write_txn_as(
                crate::WriteActor::new(memory.actor(), memory.actor_class()),
                |content| {
                    content.update_artifact(document, |txn| {
                        reaches_in(lane, txn, document)?;
                        write(txn)
                    })
                },
            ),
            Self::Unattended(notices) => memory.with_verified_actor_write_txn(|txn| {
                notices.stands_in(txn)?;
                write(txn)
            }),
        }
    }

    /// One claimed notice of `document` through the email send gate. A
    /// narrowed call's send records a gate decision, and queues its
    /// delivery, only while its lane still reaches the document in the
    /// writer that records the decision and in the snapshot that queues it
    /// (FIX 6404).
    /// # Errors
    /// As [`Vault::dispatch_esign_notice`].
    pub(super) fn dispatch(
        &self,
        vault: &Vault,
        document: EntityId,
        attempt: &AttemptRecord,
        request: OutboundDispatchRequest,
    ) -> std::result::Result<OutboundDispatchResult, OutboundDispatchError> {
        match self {
            Self::Unrestricted => vault.dispatch_esign_notice(attempt, request),
            Self::Credential(lane) => {
                vault.dispatch_esign_notice_in_scope(attempt, request, &|txn| {
                    reaches(lane, txn, document)
                })
            }
            Self::Unattended(notices) => {
                vault
                    .dispatch_esign_notice_in_scope(attempt, request, &|txn| notices.stands_in(txn))
            }
        }
    }
}

/// Whether `proof` bounds its records by the whole vault, as the row's
/// admission required of every caller before FIX 6220
/// (`require_unrestricted_record_scope`): no record or channel caveat, and
/// every axis but its verbs at the top.
fn bounded_by_whole_vault(proof: &VerifiedSlip) -> bool {
    let mut required = Scope::top();
    required.verbs = proof.scope().verbs.clone();
    proof.claims().records.is_empty()
        && proof.claims().channels.is_empty()
        && required.is_narrowing_of(proof.scope())
}

/// Whether `lane` reads the record [`NOTICE_SCOPE_TARGET`] names for
/// `document` in `txn`, as a ref its caller names resolves, the lane's owner
/// standing proved again in that snapshot.
/// # Errors
/// The read's own failure.
fn reaches(lane: &ScopedRead<'_>, txn: &heed::RoTxn<'_>, document: EntityId) -> Result<bool> {
    let target = NOTICE_SCOPE_TARGET.record(document);
    let policy = lane.live_policy_manifest_in(txn)?;
    lane.is_ref_readable_with_policy_in(txn, &policy, &target)
}

/// [`reaches`], a document out of the lane's reach refused as [`unreached`].
fn reaches_in(lane: &ScopedRead<'_>, txn: &heed::RoTxn<'_>, document: EntityId) -> Result<()> {
    if reaches(lane, txn, document)? {
        Ok(())
    } else {
        Err(unreached())
    }
}

/// The refusal of a signing document a narrowed credential's lane does not
/// reach: the answer a document that is no signing document gets.
pub(super) fn unreached() -> crate::Error {
    invalid("unknown signing document")
}
