//! FIX 6403: the credential ceiling every e-sign door judges a narrowed
//! caller by. A world-, facet- or record-scoped credential reaches a signing
//! document, and the artifacts its draft names, only where its own read lane
//! reaches them.
//!
//! An unrestricted caller (no bound credential, or one bounded by the whole
//! vault, the only caller the e-sign rows admitted before) is not judged:
//! it reads nothing new and keeps each door's own path. A narrowed caller is
//! judged by the lane every read verb reads under (its record allowlist,
//! world placement, facet and audience rules, the owner's facet exemption,
//! live grants and the credential's liveness), in the snapshot each door
//! reads and again in each snapshot that writes. A record the lane does not
//! reach answers as a document that is no signing document.
//!
//! The records judged for one signing document (CALLS `FIX 6403 e-sign scope
//! target`, proposed): the document itself and every artifact its draft
//! names, the pinned originals and, once sealed, the sealed outputs. A
//! request that would show or act on any of them refuses whole; nothing is
//! redacted. A ceremony row judges the document its capability binds; the
//! capability authorizes the rest, as on the public doors.
use super::ledger::{restrictive_state_in, state_in};
use super::model::{EsignDocument, invalid};
use super::seal::SealedDocument;
use crate::authority::VerifiedSlip;
use crate::claim::{ClaimReadStatus, ScopedRead};
use crate::federation::Scope;
use crate::memory::{Memory, MemoryResult};
use crate::{EntityId, Result, Vault};

/// Where one e-sign call is judged.
pub(super) enum EsignScope<'a> {
    /// No bound credential, or one bounded by the whole vault: the door's
    /// own path, unchanged.
    Unrestricted,
    /// A narrowed credential, judged by its own read lane.
    Credential(ScopedRead<'a>),
}

impl Memory<'_> {
    /// The scope this handle's e-sign calls are judged in. Only a narrowed
    /// credential opens its read lane here, so an unrestricted call reads
    /// nothing it did not read before. It opens its own snapshot, so a door
    /// takes it before opening one.
    /// # Errors
    /// A narrowed credential whose read lane does not open, as every read
    /// verb refuses it.
    pub(super) fn esign_scope(&self) -> MemoryResult<EsignScope<'_>> {
        // A whole-vault guest view a later pact narrowing reached past is
        // judged by its lane (FIX 9117).
        match self.presented_credential() {
            Some(proof)
                if !bounded_by_whole_vault(proof)
                    || !self.vault().guest_view_current(proof.claims())? =>
            {
                Ok(EsignScope::Credential(
                    self.read_lane(ClaimReadStatus::Recorded)?,
                ))
            }
            _ => Ok(EsignScope::Unrestricted),
        }
    }
}

impl EsignScope<'_> {
    /// Judges `document` in `txn`. An unrestricted call is not judged.
    /// # Errors
    /// A document the lane does not reach, as [`unreached`], or the read's
    /// own failure.
    pub(super) fn admit_in(&self, txn: &heed::RoTxn<'_>, document: EntityId) -> Result<()> {
        match self {
            Self::Unrestricted => Ok(()),
            Self::Credential(lane) => reaches_in(lane, txn, document),
        }
    }

    /// Judges every artifact `draft` names in `txn`, its pinned originals.
    /// An unrestricted call is not judged and parses nothing.
    /// # Errors
    /// An artifact the lane does not reach, as [`unreached`], a ref that is
    /// no id, or the read's own failure.
    pub(super) fn admit_draft_in(
        &self,
        txn: &heed::RoTxn<'_>,
        draft: &EsignDocument,
    ) -> Result<()> {
        match self {
            Self::Unrestricted => Ok(()),
            Self::Credential(lane) => reaches_draft_in(lane, txn, draft),
        }
    }

    /// Judges every artifact the sealed manifest `sealed` names in `txn`:
    /// each item's original and its sealed output. An unrestricted call is
    /// not judged and parses nothing.
    /// # Errors
    /// As [`Self::admit_draft_in`].
    pub(super) fn admit_sealed_in(
        &self,
        txn: &heed::RoTxn<'_>,
        sealed: &SealedDocument,
    ) -> Result<()> {
        match self {
            Self::Unrestricted => Ok(()),
            Self::Credential(lane) => {
                for item in &sealed.items {
                    reaches_in(lane, txn, EntityId::from_hex(&item.original_artifact)?)?;
                    reaches_in(lane, txn, EntityId::from_hex(&item.sealed_artifact)?)?;
                }
                Ok(())
            }
        }
    }

    /// Judges `document` and the originals its trail names now, in a
    /// snapshot of its own, before an outbound act builds its request. A
    /// void (`restrictive`) folds the whole chain, held events included, as
    /// its send does. An unrestricted call is not judged and reads nothing.
    /// # Errors
    /// As [`Self::admit_draft_in`], or the trail's own refusal.
    pub(super) fn admit_signing_document(
        &self,
        vault: &Vault,
        document: EntityId,
        restrictive: bool,
    ) -> Result<()> {
        match self {
            Self::Unrestricted => Ok(()),
            Self::Credential(lane) => {
                let txn = vault.store.env.read_txn()?;
                if reaches_signing_document(lane, vault, &txn, document, restrictive)? {
                    Ok(())
                } else {
                    Err(unreached())
                }
            }
        }
    }
}

/// Whether `proof` bounds its records by the whole vault, as the e-sign rows'
/// admission required of every caller before FIX 6220 and 6403
/// (`require_unrestricted_record_scope`): no record or channel caveat, and
/// every axis but its verbs at the top.
pub(super) fn bounded_by_whole_vault(proof: &VerifiedSlip) -> bool {
    let mut required = Scope::top();
    required.verbs = proof.scope().verbs.clone();
    proof.claims().records.is_empty()
        && proof.claims().channels.is_empty()
        && required.is_narrowing_of(proof.scope())
}

/// Whether `lane` reads `record` in `txn`, as a ref its caller names
/// resolves, the lane's owner standing proved again in that snapshot.
/// # Errors
/// The read's own failure.
pub(super) fn reaches(
    lane: &ScopedRead<'_>,
    txn: &heed::RoTxn<'_>,
    record: EntityId,
) -> Result<bool> {
    let policy = lane.live_policy_manifest_in(txn)?;
    lane.is_ref_readable_with_policy_in(txn, &policy, &record)
}

/// [`reaches`], a record out of the lane's reach refused as [`unreached`].
pub(super) fn reaches_in(
    lane: &ScopedRead<'_>,
    txn: &heed::RoTxn<'_>,
    record: EntityId,
) -> Result<()> {
    if reaches(lane, txn, record)? {
        Ok(())
    } else {
        Err(unreached())
    }
}

/// [`reaches_in`] for every artifact `draft` names.
pub(super) fn reaches_draft_in(
    lane: &ScopedRead<'_>,
    txn: &heed::RoTxn<'_>,
    draft: &EsignDocument,
) -> Result<()> {
    for item in &draft.items {
        reaches_in(lane, txn, EntityId::from_hex(&item.artifact_ref)?)?;
    }
    Ok(())
}

/// Whether `lane` reaches `document` and every original its trail folds to
/// in `txn`, the items read again from that snapshot: the whole chain for a
/// `restrictive` act, the chain no held event stops otherwise.
/// # Errors
/// The read's own failure, or the trail's refusal.
pub(super) fn reaches_signing_document(
    lane: &ScopedRead<'_>,
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    document: EntityId,
    restrictive: bool,
) -> Result<bool> {
    if !reaches(lane, txn, document)? {
        return Ok(false);
    }
    let state = if restrictive {
        restrictive_state_in(vault, txn, document)?
    } else {
        state_in(vault, txn, document)?
    };
    for item in &state.document.items {
        if !reaches(lane, txn, EntityId::from_hex(&item.artifact_ref)?)? {
            return Ok(false);
        }
    }
    Ok(true)
}

/// Refuses the `document` a capability binds when a narrowed caller's
/// `ceiling` does not reach it in `txn`, as the invalid capability a
/// ceremony row answers (FIX 6403). An unrestricted caller's ceiling admits
/// every document and reads nothing.
/// # Errors
/// A document out of the ceiling's reach, a `document` that is no id, or the
/// ceiling's own read failure.
pub(super) fn ceiling_admits_in(
    ceiling: &dyn Fn(&heed::RoTxn<'_>, EntityId) -> Result<bool>,
    txn: &heed::RoTxn<'_>,
    document: &str,
) -> Result<()> {
    if ceiling(txn, EntityId::from_hex(document)?)? {
        Ok(())
    } else {
        Err(invalid("invalid capability"))
    }
}

/// One write of a narrowed call on `document`: through the document
/// artifact's own content writer (the actor's Grant at the document's
/// position in a shared vault, never a whole-vault one), the lane judged
/// again on the document in the snapshot that writes, before `write`.
/// # Errors
/// The writer's own refusal, a document the lane no longer reaches, or
/// `write`'s.
pub(super) fn write_artifact<T>(
    lane: &ScopedRead<'_>,
    memory: &Memory<'_>,
    document: EntityId,
    write: impl FnOnce(&mut heed::RwTxn<'_>) -> MemoryResult<T>,
) -> MemoryResult<T> {
    memory.with_actor_content_write_txn_as(
        crate::WriteActor::new(memory.actor(), memory.actor_class()),
        |content| {
            content.update_artifact(document, |txn| {
                reaches_in(lane, txn, document)?;
                write(txn)
            })
        },
    )
}

/// The refusal of a signing document, or an artifact it names, a narrowed
/// credential's lane does not reach: the answer a document that is no
/// signing document gets.
pub(super) fn unreached() -> crate::Error {
    invalid("unknown signing document")
}
