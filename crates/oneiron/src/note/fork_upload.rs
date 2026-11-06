//! An own device's replica-local NOTE fork, sent to the NOTE's authority
//! (FIX 12789).
//!
//! A replica forks a NOTE as the authority does: the fork's document holds
//! its parent's history up to the frontier it forked at, then its own
//! operations under the fork's own peer, and its authorship entry names its
//! author's stamp token. A replica moves no head, so the fork stayed on its
//! device. The device now queues an upload of it on the owner document lane
//! ([`crate::sync::DocumentRegistry::submit_note_fork`]): the fork's id, its
//! parent head, its frontier and whether it rewrites, and, at each send, the
//! fork's own operations since that frontier, read from the fork as it then
//! stands, so nothing the queue keeps outlives an erase of the fork.
//!
//! The authority admits it in one writer, under the owner session that sent
//! it ([`crate::memory::Memory::admit_owner_note_fork`]): the parent is a
//! head of the NOTE it holds, the frontier is in that head's history, the
//! operations apply there whole and name no peer that head's history names,
//! so they rewrite none of its operations, and the fork's authorship entry
//! names a stamp token that resolves here to the uploader. A fork another
//! actor wrote is not the uploader's to vouch for and stays on its device.
//! The fork is then stored as a local fork is, through the same proposal
//! admission, pending and in no bundle; a later review is a separate act.
//! The receipt answers the requesting connection alone: accepted, or refused
//! for a stable reason, either of which settles the device's queue. An error
//! leaves the upload queued for the next send.

use serde::{Deserialize, Serialize};

use super::documents::{
    NOTE_HEAD_DOC, NOTE_PROPOSAL_DOC, NoteDocument, head_in, invalid, live_doc, load_head,
    load_retained_head, store_doc,
};
use super::proposals::{NOTE_FORK, NoteActor, remember_fork};
use super::side_keys::HexPair;
use super::sync_rows::SYNC_DS_E;
use crate::memory::{Memory, MemoryResult};
use crate::side_table::HexId;
use crate::sync::transport::document_sub_tags;
use crate::{EntityId, Vault};

/// What identifies one fork upload: the fork, the parent head it forked
/// from, the frontier of that head it forked at, and whether it rewrites.
/// The NOTE is the frame's entity; the fork id is the request id.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NoteForkUpload {
    #[serde(with = "super::id_codec")]
    pub fork: EntityId,
    #[serde(with = "super::id_codec")]
    pub parent: EntityId,
    pub frontier: Vec<u8>,
    pub rewrite: bool,
}

/// What the authority did with one fork upload.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum NoteForkUploadOutcome {
    /// The fork is stored here, pending; a replay answers the same.
    Accepted,
    /// The fork cannot be admitted here as it is, for `reason`.
    Refused { reason: String },
}

/// The authority's answer to one fork upload: the fork, the hash of the
/// upload's identity as it was sent, and the outcome.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NoteForkUploadReceipt {
    #[serde(with = "super::id_codec")]
    pub fork: EntityId,
    pub command_hash: [u8; 32],
    pub outcome: NoteForkUploadOutcome,
}

impl NoteForkUpload {
    /// The upload's payload: `[identity length: u32 BE][identity JSON]` then
    /// the fork's own operations. A queued upload keeps the payload with no
    /// operations.
    ///
    /// # Errors
    ///
    /// An identity that does not encode.
    pub fn encode_payload(&self, operations: &[u8]) -> crate::Result<Vec<u8>> {
        let identity = self.identity()?;
        let len = u32::try_from(identity.len()).map_err(|_| invalid("NOTE fork upload"))?;
        let mut payload = Vec::with_capacity(4 + identity.len() + operations.len());
        payload.extend_from_slice(&len.to_be_bytes());
        payload.extend_from_slice(&identity);
        payload.extend_from_slice(operations);
        Ok(payload)
    }

    /// The upload, its command hash and its operations, from `payload`. The
    /// identity must be the canonical encoding of what it decodes to.
    ///
    /// # Errors
    ///
    /// A payload that does not read.
    pub fn decode_payload(payload: &[u8]) -> crate::Result<(Self, [u8; 32], &[u8])> {
        let (len, rest) = payload
            .split_first_chunk::<4>()
            .ok_or(invalid("NOTE fork upload"))?;
        let (identity, operations) = rest
            .split_at_checked(u32::from_be_bytes(*len) as usize)
            .ok_or(invalid("NOTE fork upload"))?;
        let upload: Self =
            serde_json::from_slice(identity).map_err(|_| invalid("NOTE fork upload"))?;
        if upload.identity()? != identity {
            return Err(invalid("NOTE fork upload"));
        }
        Ok((upload, *blake3::hash(identity).as_bytes(), operations))
    }

    /// The hash a receipt names this upload by.
    ///
    /// # Errors
    ///
    /// An identity that does not encode.
    pub fn command_hash(&self) -> crate::Result<[u8; 32]> {
        Ok(*blake3::hash(&self.identity()?).as_bytes())
    }

    fn identity(&self) -> crate::Result<Vec<u8>> {
        serde_json::to_vec(self).map_err(|_| invalid("NOTE fork upload"))
    }
}

/// The upload `note`'s fork `fork` makes from this device, while it makes
/// one: a native fork of `note` no one decided, in no bundle, whose author
/// is still named, with its document kept here.
///
/// # Errors
///
/// Storage errors, or a fork row that cannot be read.
pub(crate) fn uploadable_fork_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    note: EntityId,
    fork: EntityId,
) -> crate::Result<Option<NoteForkUpload>> {
    let Some(row) = NOTE_FORK.get(&vault.store, txn, &fork)? else {
        return Ok(None);
    };
    if row.note != note
        || row.fork != fork
        || row.decided
        || row.proposal.is_some()
        || row.recovery_merge.is_some()
        || row.actor == NoteActor::Erased
        || !NOTE_PROPOSAL_DOC.contains(&vault.store, txn, &HexPair(HexId(note), HexId(fork)))?
    {
        return Ok(None);
    }
    Ok(Some(NoteForkUpload {
        fork,
        parent: row.parent,
        frontier: row.frontier,
        rewrite: row.rewrite,
    }))
}

/// The document frame that sends `upload` of `note` now: the fork's own
/// operations since its frontier, read from the fork as it stands. `None`
/// once the fork no longer makes that upload (decided, erased or bundled).
///
/// # Errors
///
/// Storage errors, a fork document that does not read, and a frame past the
/// document frame bound.
pub(crate) fn fork_upload_frame_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    note: EntityId,
    upload: &NoteForkUpload,
) -> crate::Result<Option<Vec<u8>>> {
    if uploadable_fork_in_txn(vault, txn, note, upload.fork)?.as_ref() != Some(upload) {
        return Ok(None);
    }
    let fork = load_head(vault, txn, note, upload.fork)?;
    let frontier = super::document::frontier(&upload.frontier)?;
    let since = fork
        .doc
        .frontiers_to_vv(&frontier)
        .ok_or(invalid("NOTE fork frontier unavailable"))?;
    let operations = fork
        .doc
        .export(loro::ExportMode::updates(&since))
        .map_err(|_| invalid("NOTE fork export"))?;
    let payload = upload.encode_payload(&operations)?;
    crate::sync::transport::encode_document(note, document_sub_tags::NOTE_FORK_UPLOAD, &payload)
        .into_result()
        .map(Some)
        .map_err(|_| invalid("NOTE fork exceeds the document frame"))
}

impl Memory<'_> {
    /// Host boundary for an own device's fork upload on the owner lane
    /// (FIX 12789). The actor must be the vault owner, its session live, and
    /// the NOTE must pass the owner export's refusals, as for a NOTE command
    /// ([`Self::admit_owner_note_operation`]); then the fork is admitted as
    /// the module says. A stable refusal is a receipt; an error leaves the
    /// device's upload queued.
    ///
    /// # Errors
    ///
    /// A payload that does not read, a refused owner or session, a replica
    /// NOTE, an author token not resolved here yet, a fork text the proposal
    /// admission refuses, and storage errors.
    pub fn admit_owner_note_fork(
        &self,
        note: EntityId,
        session_is_live: impl FnOnce(&heed::RwTxn<'_>) -> bool,
        payload: &[u8],
    ) -> MemoryResult<NoteForkUploadReceipt> {
        let (upload, command_hash, operations) = NoteForkUpload::decode_payload(payload)?;
        let receipt = self.with_actor_content_write_txn(|content| {
            content.update_note(note, |txn| {
                if SYNC_DS_E.contains(&self.vault().store, txn, &HexId(note))? {
                    return Err(invalid("replica NOTE cannot act as an admission authority").into());
                }
                if !session_is_live(txn) {
                    return Err(invalid("NOTE session revoked").into());
                }
                self.verify_owner_in_txn(txn)?;
                crate::sync::documents::owner_note_admission(self.vault(), txn, note)?;
                let outcome =
                    match self.store_uploaded_fork_in_txn(txn, note, &upload, operations)? {
                        Ok(()) => NoteForkUploadOutcome::Accepted,
                        Err(reason) => NoteForkUploadOutcome::Refused {
                            reason: reason.to_owned(),
                        },
                    };
                Ok(NoteForkUploadReceipt {
                    fork: upload.fork,
                    command_hash,
                    outcome,
                })
            })
        })?;
        if receipt.outcome == NoteForkUploadOutcome::Accepted {
            self.vault().notify_note_document(note);
        }
        Ok(receipt)
    }

    /// Stores `upload` of `note` with its `operations` as a pending fork,
    /// when it is admissible here; the stable reason it is not, else. Every
    /// refusal comes before the first write.
    fn store_uploaded_fork_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        note: EntityId,
        upload: &NoteForkUpload,
        operations: &[u8],
    ) -> crate::Result<std::result::Result<(), &'static str>> {
        let vault = self.vault();
        let actor = self.write_actor();
        // A fork stored here already answers its replay as it did.
        if let Some(row) = NOTE_FORK.get(&vault.store, txn, &upload.fork)? {
            let same = row.note == note
                && row.parent == upload.parent
                && row.rewrite == upload.rewrite
                && row.actor.is(actor.entity_ref())
                && same_frontier(&row.frontier, &upload.frontier);
            return Ok(if same {
                Ok(())
            } else {
                Err("NOTE fork identity reused")
            });
        }
        let head = head_in(&vault.store, txn, note)?.0;
        if upload.fork == note
            || upload.fork == head
            || NOTE_HEAD_DOC.contains(&vault.store, txn, &(note, upload.fork))?
            || NOTE_PROPOSAL_DOC.contains(
                &vault.store,
                txn,
                &HexPair(HexId(note), HexId(upload.fork)),
            )?
        {
            return Ok(Err("NOTE fork identity reused"));
        }
        // The parent: a head of this NOTE whose document is kept here, the
        // live one, its original one, or one a switch made its head. A
        // pending proposal never was its head.
        let parent = if upload.parent == head {
            live_doc(vault, txn, note)?.doc
        } else {
            if upload.parent != note
                && !NOTE_HEAD_DOC.contains(&vault.store, txn, &(note, upload.parent))?
            {
                return Ok(Err("NOTE fork parent is not a head kept here"));
            }
            match load_retained_head(vault, txn, note, upload.parent)? {
                Some(doc) => doc,
                None => return Ok(Err("NOTE fork parent is not a head kept here")),
            }
        };
        let Ok(frontier) = super::document::frontier(&upload.frontier) else {
            return Ok(Err("NOTE fork frontier does not read"));
        };
        let (Ok(basis), Ok(opening)) = (parent.fork_at(&frontier), parent.fork_at(&frontier))
        else {
            return Ok(Err("NOTE fork frontier is not in its parent's history"));
        };
        let before = basis.oplog_vv();
        let known = parent.oplog_vv();
        if super::storage::import_complete(&basis, operations).is_err() {
            return Ok(Err("NOTE fork operations do not apply to its parent"));
        }
        // The fork's own operations only: an operation under a peer the
        // parent's history names would rewrite or extend that history.
        if basis.oplog_vv().iter().any(|(peer, end)| {
            before.get(peer).is_none_or(|start| end > start) && known.contains_key(peer)
        }) {
            return Ok(Err("NOTE fork rewrites its parent's operations"));
        }
        // Its author is the uploader: the fork's authorship entry names a
        // stamp token that resolves here to the authenticated actor.
        // Its operations edit its text alone: every other part of the NOTE,
        // its citations and title among them, stands as the parent held it
        // at the frontier, for a later merge carries the fork into the NOTE.
        if !same_outside_text(&opening, &basis) {
            return Ok(Err("NOTE fork changes more than its text"));
        }
        // Every authorship entry the parent held at the frontier stands
        // unchanged, and the fork adds its own entry alone: a later merge
        // carries the fork's authorship map into the NOTE.
        let (Ok(inherited), Ok(records)) = (
            super::operations::authorship(&opening),
            super::operations::authorship(&basis),
        ) else {
            return Ok(Err("NOTE fork authorship does not read"));
        };
        if inherited.iter().any(|kept| !records.contains(kept)) {
            return Ok(Err("NOTE fork changes its parent's authorship"));
        }
        let added: Vec<_> = records
            .iter()
            .filter(|record| !inherited.contains(record))
            .collect();
        let [record] = added.as_slice() else {
            return Ok(Err("NOTE fork must add its own authorship entry alone"));
        };
        if record.operation != upload.fork {
            return Ok(Err("NOTE fork names no author"));
        }
        let NoteActor::Actor(token) = record.actor else {
            return Ok(Err("NOTE fork author was erased"));
        };
        match crate::provenance::resolve_actor_stamp_in_txn(vault, txn, &token)? {
            Some(author) if author == actor => {}
            Some(_) => return Ok(Err("NOTE fork author is not the uploader")),
            // The token's claim has not reached this vault yet: a later
            // send may resolve it.
            None => return Err(invalid("NOTE fork author token not resolved here")),
        }
        let fork = NoteDocument {
            note,
            head: upload.fork,
            doc: basis,
        };
        let parent = NoteDocument {
            note,
            head: upload.parent,
            doc: opening,
        };
        let stored = store_doc(vault, txn, &fork)?;
        remember_fork(
            vault,
            txn,
            &parent,
            &fork,
            actor.entity_ref(),
            upload.rewrite,
            stored,
        )?;
        Ok(Ok(()))
    }
}

/// Whether `fork` holds what `opening` holds in every root container but the
/// body text and the authorship map: a fork's own edit changes only those.
fn same_outside_text(opening: &loro::LoroDoc, fork: &loro::LoroDoc) -> bool {
    let (loro::LoroValue::Map(before), loro::LoroValue::Map(after)) =
        (opening.get_deep_value(), fork.get_deep_value())
    else {
        return false;
    };
    before
        .keys()
        .chain(after.keys())
        .filter(|key| !matches!(key.as_str(), "body" | "authorship"))
        .all(|key| before.get(key) == after.get(key))
}

/// Whether two encoded frontiers name the same frontier.
fn same_frontier(left: &[u8], right: &[u8]) -> bool {
    match (
        super::document::frontier(left),
        super::document::frontier(right),
    ) {
        (Ok(left), Ok(right)) => left == right,
        _ => false,
    }
}
