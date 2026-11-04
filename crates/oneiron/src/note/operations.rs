//! Authenticated semantic NOTE commands. Peer Loro bytes never authorize writes.

use super::document::{NoteDocument, invalid};
use super::document_store::{
    load, persist_authoritative, require_note_writer, validate_pin_source,
};
use super::pin_index::NOTE_PIN_SOURCE;
use super::side_keys::HexPair;
use super::sync_rows::{NOTE_RECEIPT_BY_REQUEST, SYNC_DS_E};
use super::{NoteActor, NotePin, NoteScalarEdit, NoteScalarEditOutcome};
use crate::memory::{CommitReceipt, Memory, MemoryResult};
use crate::provenance::ActorStamp;
use crate::provenance::birth::RowBirth;
use crate::provenance::made_by::MadeByClass;
use crate::side_table::HexId;
use crate::{EdgeActorClass, EntityId};
use serde::{Deserialize, Serialize};

pub(super) const MAX_RECEIPT_PAYLOAD: usize = 8 * 1024 * 1024;

/// Idempotent command carried by the canonical document frame. There is no
/// actor field: the receiving host obtains that from its authenticated session.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NoteOperation {
    #[serde(with = "super::id_codec")]
    pub request_id: EntityId,
    pub change: NoteChange,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum NoteChange {
    Edit {
        base: Vec<u8>,
        edits: Vec<NoteScalarEdit>,
    },
    Cite {
        pin: NotePin,
    },
    SetTitle {
        title: String,
    },
}

/// Durable provenance authored only by the admission door. Commit messages
/// remain diagnostic text; neither grants nor actor classes are read from them.
/// Its actor reads and writes as a hex id, or `"erased"` once that actor was
/// erased: the record stays, naming no one (FIX 6072, Engine R2). A stored
/// live write's record names its writer's stamp token in the actor's place
/// (FIX 11964), and a reader sees the actor the token resolves to, or no one
/// once it is forgotten; the birth's own record names the NOTE's author.
/// Every new record names the live, authenticated writer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct NoteAuthorship {
    #[serde(with = "super::id_codec")]
    #[schemars(with = "String")]
    pub operation: EntityId,
    #[schemars(with = "String")]
    pub actor: super::NoteActor,
    pub actor_class: String,
    pub grant: Option<String>,
    pub command_hash: [u8; 32],
}

impl NoteAuthorship {
    /// Whether `other` keeps this record (ErasedWins, FIX 6072): the same
    /// record, or its erased twin, the same in every field but an actor that
    /// names no one. A live actor never keeps an erased record.
    #[cfg(feature = "sync")]
    pub(crate) fn kept_by(&self, other: &Self) -> bool {
        let erased = Self {
            actor: super::NoteActor::Erased,
            ..self.clone()
        };
        self == other || *other == erased
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NoteOperationReceipt {
    #[serde(with = "super::id_codec")]
    pub request_id: EntityId,
    pub command_hash: [u8; 32],
    pub outcome: NoteScalarEditOutcome,
}

/// No length refuses an operation (rule 5, FIX 10345). A peer's bytes are
/// bounded by the frame that carried them, and a JSON decode allocates no
/// more than they hold.
impl NoteOperation {
    pub fn encode(&self) -> crate::Result<Vec<u8>> {
        serde_json::to_vec(self).map_err(|_| invalid("NOTE operation encode"))
    }
    pub fn decode(bytes: &[u8]) -> crate::Result<Self> {
        serde_json::from_slice(bytes).map_err(|_| invalid("invalid NOTE operation"))
    }
    pub(super) fn hash(&self) -> crate::Result<[u8; 32]> {
        Ok(*blake3::hash(&self.encode()?).as_bytes())
    }
}

pub(super) fn authorship(doc: &loro::LoroDoc) -> crate::Result<Vec<NoteAuthorship>> {
    let mut records = Vec::new();
    for value in doc.get_map("authorship").values() {
        let loro::ValueOrContainer::Value(loro::LoroValue::String(value)) = value else {
            return Err(invalid("invalid NOTE authorship"));
        };
        records.push(
            serde_json::from_str::<NoteAuthorship>(&value)
                .map_err(|_| invalid("invalid NOTE authorship"))?,
        );
    }
    records.sort_by_key(|record| record.operation);
    Ok(records)
}

/// Records `record` in `doc`'s authorship map, its commit naming the
/// writer's stamp token `stamp` (FIX 10930). The entry names that token in
/// its actor's place too (FIX 11964); a reader resolves it
/// ([`resolved_authorship_in_txn`]).
pub(super) fn record_authorship(
    doc: &NoteDocument,
    record: &NoteAuthorship,
    stamp: ActorStamp,
) -> crate::Result<()> {
    insert_authorship(doc, record, &stamp.token.to_hex())
}

/// [`record_authorship`] for a birth's own record, its commit naming no one
/// as the birth's stamp does: a birth is derived alike on every replica, so
/// it can name no device's stamp token. The record names the NOTE core's
/// author, its `author_ref`.
pub(super) fn record_birth_authorship(
    doc: &NoteDocument,
    record: &NoteAuthorship,
) -> crate::Result<()> {
    // The commit names no one, as the birth's own stamp does (FIX 10930);
    // the record keeps the author.
    insert_authorship(doc, record, &super::NoteActor::Erased.to_wire())
}

/// Inserts `record` and commits it under the engine stamp naming `named`. No
/// authorship count refuses it: a NOTE's edits are never capped (rule 5, FIX
/// 10345).
fn insert_authorship(
    doc: &NoteDocument,
    record: &NoteAuthorship,
    named: &str,
) -> crate::Result<()> {
    let value = serde_json::to_string(record).map_err(|_| invalid("NOTE authorship encode"))?;
    doc.doc
        .get_map("authorship")
        .insert(&record.operation.to_hex(), value)
        .map_err(|_| invalid("NOTE authorship insert"))?;
    doc.doc.commit_with(
        loro::CommitOptions::new().commit_msg(&format!("oneiron.note/v1 actor={named}")),
    );
    Ok(())
}

/// `records`, the stored entries of `note`'s authorship map, as a reader
/// sees them (FIX 11964): a live write's entry names its writer's stamp
/// token, which reads as the actor through the token's live claim and as no
/// one once the token is forgotten. The birth's own entry (its operation is
/// `note`) names the NOTE core's author; it reads as no one once this vault
/// erased that author.
///
/// # Errors
///
/// Storage errors, or a stored token claim that does not decode.
pub(super) fn resolved_authorship_in_txn(
    vault: &crate::Vault,
    txn: &heed::RoTxn<'_>,
    note: EntityId,
    records: Vec<NoteAuthorship>,
) -> crate::Result<Vec<NoteAuthorship>> {
    let mut resolved = Vec::with_capacity(records.len());
    for mut record in records {
        record.actor = match record.actor {
            NoteActor::Actor(_) if record.operation == note => {
                record.actor.erased_here(vault, txn)?
            }
            NoteActor::Actor(token) => {
                crate::provenance::resolve_actor_stamp_in_txn(vault, txn, &token)?
                    .map_or(NoteActor::Erased, |actor| NoteActor::Actor(actor.entity_ref()))
            }
            NoteActor::Erased => NoteActor::Erased,
        };
        resolved.push(record);
    }
    Ok(resolved)
}

/// `view` as a reader sees it: its authorship resolved
/// ([`resolved_authorship_in_txn`], FIX 11964).
///
/// # Errors
///
/// As [`resolved_authorship_in_txn`].
pub(super) fn resolved_view_in_txn(
    vault: &crate::Vault,
    txn: &heed::RoTxn<'_>,
    mut view: super::NoteDocumentView,
) -> crate::Result<super::NoteDocumentView> {
    let records = std::mem::take(&mut view.authorship);
    view.authorship = resolved_authorship_in_txn(vault, txn, view.document, records)?;
    Ok(view)
}

/// `receipt` as its caller reads it: an applied outcome's view resolved
/// ([`resolved_view_in_txn`], FIX 11964). The stored receipt keeps the
/// tokens, so an erase of its writer leaves it naming no one.
fn resolved_receipt_in_txn(
    vault: &crate::Vault,
    txn: &heed::RoTxn<'_>,
    mut receipt: NoteOperationReceipt,
) -> crate::Result<NoteOperationReceipt> {
    receipt.outcome = match receipt.outcome {
        NoteScalarEditOutcome::Applied(view) => {
            NoteScalarEditOutcome::Applied(resolved_view_in_txn(vault, txn, view)?)
        }
        proposed @ NoteScalarEditOutcome::Proposed(_) => proposed,
    };
    Ok(receipt)
}

impl crate::Vault {
    /// Whether a queued NOTE receipt still has its authoritative durable row.
    /// Host delivery combines this freshness check with current selector admission.
    /// Erasure deletes copied full-view receipts in the same writer as their pins.
    pub fn note_receipt_is_current(
        &self,
        note: EntityId,
        receipt: &NoteOperationReceipt,
    ) -> crate::Result<bool> {
        let txn = self.store.env.read_txn()?;
        super::citation_erase::ensure_citations_ready(&self.store, &txn, note)?;
        let key = HexPair(HexId(note), HexId(receipt.request_id));
        let Some(saved) = NOTE_RECEIPT_BY_REQUEST.get(&self.store, &txn, &key)? else {
            return Ok(false);
        };
        // The host queued the receipt as its caller read it (FIX 11964).
        Ok(resolved_receipt_in_txn(self, &txn, saved.1)? == *receipt)
    }
}

impl Memory<'_> {
    /// Host boundary for an already MAC-verified, live session. `self.actor()`
    /// and class MUST come from that credential, never the command or selector.
    /// The server supplies CoreAuth's principal, class and liveness predicate.
    /// Actor/owner, token revocation, grant/member/role, scope, policy, erasure
    /// and citation checks run under the writer lock that commits the result.
    /// The liveness predicate must read current auth state without writing it.
    /// It runs inside the write transaction, which may be one group commit
    /// shared with other writes: it reads through the transaction it is given,
    /// and must not otherwise call into the vault or wait on anything a vault
    /// caller can hold while it writes, or the vault's writer deadlocks.
    #[cfg(feature = "sync")]
    pub fn admit_note_operation(
        &self,
        note: EntityId,
        scope: crate::FederationGrantScope,
        selector: &crate::sync::SyncSelector,
        session_is_live: impl FnOnce(&heed::RwTxn<'_>) -> bool,
        operation: &NoteOperation,
    ) -> MemoryResult<NoteOperationReceipt> {
        let receipt = self.with_actor_content_write_txn(|content| {
            content.update_note(note, |txn| {
                if SYNC_DS_E.contains(&self.vault().store, txn, &HexId(note))? {
                    return Err(invalid("replica NOTE cannot act as an admission authority").into());
                }
                if !session_is_live(txn) {
                    return Err(invalid("NOTE session revoked").into());
                }
                crate::sync::selector::admit_note_in_txn(
                    self.vault(),
                    txn,
                    note,
                    scope,
                    selector,
                    Some(self.actor()),
                )?;
                // Applied and replayed receipts carry the full document view. A
                // writable NOTE alone cannot widen disclosure of its existing pins.
                // Check the same citation closure as document export before any edit
                // or saved receipt can escape this committing transaction.
                for pin in load(self.vault(), txn, note)?.pins()? {
                    super::replica::admit_pin_disclosure(self.vault(), txn, scope, selector, &pin)?;
                }
                if let NoteChange::Cite { pin } = &operation.change {
                    super::replica::admit_pin_disclosure(self.vault(), txn, scope, selector, pin)?;
                }
                self.apply_note_operation_in_txn(txn, note, operation, Some(selector.grant_id))
            })
        })?;
        #[cfg(feature = "sync")]
        self.vault().notify_note_document(note);
        Ok(receipt)
    }

    /// Host boundary for an own device on the owner lane. The actor must be
    /// the vault owner and the NOTE must pass the owner export's refusals;
    /// the operation applies with no grant. `session_is_live` keeps the
    /// contract of [`Self::admit_note_operation`]'s liveness predicate.
    #[cfg(feature = "sync")]
    pub fn admit_owner_note_operation(
        &self,
        note: EntityId,
        session_is_live: impl FnOnce(&heed::RwTxn<'_>) -> bool,
        operation: &NoteOperation,
    ) -> MemoryResult<NoteOperationReceipt> {
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
                self.apply_note_operation_in_txn(txn, note, operation, None)
            })
        })?;
        self.vault().notify_note_document(note);
        Ok(receipt)
    }

    pub(super) fn apply_local_note_operation(
        &self,
        note: EntityId,
        operation: &NoteOperation,
    ) -> MemoryResult<NoteOperationReceipt> {
        let receipt = self.with_actor_content_write_txn(|content| {
            content.update_note(note, |txn| {
                if SYNC_DS_E.contains(&self.vault().store, txn, &HexId(note))? {
                    return Err(invalid(
                        "replica NOTE edits must be submitted to its authenticated authority",
                    )
                    .into());
                }
                self.apply_note_operation_in_txn(txn, note, operation, None)
            })
        })?;
        #[cfg(feature = "sync")]
        self.vault().notify_note_document(note);
        Ok(receipt)
    }

    pub(super) fn apply_note_operation_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        note: EntityId,
        operation: &NoteOperation,
        grant: Option<EntityId>,
    ) -> MemoryResult<NoteOperationReceipt> {
        if SYNC_DS_E.contains(&self.vault().store, txn, &HexId(note))? {
            return Err(invalid("replica NOTE edits require authenticated authority").into());
        }
        super::lifecycle::refuse_sealed_note_in_txn(&self.vault().store, txn, note)?;
        self.vault()
            .authorize_shared_note_write_in_txn(txn, note, &self.write_actor())?;
        require_note_writer(self, txn, note)?;
        let doc = load(self.vault(), txn, note)?;
        let hash = operation.hash()?;
        let receipt_key = HexPair(HexId(note), HexId(operation.request_id));
        if let Some(saved) = NOTE_RECEIPT_BY_REQUEST.get(&self.vault().store, txn, &receipt_key)? {
            // An erased actor's receipt matches no one's replay (FIX 3879).
            if !saved.0.is(self.actor()) || saved.1.command_hash != hash {
                return Err(invalid("NOTE request identity reused").into());
            }
            return Ok(resolved_receipt_in_txn(self.vault(), txn, saved.1)?);
        }
        if authorship(&doc.doc)?
            .iter()
            .any(|record| record.operation == operation.request_id)
        {
            return Err(invalid("NOTE request identity reused").into());
        }
        // A required gate policy cannot disappear between citation detection and
        // candidate admission. Even free prose resolves the policy in this txn.
        let policy = crate::gate::resolve_policy_manifest(&self.vault().store, txn)?;
        let actor = self.write_actor();
        // Each commit names the actor's stamp token (FIX 10930).
        let stamp = crate::provenance::actor_stamp_in_txn(self.vault(), txn, actor)?;
        let outcome = match &operation.change {
            NoteChange::Edit { base, edits } => {
                let cited_by = cited_by(self.vault(), txn, note)?;
                if doc.edit(base, edits, stamp, &cited_by)? {
                    None
                } else {
                    if !policy.enforces_write_gate() {
                        return Err(
                            invalid("reviewed NOTE edit requires an active gate policy").into()
                        );
                    }
                    Some(NoteScalarEditOutcome::Proposed(propose_claim(
                        self, txn, note, operation,
                    )?))
                }
            }
            NoteChange::SetTitle { title } => {
                // Admitted before its operation is written (FIX 1098).
                let title = super::document_store::admit_title(
                    self.vault(),
                    txn,
                    note,
                    title,
                    &mut crate::batch::secret_scan::Lifted::default(),
                )?;
                doc.set_title(&title, stamp)?;
                None
            }
            NoteChange::Cite { pin } => {
                validate_pin_source(self.vault(), txn, pin)?;
                doc.add_pin(pin, stamp)?;
                None
            }
        };
        let outcome = match outcome {
            Some(proposed) => proposed,
            None => {
                record_authorship(
                    &doc,
                    &NoteAuthorship {
                        operation: operation.request_id,
                        actor: super::NoteActor::Actor(stamp.token),
                        actor_class: self.actor_class().gate_actor_class().to_owned(),
                        grant: grant.map(|id| id.to_hex()),
                        command_hash: hash,
                    },
                    stamp,
                )?;
                persist_authoritative(self.vault(), txn, &doc)?;
                NoteScalarEditOutcome::Applied(doc.view()?)
            }
        };
        let receipt = NoteOperationReceipt {
            request_id: operation.request_id,
            command_hash: hash,
            outcome,
        };
        let payload = serde_json::to_vec(&receipt).map_err(|_| invalid("NOTE receipt encode"))?;
        // The receipt goes to its requester whole in one NOTE_RECEIPT
        // document frame: an 18-byte head and this payload within the
        // transport's 8 MiB frame (`sync::transport::encode_document`). This
        // bound protects that frame and stays (FIX 10345).
        if payload.len() > MAX_RECEIPT_PAYLOAD - 18 {
            return Err(invalid("NOTE receipt exceeds wire bound").into());
        }
        // The stored receipt keeps the stamp tokens its view names; its
        // caller reads them resolved (FIX 11964).
        NOTE_RECEIPT_BY_REQUEST.put(
            &self.vault().store,
            txn,
            &receipt_key,
            &(super::NoteActor::Actor(self.actor()), receipt.clone()),
        )?;
        Ok(resolved_receipt_in_txn(self.vault(), txn, receipt)?)
    }
}

pub(super) fn cited_by(
    vault: &crate::Vault,
    txn: &heed::RoTxn<'_>,
    note: EntityId,
) -> crate::Result<Vec<NotePin>> {
    let mut pins = Vec::new();
    let prefix = format!("{}:", note.to_hex());
    // No byte budget refuses an edit of a NOTE many others cite: these are
    // this store's own reverse pins, each admitted when it was written (rule
    // 5, FIX 10345).
    for row in NOTE_PIN_SOURCE.iter_raw_from(&vault.store, txn, prefix.as_bytes())? {
        let (_, bytes) = row?;
        let pin: NotePin = NOTE_PIN_SOURCE.decode_value(&bytes)?;
        pin.validate()?;
        if pin.document != note {
            return Err(invalid("NOTE reverse pin source mismatch"));
        }
        pins.push(pin);
    }
    Ok(pins)
}

// The existing gated ClaimCandidate/WriteEnvelope door, in the SAME writer as
// the NOTE refusal. No seed_claims call (that wrapper opens another writer).
fn propose_claim(
    memory: &Memory<'_>,
    txn: &mut heed::RwTxn<'_>,
    note: EntityId,
    op: &NoteOperation,
) -> MemoryResult<CommitReceipt> {
    use crate::claim::{ClaimApprovalStatus, ClaimSource, ClaimSubject};
    use crate::{ClaimCandidate, WriteEnvelope, WriteProvenance};
    let id = memory.vault().new_entity_id()?;
    let claim_value =
        rmpv::Value::from(serde_json::to_string(op).map_err(|_| invalid("NOTE proposal encode"))?);
    let candidate = ClaimCandidate::new(
        "note.edit.proposal",
        ClaimSubject::Entity(note),
        claim_value,
        1.0,
    );
    let source = if memory.actor_class() == EdgeActorClass::Human {
        ClaimSource::UserStated
    } else {
        ClaimSource::Generated
    };
    let actor = memory.write_actor();
    let envelope = WriteEnvelope::new(
        actor,
        source,
        WriteProvenance::new(rmpv::Value::from("note.propose_claim"))?,
        ClaimApprovalStatus::Proposed,
    );
    let now = memory.vault().now_recorded_at();
    // The proposal is made from the NOTE at the version its edit names.
    let base: &[u8] = match &op.change {
        NoteChange::Edit { base, .. } => base,
        NoteChange::Cite { .. } | NoteChange::SetTitle { .. } => &[],
    };
    memory
        .vault()
        .batch_in()
        .claim_candidate(
            &id,
            candidate,
            &envelope,
            crate::TimeRange {
                start: now,
                end: now,
            },
            now,
        )
        .made_by(
            &id,
            RowBirth::written(
                actor,
                MadeByClass::of_source(source),
                "note.propose_claim",
                &[note],
                &[base],
                now,
            ),
        )
        .apply_recording_gate_decisions(txn)?;
    let claim = memory
        .vault()
        .get_claim_in_txn(txn, &id)?
        .ok_or_else(|| invalid("NOTE proposal missing"))?;
    if claim.approval != ClaimApprovalStatus::Proposed {
        return Err(invalid("NOTE proposal was not admitted for review").into());
    }
    let decisions = memory
        .vault()
        .store
        .gate_decisions_for_claim_in_txn(txn, id.as_bytes())?;
    let decision = decisions
        .into_iter()
        .max_by_key(|record| record.decision_id.to_hex())
        .ok_or_else(|| invalid("NOTE proposal gate receipt missing"))?;
    Ok(CommitReceipt {
        claim_short_id: id.to_hex(),
        approval: "proposed".into(),
        superseded_short_id: None,
        receipt_ref: format!("gate:{}", decision.decision_id.to_hex()),
        claim: None,
        superseded: None,
    })
}
