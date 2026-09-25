//! Authenticated semantic NOTE commands. Peer Loro bytes never authorize writes.

use super::document::{NoteDocument, invalid};
use super::document_store::{load, persist, require_note_writer, validate_pin_source};
use super::pin_index::NOTE_PIN_SOURCE;
use super::side_keys::HexPair;
use super::sync_rows::{EntityIdWire, NOTE_RECEIPT_BY_REQUEST, SYNC_DS_E};
use super::{NoteEdit, NoteEditOutcome, NotePin};
use crate::memory::{CommitReceipt, Memory, MemoryResult};
use crate::side_table::HexId;
use crate::{EdgeActorClass, EntityId, WriteActor};
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
    Edit { base: Vec<u8>, edits: Vec<NoteEdit> },
    Cite { pin: NotePin },
}

/// Durable provenance authored only by the admission door. Commit messages
/// remain diagnostic text; neither grants nor actor classes are read from them.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NoteAuthorship {
    #[serde(with = "super::id_codec")]
    pub operation: EntityId,
    #[serde(with = "super::id_codec")]
    pub actor: EntityId,
    pub actor_class: String,
    pub grant: Option<String>,
    pub command_hash: [u8; 32],
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NoteOperationReceipt {
    #[serde(with = "super::id_codec")]
    pub request_id: EntityId,
    pub command_hash: [u8; 32],
    pub outcome: NoteEditOutcome,
}

impl NoteOperation {
    pub fn encode(&self) -> crate::Result<Vec<u8>> {
        let bytes = serde_json::to_vec(self).map_err(|_| invalid("NOTE operation encode"))?;
        if bytes.len() > 4 * 1024 * 1024 {
            return Err(invalid("NOTE operation exceeds bound"));
        }
        Ok(bytes)
    }
    pub fn decode(bytes: &[u8]) -> crate::Result<Self> {
        if bytes.len() > 4 * 1024 * 1024 {
            return Err(invalid("NOTE operation exceeds bound"));
        }
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

pub(super) fn record_authorship(doc: &NoteDocument, record: &NoteAuthorship) -> crate::Result<()> {
    if authorship(&doc.doc)?.len() >= 4096 {
        return Err(invalid("NOTE authorship cap reached"));
    }
    let value = serde_json::to_string(record).map_err(|_| invalid("NOTE authorship encode"))?;
    doc.doc
        .get_map("authorship")
        .insert(&record.operation.to_hex(), value)
        .map_err(|_| invalid("NOTE authorship insert"))?;
    doc.doc.commit_with(
        loro::CommitOptions::new()
            .commit_msg(&format!("oneiron.note/v1 actor={}", record.actor.to_hex())),
    );
    Ok(())
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
        Ok(saved.1 == *receipt)
    }
}

impl Memory<'_> {
    /// Host boundary for an already MAC-verified, live session. `self.actor()`
    /// and class MUST come from that credential, never the command or selector.
    /// The server supplies CoreAuth's principal, class and liveness predicate.
    /// Actor/owner, token revocation, grant/member/role, scope, policy, erasure
    /// and citation checks run under the writer lock that commits the result.
    /// The liveness predicate must read current auth state without writing it.
    #[cfg(feature = "sync")]
    pub fn admit_note_operation(
        &self,
        note: EntityId,
        scope: crate::FederationGrantScope,
        selector: &crate::sync::SyncSelector,
        session_is_live: impl FnOnce(&heed::RwTxn<'_>) -> bool,
        operation: &NoteOperation,
    ) -> MemoryResult<NoteOperationReceipt> {
        let receipt = self.with_verified_actor_write_txn(|txn| {
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
        })?;
        #[cfg(feature = "sync")]
        self.vault().notify_note_document(note);
        Ok(receipt)
    }

    /// Host boundary for an own device on the owner lane. The actor must be
    /// the vault owner and the NOTE must pass the owner export's refusals;
    /// the operation applies with no grant.
    #[cfg(feature = "sync")]
    pub fn admit_owner_note_operation(
        &self,
        note: EntityId,
        session_is_live: impl FnOnce(&heed::RwTxn<'_>) -> bool,
        operation: &NoteOperation,
    ) -> MemoryResult<NoteOperationReceipt> {
        let receipt = self.with_verified_actor_write_txn(|txn| {
            if SYNC_DS_E.contains(&self.vault().store, txn, &HexId(note))? {
                return Err(invalid("replica NOTE cannot act as an admission authority").into());
            }
            if !session_is_live(txn) {
                return Err(invalid("NOTE session revoked").into());
            }
            self.verify_owner_in_txn(txn)?;
            crate::sync::documents::owner_note_admission(self.vault(), txn, note)?;
            self.apply_note_operation_in_txn(txn, note, operation, None)
        })?;
        self.vault().notify_note_document(note);
        Ok(receipt)
    }

    pub(super) fn apply_local_note_operation(
        &self,
        note: EntityId,
        operation: &NoteOperation,
    ) -> MemoryResult<NoteOperationReceipt> {
        let receipt = self.with_verified_actor_write_txn(|txn| {
            if SYNC_DS_E.contains(&self.vault().store, txn, &HexId(note))? {
                return Err(invalid(
                    "replica NOTE edits must be submitted to its authenticated authority",
                )
                .into());
            }
            self.apply_note_operation_in_txn(txn, note, operation, None)
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
        require_note_writer(self, txn, note)?;
        let doc = load(self.vault(), txn, note)?;
        let hash = operation.hash()?;
        let receipt_key = HexPair(HexId(note), HexId(operation.request_id));
        if let Some(saved) = NOTE_RECEIPT_BY_REQUEST.get(&self.vault().store, txn, &receipt_key)? {
            if saved.0.0 != self.actor() || saved.1.command_hash != hash {
                return Err(invalid("NOTE request identity reused").into());
            }
            return Ok(saved.1);
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
        let actor = WriteActor::new(self.actor(), self.actor_class());
        let outcome = match &operation.change {
            NoteChange::Edit { base, edits } => {
                let cited_by = cited_by(self.vault(), txn, note)?;
                if doc.edit(base, edits, &actor, &cited_by)? {
                    None
                } else {
                    if !policy.enforces_write_gate() {
                        return Err(
                            invalid("reviewed NOTE edit requires an active gate policy").into()
                        );
                    }
                    Some(NoteEditOutcome::Proposed(propose_claim(
                        self, txn, note, operation,
                    )?))
                }
            }
            NoteChange::Cite { pin } => {
                validate_pin_source(self.vault(), txn, pin)?;
                doc.add_pin(pin, &actor)?;
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
                        actor: self.actor(),
                        actor_class: self.actor_class().gate_actor_class().to_owned(),
                        grant: grant.map(|id| id.to_hex()),
                        command_hash: hash,
                    },
                )?;
                persist(self.vault(), txn, &doc)?;
                NoteEditOutcome::Applied(doc.view()?)
            }
        };
        let receipt = NoteOperationReceipt {
            request_id: operation.request_id,
            command_hash: hash,
            outcome,
        };
        let payload = serde_json::to_vec(&receipt).map_err(|_| invalid("NOTE receipt encode"))?;
        if payload.len() > MAX_RECEIPT_PAYLOAD - 18 {
            return Err(invalid("NOTE receipt exceeds wire bound").into());
        }
        NOTE_RECEIPT_BY_REQUEST.put(
            &self.vault().store,
            txn,
            &receipt_key,
            &(EntityIdWire(self.actor()), receipt.clone()),
        )?;
        Ok(receipt)
    }
}

pub(super) fn cited_by(
    vault: &crate::Vault,
    txn: &heed::RoTxn<'_>,
    note: EntityId,
) -> crate::Result<Vec<NotePin>> {
    let mut pins = Vec::new();
    let mut budget = 0usize;
    let prefix = format!("{}:", note.to_hex());
    for row in NOTE_PIN_SOURCE.iter_raw_from(&vault.store, txn, prefix.as_bytes())? {
        let (_, bytes) = row?;
        budget = budget.saturating_add(bytes.len());
        if budget > 4 * 1024 * 1024 {
            return Err(invalid("NOTE citation guard budget exceeded"));
        }
        // Undecoded rows, deliberately: decoding through the typed table would
        // parse each row before this budget guard could refuse it.
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
    let id = EntityId::now();
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
    let envelope = WriteEnvelope::new(
        WriteActor::new(memory.actor(), memory.actor_class()),
        source,
        WriteProvenance::new(rmpv::Value::from("note.propose_claim"))?,
        ClaimApprovalStatus::Proposed,
    );
    let now = crate::unix_seconds_now();
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
    })
}
