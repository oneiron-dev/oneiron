//! Claims are the document state machine. The audit copy survives document deletion.
use super::model::*;
use crate::claim::{
    ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus, ClaimSource, ClaimSubject,
};
use crate::{EntityId, Error, Result, TimeRange, Vault};
use rmpv::Value;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
const AUDIT: &[u8] = b"esign.audit.v1/";

pub(super) fn encoded(row: &EsignEventRow) -> Result<Vec<u8>> {
    serde_json::to_vec(row).map_err(|_| invalid("event encoding"))
}
pub(super) fn hash(row: &EsignEventRow) -> Result<[u8; 32]> {
    Ok(Sha256::digest(encoded(row)?).into())
}
pub(super) fn decode_event(body: &ClaimBody) -> Result<EsignEventRow> {
    let Value::Binary(bytes) = &body.value else {
        return Err(invalid("event payload must be a typed binary record"));
    };
    let row: EsignEventRow =
        serde_json::from_slice(bytes).map_err(|_| invalid("event payload schema"))?;
    if row.event.predicate() != body.predicate
        || row.actor.actor.is_empty()
        || row.actor.actor.len() > 4096
        || row.actor.ip.as_ref().is_some_and(|v| v.len() > 256)
        || row
            .actor
            .user_agent
            .as_ref()
            .is_some_and(|v| v.len() > 4096)
        || body.approval != ClaimApprovalStatus::Auto
        || body.lifecycle != ClaimLifecycleStatus::Active
        || body.stale
    {
        return Err(invalid("event header"));
    }
    if let EsignEvent::Drafted { document } = &row.event {
        validate_document(document, row.at)?;
    }
    Ok(row)
}

pub(super) fn events_in(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    document: EntityId,
) -> Result<Vec<EsignEventRow>> {
    let mut rows = BTreeMap::new();
    for id in vault.claims_for_subject_in_txn(txn, &document)? {
        let Some(body) = vault.get_claim_in_txn(txn, &id)? else {
            continue;
        };
        if !body.predicate.starts_with("esign.") {
            continue;
        }
        let row = decode_event(&body)?;
        if rows.insert(row.sequence, row).is_some() {
            return Err(invalid("forked document event sequence"));
        }
    }
    let mut previous = [0; 32];
    let mut previous_at = 0;
    let mut output = Vec::new();
    for (sequence, row) in rows {
        if sequence != output.len() as u64
            || row.previous_sha256 != previous
            || row.at < previous_at
        {
            return Err(invalid("broken document hash chain"));
        }
        previous = hash(&row)?;
        previous_at = row.at;
        output.push(row);
    }
    Ok(output)
}
fn fold(rows: &[EsignEventRow]) -> Result<Option<EsignState>> {
    let Some(first) = rows.first() else {
        return Ok(None);
    };
    let EsignEvent::Drafted { document } = &first.event else {
        return Err(invalid("missing document draft"));
    };
    let mut state = EsignState::draft(document.clone(), first.at)?;
    for row in &rows[1..] {
        state.apply(&row.event, row.at)?;
    }
    Ok(Some(state))
}
pub(super) fn state_in(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    document: EntityId,
) -> Result<EsignState> {
    fold(&events_in(vault, txn, document)?)?.ok_or_else(|| invalid("unknown signing document"))
}
pub(super) fn append(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    document: EntityId,
    event: EsignEvent,
    actor: EsignAuditActor,
    now: u64,
) -> Result<EsignState> {
    if vault.get_blob_artifact_in_txn(txn, &document)?.is_none() {
        return Err(Error::EntityNotFound);
    }
    let rows = events_in(vault, txn, document)?;
    let state = if let Some(mut state) = fold(&rows)? {
        state.apply(&event, now)?;
        state
    } else if let EsignEvent::Drafted { document } = &event {
        EsignState::draft(document.clone(), now)?
    } else {
        return Err(invalid("first event must create a draft"));
    };
    let row = EsignEventRow {
        sequence: rows.len() as u64,
        previous_sha256: rows.last().map(hash).transpose()?.unwrap_or([0; 32]),
        event,
        actor,
        at: now,
    };
    if rows.last().is_some_and(|prior| now < prior.at) {
        return Err(invalid("event clock moved backwards"));
    }
    let bytes = encoded(&row)?;
    let mut body = ClaimBody::new(
        row.event.predicate(),
        ClaimSubject::Entity(document),
        Value::Binary(bytes.clone()),
        1.0,
        ClaimApprovalStatus::Auto,
        ClaimLifecycleStatus::Active,
    );
    body.source = Some(ClaimSource::Observed);
    vault.put_reserved_claim_in_txn(
        txn,
        &EntityId::now(),
        &body,
        TimeRange {
            start: now,
            end: now,
        },
        now,
    )?;
    vault.store.vault_meta.put(
        txn,
        &[
            AUDIT,
            document.as_bytes(),
            row.sequence.to_be_bytes().as_slice(),
        ]
        .concat(),
        &bytes,
    )?;
    Ok(state)
}

impl Vault {
    /// Creates the signing overlay on an existing artifact. Original item
    /// versions are pinned before the first event; later send rechecks them.
    pub fn create_esign_document(
        &self,
        document: EntityId,
        body: &EsignDocument,
        actor: EsignAuditActor,
        now: u64,
    ) -> Result<()> {
        validate_document(body, now)?;
        self.with_write_txn(|txn| {
            if !events_in(self, txn, document)?.is_empty() {
                return Err(invalid("document already exists"));
            }
            for item in &body.items {
                let id = EntityId::from_hex(&item.artifact_ref)?;
                let head = super::super::read_blob_artifact_head_in_txn(&self.store, txn, &id)?
                    .ok_or_else(|| invalid("missing original PDF version"))?;
                if head.version != item.original_version {
                    return Err(invalid("original version changed"));
                }
                let artifact = self
                    .get_blob_artifact_in_txn(txn, &id)?
                    .ok_or(Error::EntityNotFound)?;
                if artifact.media_type != "application/pdf" {
                    return Err(invalid("signing item is not a PDF"));
                }
            }
            append(
                self,
                txn,
                document,
                EsignEvent::Drafted {
                    document: body.clone(),
                },
                actor,
                now,
            )?;
            Ok(())
        })
    }
    pub fn esign_document(&self, document: EntityId) -> Result<EsignState> {
        let txn = self.store.env.read_txn()?;
        state_in(self, &txn, document)
    }
    /// Append-only trail remains queryable after the document's erase.
    pub fn esign_audit(&self, document: EntityId) -> Result<Vec<EsignEventRow>> {
        let txn = self.store.env.read_txn()?;
        let prefix = [AUDIT, document.as_bytes()].concat();
        let mut rows = Vec::new();
        let mut previous = [0; 32];
        for row in self.store.vault_meta.prefix_iter(&txn, &prefix)? {
            let (_, bytes) = row?;
            let event: EsignEventRow =
                serde_json::from_slice(&bytes).map_err(|_| invalid("audit schema"))?;
            if event.sequence != rows.len() as u64 || event.previous_sha256 != previous {
                return Err(invalid("audit hash chain"));
            }
            previous = hash(&event)?;
            rows.push(event);
        }
        Ok(rows)
    }
}

pub(crate) fn validate_event_claim(body: &ClaimBody) -> Result<()> {
    if body.predicate.starts_with("esign.") {
        decode_event(body)?;
    }
    Ok(())
}
