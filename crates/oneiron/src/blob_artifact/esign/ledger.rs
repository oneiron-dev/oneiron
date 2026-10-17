//! Claims are the document state machine. The audit copy survives document deletion.
use super::model::*;
use crate::claim::{
    ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus, ClaimSource, ClaimSubject,
};
use crate::side_table::{self, LegacyJson, SideTable};
use crate::{EntityId, Error, Result, TimeRange, Vault};
use rmpv::Value;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

/// Esign document audit event. Key: id16 (document) + u64be (sequence).
const AUDIT: SideTable<(EntityId, u64), EsignEventRow, LegacyJson> =
    SideTable::new(&side_table::ESIGN_AUDIT);

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
    Ok(chain_in(vault, txn, document)?.0)
}
/// The verified event chain, and whether any event in it awaits its owner's
/// answer.
fn chain_in(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    document: EntityId,
) -> Result<(Vec<EsignEventRow>, bool)> {
    let mut rows = BTreeMap::new();
    let mut held = false;
    for id in vault.claims_for_subject_in_txn(txn, &document)? {
        let Some(body) = vault.get_claim_in_txn(txn, &id)? else {
            continue;
        };
        if !body.predicate.starts_with("esign.") {
            continue;
        }
        let row = decode_event(&body)?;
        held |= !crate::gate::claim_consolidation_eligible_in_txn(
            &vault.store,
            txn,
            &id,
            crate::gate::ConsolidationReader::EsignLedger,
        )?;
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
    Ok((output, held))
}
fn awaits_owner_answer() -> Error {
    invalid("a document event awaits its owner's answer")
}
/// A decline, void or expiry narrows the document, so it lands on the whole
/// chain even while an event in it awaits its owner's answer.
fn restricts(event: &EsignEvent) -> bool {
    matches!(
        event,
        EsignEvent::Declined { .. } | EsignEvent::Voided { .. } | EsignEvent::Expired { .. }
    )
}
/// One page of the documents this vault holds a signing draft for: the
/// subjects of at most `limit` draft claims after `after`, in claim-id order,
/// and the last claim the page read. The housekeeping pass walks the pages and
/// feeds each to the expiry and seal sweeps, which take a caller's document
/// list; a short page ends the walk.
pub(crate) fn esign_document_page_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    after: Option<EntityId>,
    limit: usize,
) -> Result<(Vec<EntityId>, Option<EntityId>)> {
    let claims = crate::claim::claim_ids_for_predicate_page_in_txn(
        &vault.store,
        txn,
        DRAFT_PREDICATE,
        after,
        limit,
    )?;
    let mut documents = std::collections::BTreeSet::new();
    for id in &claims {
        if let Some(body) = vault.get_claim_in_txn(txn, id)?
            && let ClaimSubject::Entity(document) = body.subject
        {
            documents.insert(document);
        }
    }
    let last = (claims.len() == limit)
        .then(|| claims.last().copied())
        .flatten();
    Ok((documents.into_iter().collect(), last))
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
    let (rows, held) = chain_in(vault, txn, document)?;
    if held {
        return Err(awaits_owner_answer());
    }
    fold(&rows)?.ok_or_else(|| invalid("unknown signing document"))
}
/// Whether an event of `document` awaits its owner's answer.
pub(super) fn held_in(vault: &Vault, txn: &heed::RoTxn<'_>, document: EntityId) -> Result<bool> {
    Ok(chain_in(vault, txn, document)?.1)
}
/// [`state_in`] for a restriction to narrow: the whole chain, held events
/// included.
pub(super) fn restrictive_state_in(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    document: EntityId,
) -> Result<EsignState> {
    fold(&events_in(vault, txn, document)?)?.ok_or_else(|| invalid("unknown signing document"))
}
/// Appends `Sent` in its own write, for a test that drives the ceremony
/// from another crate (`crate::test_support`).
#[cfg(any(test, feature = "test-support"))]
pub(crate) fn mark_sent_for_test(
    vault: &Vault,
    document: EntityId,
    actor: EsignAuditActor,
    now: u64,
) -> Result<()> {
    vault.with_write_txn(|txn| append(vault, txn, document, EsignEvent::Sent, actor, now).map(drop))
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
    let (rows, held) = chain_in(vault, txn, document)?;
    if held && !restricts(&event) {
        return Err(awaits_owner_answer());
    }
    let state = if let Some(mut state) = fold(&rows)? {
        state.apply(&event, now)?;
        state
    } else if let EsignEvent::Drafted { document } = &event {
        EsignState::draft(document.clone(), now)?
    } else {
        return Err(invalid("first event must create a draft"));
    };
    // Refuse unrenderable input before any event or Completed recipient state
    // commits. Signed rechecks all of that recipient's saved values as a backstop.
    super::field_admission::validate_event_fields(vault, txn, &state, &event)?;
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
        Value::Binary(bytes),
        1.0,
        ClaimApprovalStatus::Auto,
        ClaimLifecycleStatus::Active,
    )?;
    body.source = Some(ClaimSource::Observed);
    vault.put_reserved_claim_in_txn(
        txn,
        &vault.new_entity_id()?,
        &body,
        TimeRange {
            start: now,
            end: now,
        },
        now,
    )?;
    AUDIT.put(&vault.store, txn, &(document, row.sequence), &row)?;
    Ok(state)
}

/// Whether only a member of a project (a seat in its home room, its leader or
/// a board holder) may create a document for it, and so put its board on a
/// held sign act's chain. A live vault owner is never refused: it may send a
/// document for any live project.
pub const PROJECT_MEMBERS_ONLY: bool = true;

/// Whether the hex `actor` is one of the vault's live owners.
fn is_live_owner(vault: &Vault, txn: &heed::RoTxn<'_>, actor: &str) -> Result<bool> {
    match EntityId::from_hex(actor) {
        Ok(id) => crate::policy_model::is_live_vault_owner_in_txn(vault, txn, &id),
        Err(_) => Ok(false),
    }
}

impl Vault {
    /// Creates the signing overlay on an existing artifact. Original item
    /// versions are pinned before the first event; later send rechecks them.
    /// A document for a project needs the project live and, under
    /// [`PROJECT_MEMBERS_ONLY`], `actor` among its members or a live vault
    /// owner.
    pub fn create_esign_document(
        &self,
        document: EntityId,
        body: &EsignDocument,
        actor: EsignAuditActor,
        now: u64,
    ) -> Result<()> {
        validate_document(body, now)?;
        self.with_write_txn_grouped(|txn| {
            if !events_in(self, txn, document)?.is_empty() {
                return Err(invalid("document already exists"));
            }
            if let Some(project) = body.project {
                let (_, effective) = self
                    .effective_project_in_txn(txn, project)?
                    .ok_or_else(|| invalid("the document's project is not a live project"))?;
                let by = actor.actor.as_str();
                let member = effective.seats(by)
                    || effective.leader == by
                    || effective.board.iter().any(|holder| holder == by);
                if PROJECT_MEMBERS_ONLY && !member && !is_live_owner(self, txn, by)? {
                    return Err(invalid(
                        "only a member of a project or a vault owner sends a document for it",
                    ));
                }
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
        let mut rows = Vec::new();
        let mut previous = [0; 32];
        for row in AUDIT.iter_from(&self.store, &txn, document.as_bytes())? {
            let (_, event) = row?;
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
        decode_event(body).map_err(|_| Error::InvalidClaimBody("invalid esign event body"))?;
    }
    Ok(())
}

pub(crate) fn reject_event_delete(
    store: &crate::store::Store,
    txn: &heed::RoTxn<'_>,
    id: &EntityId,
) -> Result<()> {
    // A put reaches this on any prior row, a custody record among them, whose
    // body carries its value (ARCH-0069 S1): the copy is wiped.
    if let Some(raw) = crate::ports::EntityStoreRead::port_entity_raw_wiped(store, txn, id)?
        && let Some(header) = crate::batch::EntityMetadataHeader::parse(&raw)
        && header.entity_type == crate::registry::ENTITY_TYPE_CLAIM
        && let Ok(body) =
            crate::claim::decode_claim_body(&raw[crate::batch::ENTITY_METADATA_HEADER_LEN..], true)
        && body.predicate.starts_with("esign.")
    {
        return Err(Error::InvalidClaimBody("esign events are append-only"));
    }
    Ok(())
}
