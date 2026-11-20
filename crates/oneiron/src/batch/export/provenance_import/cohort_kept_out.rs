//! A provenance cohort kept as archive data: its subject link is not here,
//! or the link keeps its own history, or the gate would pend the cohort. A
//! row this vault already holds stays as it is.
use std::collections::BTreeSet;
use std::io::{Read, Seek};

use super::{
    ClaimBody, ClaimLifecycleStatus, CohortRestore, EDGE_KEY_LEN, ENTITY_ID_LEN, EntityId,
    ExportBody, ExportEntity, ExportSecrets, ImportOmissionReason, IndexedArchive, Result, Tag,
    Vault, decode_claim_body, id_at, invalid, matches_row,
};
/// Whether this vault holds provenance on the cohort's subject link that the
/// cohort does not carry: a claim on the link, of any lifecycle, that is none
/// of `rows`. That is the vault's own history of a link it holds.
pub(super) fn holds_own_history(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    subject: &[u8],
    rows: &[(ExportEntity, EntityId, ClaimBody)],
) -> Result<bool> {
    if subject.len() != EDGE_KEY_LEN {
        return Err(invalid("archive cohort subject is not an edge"));
    }
    let kind = crate::edge::EdgeKind::try_from_u8(subject[ENTITY_ID_LEN])
        .ok_or_else(|| invalid("archive cohort subject is not an edge"))?;
    let (source, target) = (id_at(subject, 0)?, id_at(subject, ENTITY_ID_LEN + 1)?);
    Ok(vault
        .edge_provenance_audit_in_txn(txn, &crate::provenance::EdgeRef::new(source, kind, target))?
        .cohort
        .iter()
        .any(|(claim, _)| !rows.iter().any(|(_, id, _)| *id == claim.id)))
}
/// Whether the held claim `raw` is the archived claim `row` (`body`) as this
/// vault's own history of its link closed it, and nothing else: an active
/// archived claim that a later claim on the link superseded here, or that was
/// retracted here. A close re-puts the claim with its closed record, that
/// record's `valid_to` and the closed lifecycle, and moves the envelope's
/// `occurred.end` to that `valid_to`
/// (`provenance::lifecycle::closed_claim_put_payload`); every other byte stays
/// the archive's (REVIEW-9652 P1).
pub(super) fn closed_here(
    row: &ExportEntity,
    body: &ClaimBody,
    raw: &[u8],
    secrets: ExportSecrets,
) -> Result<bool> {
    use crate::write_envelope::provenance::edge_lifecycle::{
        close_record_for_supersession, retract_record,
    };
    if body.lifecycle != ClaimLifecycleStatus::Active {
        return Ok(false);
    }
    let Some(stored) = raw
        .get(crate::batch::ENTITY_METADATA_HEADER_LEN..)
        .and_then(|bytes| decode_claim_body(bytes, true).ok())
    else {
        return Ok(false);
    };
    let Some(close_at) = stored.valid_to else {
        return Ok(false);
    };
    let record = crate::provenance::decode_edge_provenance_body(&body.value)?;
    let closed = match stored.lifecycle {
        ClaimLifecycleStatus::Superseded => close_record_for_supersession(&record, close_at),
        ClaimLifecycleStatus::Retracted => retract_record(&record, close_at),
        _ => return Ok(false),
    };
    let Some((closed, valid_to)) = closed
        .ok()
        .and_then(|closed| closed.valid_to.map(|valid_to| (closed, valid_to)))
    else {
        return Ok(false);
    };
    let mut wrapper = body.clone();
    wrapper.value = crate::provenance::encode_edge_provenance_value(&closed);
    wrapper.valid_to = Some(valid_to);
    wrapper.lifecycle = stored.lifecycle;
    let closed_row = ExportEntity {
        occurred_end: valid_to,
        ..row.clone()
    };
    Ok(matches_row(
        &closed_row,
        raw,
        &ExportBody::from_bytes_with(
            &crate::write_envelope::claim_body::encode_claim_body(&wrapper)?,
            row.entity_type,
            secrets,
        ),
        secrets,
    ))
}
/// Keeps the cohort queued under `key`, whose subject link is not here or
/// keeps its own history, as archive data: a row this vault already holds
/// stays as it is, compared as [`super::restore_cohort`] compares it, and every
/// other row is marked omitted. With `own_history`, the link's own history
/// may have closed a row this vault took from an earlier archive, so a held
/// row is also left as it is when it is the archived row as such a close
/// leaves it ([`closed_here`]).
#[expect(clippy::too_many_arguments)]
pub(super) fn keep_cohort_out<R: Read + Seek>(
    key: EntityId,
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    archive: &mut IndexedArchive<'_, R>,
    rows: &[(ExportEntity, EntityId, ClaimBody)],
    secrets: ExportSecrets,
    own_history: bool,
    reason: ImportOmissionReason,
) -> Result<CohortRestore> {
    let mut unchanged = 0;
    let mut kept_out = Vec::new();
    for (row, id, body) in rows {
        match crate::ports::EntityStoreRead::port_entity_raw(&vault.store, txn, id)? {
            Some(existing) => {
                let expected = ExportBody::from_bytes_with(
                    &crate::write_envelope::claim_body::encode_claim_body(body)?,
                    row.entity_type,
                    secrets,
                );
                if !crate::vault::live_entity_row_in_txn(&vault.store, txn, id)?.is_live() {
                    return Err(invalid("archive provenance ID collision"));
                }
                let held = matches_row(row, &existing, &expected, secrets)
                    || (own_history && closed_here(row, body, &existing, secrets)?);
                if !held {
                    return Err(invalid("archive provenance ID collision"));
                }
                unchanged += 1;
            }
            None => {
                archive.index.put(Tag::Omitted, id.as_bytes(), &[])?;
                kept_out.push((*id, reason));
            }
        }
    }
    archive.index.remove(Tag::CohortPending, key.as_bytes())?;
    for (_, id, _) in rows {
        archive.index.remove(Tag::Waiting, id.as_bytes())?;
    }
    Ok(CohortRestore {
        inserted: BTreeSet::new(),
        unchanged,
        kept_out,
    })
}
