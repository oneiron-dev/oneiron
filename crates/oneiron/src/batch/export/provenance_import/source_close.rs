//! A held provenance row the source closed after this vault took it (FIX
//! WHOLE-VAULT-IMPORT-HELD-ROW-CLOSED-AT-SOURCE-ABORTS; Engine ANSWER
//! HELD-ROW-CLOSED-AT-SOURCE 20 Nov 05:23): the later archive carries it
//! closed, and a link with no history of its own follows the source.
use super::{
    ClaimBody, ClaimLifecycleStatus, ExportBody, ExportEntity, ExportSecrets, Result,
    decode_claim_body, matches_row,
};
use crate::write_envelope::claim_body::encode_claim_body;
use crate::write_envelope::provenance::edge_lifecycle::{
    close_record_for_supersession, retract_record,
};

/// How the archive closed a held active row that it carries closed.
pub(super) enum SourceClose {
    /// A later archived claim on the link superseded it.
    Superseded,
    /// It was retracted at this time.
    Retracted(u64),
}
/// How the archived claim `row` (`body`) closed the held active claim `raw`,
/// when `raw` is exactly that archived row before the archive's close: the
/// held record closed as the source's writer closed it, at the archived
/// `valid_to`, is the archived row byte for byte, and the held envelope is
/// the archived one with `occurred.end` where the open record put it. The
/// reverse of [`super::cohort_kept_out::closed_here`]. `None` for any other difference.
pub(super) fn closed_at_source(
    row: &ExportEntity,
    body: &ClaimBody,
    raw: &[u8],
    secrets: ExportSecrets,
) -> Result<Option<SourceClose>> {
    let Some(close_at) = body.valid_to else {
        return Ok(None);
    };
    let Some(stored) = raw
        .get(crate::batch::ENTITY_METADATA_HEADER_LEN..)
        .and_then(|bytes| decode_claim_body(bytes, true).ok())
        .filter(|stored| stored.lifecycle == ClaimLifecycleStatus::Active)
    else {
        return Ok(None);
    };
    let Ok(record) = crate::provenance::decode_edge_provenance_body(&stored.value) else {
        return Ok(None);
    };
    let (closed, close) = match body.lifecycle {
        ClaimLifecycleStatus::Superseded => (
            close_record_for_supersession(&record, close_at),
            SourceClose::Superseded,
        ),
        ClaimLifecycleStatus::Retracted => (
            retract_record(&record, close_at),
            SourceClose::Retracted(close_at),
        ),
        _ => return Ok(None),
    };
    let Ok(closed) = closed else {
        return Ok(None);
    };
    let as_archived = |bytes: &[u8]| ExportBody::from_bytes_with(bytes, row.entity_type, secrets);
    let open_row = ExportEntity {
        occurred_end: record.valid_to.unwrap_or(u64::MAX),
        ..row.clone()
    };
    if !matches_row(
        &open_row,
        raw,
        &as_archived(&encode_claim_body(&stored)?),
        secrets,
    ) {
        return Ok(None);
    }
    let mut wrapper = stored;
    wrapper.value = crate::provenance::encode_edge_provenance_value(&closed);
    wrapper.valid_to = closed.valid_to;
    wrapper.lifecycle = body.lifecycle;
    Ok(
        (as_archived(&encode_claim_body(&wrapper)?) == as_archived(&encode_claim_body(body)?))
            .then_some(close),
    )
}
