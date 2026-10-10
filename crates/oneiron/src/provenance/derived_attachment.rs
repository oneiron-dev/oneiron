//! Validate generated support evidence at the provenance write door.
//! The parent-computed locator hash is rechecked against the current source
//! before an edge/provenance row can commit in the same transaction.

use super::EdgeRef;
use crate::batch::{ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader};
use crate::claim::{
    ClaimSource, claim_evidence_admissible, claim_evidence_taint, decode_claim_body,
};
use crate::dreamer_consolidation::resources::{native_turn_source, stored_project};
use crate::dreamer_consolidation::{
    TurnText, cited_evidence_bytes, decode_consolidation_evidence, decode_verified_citations,
    live_turn_text_in, source_meet, swarm_evidence_content_hash,
};
use crate::edge::EdgeKind;
use crate::error::{Error, Result};
use crate::registry::{ENTITY_TYPE_CLAIM, ENTITY_TYPE_TURN};
use crate::write_envelope::WriteActor;
use crate::{EntityId, Vault};
use rmpv::Value;
use std::collections::BTreeSet;

/// The one PROJECT a generated support row lands in: its source's and its
/// head's, which must agree, so a project-local attachment's provenance stays
/// inside that project's scoped reads and export (ONE-1592 P3). Both rows are
/// stored entity rows, header included.
pub(crate) fn support_project(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    subject: &EdgeRef,
    source_row: &[u8],
    head_row: &[u8],
) -> Result<EntityId> {
    let project = |id: EntityId, row: &[u8]| {
        let header = EntityMetadataHeader::parse(row)
            .ok_or(Error::InvalidClaimBody("derived support endpoint header"))?;
        stored_project(
            &vault.store,
            txn,
            id,
            header.entity_type,
            &row[ENTITY_METADATA_HEADER_LEN..],
        )
    };
    match (
        project(subject.source, source_row)?,
        project(subject.target, head_row)?,
    ) {
        (Some(source), Some(head)) if source == head => Ok(head),
        _ => Err(Error::InvalidClaimBody("derived support crosses projects")),
    }
}

/// `reader` is the provenance writer: a TURN range is re-sliced from the turn
/// text it can read in this transaction, the same projection it cited, and
/// must still cover exactly the MESSAGE slices the evidence names. Returns
/// the evidence's trust class and the [`support_project`] the row lands in.
pub(super) fn verify(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    subject: &EdgeRef,
    evidence: &Value,
    reader: WriteActor,
) -> Result<(ClaimSource, EntityId)> {
    let decoded = decode_consolidation_evidence(evidence)?.ok_or(Error::InvalidClaimBody(
        "derived edge requires typed evidence",
    ))?;
    if !decoded.chain.is_empty()
        || decoded.refs != [subject.source]
        || subject.kind != EdgeKind::Supports
        || subject.source == subject.target
    {
        return Err(Error::InvalidClaimBody("derived support evidence mismatch"));
    }
    let source_row = vault
        .store
        .entities
        .get(txn, subject.source.as_bytes())?
        .ok_or(Error::EntityNotFound)?;
    let head_row = vault
        .store
        .entities
        .get(txn, subject.target.as_bytes())?
        .ok_or(Error::EntityNotFound)?;
    let source_header = EntityMetadataHeader::parse(&source_row)
        .ok_or(Error::InvalidClaimBody("derived support source header"))?;
    if EntityMetadataHeader::parse(&head_row)
        .is_none_or(|header| header.entity_type != ENTITY_TYPE_CLAIM)
    {
        return Err(Error::InvalidClaimBody(
            "derived support head is not a claim",
        ));
    }
    let project = support_project(vault, txn, subject, &source_row, &head_row)?;
    let source_body = &source_row[ENTITY_METADATA_HEADER_LEN..];
    let stored_source = match source_header.entity_type {
        ENTITY_TYPE_TURN => native_turn_source(vault, source_body)?,
        ENTITY_TYPE_CLAIM => {
            let claim = decode_claim_body(source_body, true)?;
            if !claim_evidence_admissible(&claim) {
                return Err(Error::InvalidClaimBody(
                    "generated claim cannot corroborate",
                ));
            }
            let source = claim.source.unwrap_or(ClaimSource::Imported);
            source_meet(source, claim_evidence_taint(&claim).unwrap_or(source))
        }
        _ => {
            return Err(Error::InvalidClaimBody(
                "derived support endpoints mismatch",
            ));
        }
    };
    let locators = decode_verified_citations(evidence)?;
    // Every TURN source re-collects its MESSAGE text on the caller's writer,
    // a whole-TURN locator included, so a moved or withheld row refuses here.
    let text = if source_header.entity_type == ENTITY_TYPE_TURN {
        Some(live_turn_text_in(
            vault,
            txn,
            reader,
            &subject.source,
            source_body,
        )?)
    } else {
        None
    };
    let mut unique = BTreeSet::new();
    for (locator, reported_hash, messages) in locators {
        if locator.source_id != subject.source || !unique.insert((locator.source_id, reported_hash))
        {
            return Err(Error::InvalidClaimBody(
                "derived support locator source or duplicate",
            ));
        }
        if source_header.entity_type == ENTITY_TYPE_CLAIM {
            if locator.claim_id != Some(subject.source) || locator.byte_range.is_some() {
                return Err(Error::InvalidClaimBody(
                    "derived support claim locator mismatch",
                ));
            }
        } else if locator.claim_id.is_some() {
            return Err(Error::InvalidClaimBody(
                "derived support turn locator mismatch",
            ));
        }
        let bytes =
            cited_evidence_bytes(locator, source_body, text.as_ref().and_then(TurnText::text))?;
        if swarm_evidence_content_hash(&bytes) != reported_hash {
            return Err(Error::InvalidClaimBody(
                "derived support locator hash mismatch",
            ));
        }
        let live = match &text {
            Some(text) => text.spans(locator.byte_range)?,
            None => Vec::new(),
        };
        if live != messages {
            return Err(Error::InvalidClaimBody(
                "derived support message slices mismatch",
            ));
        }
    }
    let meet = source_meet(ClaimSource::Generated, stored_source);
    if source_meet(meet, decoded.source_meet) != decoded.source_meet {
        return Err(Error::InvalidClaimBody(
            "derived support source trust widened",
        ));
    }
    Ok((decoded.source_meet, project))
}
