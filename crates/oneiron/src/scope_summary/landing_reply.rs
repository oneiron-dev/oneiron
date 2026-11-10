//! Shared admission of a reply against its stored, signed summary landing.

use super::codec::{decode_scope_summary_body, invalid};
use crate::claim::{claim_author, decode_claim_body};
use crate::conversation_dag::{conversation_of, require_type};
use crate::edge::EdgeKind;
use crate::ports::{EdgeDirection, EdgeStoreRead};
use crate::registry::{ENTITY_TYPE_CLAIM, ENTITY_TYPE_SUMMARY};
use crate::store::{ManifestDbs, Store};
use crate::{EntityId, Error, Result};

/// Binds a landing reply to a stored scope summary and a signed header on
/// `target`. An absent landing is refused, including on out-of-order replay.
pub(crate) fn validate_landing_reply_in(
    dbs: &impl ManifestDbs,
    store: &Store,
    txn: &heed::RoTxn<'_>,
    summary: &EntityId,
    room: Option<EntityId>,
    text: &str,
    target: EntityId,
) -> Result<()> {
    let stored =
        require_type(dbs, txn, summary, ENTITY_TYPE_SUMMARY).map_err(|err| match err {
            Error::Record(_) | Error::EntityNotFound => {
                invalid("landing reply requires a stored scope summary")
            }
            local => local,
        })?;
    let logical = crate::entity_doc::resolve_record_body(dbs, txn, summary, &stored)?;
    let body = decode_scope_summary_body(&logical)?;
    let scope = body
        .scope
        .as_ref()
        .ok_or_else(|| invalid("landing reply requires a conversation scope"))?;
    if room.is_some_and(|room| room != scope.conversation) || text != body.text {
        return Err(invalid("landing reply differs from its summary"));
    }
    if conversation_of(dbs, txn, &target)? != scope.conversation {
        return Err(invalid("landing reply target is in another conversation"));
    }
    // Replay can retain unverified MACHINE claims before genesis. Such a row
    // cannot authorize words under the landing writer's name.
    let fold = crate::authority::authority_fold_readonly_for_store_in_txn(
        store,
        store.privacy_posture,
        txn,
    )?;
    if fold.vault_id.is_none() {
        return Err(invalid("landing reply requires a verifiable landing"));
    }
    let writer = super::landing_writer_id()?;
    for edge in dbs.port_edges(
        txn,
        &target,
        EdgeDirection::In,
        Some(EdgeKind::ClaimOf),
        None,
    )? {
        let claim = edge?.target;
        let crate::vault::LiveEntityRow::Live {
            entity_type: ENTITY_TYPE_CLAIM,
            body: bytes,
        } = crate::vault::live_entity_row_in_txn(dbs, txn, &claim)?
        else {
            continue;
        };
        let header = decode_claim_body(&bytes, true)?;
        if super::merge_summary_ref(&header)? != Some((target, *summary))
            || claim_author(&header) != Some(writer)
            || !matches!(header.evidence.as_ref(), Some(rmpv::Value::Map(fields))
                if fields.iter().any(|(key, _)| key.as_str() == Some("machine_signature")))
        {
            continue;
        }
        // Require a proof even if the MACHINE row has not arrived: otherwise
        // the verifier can treat an unsigned, unknown author as non-MACHINE.
        // This is an existing stored claim, so recheck its origin rather than
        // imposing new local-writer enrollment or requiring an envelope.
        // A proof that does not verify is the row's fault; a storage fault is
        // the engine's and propagates.
        match crate::authority::verify_machine_claim_in_txn(
            store,
            txn,
            store.privacy_posture,
            &claim,
            &header,
            true,
            None,
        ) {
            Ok(()) => return Ok(()),
            Err(Error::Claim(_) | Error::Record(_)) => {}
            Err(local) => return Err(local),
        }
    }
    Err(invalid(
        "landing reply requires its signed merge.summary landing",
    ))
}
