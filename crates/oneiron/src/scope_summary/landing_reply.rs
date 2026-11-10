//! Shared admission of a reply against its stored, signed summary landing.

use super::codec::{decode_scope_summary_body, invalid};
use crate::claim::{claim_author, decode_claim_body};
use crate::conversation_dag::{edge_ids, named_room, require_type};
use crate::edge::EdgeKind;
use crate::error::ClaimError;
use crate::ports::{EdgeDirection, EdgeStoreRead};
use crate::registry::{
    ENTITY_TYPE_CLAIM, ENTITY_TYPE_CONVERSATION, ENTITY_TYPE_SUMMARY, ENTITY_TYPE_TURN,
};
use crate::store::{ManifestDbs, Store};
use crate::{EntityId, Error, Result};

/// Verdict of [`validate_landing_reply_in`]: `Bound` admits the reply under
/// its signed landing, `Waits` defers it until a later replay delivers the
/// missing prerequisite. Refusal stays `Err`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum LandingReplyVerdict {
    Bound,
    Waits,
}

/// Binds a landing reply to a stored scope summary and a header on `target`
/// whose signing key the vault's authority fold binds to the landing writer.
///
/// `Bound` admits the reply: the summary is stored, the room and text match
/// it, the target sits in its conversation, and a `merge.summary` header
/// naming (`target`, `summary`) by the writer verifies and is signer-bound.
/// `Waits` defers it: a prerequisite a later replay can still deliver is
/// absent (the summary is not stored, the vault id is unresolved, the target
/// has no resolvable room yet, no eligible header names the landing, or a
/// matching header's history or enrollment has not arrived). Present data
/// that contradicts the landing refuses: a wrong room or text, a target in
/// another conversation or of contradictory topology, or a matching header
/// whose signature is invalid. Storage faults propagate.
pub(crate) fn validate_landing_reply_in(
    dbs: &impl ManifestDbs,
    store: &Store,
    txn: &heed::RoTxn<'_>,
    summary: &EntityId,
    room: Option<EntityId>,
    text: &str,
    target: EntityId,
) -> Result<LandingReplyVerdict> {
    let stored = match require_type(dbs, txn, summary, ENTITY_TYPE_SUMMARY) {
        Ok(stored) => stored,
        Err(Error::EntityNotFound) => return Ok(LandingReplyVerdict::Waits),
        Err(Error::Record(_) | Error::Claim(_)) => {
            return Err(invalid("landing reply requires a stored scope summary"));
        }
        Err(local) => return Err(local),
    };
    let logical = crate::entity_doc::resolve_record_body(dbs, txn, summary, &stored)?;
    let body = decode_scope_summary_body(&logical)?;
    let scope = body
        .scope
        .as_ref()
        .ok_or_else(|| invalid("landing reply requires a conversation scope"))?;
    if room.is_some_and(|room| room != scope.conversation) || text != body.text {
        return Err(invalid("landing reply differs from its summary"));
    }
    // The target's room: absent or not yet placed waits for a later replay;
    // a room that contradicts the landing refuses. Storage faults propagate.
    match named_room(dbs, txn, &target)? {
        Ok(room) => match require_type(dbs, txn, &room, ENTITY_TYPE_CONVERSATION) {
            Ok(_) => {
                if room != scope.conversation {
                    return Err(invalid("landing reply target is in another conversation"));
                }
            }
            Err(Error::EntityNotFound) => return Ok(LandingReplyVerdict::Waits),
            Err(Error::Record(_) | Error::Claim(_)) => {
                return Err(invalid("landing reply target is in another conversation"));
            }
            Err(local) => return Err(local),
        },
        Err(Error::EntityNotFound) => return Ok(LandingReplyVerdict::Waits),
        Err(Error::Record(_) | Error::Claim(_)) => {
            // The target names no single room: a missing placement waits, a
            // contradictory topology refuses. Disambiguate without matching
            // on message text.
            match crate::vault::live_entity_row_in_txn(dbs, txn, &target)? {
                crate::vault::LiveEntityRow::Live {
                    entity_type: ENTITY_TYPE_TURN,
                    ..
                } => {
                    let owners = edge_ids(dbs, txn, &target, EdgeKind::ChildOf, false, 2)?;
                    if owners.len() >= 2 {
                        return Err(invalid("landing reply target is in another conversation"));
                    }
                    return Ok(LandingReplyVerdict::Waits);
                }
                crate::vault::LiveEntityRow::Live { .. } => {
                    return Err(invalid("landing reply target is in another conversation"));
                }
                crate::vault::LiveEntityRow::DeletedShell | crate::vault::LiveEntityRow::Absent => {
                    return Ok(LandingReplyVerdict::Waits);
                }
            }
        }
        Err(local) => return Err(local),
    }
    // Replay can retain unverified MACHINE claims before genesis. Such a row
    // cannot authorize words under the landing writer's name; the reply
    // waits for genesis rather than refusing it.
    let fold = crate::authority::authority_fold_readonly_for_store_in_txn(
        store,
        store.privacy_posture,
        txn,
    )?;
    if fold.vault_id.is_none() {
        return Ok(LandingReplyVerdict::Waits);
    }
    let writer = super::landing_writer_id()?;
    let mut waits = false;
    let mut refused = false;
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
        // A header counts only when its origin verifies and the fold binds
        // its signing key to the landing writer: a provisional row's key
        // proves nothing about who the writer is. A pending history or a
        // not-yet-bound signer waits for a later replay; a proof that does
        // not verify is the row's fault. A storage fault is the engine's
        // and propagates.
        match crate::authority::verify_machine_claim_in_txn(
            store,
            txn,
            store.privacy_posture,
            &claim,
            &header,
            true,
            None,
        ) {
            Ok(()) => {
                if crate::authority::machine_claim_signer_bound_in_txn(
                    store, txn, &fold, &claim, &header, writer,
                )? {
                    return Ok(LandingReplyVerdict::Bound);
                }
                waits = true;
            }
            Err(Error::Claim(ClaimError::RemoteMachineHistoryPending)) => {
                waits = true;
            }
            Err(Error::Claim(_) | Error::Record(_) | Error::EntityNotFound) => {
                refused = true;
            }
            Err(local) => return Err(local),
        }
    }
    if waits {
        return Ok(LandingReplyVerdict::Waits);
    }
    if refused {
        return Err(invalid(
            "landing reply requires its signed merge.summary landing",
        ));
    }
    Ok(LandingReplyVerdict::Waits)
}
