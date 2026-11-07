//! A staged executor capsule's actual post-route request, in its own writer.
//! FIX 4192: the new request is published as pieces beside the old one's,
//! and each piece the old request named and no request of the run and actor
//! names now is released after the capsule row names the new request.

use std::collections::BTreeSet;

use super::super::pieces::{manifest_pieces_in_txn, release_superseded_in_txn};
use super::*;
use crate::code_run::replay::ResultOccurrence;
use crate::code_run::replay_capsule::{CapsuleHost, CapsuleRequestUpdate};
use crate::provenance::body::{owned_body_in_txn, release_body_in_txn};

pub(crate) fn refresh_staged_request(
    vault: &Vault,
    update: &CapsuleRequestUpdate<'_>,
) -> Result<Option<u64>> {
    let sent = update
        .request
        .canonical_bytes()
        .map_err(|error| Error::InvalidConfig(format!("capsule request: {error}")))?;
    let Some(actor) = staged_actor(vault, update)? else {
        return Ok(None);
    };
    let scope = PieceScope {
        run: update.run,
        actor,
    };
    let reserved = spilling(
        vault.code_result_inline_bytes(),
        &unheld_lens(vault, &sent, scope)?,
    );
    with_spill(vault, reserved, |wtxn, spill| {
        let Some(mut capsule) = CAPSULES.get(&vault.store, wtxn, &update.key)? else {
            return Ok(None);
        };
        let Some(actor) = capsule.content.actor() else {
            return Ok(None);
        };
        if capsule.run != update.run
            || capsule.host != CapsuleHost::EngineStep
            || capsule.messages_digest != update.previous_messages
            || capsule.binding.is_some()
            || actor_gone_in_txn(vault, wtxn, &actor)
        {
            return Ok(None);
        }
        let scope = PieceScope {
            run: capsule.run,
            actor,
        };
        let mut superseded = BTreeSet::new();
        let prior = match &capsule.request {
            CapsuleRequest::Kept {
                body, path, erased, ..
            } => {
                if *erased {
                    return Ok(None);
                }
                let Some(prior) = held_prior_in_txn(vault, wtxn, capsule.run, *body, path)? else {
                    return Ok(None);
                };
                manifest_pieces_in_txn(&vault.store, wtxn, *body, &mut superseded)?;
                Some(prior)
            }
            CapsuleRequest::Withheld { .. } => None,
        };
        let key_bytes = CAPSULES.key_bytes(&update.key);
        match admit_request_or_refusal_in_txn(vault, wtxn, &key_bytes, &sent)? {
            Ok(admitted) => {
                let pieces = RequestPieces::of(&admitted.bytes)?;
                spill.holds(&pieces.lens_in_txn(&vault.store, wtxn, scope)?)?;
                let stored_hash = *blake3::hash(&admitted.bytes).as_bytes();
                let path = format!("{}.{}", update.path, blake3::Hash::from(stored_hash));
                let body = pieces.publish_in_txn(vault, wtxn, spill, scope, &path)?;
                capsule.request = CapsuleRequest::Kept {
                    body,
                    path,
                    stored_hash,
                    erased: false,
                };
                capsule.exposures = stored_slots(update.exposures, update.request, &admitted);
            }
            Err(Error::Gate(GateError::GateWriteRejected { reason_codes, .. }))
                if capsule.start.is_some() =>
            {
                capsule.request = CapsuleRequest::Withheld {
                    reasons: reason_codes
                        .iter()
                        .map(|reason| (*reason).to_owned())
                        .collect(),
                };
                capsule.exposures = update
                    .exposures
                    .iter()
                    .map(|slot| ExposureSlot {
                        stored: None,
                        ..slot.clone()
                    })
                    .collect();
            }
            Err(error) => return Err(error.into()),
        }
        capsule.request_hash = *blake3::hash(&sent).as_bytes();
        capsule.messages_digest = update.messages;
        // The appended host evidence has no complete row witness yet.
        capsule.source_rows = None;
        capsule.seed = update
            .request
            .params
            .get("seed")
            .and_then(serde_json::Value::as_u64);
        CAPSULES.put(vault, wtxn, &update.key, &capsule)?;
        if let Some((occurrence, handle, digest)) = prior {
            let marks = occurrence.mark_key(&handle);
            crate::code_run::drop_code_run_result_marks_in_txn(&vault.store, wtxn, &marks)?;
            release_body_in_txn(&vault.store, wtxn, &capsule.run, &occurrence.id())?;
            super::super::start_parts::drop_unheld_body_in_txn(&vault.store, wtxn, &digest)?;
        }
        release_superseded_in_txn(&vault.store, wtxn, scope, &superseded)?;
        Ok(Some(sent.len() as u64))
    })
}

/// The actor of the staged capsule `update` names, read before its writer
/// opens, which names the pieces the refresh mints for (FIX 4192). `None`
/// when the capsule is gone or its actor was erased.
fn staged_actor(vault: &Vault, update: &CapsuleRequestUpdate<'_>) -> Result<Option<EntityId>> {
    let rtxn = vault.store.env.read_txn()?;
    Ok(CAPSULES
        .get(&vault.store, &rtxn, &update.key)?
        .and_then(|capsule| capsule.content.actor()))
}

/// The capsule's own request body as run `run` holds it at `path`, in
/// `txn`: its occurrence, handle and digest, which the refresh releases.
/// `None` when the run no longer holds it whole with `body`'s bytes, or the
/// occurrence is withheld.
fn held_prior_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    run: EntityId,
    body: OutputRef,
    path: &str,
) -> Result<Option<(ResultOccurrence, String, [u8; 32])>> {
    let output = crate::code_run::CodeRunRawOutput {
        path: path.to_owned(),
        ..crate::code_run::CodeRunRawOutput::of_ref(body)
    };
    let occurrence = ResultOccurrence::of(Some(run), &output)?;
    let held = owned_body_in_txn(&vault.store, txn, &run, &occurrence.id())?;
    if !held.is_some_and(|owned| {
        owned
            .state
            .held()
            .is_some_and(|held| held.blake3 == body.hash)
    }) || vault
        .code_run_result_withheld_in_txn(txn, Some(run), &output)?
        .is_some()
    {
        return Ok(None);
    }
    Ok(Some((occurrence, output.handle, body.hash)))
}
