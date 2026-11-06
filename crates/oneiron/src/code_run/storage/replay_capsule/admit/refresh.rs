//! A staged executor capsule's actual post-route request, in its own writer.

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
    let reserved = spilling(vault.code_result_inline_bytes(), &[sent.len()]);
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
        let prior = match &capsule.request {
            CapsuleRequest::Kept {
                body, path, erased, ..
            } => {
                if *erased {
                    return Ok(None);
                }
                let output = crate::code_run::CodeRunRawOutput {
                    path: path.clone(),
                    ..crate::code_run::CodeRunRawOutput::of_ref(*body)
                };
                let occurrence = ResultOccurrence::of(Some(capsule.run), &output)?;
                let held = owned_body_in_txn(&vault.store, wtxn, &capsule.run, &occurrence.id())?;
                if !held.is_some_and(|owned| {
                    owned
                        .state
                        .held()
                        .is_some_and(|held| held.blake3 == body.hash)
                }) || vault
                    .code_run_result_withheld_in_txn(wtxn, Some(capsule.run), &output)?
                    .is_some()
                {
                    return Ok(None);
                }
                Some((occurrence, output.handle, body.hash))
            }
            CapsuleRequest::Withheld { .. } => None,
        };
        let key_bytes = CAPSULES.key_bytes(&update.key);
        match admit_request_or_refusal_in_txn(vault, wtxn, &key_bytes, &sent)? {
            Ok(admitted) => {
                spill.holds(&[admitted.bytes.len()])?;
                let stored_hash = *blake3::hash(&admitted.bytes).as_bytes();
                let path = format!("{}.{}", update.path, blake3::Hash::from(stored_hash));
                let body =
                    spill.publish_in_txn(vault, wtxn, capsule.run, &path, &admitted.bytes)?;
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
        Ok(Some(sent.len() as u64))
    })
}
