//! A capsule's route prompt (FIX 6255): the prompt its answering rung put
//! first, kept as a body the run owns beside the capsule's request and
//! start. It is admitted through the side-row wall under the capsule's key,
//! so each secret in it is its custody handle, and published from the
//! masked bytes in the writer that finalizes the capsule, its instances
//! minted before that writer opens. No raw prompt byte reaches a body. A
//! prompt the wall refuses outright is withheld: no copy of it is kept, raw
//! or masked, and the capsule keeps the wall's reasons.
//!
//! The capsule names the body by ref, with the digest of the prompt as it
//! was sent (FIX 6356): a replay checks the route configured now against
//! that digest before the stored prompt takes its place. One reader reads
//! it back ([`route_prompt_at`]). An erase of the capsule's actor releases
//! it with the capsule's other bodies (`erase`), and a restore that retired
//! its custody marks its ref erased (`restore`). Its lifetime is the run's:
//! it has no retention rule of its own.

use heed::RwTxn;

use super::super::super::replay_capsule::{
    CapsuleRequest, CapsuleRungBinding, ReplayRoutePin, StepReplayCapsule, StoredRungBinding,
    route_prompt_digest,
};
use super::super::records::body_drifted;
use super::admit::{Spill, Unwritten, spilling, with_spill};
use super::erase::actor_gone_in_txn;
use super::{CAPSULES, capsule_key, held_body, kept_in_txn};
use crate::batch::secret_scan::{SidePart, admit_side_parts};
use crate::dreamer_runner::shadow_values::{ShadowUnavailable, ShadowUnavailableReason as Reason};
use crate::error::GateError;
use crate::model_binding::ModelRole;
use crate::{EntityId, Error, Result, Vault};

/// Where the wall's custody records name what they lifted from a capsule's
/// route prompt, beside the capsule's key.
const PROMPT_PLACE: &str = "side:CODE_RUN_REPLAY_CAPSULE:route_prompt";

/// A route prompt as read, or why it cannot be read.
type Outcome<T> = std::result::Result<T, ShadowUnavailable>;

/// Records the rung that answered the capsule at `key`, the role whose
/// admission sent the call (`role`, FIX 6359), and the route it went out on
/// when it pinned one (PR-S1), once and in one write: its route prompt
/// admitted and published as a body the run owns (FIX 6255), and the
/// capsule naming it by ref with the digest of the prompt as sent. A capsule
/// already finalized keeps its rung and its pin. An erased capsule, or one
/// whose actor is gone by now, takes neither and publishes nothing. A pin
/// whose prompt digest is not the rung's own is not kept.
pub(crate) fn finalize_capsule(
    vault: &Vault,
    key: &(EntityId, u64, u64),
    binding: CapsuleRungBinding,
    role: ModelRole,
    route_pin: Option<ReplayRoutePin>,
) -> Result<()> {
    let CapsuleRungBinding {
        model,
        locality,
        prompt,
    } = binding;
    let prompt_digest = route_prompt_digest(prompt.as_deref());
    let route_pin = route_pin.filter(|pin| pin.route_prompt_digest == prompt_digest);
    let sent = prompt.as_deref().map(encode_prompt).transpose()?;
    let lens = [sent.as_ref().map_or(0, Vec::len)];
    let reserved = spilling(vault.code_result_inline_bytes(), &lens);
    with_spill(vault, reserved, |wtxn, spill| {
        let Some(mut capsule) = CAPSULES.get(&vault.store, wtxn, key)? else {
            return Ok(());
        };
        let Some(actor) = capsule.content.actor() else {
            return Ok(());
        };
        if capsule.binding.is_some() || actor_gone_in_txn(vault, wtxn, &actor) {
            return Ok(());
        }
        let prompt = match &sent {
            Some(sent) => Some(store_prompt_in_txn(vault, wtxn, spill, &capsule, sent)?),
            None => None,
        };
        capsule.binding = Some(StoredRungBinding {
            model: model.clone(),
            locality,
            prompt,
            prompt_digest,
            role,
        });
        capsule.route_pin.clone_from(&route_pin);
        CAPSULES.put(vault, wtxn, key, &capsule)?;
        Ok(())
    })
}

/// `sent`, the route prompt's canonical JSON as sent, as the wall admits it
/// under the capsule's key, published in `wtxn` as a body the capsule's run
/// owns: `Withheld`, with nothing the wall wrote kept and nothing published,
/// when the wall refuses it outright.
fn store_prompt_in_txn(
    vault: &Vault,
    wtxn: &mut RwTxn<'_>,
    spill: &Spill,
    capsule: &StepReplayCapsule,
    sent: &[u8],
) -> std::result::Result<CapsuleRequest, Unwritten> {
    let admitted = match admit_prompt_or_refusal_in_txn(vault, wtxn, capsule, sent)? {
        Ok(admitted) => admitted,
        Err(reasons) => {
            tracing::debug!("a capsule's route prompt is withheld; its rung is kept");
            return Ok(CapsuleRequest::Withheld { reasons });
        }
    };
    spill.holds(&[admitted.len()])?;
    let path = route_prompt_path(capsule);
    let body = spill.publish_in_txn(vault, wtxn, capsule.run, &path, &admitted)?;
    Ok(CapsuleRequest::Kept {
        body,
        path,
        stored_hash: *blake3::hash(&admitted).as_bytes(),
        erased: false,
    })
}

/// The route prompt as the wall admits it, in a savepoint of `wtxn` kept
/// only once it admits: its canonical JSON, each secret in it its handle.
/// The reasons the wall refused it outright, with nothing it wrote kept, in
/// its place.
fn admit_prompt_or_refusal_in_txn(
    vault: &Vault,
    wtxn: &mut RwTxn<'_>,
    capsule: &StepReplayCapsule,
    sent: &[u8],
) -> Result<std::result::Result<Vec<u8>, Vec<String>>> {
    let key = CAPSULES.key_bytes(&capsule_key(capsule));
    let mut savepoint = vault.store.env.nested_write_txn(wtxn)?;
    let mut parts = [SidePart::Body(sent.to_vec())];
    let at = (PROMPT_PLACE, key.as_slice());
    let admitted = match admit_side_parts(vault, &mut savepoint, at, &mut parts, reads_prompt) {
        Ok(true) => admitted_prompt(&parts)?,
        Ok(false) => sent.to_vec(),
        Err(Error::Gate(GateError::GateWriteRejected { reason_codes, .. })) => {
            let reasons = reason_codes
                .iter()
                .map(|reason| (*reason).to_owned())
                .collect();
            return Ok(Err(reasons));
        }
        Err(error) => return Err(error),
    };
    savepoint.commit()?;
    Ok(Ok(admitted))
}

/// Where the run keeps a capsule's route prompt, beside its request and
/// start.
fn route_prompt_path(capsule: &StepReplayCapsule) -> String {
    format!(
        "replay/capsule/{}/{:06}.route_prompt.json",
        capsule.lease_generation, capsule.step
    )
}

/// A route prompt's canonical JSON: the prompt as one JSON string.
fn encode_prompt(prompt: &str) -> Result<Vec<u8>> {
    serde_json::to_vec(prompt)
        .map_err(|error| Error::InvalidConfig(format!("capsule route prompt: {error}")))
}

/// Whether an admitted copy still reads as a route prompt.
fn reads_prompt(parts: &[SidePart]) -> bool {
    matches!(parts, [SidePart::Body(body)] if serde_json::from_slice::<String>(body).is_ok())
}

/// A route prompt as the wall admitted it, encoded again from its text.
fn admitted_prompt(parts: &[SidePart]) -> Result<Vec<u8>> {
    let [SidePart::Body(admitted)] = parts else {
        return Err(Error::InvariantViolation(
            "an admitted route prompt is no longer a body",
        ));
    };
    let prompt: String = serde_json::from_slice(admitted)
        .map_err(|error| Error::InvalidConfig(format!("capsule route prompt: {error}")))?;
    encode_prompt(&prompt)
}

/// The route prompt the capsule's answering rung put first, as stored (FIX
/// 6255), read as [`route_prompt_at`] reads it. A capsule not finalized has
/// no rung to read it from (`RoutePinMissing`).
///
/// # Errors
///
/// Storage and custody errors.
pub(crate) fn capsule_route_prompt(
    vault: &Vault,
    capsule: &StepReplayCapsule,
) -> Result<Outcome<Option<String>>> {
    let Some(binding) = &capsule.binding else {
        return Ok(Err(ShadowUnavailable::new(
            Reason::RoutePinMissing,
            "capture",
        )));
    };
    route_prompt_at(vault, &capsule_key(capsule), capsule.run, binding)
}

/// The route prompt `binding` names for the capsule at `key` of run `run`
/// (FIX 6255), each secret in it its custody handle, never revealed:
/// `Ok(None)` when the rung put no prompt, and only then. It is read in a
/// snapshot of its own while the capsule still holds its content and is
/// still finalized with exactly `binding`, under the custody read guard and
/// with the body pinned past the collector; the run's own occurrence and its
/// marks are checked, and the bytes are read whole, checked against their
/// stored hash and read as a JSON string. A prompt withheld at capture, or
/// one released, marked, gone, drifted or not its hash, is `SourceWithheld`;
/// one a restore marked erased is `SourceErased`. A cause never quotes the
/// prompt.
///
/// # Errors
///
/// Storage and custody errors.
pub(crate) fn route_prompt_at(
    vault: &Vault,
    key: &(EntityId, u64, u64),
    run: EntityId,
    binding: &StoredRungBinding,
) -> Result<Outcome<Option<String>>> {
    let still = |rtxn: &heed::RoTxn<'_>| -> Result<bool> {
        let row = kept_in_txn(vault, rtxn, key)?;
        Ok(row.is_some_and(|row| row.run == run && row.binding.as_ref() == Some(binding)))
    };
    let (body, path, stored_hash) = match &binding.prompt {
        None => {
            let rtxn = vault.store.env.read_txn()?;
            return Ok(if still(&rtxn)? {
                Ok(None)
            } else {
                Err(withheld("capsule_moved"))
            });
        }
        Some(CapsuleRequest::Withheld { .. }) => {
            return Ok(Err(withheld("route_prompt_withheld")));
        }
        Some(CapsuleRequest::Kept { erased: true, .. }) => {
            return Ok(Err(ShadowUnavailable::new(
                Reason::SourceErased,
                "route_prompt_erased",
            )));
        }
        Some(CapsuleRequest::Kept {
            body,
            path,
            stored_hash,
            erased: false,
        }) => (*body, path, stored_hash),
    };
    let held = match held_body(vault, run, path, body, still) {
        // Bytes that drifted from their row are no prompt, as bytes no
        // longer its hash are; a read that fails stays an error.
        Err(error) if body_drifted(&error) => return Ok(Err(withheld("route_prompt_drifted"))),
        held => held?,
    };
    let Some(bytes) = held else {
        return Ok(Err(withheld("route_prompt_unreadable")));
    };
    if blake3::hash(&bytes).as_bytes() != stored_hash {
        return Ok(Err(withheld("route_prompt_digest")));
    }
    Ok(serde_json::from_slice::<String>(&bytes)
        .map(Some)
        .map_err(|_| withheld("route_prompt_undecodable")))
}

/// A route prompt that cannot be read now, for `cause`.
fn withheld(cause: &str) -> ShadowUnavailable {
    ShadowUnavailable::new(Reason::SourceWithheld, cause)
}
