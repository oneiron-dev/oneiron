//! The client's side of `vault.secrets.custody.submit` (FIX 4993): the
//! input sealed to the holder under the binding `vault.secrets.custody.get`
//! answered, by the door's own seal, so no plaintext goes to the server
//! just to be sealed.

use base64::Engine as _;

use super::{
    SecretCustodyCandidateReply, SecretCustodyPermit, SecretCustodySubmitRequest,
    SecretCustodyViewReply, digest, entity_id,
};
use crate::EntityId;
use crate::authority::{CustodyChange, CustodyRecipientPermit};
use crate::memory::{MemoryError, MemoryResult};
use crate::secret_custody::{CustodyInputBinding, seal_custody_input};

/// Seals `body` on the caller's own side and answers the
/// `vault.secrets.custody.submit` input that carries it, so no plaintext
/// goes to the server just to be sealed. `view` is what
/// `vault.secrets.custody.get` answered. `holder` is the candidate the
/// input is sealed to, the view's own install when `None`. `recipients`
/// are the candidates permitted to hold the bytes, the holder alone when
/// empty. Each permit is the view's exact one, and they bind ascending by
/// machine. A register approves the view's generation and a rotate the one
/// above it. A register's `body` is its whole record,
/// [`crate::secret_custody::encode_secret_custody_body`], value in it; a
/// rotate's is the new value. The seal is the door's own
/// ([`crate::secret_custody::seal_custody_input`]).
///
/// # Errors
/// A change other than a register or rotate; a rotate that names a
/// manifest, which the submit door refuses too; a holder or recipient the
/// view lists no candidate for; a malformed view field; a key that does not
/// import; a seal that fails.
pub fn seal_custody_submit(
    view: &SecretCustodyViewReply,
    change: CustodyChange,
    holder: Option<&str>,
    recipients: &[String],
    manifest_ref: Option<String>,
    body: &[u8],
) -> MemoryResult<SecretCustodySubmitRequest> {
    let generation = match change {
        CustodyChange::Register => Some(view.generation),
        CustodyChange::Rotate => view.generation.checked_add(1),
        CustodyChange::Rewrap | CustodyChange::Revoke => {
            return Err(MemoryError::bad_request(
                "a sealed input carries a register or a rotate",
            ));
        }
    };
    let Some(generation) = generation else {
        return Err(MemoryError::bad_request("no generation follows the last"));
    };
    if change == CustodyChange::Rotate && manifest_ref.is_some() {
        return Err(MemoryError::bad_request("only a register names a manifest"));
    }
    let holder = match holder {
        Some(holder) => entity_id("holder", holder)?,
        None => this_install(view)?,
    };
    let held_by = offered(view, holder)?;
    let named = if recipients.is_empty() {
        vec![holder]
    } else {
        recipients
            .iter()
            .map(|machine| entity_id("recipients", machine))
            .collect::<MemoryResult<Vec<_>>>()?
    };
    let mut permits = named
        .into_iter()
        .map(|machine| {
            let candidate = offered(view, machine)?;
            let wire = SecretCustodyPermit {
                machine: machine.to_hex(),
                profile: candidate.profile.clone(),
                encryption_key_digest: candidate.encryption_key_digest.clone(),
            };
            Ok((wire.permit()?, wire))
        })
        .collect::<MemoryResult<Vec<_>>>()?;
    permits.sort_unstable_by_key(|(permit, _)| permit.machine);
    permits.dedup_by_key(|(permit, _)| permit.machine);
    let bound: Vec<CustodyRecipientPermit> = permits.iter().map(|(permit, _)| *permit).collect();
    let key = base64::engine::general_purpose::STANDARD
        .decode(held_by.encryption_key_base64.as_bytes())
        .map_err(|_| MemoryError::bad_request("the holder's key is not standard base64"))?;
    let sealed = seal_custody_input(
        &CustodyInputBinding {
            vault_id: digest("vault_id", &view.vault_id)?,
            secret_id: entity_id("secret_id", &view.secret_id)?,
            change,
            generation,
            seen: digest("seen", &view.seen)?,
            holder,
            permits: &bound,
        },
        &key,
        body,
    )?;
    Ok(SecretCustodySubmitRequest {
        change: change.as_str().to_owned(),
        secret_id: view.secret_id.clone(),
        generation,
        seen: view.seen.clone(),
        holder: holder.to_hex(),
        recipients: permits.into_iter().map(|(_, wire)| wire).collect(),
        manifest_ref,
        input_base64: base64::engine::general_purpose::STANDARD.encode(sealed),
    })
}

/// The candidate `view` offers for `machine`.
fn offered(
    view: &SecretCustodyViewReply,
    machine: EntityId,
) -> MemoryResult<&SecretCustodyCandidateReply> {
    let hex = machine.to_hex();
    view.candidates
        .iter()
        .find(|candidate| candidate.machine == hex)
        .ok_or_else(|| MemoryError::bad_request(format!("{hex} is no install the view offers")))
}

/// The view's own install, which holds a change that names no holder.
fn this_install(view: &SecretCustodyViewReply) -> MemoryResult<EntityId> {
    let here = view
        .candidates
        .iter()
        .find(|candidate| candidate.this_install)
        .ok_or_else(|| MemoryError::bad_request("the custody view offers no install of its own"))?;
    entity_id("machine", &here.machine)
}
