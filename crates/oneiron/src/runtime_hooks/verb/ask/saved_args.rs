//! The args a hook's ask saved for a call, read back by the call's own host
//! (FIX CHAT-WITNESS-ASK-RESUME-ARGS-DRIFT). A host that stamps a call's args
//! itself, with the time it ran or an id it minted, rebuilds its retry from
//! the stamps the first try saved, so the resumed chain checks the call the
//! ask held. The resumed chain hands these same args to the host's own check,
//! so the read shows the host nothing a resume does not; it is never a
//! caller's answer.

use serde_json::Value;

use super::ASKS;
use crate::runtime_hooks::store;
use crate::runtime_hooks::verb::{VerbCall, VerbHookStorage};
use crate::skill_hub::pack_catalog::HookActorClass;
use crate::{EntityId, Error, Result, Vault};

/// The args the ask saved under `call`'s invocation in `storage`: the
/// vault's saved calls, or the session keep of a call that keeps no record.
/// `None` when no call is saved there, when the saved call is another's
/// (another verb, actor or class), or when its args name a row erased since,
/// which never runs (FIX 22240).
///
/// # Errors
///
/// Reading the saved call, or its args no longer decoding.
pub(in crate::runtime_hooks::verb) fn saved_args(
    vault: &Vault,
    storage: VerbHookStorage<'_>,
    call: &VerbCall,
) -> Result<Option<Value>> {
    let own = |verb: &str, actor: &EntityId, class: &HookActorClass| {
        verb == call.verb && *actor == call.actor && *class == call.class
    };
    match storage {
        VerbHookStorage::Session(hooks) => {
            let keep = &vault.runtime().verb_hook_state().session;
            let Some(row) = keep
                .ask(hooks.pause_key(), call.invocation.0)
                .filter(|row| own(&row.verb, &row.actor, &row.class))
            else {
                return Ok(None);
            };
            if store::args_erased(vault, &row.args.to_string())? {
                return Ok(None);
            }
            Ok(Some(row.args))
        }
        VerbHookStorage::Canonical => {
            let row = {
                let rtxn = vault.store.env.read_txn()?;
                ASKS.get(&vault.store, &rtxn, &call.invocation.0)?
            };
            let Some(row) = row.filter(|row| own(&row.verb, &row.actor, &row.class)) else {
                return Ok(None);
            };
            if store::args_erased(vault, &row.args)? {
                return Ok(None);
            }
            serde_json::from_str(&row.args)
                .map(Some)
                .map_err(|_| Error::CorruptedIndex("verb hook ask args"))
        }
    }
}
