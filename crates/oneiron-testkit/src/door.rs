//! The in-process verb door: a public verb, by name, with JSON in and JSON
//! out, through the same generated verb table every transport uses
//! (`oneiron::verbs::VERB_TABLE`). A door test and a fixture seed call verbs
//! here; the answer is what an SDK caller would get back.

use oneiron::memory::{Memory, MemoryResult};
use oneiron::verb_table::VerbTable;
use oneiron::verbs::VERB_TABLE;
use oneiron::{EdgeActorClass, Vault};
use serde_json::Value;

/// The vault's embedded owner, as a caller: the owner PERSON is created on
/// first use, the way an embedded host's first call creates it.
///
/// # Errors
/// The vault refuses to create or read its owner.
pub fn owner(vault: &Vault) -> MemoryResult<Memory<'_>> {
    let owner = vault.ensure_embedded_owner_actor()?;
    Ok(vault.memory(owner, EdgeActorClass::Human))
}

/// Runs the public verb `verb` with `input` as `caller`: its admission,
/// grant checks, hooks and receipts all run, as on every transport.
///
/// # Errors
/// The verb's refusal or failure, in the shape every transport returns it.
pub fn invoke(caller: &Memory<'_>, verb: &str, input: Value) -> MemoryResult<Value> {
    VERB_TABLE.invoke_with_notice(caller, verb, input).0
}
