//! Who takes an owner act at a door that also admits the owner's delegate
//! (restriction wave 11).
//!
//! Some owner doors admit the owner's delegate: an agent the owner lets take
//! the act through one owner Setting key. The owner path does not change, and
//! members are never let in. Every delegate admission is checked in the act's
//! own transaction, and the act's record names the agent, never the owner.

use crate::EdgeActorClass;
use crate::EntityId;
use crate::Vault;
use crate::consent::AuthenticatedOwner;
use crate::memory::{MEMORY_CODE_FORBIDDEN, MemoryError, MemoryResult};
use crate::setting::{Setting, SettingScope};

use super::principal_standing_in_txn;

/// Who takes an owner act at a door that also admits the owner's delegate.
#[derive(Debug, Clone, Copy)]
pub enum OwnerOrDelegate<'a> {
    /// The vault owner, by a proof the door revalidates in its own transaction.
    Owner(&'a AuthenticatedOwner),
    /// An agent whose binding the caller verified. The door checks it again in
    /// its own transaction.
    Delegate(EntityId),
}

/// An agent admitted as the owner's delegate in one transaction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct OwnerDelegate {
    /// The delegate agent.
    pub(crate) agent: EntityId,
    /// The one live Grant that lists the door's verb.
    pub(crate) grant: EntityId,
}

/// Whether `agent` may take the owner act `verb` as the owner's delegate in
/// `txn`: the door's key reads true at the agent, and one live Grant lists
/// the verb. The key is read first; either check failing refuses as the
/// facade refuses an agent today, with a suggestion naming the key.
///
/// # Errors
///
/// `FORBIDDEN` when the key reads false at the agent or no live Grant lists
/// the verb; storage errors.
pub(crate) fn owner_delegate_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    agent: EntityId,
    verb: &str,
    key: &Setting<bool>,
    item: Option<&str>,
) -> MemoryResult<OwnerDelegate> {
    let allowed = key
        .read_in_txn(vault, txn, &[SettingScope::Agent(agent)], item)
        .map_err(MemoryError::from)?
        .value;
    if !allowed {
        return Err(delegate_refusal(verb, key));
    }
    let grant = principal_standing_in_txn(vault, txn, agent, EdgeActorClass::Agent, verb)
        .map_err(MemoryError::from)?
        .and_then(|standing| standing.grant);
    match grant {
        Some(grant) => Ok(OwnerDelegate { agent, grant }),
        None => Err(delegate_refusal(verb, key)),
    }
}

/// Today's owner refusal for `verb`, with a suggestion naming the key that
/// lets an agent take it.
fn delegate_refusal(verb: &str, key: &Setting<bool>) -> MemoryError {
    let mut refusal = MemoryError::new(
        MEMORY_CODE_FORBIDDEN,
        format!("{verb} is the vault owner's"),
        &["Present the owner's own verified, unattenuated credential."],
    );
    refusal.suggestions.push(format!(
        "The owner lets an agent do this with the setting `{}`.",
        key.spec.name
    ));
    refusal
}
