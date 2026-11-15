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
use crate::attempt_queue::setting_keys::ATTEMPT_QUEUE_AGENT_MAY_FORCE_CANCEL;
use crate::campaign::compliance::setting_keys::CAMPAIGN_COMPLIANCE_AGENT_MAY_DECIDE;
use crate::campaign::compliance::{COMPLIANCE_INSTALL_VERB, COMPLIANCE_REJECT_VERB};
use crate::codebase::setting_keys::CODEBASE_REGISTRATION_AGENT_MAY_REGISTER;
use crate::consent::AuthenticatedOwner;
use crate::dispatch_byoa::setting_keys::DISPATCH_BYOA_RUNNER_SEATS_AGENT_MAY_MANAGE;
use crate::dispatch_byoa::{
    RUNNER_SEAT_QUOTAS_VERB, RUNNER_SEAT_TOP_UP_VERB, RUNNER_WORK_RESUME_VERB,
};
use crate::dreamer_runner::PROGRAM_HOLD_RELEASE_VERB;
use crate::error::Error;
use crate::memory::{MEMORY_CODE_FORBIDDEN, MemoryError, MemoryResult};
use crate::setting::{Setting, SettingScope};
use crate::task_verb::run_doors::CANCEL_FORCE_VERB;
use crate::verbs::REPO_ANCHOR_BIND_VERB;

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

/// The owner Setting key, and its item, that lets an agent take the owner act
/// `verb` as the owner's delegate; `None` for a verb whose door admits no
/// delegate. Each door and the facade's precheck read this one table.
fn delegate_key(verb: &str) -> Option<(&'static Setting<bool>, Option<&'static str>)> {
    match verb {
        CANCEL_FORCE_VERB | PROGRAM_HOLD_RELEASE_VERB => {
            Some((&ATTEMPT_QUEUE_AGENT_MAY_FORCE_CANCEL, None))
        }
        RUNNER_SEAT_QUOTAS_VERB => {
            Some((&DISPATCH_BYOA_RUNNER_SEATS_AGENT_MAY_MANAGE, Some("quotas")))
        }
        RUNNER_SEAT_TOP_UP_VERB => {
            Some((&DISPATCH_BYOA_RUNNER_SEATS_AGENT_MAY_MANAGE, Some("top_up")))
        }
        RUNNER_WORK_RESUME_VERB => {
            Some((&DISPATCH_BYOA_RUNNER_SEATS_AGENT_MAY_MANAGE, Some("resume")))
        }
        REPO_ANCHOR_BIND_VERB => Some((&CODEBASE_REGISTRATION_AGENT_MAY_REGISTER, None)),
        COMPLIANCE_INSTALL_VERB | COMPLIANCE_REJECT_VERB => {
            Some((&CAMPAIGN_COMPLIANCE_AGENT_MAY_DECIDE, None))
        }
        _ => None,
    }
}

/// Whether `verb` names an owner act whose door also admits the owner's
/// delegate.
pub(crate) fn is_owner_delegate_verb(verb: &str) -> bool {
    delegate_key(verb).is_some()
}

/// Whether `agent` may take the owner act `verb` as the owner's delegate
/// now, read in its own read transaction: the facade's precheck before the
/// door's hooks run, and `can({verb})`'s answer. The door admits again in the
/// act's own transaction.
///
/// # Errors
///
/// As [`owner_delegate_in_txn`].
pub fn owner_delegate_admits(vault: &Vault, agent: EntityId, verb: &str) -> MemoryResult<()> {
    let txn = vault.store.env.read_txn().map_err(Error::from)?;
    owner_delegate_in_txn(vault, &txn, agent, verb).map(drop)
}

/// Whether `agent` may take the owner act `verb` as the owner's delegate in
/// `txn`: the door's key (from the one table every door reads) reads true at
/// the agent, and one live Grant lists the verb. The key is read first;
/// either check failing refuses as the facade refuses an agent today, with a
/// suggestion naming the key. A verb whose door admits no delegate gets the
/// owner refusal alone.
///
/// # Errors
///
/// `FORBIDDEN` when `verb` admits no delegate, the key reads false at the
/// agent or no live Grant lists the verb; storage errors.
pub(crate) fn owner_delegate_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    agent: EntityId,
    verb: &str,
) -> MemoryResult<OwnerDelegate> {
    let Some((key, item)) = delegate_key(verb) else {
        return Err(owner_refusal(verb));
    };
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

/// Today's owner refusal for `verb`.
fn owner_refusal(verb: &str) -> MemoryError {
    MemoryError::new(
        MEMORY_CODE_FORBIDDEN,
        format!("{verb} is the vault owner's"),
        &["Present the owner's own verified, unattenuated credential."],
    )
}

/// Today's owner refusal for `verb`, with a suggestion naming the key that
/// lets an agent take it.
fn delegate_refusal(verb: &str, key: &Setting<bool>) -> MemoryError {
    let mut refusal = owner_refusal(verb);
    refusal.suggestions.push(format!(
        "The owner lets an agent do this with the setting `{}`.",
        key.spec.name
    ));
    refusal
}
