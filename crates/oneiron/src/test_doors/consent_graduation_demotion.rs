//! Doors for `tests/graduated_scope_demotion_authors.rs` (census L7-33): the
//! owner-authored grant rows that let a role carry the `policy.change` verb
//! class (the shipped rows give it to no role, so no Admin is a policy holder
//! until its owner says so), and an agent's run spawning an attenuated child
//! through the dispatcher, which pins the child to that run (FIX 9559).

use crate::agent_def::{AgentCeiling, AgentDefinition, AgentScope};
use crate::agent_dispatch::{
    AgentDispatchOutcome, AgentDispatchTarget, AgentDispatcher, DispatchAgent,
};
use crate::attempt_queue::{AttemptQueue, ClaimAttempt, ClaimOutcome};
use crate::claim::{ClaimApprovalStatus, ClaimLifecycleStatus, ClaimSource};
use crate::consent::AuthenticatedOwner;
use crate::error::{Error, Result};
use crate::federation::FederationGrantRole;
use crate::federation::ScopeAxis;
use crate::federation::grant_policy::{GrantPolicyRow, ROWS_KEY, encode_row, parse_rows};
use crate::vault::Vault;
use crate::{EntityId, TimeRange};

/// Installs, through the owner's manifest door, grant rows that give each of
/// `roles` the `policy.change` verb in the member grants minted from now on
/// (the lib test `owner_rows::tests::admit_policy_verb`, on this door).
///
/// # Errors
///
/// A missing or unreadable stored manifest (`InvalidConfig`), and the owner
/// install door's refusals.
pub fn admit_policy_verb(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    roles: &[FederationGrantRole],
) -> Result<()> {
    let unreadable = || Error::InvalidConfig("the stored policy manifest does not read".to_owned());
    let id = crate::gate::default_policy_manifest_id()?;
    let raw = vault.get_raw(&id)?.ok_or_else(unreadable)?;
    let body = raw
        .get(crate::batch::ENTITY_METADATA_HEADER_LEN..)
        .ok_or_else(unreadable)?;
    let rmpv::Value::Map(mut entries) =
        rmpv::decode::read_value(&mut &body[..]).map_err(|_| unreadable())?
    else {
        return Err(unreadable());
    };
    let (_, value) = entries
        .iter_mut()
        .find(|(key, _)| key.as_str() == Some(ROWS_KEY))
        .ok_or_else(unreadable)?;
    let mut rows = parse_rows(value).ok_or_else(unreadable)?;
    for row in &mut rows {
        if let GrantPolicyRow::RoleDefault { role, scope } = row
            && roles.contains(role)
            && let ScopeAxis::Some(verbs) = &mut scope.verbs
        {
            verbs.insert("policy.change".to_owned());
        }
    }
    *value = rmpv::Value::Array(rows.iter().map(encode_row).collect::<Result<_>>()?);
    let mut bytes = Vec::new();
    rmpv::encode::write_value(&mut bytes, &rmpv::Value::Map(entries)).map_err(|_| unreadable())?;
    vault.install_owner_policy_manifest(owner, id, bytes, 1)
}

/// Writes a minimal human-authored agent definition named `name` with
/// `ceiling`, as the owner's own agent; its id.
fn define_agent_with(vault: &Vault, name: &str, ceiling: AgentCeiling) -> Result<EntityId> {
    let definition = AgentDefinition::new(
        name,
        "Ramp demotion fixture agent",
        "1",
        None,
        Vec::new(),
        Vec::new(),
        Vec::new(),
        None,
        AgentScope::All,
        ceiling,
        None,
        ClaimApprovalStatus::Approved,
        ClaimLifecycleStatus::Active,
        ClaimSource::UserStated,
        1.0,
        false,
        true,
        rmpv::Value::Map(vec![(
            rmpv::Value::from("definedVia"),
            rmpv::Value::from("ramp_demotion"),
        )]),
        None,
        true,
        None,
    );
    let id = EntityId::now();
    vault.put_agent_definition(&id, &definition, TimeRange { start: 1, end: 1 }, 1)?;
    Ok(id)
}

/// Writes the agent `name` with a `Proposed` ceiling, as the owner's own
/// agent; its id.
///
/// # Errors
///
/// The vault's.
pub fn define_agent(vault: &Vault, name: &str) -> Result<EntityId> {
    define_agent_with(vault, name, AgentCeiling::Proposed)
}

/// Spawns a child of the agent `parent` the way a run does: dispatches and
/// leases `parent`'s run, then dispatches from that run a child whose source
/// definition is `Auto`, wider than `parent`'s ceiling, so the dispatcher
/// mints the attenuated fork and pins the run to its id (FIX 9559). The
/// fork's agent id.
///
/// # Errors
///
/// The dispatcher's, and a run or child that is not dispatched, leased or
/// forked.
pub fn spawn_attenuated_child(vault: &Vault, parent: EntityId) -> Result<EntityId> {
    let source = define_agent_with(vault, "ramp child source", AgentCeiling::Auto)?;
    let now = vault.now_recorded_at();
    let AgentDispatchOutcome::Dispatched(run) =
        AgentDispatcher::new(vault).dispatch(DispatchAgent {
            target: AgentDispatchTarget::Custom(parent),
            parent_attempt: None,
            dedupe_key: None,
            run_id: None,
            now,
        })?
    else {
        return Err(Error::InvalidConfig(
            "the parent's run was not dispatched".into(),
        ));
    };
    let ClaimOutcome::Claimed(leased) = AttemptQueue::new(vault).claim(ClaimAttempt {
        lease_owner: "test-door".into(),
        now,
    })?
    else {
        return Err(Error::InvalidConfig(
            "the parent's run was not leased".into(),
        ));
    };
    if leased.id != run.attempt.id {
        return Err(Error::InvalidConfig(
            "another attempt was leased first".into(),
        ));
    }
    let AgentDispatchOutcome::Dispatched(child) =
        AgentDispatcher::new(vault).dispatch(DispatchAgent {
            target: AgentDispatchTarget::Custom(source),
            parent_attempt: Some(leased.id),
            dedupe_key: None,
            run_id: None,
            now,
        })?
    else {
        return Err(Error::InvalidConfig("the child was not dispatched".into()));
    };
    let fork = child.input.target.agent_definition_ref()?;
    if fork == source {
        return Err(Error::InvalidConfig(
            "the child was not forked for attenuation".into(),
        ));
    }
    Ok(fork)
}
