//! The Dreamer's Steward grant and the strength archive, for integration
//! tests (untangle 6.3; X02's test pointed at a narrowed Steward grant).

use std::collections::BTreeSet;

use crate::attempt_queue::AttemptId;
use crate::dreamer_consolidation::strength::ConsolidationStrengthPolicy;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::federation::{SystemAgentGrantState, grant_scope};
use crate::vault::Vault;

/// The Steward's full default verbs.
pub const STEWARD_VERBS: [&str; 4] = grant_scope::STEWARD_VERBS;
/// The Steward's `read` verb.
pub const STEWARD_READ_VERB: &str = grant_scope::STEWARD_READ_VERB;
/// The Steward's `archive` verb.
pub const STEWARD_ARCHIVE_VERB: &str = grant_scope::STEWARD_ARCHIVE_VERB;

/// What the Dreamer may do now, as the policy fold reads its rows.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WeaveReach {
    /// It reads the words it weaves.
    pub reads: bool,
    /// It lands what it derives Auto.
    pub lands_auto: bool,
}

/// One strength-archive receipt written for a claim.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StrengthArchiveReceipt {
    /// The grant the archive was judged by.
    pub grant_ref: Option<String>,
    /// The read frontier the archive saw.
    pub read_frontier_hash: [u8; 32],
}

/// The Dreamer's actor id.
///
/// # Errors
///
/// The vault's.
pub fn dreamer(vault: &Vault) -> Result<EntityId> {
    Ok(vault.dreamer_authority()?.entity_ref())
}

/// The embedded owner's proof.
///
/// # Errors
///
/// The vault's.
pub fn owner(vault: &Vault) -> Result<crate::consent::AuthenticatedOwner> {
    let owner = vault
        .ensure_embedded_owner_actor()
        .map_err(|error| Error::InvalidConfig(format!("embedded owner: {error:?}")))?;
    vault.authenticate_owner(
        owner,
        &owner.to_hex(),
        true,
        crate::store::GateDecisionId::now(),
    )
}

/// Stands `agent`'s Steward grant with `verbs` and marks it, as a first mint
/// leaves it; a later call stands a fresh grant that replaces it.
///
/// # Errors
///
/// The vault's.
pub fn stand_steward_grant(vault: &Vault, agent: EntityId, verbs: &[&str]) -> Result<EntityId> {
    vault.stand_steward_grant_for_test(agent, verbs)
}

/// Marks `agent` opted out of its Steward grant.
///
/// # Errors
///
/// The vault's.
pub fn mark_steward_opt_out(vault: &Vault, agent: EntityId) -> Result<()> {
    vault.mark_steward_opt_out_for_test(agent)
}

/// The Dreamer's reach under the live policy and its grant.
///
/// # Errors
///
/// The vault's.
pub fn weave_reach(vault: &Vault) -> Result<WeaveReach> {
    let reach = vault.dreamer_weave_reach()?;
    Ok(WeaveReach {
        reads: reach.reads,
        lands_auto: reach.lands_auto,
    })
}

/// Sets a strength policy under which every landed claim is quiet and weak.
///
/// # Errors
///
/// The vault's.
pub fn archive_every_quiet_claim(vault: &Vault) -> Result<()> {
    vault.set_consolidation_strength_policy(&ConsolidationStrengthPolicy {
        archive_below: 1.0,
        quiet_ms: 1,
    })
}

/// A clock reading thirty days after the vault's recorded now, in ms.
#[must_use]
pub fn a_month_on_ms(vault: &Vault) -> u64 {
    (vault.now_recorded_at() + 30 * 86_400).saturating_mul(1_000)
}

/// Runs the strength archive for the Dreamer's `attempt` at `now_ms`; the
/// number of claims it archived.
///
/// # Errors
///
/// The vault's.
pub fn archive_quiet_claims(vault: &Vault, attempt: AttemptId, now_ms: u64) -> Result<u64> {
    crate::dreamer_consolidation::strength::archive_quiet_claims(vault, attempt, now_ms)
}

/// The strength-archive receipts written for `claim`.
///
/// # Errors
///
/// The vault's.
pub fn strength_archive_receipts(
    vault: &Vault,
    claim: &EntityId,
) -> Result<Vec<StrengthArchiveReceipt>> {
    let txn = vault.store.env.read_txn()?;
    Ok(vault
        .store
        .gate_decisions_for_claim_in_txn(&txn, claim.as_bytes())?
        .into_iter()
        .filter(|record| record.content_kind == "dreamer_strength_archive")
        .map(|record| StrengthArchiveReceipt {
            grant_ref: record.grant_ref,
            read_frontier_hash: record.read_frontier_hash,
        })
        .collect())
}

/// Where a base agent's Steward grant stands, as the host's first mint or
/// the owner's narrowing left it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GrantMark {
    /// A grant stands; the verbs it gives while it stands.
    Minted {
        /// The grant row.
        grant: EntityId,
        /// The verbs the standing grant gives.
        verbs: BTreeSet<String>,
    },
    /// The owner opted out.
    OptedOut,
}

/// A vault whose install can carry the embedded owner's signed acts, as a
/// serving host's: rooted under the test host, the engine's MACHINE writers
/// provisioned, the embedded owner seeded, an in-memory device keystore
/// installed, and this install's machine profile enrolled, so the owner's
/// agent-grant act has a carrier.
///
/// # Errors
///
/// The vault's or the authority log's.
pub fn open_owner_carrier_vault(path: &std::path::Path) -> Result<Vault> {
    let vault = Vault::open(path, crate::VaultConfig::device())?;
    let issuer = crate::test_support::provision_engine_machines(&vault);
    vault
        .ensure_embedded_owner_actor()
        .map_err(|error| Error::InvalidConfig(format!("embedded owner: {error:?}")))?;
    // The install's machine keys come from its device keystore, as a host's.
    vault.install_device_keystore(std::sync::Arc::new(
        oneiron_keystore::MemoryKeystore::default(),
    ));
    vault.ensure_serving_install_profile(&issuer, crate::authority::MachineRole::Unanswered)?;
    Ok(vault)
}

/// The shipped policy with every row naming the Dreamer taken out, as an
/// owner who removed them before the first mint leaves it.
///
/// # Errors
///
/// The vault's.
pub fn drop_dreamer_rows(vault: &Vault) -> Result<()> {
    let dreamer = dreamer(vault)?.to_hex();
    let names_dreamer = |row: &rmpv::Value| {
        row.as_map().is_some_and(|fields| {
            fields.iter().any(|(key, value)| {
                key.as_str() == Some("actor_ref") && value.as_str() == Some(dreamer.as_str())
            })
        })
    };
    let rmpv::Value::Map(mut entries) =
        rmpv::decode::read_value(&mut crate::gate::default_policy_manifest()?.as_slice())
            .map_err(|_| Error::InvalidConfig("default policy".into()))?
    else {
        return Err(Error::InvalidConfig("default policy is not a map".into()));
    };
    for (_, value) in &mut entries {
        if let rmpv::Value::Array(rows) = value {
            rows.retain(|row| !names_dreamer(row));
        }
    }
    entries.retain(|(_, value)| !names_dreamer(value));
    let mut bytes = Vec::new();
    rmpv::encode::write_value(&mut bytes, &rmpv::Value::Map(entries))
        .map_err(|_| Error::InvalidConfig("encode policy".into()))?;
    crate::test_support::put_policy_manifest_bytes(
        vault,
        crate::gate::default_policy_manifest_id()?,
        &bytes,
    )
}

/// Rewrites the shipped policy with `edit` and puts it back as the vault's
/// trusted default pack.
fn rewrite_shipped_policy(
    vault: &Vault,
    edit: impl FnOnce(&mut Vec<(rmpv::Value, rmpv::Value)>) -> Result<()>,
) -> Result<()> {
    let rmpv::Value::Map(mut entries) =
        rmpv::decode::read_value(&mut crate::gate::default_policy_manifest()?.as_slice())
            .map_err(|_| Error::InvalidConfig("default policy".into()))?
    else {
        return Err(Error::InvalidConfig("default policy is not a map".into()));
    };
    edit(&mut entries)?;
    let mut bytes = Vec::new();
    rmpv::encode::write_value(&mut bytes, &rmpv::Value::Map(entries))
        .map_err(|_| Error::InvalidConfig("encode policy".into()))?;
    crate::test_support::put_policy_manifest_bytes(
        vault,
        crate::gate::default_policy_manifest_id()?,
        &bytes,
    )
}

/// The value under `key` in a policy map.
fn policy_entry<'a>(
    entries: &'a mut [(rmpv::Value, rmpv::Value)],
    key: &str,
) -> Result<&'a mut rmpv::Value> {
    entries
        .iter_mut()
        .find(|(name, _)| name.as_str() == Some(key))
        .map(|(_, value)| value)
        .ok_or_else(|| Error::InvalidConfig(format!("the shipped policy has no {key}")))
}

/// The shipped policy with the trust of tool output written as the
/// shorthand row `false` (no Auto, bound to no writer), as the policy decode
/// accepts it. The Dreamer's rows stay as shipped.
///
/// # Errors
///
/// The vault's.
pub fn write_shorthand_tool_output_trust(vault: &Vault) -> Result<()> {
    rewrite_shipped_policy(vault, |entries| {
        let rmpv::Value::Map(sources) = policy_entry(entries, "source_trust")? else {
            return Err(Error::InvalidConfig("source trust is not a map".into()));
        };
        *policy_entry(sources, "tool_output")? = rmpv::Value::Boolean(false);
        Ok(())
    })
}

/// The shipped policy with every actor ceiling but the Dreamer's taken out,
/// so the Dreamer's Auto row is the only one in the list.
///
/// # Errors
///
/// The vault's.
pub fn keep_only_the_dreamer_ceiling(vault: &Vault) -> Result<()> {
    let dreamer = dreamer(vault)?.to_hex();
    rewrite_shipped_policy(vault, |entries| {
        let rmpv::Value::Array(rows) = policy_entry(entries, "actor_ceilings")? else {
            return Err(Error::InvalidConfig("actor ceilings are not a list".into()));
        };
        rows.retain(|row| {
            row.as_map().is_some_and(|fields| {
                fields.iter().any(|(key, value)| {
                    key.as_str() == Some("actor_ref") && value.as_str() == Some(dreamer.as_str())
                })
            })
        });
        if rows.len() != 1 {
            return Err(Error::InvalidConfig(format!(
                "the shipped policy holds {} Dreamer ceilings",
                rows.len()
            )));
        }
        Ok(())
    })
}

/// Where `agent`'s Steward grant stands, or `None` before any mint.
///
/// # Errors
///
/// The vault's.
pub fn grant_mark(vault: &Vault, agent: EntityId) -> Result<Option<GrantMark>> {
    let txn = vault.store.env.read_txn()?;
    Ok(match vault.system_agent_grant_state_in(&txn, agent)? {
        None => None,
        Some(SystemAgentGrantState::OptedOut) => Some(GrantMark::OptedOut),
        Some(SystemAgentGrantState::Minted { grant }) => Some(GrantMark::Minted {
            grant,
            verbs: crate::federation::standing_steward_verbs_in(&vault.store, &txn, grant, agent)?,
        }),
    })
}
