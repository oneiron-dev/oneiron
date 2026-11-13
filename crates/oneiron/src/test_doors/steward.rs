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

/// Records verified sources for a Dreamer claim through the strength writer.
/// Verification and observation share one writer transaction.
///
/// # Errors
///
/// The vault's, an unreadable source, or evidence of an inadmissible kind.
pub fn record_strength_observations(
    vault: &Vault,
    claim: EntityId,
    sources: &[EntityId],
    now_ms: u64,
) -> Result<()> {
    use crate::claim::{ClaimSource, ScopedReadActorKey};
    use crate::dreamer_consolidation::evidence::VerifiedEvidenceSet;

    let key = ScopedReadActorKey::for_engine_actor(vault.dreamer_authority()?)
        .ok_or(Error::InvalidClaimBody("an actor with no read"))?;
    let read = vault.scoped_read(key);
    vault.with_write_txn_grouped(|txn| {
        let evidence = VerifiedEvidenceSet::verify_whole_in_txn(
            vault,
            &read,
            txn,
            sources,
            ClaimSource::Generated,
        )?;
        crate::dreamer_consolidation::strength::record_verified_in_txn(
            vault, txn, claim, &evidence, now_ms,
        )
    })
}

/// Stands `agent`'s Steward grant with `verbs` as the one row that stands,
/// as a first mint leaves it; a later call stands a fresh grant that
/// replaces it.
///
/// # Errors
///
/// The vault's.
pub fn stand_steward_grant(vault: &Vault, agent: EntityId, verbs: &[&str]) -> Result<EntityId> {
    vault.stand_steward_grant_for_test(agent, verbs)
}

/// Stands `agent`'s Steward grant with `verbs` and marks it, as
/// [`stand_steward_grant`] does, then holds the grant row to the record kinds
/// `bands` and every other data axis whole. The host's mint leaves every axis
/// whole, and no owner door narrows one yet: this door writes the row such a
/// door would leave.
///
/// # Errors
///
/// The vault's.
pub fn stand_steward_grant_in_bands(
    vault: &Vault,
    agent: EntityId,
    verbs: &[&str],
    bands: &[u8],
) -> Result<EntityId> {
    use crate::federation::{decode_federation_grant_body, encode_federation_grant_body};
    use crate::ports::EntityStoreRead;
    let id = vault.stand_steward_grant_for_test(agent, verbs)?;
    vault.with_write_txn_grouped(|txn| {
        let raw = vault
            .store
            .port_entity_record(&*txn, &id)?
            .ok_or(Error::InvariantViolation("the Steward grant row"))?;
        let mut grant = decode_federation_grant_body(&raw.body)?;
        grant.authority_scope.bands = bands.iter().copied().collect();
        let now = crate::ports::recorded_at_in_txn(&vault.store, txn)?;
        crate::batch::apply_ops(
            &vault.store,
            &vault.config,
            &vault.analyzer,
            txn,
            vec![crate::batch::BatchOp::Put {
                id,
                entity_type: crate::registry::ENTITY_TYPE_FEDERATION_GRANT,
                occurred: crate::TimeRange {
                    start: now,
                    end: now,
                },
                learned_at: now,
                row_version: None,
                data: encode_federation_grant_body(&grant)?,
                allow_maintenance: true,
                allow_reserved_predicate: false,
                hub_sync_imported: false,
            }],
            vault
                .text_index_trusted
                .load(std::sync::atomic::Ordering::Acquire),
            false,
            true,
        )
    })?;
    Ok(id)
}

/// Every member the roster of shared vault `vault_id` lists, at their role.
///
/// # Errors
///
/// The vault's.
pub fn shared_roster(
    vault: &Vault,
    vault_id: u64,
) -> Result<Vec<(EntityId, crate::federation::FederationGrantRole)>> {
    let txn = vault.store.env.read_txn()?;
    vault.shared_members_in_txn(&txn, vault_id)
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

/// The shipped policy with no actor ceiling and with `Generated` trust written
/// as the shorthand row `false` (this source never lands by itself), as the
/// policy decode accepts it. The Dreamer's read row stays as shipped, so a
/// first mint over it copies `read` alone.
///
/// # Errors
///
/// The vault's.
pub fn write_generated_false_without_ceilings(vault: &Vault) -> Result<()> {
    rewrite_shipped_policy(vault, |entries| {
        *policy_entry(entries, "actor_ceilings")? = rmpv::Value::Array(Vec::new());
        let rmpv::Value::Map(sources) = policy_entry(entries, "source_trust")? else {
            return Err(Error::InvalidConfig("source trust is not a map".into()));
        };
        *policy_entry(sources, "generated")? = rmpv::Value::Boolean(false);
        Ok(())
    })
}

/// The shipped policy with one class-wide `system` Auto ceiling and the
/// `Generated` permit bound to the Dreamer's id spelt in upper case, as the
/// source-trust decode accepts it. The Dreamer's read row stays as shipped.
///
/// # Errors
///
/// The vault's.
pub fn write_upper_case_dreamer_permit(vault: &Vault) -> Result<()> {
    use rmpv::Value;
    let dreamer = dreamer(vault)?.to_hex().to_uppercase();
    rewrite_shipped_policy(vault, |entries| {
        *policy_entry(entries, "actor_ceilings")? = Value::Array(vec![Value::Map(vec![
            (Value::from("actor_class"), Value::from("system")),
            (Value::from("ceiling"), Value::from("auto")),
        ])]);
        let Value::Map(sources) = policy_entry(entries, "source_trust")? else {
            return Err(Error::InvalidConfig("source trust is not a map".into()));
        };
        *policy_entry(sources, "generated")? = Value::Map(vec![
            (Value::from("actor_ref"), Value::from(dreamer)),
            (
                Value::from("max_auto_sensitivity"),
                Value::from(u64::from(crate::claim::UNSTAMPED_CLAIM_SENSITIVITY_BAND)),
            ),
            (Value::from("receipted"), Value::Boolean(true)),
            (Value::from("warned"), Value::Boolean(true)),
        ]);
        Ok(())
    })
}

/// Revokes every live MACHINE binding of base agent `agent` with the host
/// root's signed `RevokeActor`, as a host that withdraws the agent's
/// delegation does. Its Steward grant stays as it stands. Returns how many
/// bindings it revoked.
///
/// # Errors
///
/// The vault's or the authority log's.
pub fn revoke_base_agent_bindings(vault: &Vault, agent: EntityId) -> Result<usize> {
    use crate::authority::{ActorBindingStatus, AuthorityOp};
    let issuer = crate::test_support::test_host_issuer();
    let fold = vault.authority_fold()?;
    let live: Vec<_> = fold
        .actor_bindings
        .iter()
        .filter(|(key, binding)| {
            binding.actor_ref == agent
                && binding.status == ActorBindingStatus::Active
                && fold.roster.get(*key).is_some_and(|device| !device.revoked)
        })
        .map(|(key, binding)| (key.clone(), binding.epoch))
        .collect();
    for (authority_key, epoch) in &live {
        vault.log_host_op_for_test(
            &issuer,
            AuthorityOp::RevokeActor {
                authority_key: authority_key.clone(),
                epoch: *epoch,
            },
        )?;
    }
    Ok(live.len())
}

/// Whether a read key built for engine actor `actor` by
/// `ScopedReadActorKey::with_actor_class`, the constructor the engine's
/// readers outside `for_engine_actor` use, reads `entity` now. A refused
/// read counts as not read.
///
/// # Errors
///
/// The vault's.
pub fn class_key_reads(vault: &Vault, actor: EntityId, entity: EntityId) -> Result<bool> {
    let key = crate::claim::ScopedReadActorKey::with_actor_class(actor.to_hex(), "system")
        .ok_or_else(|| Error::InvalidConfig("engine actor read key".into()))?;
    let read = vault.scoped_read(key);
    let txn = vault.store.env.read_txn()?;
    Ok(read
        .entity_raw_live_in(&txn, &entity)
        .is_ok_and(|row| row.is_some()))
}

/// Whether `row` is a Steward grant row naming `agent`: role and preset
/// Steward, an access grant with no expiry.
fn names_as_steward(row: &crate::federation::FederationGrant, agent: EntityId) -> bool {
    row.role == crate::federation::FederationGrantRole::Steward
        && row.preset == crate::federation::FederationGrantPreset::Steward
        && row.kind == crate::federation::FederationGrantKind::Access
        && row.expires_at.is_none()
        && row.member_ref == agent
}

/// Puts one more Steward grant row for `agent` with `verbs` beside the rows
/// that stand, on the vault's own root, as a row another of the owner's
/// machines stood arrives here: the row alone, no act and nothing else
/// written. No verbs is that machine's record of an opt-out. For a vault
/// that is not shared.
///
/// # Errors
///
/// The vault's.
pub fn receive_steward_grant_row(
    vault: &Vault,
    agent: EntityId,
    verbs: &[&str],
) -> Result<EntityId> {
    use crate::federation::{
        FederationGrant, FederationGrantPreset, FederationGrantRole, encode_federation_grant_body,
        own_device_residence_scope,
    };
    let mut grant = FederationGrant::new(
        own_device_residence_scope(),
        agent,
        FederationGrantRole::Steward,
        FederationGrantPreset::Steward,
    );
    grant.authority_scope.verbs = verbs.iter().map(|verb| (*verb).to_owned()).collect();
    let data = encode_federation_grant_body(&grant)?;
    let id = EntityId::now();
    vault.with_write_txn_grouped(|txn| {
        let now = crate::ports::recorded_at_in_txn(&vault.store, txn)?;
        crate::batch::apply_ops(
            &vault.store,
            &vault.config,
            &vault.analyzer,
            txn,
            vec![crate::batch::BatchOp::Put {
                id,
                entity_type: crate::registry::ENTITY_TYPE_FEDERATION_GRANT,
                occurred: crate::TimeRange {
                    start: now,
                    end: now,
                },
                learned_at: now,
                row_version: None,
                data,
                allow_maintenance: true,
                allow_reserved_predicate: false,
                hub_sync_imported: false,
            }],
            vault
                .text_index_trusted
                .load(std::sync::atomic::Ordering::Acquire),
            false,
            true,
        )
    })?;
    Ok(id)
}

/// Every Steward grant row that stands naming `agent`, oldest first, each
/// with the verbs it gives; a row with no verbs is an opt-out's record. Read
/// from the stored rows alone.
///
/// # Errors
///
/// The vault's.
pub fn steward_grant_rows(vault: &Vault, agent: EntityId) -> Result<Vec<(EntityId, Vec<String>)>> {
    use crate::ports::EntityStoreRead;
    let txn = vault.store.env.read_txn()?;
    let mut rows = Vec::new();
    for id in vault.store.port_entity_ids_by_type(
        &txn,
        crate::registry::ENTITY_TYPE_FEDERATION_GRANT,
        None,
    )? {
        let id = id?;
        let Some(raw) = vault.store.port_entity_record(&txn, &id)? else {
            continue;
        };
        if raw.body.is_empty() {
            continue;
        }
        let Ok(row) = crate::federation::decode_federation_grant_body(&raw.body) else {
            continue;
        };
        if !names_as_steward(&row, agent) {
            continue;
        }
        let verbs = match &row.authority_scope.verbs {
            crate::federation::ScopeAxis::Some(verbs) => verbs.iter().cloned().collect(),
            crate::federation::ScopeAxis::All | crate::federation::ScopeAxis::Bottom => Vec::new(),
        };
        rows.push((id, verbs));
    }
    rows.sort();
    Ok(rows)
}

/// The scope the standing Steward grant rows naming base agent `agent` hold
/// together: the meet of their authority scopes, so each data axis is the
/// narrowest any row holds. `None` while no row stands. Read from the stored
/// rows alone.
///
/// # Errors
///
/// The vault's.
pub fn steward_reach_scope(
    vault: &Vault,
    agent: EntityId,
) -> Result<Option<crate::federation::Scope>> {
    let txn = vault.store.env.read_txn()?;
    Ok(crate::federation::steward_reach_in(&vault.store, &txn, agent)?.map(|reach| reach.scope))
}

/// Every grant row that stands as a Steward grant naming `agent` with a verb
/// to give; an opt-out's record is not among them
/// ([`steward_grant_rows`] lists it).
///
/// # Errors
///
/// The vault's.
pub fn standing_steward_grants(vault: &Vault, agent: EntityId) -> Result<Vec<EntityId>> {
    use crate::ports::EntityStoreRead;
    let txn = vault.store.env.read_txn()?;
    let mut standing = Vec::new();
    for id in vault.store.port_entity_ids_by_type(
        &txn,
        crate::registry::ENTITY_TYPE_FEDERATION_GRANT,
        None,
    )? {
        let id = id?;
        if !crate::federation::standing_steward_verbs_in(&vault.store, &txn, id, agent)?.is_empty()
        {
            standing.push(id);
        }
    }
    Ok(standing)
}

/// Where `agent`'s Steward grant stands, or `None` before any mint. The
/// verbs are the newest standing row's.
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
