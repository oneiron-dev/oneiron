//! OF-397/OF-540: the execution context a host binds on a leased agent run,
//! so its pack receipt closes attributed.
//!
//! The host binds it while the lease still holds, before any close; the
//! terminal transaction then freezes it beside the pack manifest. Every field
//! is a fact of the run, never a guess:
//!
//! - the executor is the model the pack loaded under, else the seat the run
//!   was born on. A run with neither binds nothing and closes unattributed;
//! - the judge is the run's decision ladder at its top model rung, the judge
//!   the run's Done climbs to, else the person;
//! - a team run's pattern and decider are its frozen stamp's: the pattern's
//!   context and the team run's decision, which its `TeamReceipt` names. A
//!   run outside any team is solo, and its own agent decides.
//!
//! Neither pattern context is a loaded skill, so neither earns pack credit: a
//! pattern skill's payoff comes from its team receipt alone. The use lists
//! start empty and only grow from witnessed use; credit follows the
//! lineage-credit settings where the run's project and type apply, by
//! default the full used chain with no per-hop check.
//!
//! At close the host witnesses the run's output
//! ([`witness_agent_run_close`]): the output derives from what the run
//! derived, and the used chain reaches up the stored lineage from there.

use std::collections::{BTreeSet, VecDeque};

use crate::Vault;
use crate::agent_dispatch::{AGENT_DISPATCH_ATTEMPT_TYPE, decode_agent_dispatch_input};
use crate::attempt_queue::{AttemptId, AttemptQueue, AttemptRecord, AttemptState};
use crate::dreamer_runner::DreamerRunnerStore;
use crate::edge::EdgeKind;
use crate::entity_id::{EntityId, derived_domains};
use crate::error::Result;
use crate::learning::TypeRef;
use crate::learning_setting::{
    CREDIT_CHECK_EVERY_HOP, CREDIT_DEPTH_CAP, CREDIT_ENABLED, SettingSpec, setting_value_scoped,
};
use crate::llm::decision::{DecisionProvider, HeldLadder, ProviderPin};
use crate::ports::{EdgeDirection, EdgeStore};
use crate::receipt::{CreditOptions, PackAttributionFields, UsedProvenanceEdge};

/// The role a run outside any team plays.
const SOLO_ROLE: &str = "solo";

/// Hops of stored lineage the close witness follows above a run's own
/// derivations when the run's credit sets no depth cap.
const WITNESS_MAX_HOPS: u32 = 64;

/// Used edges one run's receipt carries at most; the lineage walk stops there.
pub(super) const WITNESS_MAX_EDGES: usize = 1024;

/// The role a team run's member plays.
const MEMBER_ROLE: &str = "member";

/// Binds the execution context of the leased agent run `attempt`, once.
/// Returns whether it bound one now: a run that is no agent dispatch, no
/// longer holds `lease_owner`'s lease, already carries one, or names no
/// executor binds nothing.
///
/// # Errors
///
/// Storage errors, a malformed dispatch payload, and the attribution door's
/// own refusals.
pub fn bind_agent_run_attribution(
    vault: &Vault,
    attempt: AttemptId,
    lease_owner: &str,
    judges: &HeldLadder,
) -> Result<bool> {
    let Some(status) = DreamerRunnerStore::new(vault).status(attempt)? else {
        return Ok(false);
    };
    let record = &status.attempt;
    if status.payload.attempt_type != AGENT_DISPATCH_ATTEMPT_TYPE
        || !matches!(record.state, AttemptState::Leased | AttemptState::Landing)
        || record.lease_owner.as_deref() != Some(lease_owner)
    {
        return Ok(false);
    }
    {
        let rtxn = vault.store.env.read_txn()?;
        if crate::receipt::has_attempt_pack_attribution_in_txn(&vault.store, &rtxn, attempt)? {
            return Ok(false);
        }
    }
    let Some(executor) = run_executor_model(vault, record)? else {
        return Ok(false);
    };
    let input = decode_agent_dispatch_input(&status.payload.input)?;
    let (pattern, role, decider) = match &input.team {
        Some(team) => (
            pattern_context(team.pattern.as_str())?,
            MEMBER_ROLE,
            EntityId::derive(
                derived_domains::COORDINATION_PATTERN,
                &[b"decider", team.team_ref.as_bytes()],
            )?,
        ),
        None => (
            pattern_context(SOLO_ROLE)?,
            SOLO_ROLE,
            input.target.agent_definition_ref()?,
        ),
    };
    let type_ref = TypeRef::from(&input.type_ref);
    let credit = credit_options(vault, input.project_ref, &type_ref)?;
    let fields = PackAttributionFields {
        type_ref,
        executor,
        judge: ladder_judge(judges),
        pattern,
        team_shape: vec![role.to_owned()],
        decider,
        project: input.project_ref,
        output: None,
        contributions: Vec::new(),
        used_edges: Vec::new(),
        credit,
    };
    AttemptQueue::new(vault).set_pack_attribution(
        attempt,
        lease_owner,
        record.attempt_count,
        &fields,
    )?;
    Ok(true)
}

/// Witnesses the close of the leased agent run `attempt`, before the
/// terminal door freezes its receipt: `output` becomes the receipt's output
/// and derives from each entity the run itself derived (one DerivedFrom edge
/// each, written here), and the used chain grows by those edges and by the
/// stored lineage above the run's derivations, as deep as the run's credit
/// reaches. Returns whether it witnessed: a run with no bound attribution
/// witnesses nothing.
///
/// Only lineage is witnessed here. A skill the run loaded or called has not
/// contributed by that alone, so the contribution list stays as the run's
/// checks left it.
///
/// # Errors
///
/// A lease `lease_owner` no longer holds, an output other than the one
/// already witnessed, and storage errors.
pub fn witness_agent_run_close(
    vault: &Vault,
    attempt: &AttemptRecord,
    lease_owner: &str,
    output: EntityId,
) -> Result<bool> {
    let mut txn = vault.store.env.write_txn()?;
    AttemptQueue::new(vault).require_skill_load_lease_in_txn(
        &txn,
        attempt.id,
        lease_owner,
        attempt.attempt_count,
    )?;
    let Some(mut fields) =
        crate::receipt::attempt_pack_attribution_in_txn(&vault.store, &txn, attempt.id)?
    else {
        return Ok(false);
    };
    // A replayed close finds its own witness; the run wrote nothing since.
    if fields.output == Some(output) {
        return Ok(true);
    }
    let mut seen: BTreeSet<(EntityId, EntityId)> = fields
        .used_edges
        .iter()
        .map(|edge| (edge.derived, edge.source))
        .collect();
    let derived: BTreeSet<EntityId> = fields
        .used_edges
        .iter()
        .map(|edge| edge.derived)
        .filter(|node| *node != output)
        .collect();
    let stored: BTreeSet<EntityId> = vault
        .port_edge_neighbors(
            &txn,
            &output,
            EdgeDirection::Out,
            Some(EdgeKind::DerivedFrom),
            usize::MAX,
        )?
        .into_iter()
        .map(|edge| edge.target)
        .collect();
    let mut batch = vault.batch_in();
    let mut new_edges = false;
    for node in &derived {
        if fields.used_edges.len() >= WITNESS_MAX_EDGES {
            break;
        }
        if !stored.contains(node) {
            batch = batch.edge(&output, EdgeKind::DerivedFrom, node, 1.0);
            new_edges = true;
        }
        if seen.insert((output, *node)) {
            fields.used_edges.push(UsedProvenanceEdge {
                derived: output,
                source: *node,
                check: None,
            });
        }
    }
    if new_edges {
        batch.apply(&mut txn)?;
    }
    witness_lineage_in_txn(vault, &txn, &mut fields, &mut seen, output)?;
    fields.output = Some(output);
    crate::receipt::put_attempt_pack_attribution_in_txn(
        &vault.store,
        &mut txn,
        attempt.id,
        &fields,
    )?;
    txn.commit()?;
    Ok(true)
}

/// Appends the stored lineage above the run's own derivations to `fields`'
/// used chain: hop 1 is the output to a derivation, hop 2 the run's own
/// edge, so the stored walk starts at hop 3 and stops at the run's credit
/// depth.
fn witness_lineage_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    fields: &mut PackAttributionFields,
    seen: &mut BTreeSet<(EntityId, EntityId)>,
    output: EntityId,
) -> Result<()> {
    let hops = fields
        .credit
        .depth_cap
        .unwrap_or(WITNESS_MAX_HOPS)
        .min(WITNESS_MAX_HOPS);
    let mut queue: VecDeque<(EntityId, u32)> = fields
        .used_edges
        .iter()
        .filter(|edge| edge.derived != output)
        .map(|edge| (edge.source, 3))
        .collect();
    let mut walked = BTreeSet::new();
    while let Some((node, hop)) = queue.pop_front() {
        if hop > hops || !walked.insert(node) {
            continue;
        }
        for edge in vault.port_edge_neighbors(
            txn,
            &node,
            EdgeDirection::Out,
            Some(EdgeKind::DerivedFrom),
            usize::MAX,
        )? {
            if fields.used_edges.len() >= WITNESS_MAX_EDGES {
                return Ok(());
            }
            if edge.target != node && seen.insert((node, edge.target)) {
                fields.used_edges.push(UsedProvenanceEdge {
                    derived: node,
                    source: edge.target,
                    check: None,
                });
                queue.push_back((edge.target, hop + 1));
            }
        }
    }
    Ok(())
}

/// The lineage-credit controls in force where `project` and `type_ref`
/// apply, frozen on the run as it binds.
fn credit_options(
    vault: &Vault,
    project: Option<EntityId>,
    type_ref: &TypeRef,
) -> Result<CreditOptions> {
    let value = |spec: &SettingSpec| setting_value_scoped(vault, spec, project, Some(type_ref));
    let cap = value(&CREDIT_DEPTH_CAP)?;
    #[expect(
        clippy::cast_possible_truncation,
        clippy::cast_sign_loss,
        reason = "the catalog bounds the cap to 0..=1024 hops"
    )]
    let depth_cap = (cap < CREDIT_DEPTH_CAP.max).then(|| cap.floor() as u32);
    Ok(CreditOptions {
        enabled: value(&CREDIT_ENABLED)? >= 0.5,
        depth_cap,
        check_every_hop: value(&CREDIT_CHECK_EVERY_HOP)? >= 0.5,
    })
}

/// The id of a coordination pattern's context: `solo`, or a team pattern's
/// wire token. It names the pattern, never a skill.
fn pattern_context(token: &str) -> Result<EntityId> {
    EntityId::derive(
        derived_domains::COORDINATION_PATTERN,
        &[b"pattern", token.as_bytes()],
    )
}

/// The model that executed `record`: the one its pack loaded under, else the
/// seat its run was born on. A run's id is its attempt's.
pub(crate) fn run_executor_model(vault: &Vault, record: &AttemptRecord) -> Result<Option<String>> {
    if let Some(model) = &record.executor_model {
        return Ok(Some(model.clone()));
    }
    let run = EntityId::from_bytes(*record.id.as_bytes())?;
    Ok(vault
        .model_seat_receipt(run)?
        .map(|seat| seat.model.to_string()))
}

/// The ladder's top model rung, else its person, as `model@revision`.
fn ladder_judge(ladder: &HeldLadder) -> String {
    [
        &ladder.big,
        &ladder.escalation,
        &ladder.system_one,
        &ladder.local,
    ]
    .into_iter()
    .flatten()
    .next()
    .map_or_else(|| pinned(&ladder.human_pin), |rung| pinned(&rung.pin()))
}

fn pinned(pin: &ProviderPin) -> String {
    if pin
        .model
        .rsplit_once('@')
        .is_some_and(|(id, revision)| !id.is_empty() && !revision.is_empty())
    {
        pin.model.clone()
    } else {
        format!("{}@{}", pin.model, pin.version)
    }
}
