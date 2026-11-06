//! FIX 12569: each vault's own small draft model (I5-DRAFTER = A), retrained
//! at night on the vault's own conversations as Coach-owned work on the
//! shared night scheduler, on by default with an off switch. A qualified
//! version goes into service only when it beats the current one with
//! token-identical output, and a slowdown rolls it back (DRAFTER-ACTIVATE =
//! A + revert); earlier versions are kept, so the owner or an agent can
//! revert to any of them. The drafter trains on the vault's own
//! conversations, rooms with other people included, and never leaves the
//! vault; a setting excludes worlds, and an erase of a source drops every
//! version trained on it, the target serving stock until the next retrain
//! (DRAFTER-DATA = A).
//!
//! This module holds the records and their doors:
//! - [`DrafterVersion`], one attempted or trained head and its run;
//! - [`DrafterBinding`], one target's active pointer, stock or a version,
//!   with its generation and the version it replaced;
//! - [`DrafterEvent`], the content-free history;
//! - [`DrafterPolicy`], the owner's switch, excluded worlds and recipe.
//!
//! The doors list versions, read the status, set the policy and revert a
//! binding. A source erase reaches every version whose ancestry names the
//! source at both delete doors and at an actor's erase, in the erase's own
//! transaction ([`erase_drafters_for_source_in_txn`]). Each version's sealed
//! artifact sits under its own erasable key ([`DrafterSealing`]).
//!
//! The drafter trains on the vault's whole chat traffic (FIX 15128, FIX
//! 15129, `traffic`): the host hands every answered reply over once it is
//! saved whole, and [`crate::Vault::keep_drafter_example`] keeps it as one
//! training example, apart from the chat breakpoint: the request exactly as
//! its rung sent it and the span the reply generated, sealed under the
//! example's own erasable key, every record it was read from indexed so its
//! erase drops the example ([`erase_drafter_examples_for_source_in_txn`]).
//! The newest [`DRAFTER_EXAMPLES_KEPT`] are kept.
//!
//! The nightly job, `coach.drafter_retrain`, pins the policy revision and
//! its cutoff and records how the night ended. With a recipe a trainer
//! connector of its host lists and a target its host serves a drafter for,
//! the night exports the vault's own corpus for that target (FIX 14973,
//! `corpus.rs`) and writes a `prepared` version with the corpus sealed under
//! the version's keys, its split and its dependency set. The host trains it
//! (FIX 14974, `training`): its quote admitted, the version `training`
//! before the trainer starts, its output sealed under the version's own key
//! and published as `returned`. The night stays open while it trains and
//! then records `trained` or `failed`; any other night records why it held.
//!
//! A host serves a binding on its own managed worker through
//! [`DrafterServingRuntime`] (FIX 14976, `serving`): it reads each target's
//! plan, materialises a version's sealed load set into the vault's private
//! `drafter-serving/` directory (`load_set`), restarts its worker with that
//! draft, and records the transition once the new incarnation proves the
//! draft's identity. Every door that moves a binding tells the host after
//! commit.
//!
//! A host evaluates each trained version on the vault's held-out turns
//! (FIX 14975, `evaluation`): it replays them through the target alone, the
//! head that serves now and the version, on evaluator incarnations of the
//! serving worker, and records what it measured; the engine decides. A
//! version token-identical to the target alone, up to ties within the
//! recipe's logit epsilon, qualifies; one that also beats the serving head
//! with no measured slowdown goes into service on its own
//! ([`crate::Vault::try_activate_drafter`]), and any slowdown, output
//! violation or worker error the host then observes on its serving
//! incarnation rolls it back ([`crate::Vault::observe_drafter_serving`]).
//! The recipe names every number.

mod corpus;
mod custody;
mod doors;
mod erase;
mod evaluation;
mod load_set;
mod nightly;
mod policy;
mod report;
mod serving;
mod traffic;
mod training;
mod types;

use std::collections::{BTreeMap, BTreeSet};

use heed::{RoTxn, RwTxn};
use serde::Serialize;

use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::side_table::{self, Named, SideTable};
use crate::store::Store;

pub use custody::DrafterSealing;
pub use doors::{
    DrafterListRequest, DrafterRevertReceipt, DrafterRevertRequest, DrafterStatus,
    DrafterStatusRequest, DrafterVersionView, drafter_status_as_owner, list_drafters_as_agent,
    list_drafters_as_owner, revert_drafter_as_agent, revert_drafter_as_owner,
};
pub(crate) use erase::{erase_drafter_actor_in_txn, erase_drafters_for_source_in_txn};
pub use evaluation::{
    DRAFTER_QUALIFICATION_KEY, DrafterActivation, DrafterActivationRefusal,
    DrafterActivationServing, DrafterArmIdentity, DrafterCaseMeasure, DrafterEvaluation,
    DrafterEvaluationArm, DrafterEvaluationCorpus, DrafterEvaluationDecision,
    DrafterEvaluationEvidence, DrafterEvaluationPlan, DrafterFailReason, DrafterHeldOutCase,
    DrafterMeasurementSchedule, DrafterObservation, DrafterObservationVerdict,
    DrafterObserveOutcome, DrafterQualificationRule, DrafterSampleRule, DrafterSlowdownRule,
    DrafterSpeedComparison, DrafterSpeedMetric, DrafterSpeedOutcome, DrafterSpeedStatistic,
    DrafterSpeedVerdict, DrafterTieEvidence, DrafterTokenIdentity, DrafterUnknownReason,
    compare_speed,
};
pub use load_set::{SEALED_CHUNK_BYTES, drafter_file_name_is_plain, drafter_load_set_blake3};
pub use nightly::DrafterNightStep;
pub use policy::{DrafterPolicy, DrafterPolicySetRequest, set_drafter_policy_as_owner};
pub(crate) use report::unseen_drafter_line_in_txn;
pub use report::{DRAFTER_GROUP, DRAFTER_VIEW, DigestDrafter, DigestDrafterItem};
pub use serving::{
    DrafterLoadSetPlan, DrafterMaterialized, DrafterServedView, DrafterServingPlan,
    DrafterServingPlans, DrafterServingRuntime, DrafterUnservedReason,
};
pub(crate) use traffic::erase_drafter_examples_for_source_in_txn;
pub use traffic::{DRAFTER_EXAMPLES_KEPT, DrafterExampleKept, DrafterTrafficReply};
pub use training::{
    DRAFTER_TRAINABLE_PREFIX, DrafterParentLoadSet, DrafterTrainingDispatch, DrafterTrainingJob,
    DrafterTrainingMark,
};
pub use types::*;

/// The verb an agent's Grant lists to read the vault's drafter versions.
pub const DRAFTER_READ_GRANT_VERB: &str = "drafter_read";
/// The verb an agent's Grant lists to revert a target to a retained version.
pub const DRAFTER_REVERT_GRANT_VERB: &str = "drafter_revert";

const VERSIONS: SideTable<EntityId, DrafterVersion, Named> =
    SideTable::new(&side_table::DRAFTER_VERSION);
const BINDINGS: SideTable<[u8; 32], DrafterBinding, Named> =
    SideTable::new(&side_table::DRAFTER_BINDING);
const EVENTS: SideTable<EntityId, DrafterEvent, Named> = SideTable::new(&side_table::DRAFTER_EVENT);
const POLICY: SideTable<(), DrafterPolicy, Named> = SideTable::new(&side_table::DRAFTER_POLICY);

fn invalid(reason: &str) -> Error {
    Error::InvalidConfig(reason.into())
}

fn hash_json(value: &impl Serialize) -> Result<[u8; 32]> {
    let bytes = crate::llm::canonical_json_bytes(value)
        .map_err(|_| invalid("drafter pin encoding failed"))?;
    Ok(*blake3::hash(&bytes).as_bytes())
}

/// The owner's policy in `txn`: the shipped default, on, when none is set.
fn policy_in_txn(store: &Store, txn: &RoTxn<'_>) -> Result<DrafterPolicy> {
    Ok(POLICY.get(store, txn, &())?.unwrap_or_default())
}

/// Every version in `txn`, by id.
fn versions_by_id(store: &Store, txn: &RoTxn<'_>) -> Result<BTreeMap<EntityId, DrafterVersion>> {
    Ok(VERSIONS.scan(store, txn)?.into_iter().collect())
}

/// `version` and each version it continued from, nearest first. A parent
/// the table no longer holds, or a cycle, ends the chain.
fn ancestry<'v>(
    versions: &'v BTreeMap<EntityId, DrafterVersion>,
    version: &'v DrafterVersion,
) -> Vec<&'v DrafterVersion> {
    let mut chain = vec![version];
    let mut seen = BTreeSet::from([version.id]);
    let mut next = version.parent;
    while let DrafterServing::Version(parent) = next {
        if !seen.insert(parent) {
            break;
        }
        let Some(found) = versions.get(&parent) else {
            break;
        };
        chain.push(found);
        next = found.parent;
    }
    chain
}

/// Whether `version`'s ancestry trained on a world of `worlds`.
fn ancestry_names_world(
    versions: &BTreeMap<EntityId, DrafterVersion>,
    version: &DrafterVersion,
    worlds: &BTreeSet<EntityId>,
) -> bool {
    !worlds.is_empty()
        && ancestry(versions, version)
            .iter()
            .any(|step| step.dependencies.names_world_of(worlds))
}

/// Records one event in `txn`, under a fresh time-ordered id.
fn record_event_in_txn(
    store: &Store,
    txn: &mut RwTxn<'_>,
    by: DrafterActor,
    kind: DrafterEventKind,
    change: Option<DrafterBindingChange>,
    at: u64,
) -> Result<DrafterEvent> {
    let event = DrafterEvent {
        id: store.clock.entity_id()?,
        at,
        by,
        kind,
        change,
    };
    EVENTS.put(store, txn, &event.id, &event)?;
    Ok(event)
}

/// One change of a binding: what it serves next, what it keeps as the
/// previous head, who changed it, the event that records it and when.
struct BindingMove {
    to: DrafterServing,
    previous: DrafterServing,
    by: DrafterActor,
    kind: DrafterEventKind,
    at: u64,
}

/// Moves `binding`, stored under `key`, as `step` says, in `txn`: its
/// generation bumps and the event that records the change is written in the
/// same transaction.
fn move_binding_in_txn(
    store: &Store,
    txn: &mut RwTxn<'_>,
    key: &[u8; 32],
    mut binding: DrafterBinding,
    step: BindingMove,
) -> Result<(DrafterBinding, DrafterEvent)> {
    let from = binding.serving;
    binding.serving = step.to;
    binding.previous = step.previous;
    binding.generation += 1;
    let change = DrafterBindingChange {
        target: binding.target.clone(),
        from,
        to: step.to,
        generation: binding.generation,
    };
    let event = record_event_in_txn(store, txn, step.by, step.kind, Some(change), step.at)?;
    binding.changed_by = Some(event.id);
    binding.changed_at = step.at;
    BINDINGS.put(store, txn, key, &binding)?;
    Ok((binding, event))
}
