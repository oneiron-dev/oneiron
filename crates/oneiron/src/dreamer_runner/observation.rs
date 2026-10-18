//! Owner reads of recipe receipts and their Dreamer/Coach descendants.
//! Completion of a recipe receipt alone never claims its children settled.
use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use super::store::{PARKED, RUN_TREE};
use super::{DREAMER_RECIPE_WAKE_ATTEMPT_KIND, decode_dreamer_attempt_payload};
use crate::attempt_queue::{AttemptId, AttemptQueue, AttemptState};
use crate::consent::AuthenticatedOwner;
use crate::dreamer_wake::{WakePolicyTrigger, WakeRecipeInputView};
use crate::memory::DreamerParkCauseView;
use crate::{EntityId, Error, Result, Vault};

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct WakeSettlementsRequest {
    pub after: Option<EntityId>,
    pub limit: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct WakeSettlementRequest {
    pub wake: EntityId,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct WakeSettlementsPage {
    pub wakes: Vec<WakeSettlementView>,
    /// Resume after this wake when more receipts remain.
    pub next: Option<EntityId>,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct WakeSettlementView {
    pub wake: EntityId,
    pub input: Option<WakeRecipeInputView>,
    /// Every descendant is terminal, not merely the recipe dispatcher.
    pub settled: bool,
    pub jobs: Vec<WakeRecipeJobView>,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct WakeRecipeJobView {
    pub attempt: EntityId,
    pub parent: Option<EntityId>,
    pub kind: String,
    pub state: AttemptState,
    pub created_at: u64,
    pub updated_at: u64,
    /// The actual Dreamer, Coach or resident principal, never inferred from a name.
    pub actor: Option<EntityId>,
    pub facet: Option<String>,
    pub authority_receipt: Option<[u8; 16]>,
    pub park_cause: Option<DreamerParkCauseView>,
    pub parked_at: Option<u64>,
    pub result_ref: Option<String>,
    /// Exact claim identities retained by the promotion/merge output ledgers.
    pub conclusions: Vec<EntityId>,
}

fn entity(id: AttemptId) -> Result<EntityId> {
    EntityId::from_bytes(*id.as_bytes()).map_err(Error::from)
}

fn settlement_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    wake: EntityId,
) -> Result<Option<WakeSettlementView>> {
    let queue = AttemptQueue::new(vault);
    let root = AttemptId::from_bytes(wake.as_bytes())?;
    let Some(record) = queue.get_in_txn(txn, root)? else {
        return Ok(None);
    };
    let tree: BTreeMap<_, _> = RUN_TREE.scan(&vault.store, txn)?.into_iter().collect();
    if !tree.contains_key(&root)
        || tree[&root].parent_attempt.is_some()
        || vault.dreamer_attempt_authority_in_txn(txn, root)?.is_none()
    {
        return Err(Error::InvalidConfig("wake must name a shared-runner root".into()));
    }
    let input = if record.kind == DREAMER_RECIPE_WAKE_ATTEMPT_KIND {
        let payload = decode_dreamer_attempt_payload(&record.payload)?;
        let trigger: WakePolicyTrigger = serde_json::from_str(
            payload.input.as_str().ok_or_else(|| Error::InvalidConfig("invalid recipe input".into()))?,
        ).map_err(|_| Error::InvalidConfig("invalid recipe input".into()))?;
        Some(WakeRecipeInputView::from(&trigger))
    } else {
        None
    };
    let mut selected = BTreeSet::from([root]);
    loop {
        let before = selected.len();
        for (id, link) in &tree {
            if link.parent_attempt.is_some_and(|parent| selected.contains(&parent)) {
                selected.insert(*id);
            }
        }
        if before == selected.len() {
            break;
        }
    }
    let mut jobs = Vec::new();
    let mut settled = true;
    for id in selected {
        let record = queue.get_in_txn(txn, id)?.ok_or(Error::CorruptedIndex("recipe child missing"))?;
        let authority = vault.dreamer_attempt_authority_in_txn(txn, id)?;
        let park = PARKED.get(&vault.store, txn, &id)?;
        settled &= record.state.is_terminal();
        jobs.push(WakeRecipeJobView {
            attempt: entity(id)?,
            parent: tree.get(&id).and_then(|link| link.parent_attempt).map(entity).transpose()?,
            kind: record.kind,
            state: record.state,
            created_at: record.created_at,
            updated_at: record.updated_at,
            actor: authority.as_ref().map(|stamp| stamp.actor),
            facet: authority.as_ref().map(|stamp| stamp.facet.clone()),
            authority_receipt: authority.map(|stamp| stamp.receipt_id),
            park_cause: park.as_ref().map(|park| park.cause.into()),
            parked_at: park.as_ref().map(|park| park.parked_at),
            result_ref: record.result_ref.map(|reference| reference.into_string()),
            conclusions: crate::dreamer_consolidation::nightly_merge::outputs_in_txn(vault, txn, id)?,
        });
    }
    Ok(Some(WakeSettlementView {
        wake,
        input,
        settled,
        jobs,
    }))
}

pub fn settlement_as_owner(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    input: &WakeSettlementRequest,
) -> Result<Option<WakeSettlementView>> {
    let txn = vault.store.env.read_txn()?;
    owner.revalidate_as_vault_owner_in_txn(vault, &txn)?;
    settlement_in_txn(vault, &txn, input.wake)
}

pub fn settlements_as_owner(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    input: &WakeSettlementsRequest,
) -> Result<WakeSettlementsPage> {
    let txn = vault.store.env.read_txn()?;
    owner.revalidate_as_vault_owner_in_txn(vault, &txn)?;
    let mut wakes = Vec::new();
    let mut more = false;
    if input.limit == 0 {
        return Err(Error::InvalidConfig("settlement page limit must be positive".into()));
    }
    for row in RUN_TREE.iter_from(&vault.store, &txn, &[])? {
        let (id, link) = row?;
        if link.parent_attempt.is_some() {
            continue;
        }
        let wake = entity(id)?;
        if input.after.is_some_and(|after| wake <= after) {
            continue;
        }
        if vault.dreamer_attempt_authority_in_txn(&txn, id)?.is_none() {
            continue;
        }
        if wakes.len() >= input.limit as usize {
            more = true;
            break;
        }
        if let Some(view) = settlement_in_txn(vault, &txn, wake)? {
            wakes.push(view);
        }
    }
    let next = if more { wakes.last().map(|wake| wake.wake) } else { None };
    Ok(WakeSettlementsPage { wakes, next })
}
