//! Dial resolution: each `HEALTH_*` dial read for a project and task type.
//! Entry: `DialBook::read`, then `DialBook::of` or `for_attempt` per attempt.
//! Owns `Dials` and `DialBook`; the dial catalog is in `vocabulary`.

use std::collections::{BTreeMap, BTreeSet};

use super::{
    Dispatched, Dispatches, HEALTH_CARD_FLOOR, HEALTH_CHECK_FAILS, HEALTH_COST_MIN_RUNS,
    HEALTH_COST_SPIKE, HEALTH_DUP_MIN_COST, HEALTH_ESCALATE_TTL_HOURS, HEALTH_LOOP_REPEATS,
    HEALTH_OWNER_COPY, HEALTH_REVIEW, HEALTH_REVIEW_WINDOW_HOURS, HEALTH_SILENT_MINUTES,
    HEALTH_WAIT_MINUTES, HEALTH_WAIT_SHARE, HEALTH_WIDEN_DENIALS,
};
use crate::attempt_queue::AttemptId;
use crate::learning_setting::{SettingSpec, setting_value_in_scope_in_txn};
use crate::{EntityId, Result, Vault};

/// The dials in force for one project and task type.
pub(super) struct Dials {
    pub(super) review: bool,
    pub(super) loop_repeats: u64,
    pub(super) check_fails: u64,
    pub(super) wait_share: f64,
    pub(super) wait_secs: u64,
    pub(super) silent_secs: u64,
    pub(super) widen_denials: u64,
    pub(super) cost_spike: f64,
    pub(super) ttl_secs: u64,
    pub(super) card_floor: f64,
    pub(super) dup_min_cost: u64,
    /// Every card copies to the owner at once.
    pub(super) owner_copy: bool,
    /// How far back the review reads for this scope.
    pub(super) window_secs: u64,
    /// The settled runs a task type's p90 needs.
    pub(super) cost_min_runs: usize,
}

/// The dials for each project and task type the review meets (agent-mind
/// §3.7): the narrowest owner pin (project, then type, then vault), else the
/// narrowest scoped seed (project, then type), else the vault fit, else the
/// vault seed, else the catalog seed. A finding with no dispatch behind it
/// reads the vault's.
pub(super) struct DialBook {
    vault: Dials,
    scoped: BTreeMap<Option<EntityId>, BTreeMap<String, Dials>>,
}

impl DialBook {
    pub(super) fn read(vault: &Vault, dispatched: &Dispatches) -> Result<Self> {
        let rtxn = vault.store.env.read_txn()?;
        let mut book = Self {
            vault: read_dials(vault, &rtxn, None, None)?,
            scoped: BTreeMap::new(),
        };
        for dispatch in dispatched.values() {
            let types = book.scoped.entry(dispatch.project).or_default();
            if !types.contains_key(&dispatch.type_node) {
                let dials = read_dials(vault, &rtxn, dispatch.project, Some(&dispatch.type_node))?;
                types.insert(dispatch.type_node.clone(), dials);
            }
        }
        Ok(book)
    }

    /// One dispatch's dials; the vault's for none.
    pub(super) fn of(&self, dispatch: Option<&Dispatched>) -> &Dials {
        dispatch
            .and_then(|dispatch| self.scoped.get(&dispatch.project)?.get(&dispatch.type_node))
            .unwrap_or(&self.vault)
    }

    /// The dials of an attempt's dispatch.
    pub(super) fn for_attempt(
        &self,
        dispatched: &Dispatches,
        attempt: Option<AttemptId>,
    ) -> &Dials {
        self.of(attempt.and_then(|attempt| dispatched.get(attempt.as_bytes())))
    }

    /// Whether any scope the review meets is reviewed at all.
    pub(super) fn any_review(&self) -> bool {
        self.vault.review
            || self
                .scoped
                .values()
                .flat_map(BTreeMap::values)
                .any(|dials| dials.review)
    }

    /// Each review window a scope the review meets reads, once.
    pub(super) fn windows(&self) -> BTreeSet<u64> {
        std::iter::once(&self.vault)
            .chain(self.scoped.values().flat_map(BTreeMap::values))
            .map(|dials| dials.window_secs)
            .collect()
    }
}

/// The dials one project and task type resolve to: goal, project, task type,
/// then vault rows (OF-542). A type row matches its node at any tree version.
pub(super) fn read_dials(
    vault: &Vault,
    rtxn: &heed::RoTxn<'_>,
    project: Option<EntityId>,
    type_node: Option<&str>,
) -> Result<Dials> {
    let type_ref = type_node.map(|node_id| crate::learning::TypeRef {
        node_id: node_id.to_owned(),
        tree_version: 0,
    });
    let value = |spec: &SettingSpec| {
        setting_value_in_scope_in_txn(vault, rtxn, spec, project, type_ref.as_ref())
    };
    Ok(Dials {
        review: value(&HEALTH_REVIEW)? >= 0.5,
        loop_repeats: value(&HEALTH_LOOP_REPEATS)?.round() as u64,
        check_fails: value(&HEALTH_CHECK_FAILS)?.round() as u64,
        wait_share: value(&HEALTH_WAIT_SHARE)?,
        wait_secs: (value(&HEALTH_WAIT_MINUTES)? * 60.0).round() as u64,
        silent_secs: (value(&HEALTH_SILENT_MINUTES)? * 60.0).round() as u64,
        widen_denials: value(&HEALTH_WIDEN_DENIALS)?.round() as u64,
        cost_spike: value(&HEALTH_COST_SPIKE)?,
        ttl_secs: (value(&HEALTH_ESCALATE_TTL_HOURS)? * 3600.0).round() as u64,
        card_floor: value(&HEALTH_CARD_FLOOR)?,
        dup_min_cost: value(&HEALTH_DUP_MIN_COST)?.round() as u64,
        owner_copy: value(&HEALTH_OWNER_COPY)? >= 0.5,
        window_secs: (value(&HEALTH_REVIEW_WINDOW_HOURS)? * 3600.0).round() as u64,
        cost_min_runs: (value(&HEALTH_COST_MIN_RUNS)?.round() as usize).max(1),
    })
}
