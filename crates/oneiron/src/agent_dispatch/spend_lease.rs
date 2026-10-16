//! Spend scopes: each launch's lease tree under one hard cap (OF-532,
//! ARCH-0079 #budget, #reader-forks).
//!
//! A root scope holds the cap the customer set and saw at the launch's start,
//! under the same two start conditions [`JobMaximum::start`] enforces. Every
//! agent the tree launches reserves a child scope under its parent's, in the
//! launch's own transaction: a carve when its spawn set `budget` (a hard cap
//! it can never pass), else a hold of its calibrated expected spend that may
//! top up from the parent chain, up to the nearest hard ancestor's cap.
//!
//! Count is never the cap. There is no width gate, no child limit and no
//! refusal for an estimate: the only refusal is
//! [`SpendRefused::OverCap`], spend or a carve the cap cannot cover. Spend
//! already made is recorded whole, never truncated.
//!
//! A scope whose parent closed while it stayed open (a child outliving its
//! spawner) settles into, and tops up from, the nearest open ancestor, which
//! absorbed the closed parent's holds.

use crate::attempt_queue::{AttemptId, AttemptQueue};
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::llm::run_admission::{DeclaredMaximum, JobMaximum, MaximumShown};
use crate::llm::{BudgetExhaustionPolicy, BudgetGuard};

use super::AgentDispatcher;
use super::spend_record::{
    ChildSpend, MAX_SPEND_DEPTH, SCOPE, SpendPayer, SpendRead, SpendRefused, SpendScope,
    SpendScopeId, SpendSettlement, SpendSignal, SpendState,
};
use super::widen_record::invalid;

impl AgentDispatcher<'_> {
    /// Opens a launch's root scope under the cap the customer set and was
    /// shown at its start. Refuses a cap that was not shown, and a zero cap.
    /// Re-opening the same root with the same cap returns it unchanged.
    pub fn open_root_spend_scope(
        &self,
        launch: SpendScopeId,
        maximum: DeclaredMaximum,
        shown: Option<MaximumShown>,
        now: u64,
    ) -> std::result::Result<SpendScope, SpendRefused> {
        let mut txn = self.vault.store.env.write_txn()?;
        let scope = self.open_root_spend_scope_in_txn(&mut txn, launch, maximum, shown, now)?;
        txn.commit()?;
        Ok(scope)
    }

    pub fn open_root_spend_scope_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        launch: SpendScopeId,
        maximum: DeclaredMaximum,
        shown: Option<MaximumShown>,
        now: u64,
    ) -> std::result::Result<SpendScope, SpendRefused> {
        self.open_root_in_txn(txn, launch, maximum, shown, None, now)
    }

    /// [`Self::open_root_spend_scope`] for a tree a payer funds (OF-531):
    /// `payer` was shown this cap for this scope and accepted it, and the root
    /// records that consent. Refuses a payer that is not a live PERSON, or a
    /// grantor that is neither the payer nor an actor anchored to the payer.
    /// Re-opening the same root with the same cap and payer returns it.
    pub fn open_root_spend_scope_for_payer(
        &self,
        launch: SpendScopeId,
        maximum: DeclaredMaximum,
        shown: Option<MaximumShown>,
        payer: SpendPayer,
        now: u64,
    ) -> std::result::Result<SpendScope, SpendRefused> {
        let mut txn = self.vault.store.env.write_txn()?;
        let scope = self
            .open_root_spend_scope_for_payer_in_txn(&mut txn, launch, maximum, shown, payer, now)?;
        txn.commit()?;
        Ok(scope)
    }

    pub fn open_root_spend_scope_for_payer_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        launch: SpendScopeId,
        maximum: DeclaredMaximum,
        shown: Option<MaximumShown>,
        payer: SpendPayer,
        now: u64,
    ) -> std::result::Result<SpendScope, SpendRefused> {
        if !payer_binds_in_txn(self.vault, txn, &payer)? {
            return Err(invalid("the payer's consent is not bound to the payer").into());
        }
        self.open_root_in_txn(txn, launch, maximum, shown, Some(payer), now)
    }

    fn open_root_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        launch: SpendScopeId,
        maximum: DeclaredMaximum,
        shown: Option<MaximumShown>,
        payer: Option<SpendPayer>,
        now: u64,
    ) -> std::result::Result<SpendScope, SpendRefused> {
        // The owner's start conditions are JobMaximum's; one rule, one place.
        JobMaximum::start(launch.as_str(), maximum.clone(), shown).map_err(SpendRefused::Start)?;
        SpendScopeId::launch(launch.as_str())?;
        if let Some(existing) = SCOPE.get(&self.vault.store, txn, &launch.0)? {
            if existing.parent.is_none()
                && existing.hard
                && existing.unit == maximum.unit
                && existing.cap_units == maximum.units
                && existing.payer == payer
            {
                return Ok(existing);
            }
            return Err(
                invalid("the launch's spend scope exists with another cap or payer").into(),
            );
        }
        let scope = SpendScope {
            scope: launch,
            parent: None,
            unit: maximum.unit,
            cap_units: maximum.units,
            hard: true,
            spent_units: 0,
            held_units: 0,
            state: SpendState::Open,
            shown_at_ms: shown.map(|shown| shown.at_ms),
            opened_at: now,
            closed_at: None,
            agent: None,
            payer,
        };
        SCOPE.put(&self.vault.store, txn, &scope.scope.0, &scope)?;
        Ok(scope)
    }

    /// Reserves `child`'s scope under `parent` in one transaction: units move
    /// from the parent's available into its held units. Refuses only a carve
    /// the nearest hard ancestor cannot cover. A hold larger than what is
    /// available holds what is available; the cap is enforced at spend.
    pub fn reserve_child_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        parent: &SpendScopeId,
        child: &AttemptId,
        ask: ChildSpend,
        now: u64,
    ) -> std::result::Result<SpendScope, SpendRefused> {
        self.reserve_agent_in_txn(txn, parent, child, None, ask, now)
    }

    /// [`Self::reserve_child_in_txn`] for an agent launch: its settlement
    /// calibrates `agent`.
    pub(super) fn reserve_agent_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        parent: &SpendScopeId,
        child: &AttemptId,
        agent: Option<EntityId>,
        ask: ChildSpend,
        now: u64,
    ) -> std::result::Result<SpendScope, SpendRefused> {
        let id = SpendScopeId::for_attempt(child);
        if SCOPE.contains(&self.vault.store, txn, &id.0)? {
            return Err(invalid("the child's spend scope is already reserved").into());
        }
        let host = self.effective_scope_in_txn(txn, parent)?;
        let available = self.available_from_in_txn(txn, &host)?;
        let (amount, hard) = match ask {
            ChildSpend::Carve { cap_units } => {
                if cap_units > available {
                    return Err(SpendRefused::OverCap {
                        scope: host.scope,
                        available_units: available,
                        asked_units: cap_units,
                    });
                }
                (cap_units, true)
            }
            ChildSpend::Hold { expected_units } => (expected_units.min(available), false),
        };
        let mut host = self.make_local_in_txn(txn, host, amount)?;
        host.held_units = host.held_units.saturating_add(amount);
        SCOPE.put(&self.vault.store, txn, &host.scope.0, &host)?;
        let scope = SpendScope {
            scope: id,
            parent: Some(host.scope),
            unit: host.unit,
            cap_units: amount,
            hard,
            spent_units: 0,
            held_units: 0,
            state: SpendState::Open,
            shown_at_ms: None,
            opened_at: now,
            closed_at: None,
            agent,
            payer: None,
        };
        SCOPE.put(&self.vault.store, txn, &scope.scope.0, &scope)?;
        Ok(scope)
    }

    /// A launch's own hard scope outside any tree: the spawn pinned `budget`
    /// and its parent spends unmetered. It narrows; it grants nothing.
    pub(super) fn open_pinned_scope_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        attempt: &AttemptId,
        agent: Option<EntityId>,
        unit: crate::llm::run_admission::LeaseUnit,
        cap_units: u64,
        now: u64,
    ) -> Result<SpendScope> {
        let id = SpendScopeId::for_attempt(attempt);
        if SCOPE.contains(&self.vault.store, txn, &id.0)? {
            return Err(invalid("the launch's spend scope is already reserved"));
        }
        let scope = SpendScope {
            scope: id,
            parent: None,
            unit,
            cap_units,
            hard: true,
            spent_units: 0,
            held_units: 0,
            state: SpendState::Open,
            shown_at_ms: None,
            opened_at: now,
            closed_at: None,
            agent,
            payer: None,
        };
        SCOPE.put(&self.vault.store, txn, &scope.scope.0, &scope)?;
        Ok(scope)
    }

    /// Spends `units` against `scope`. A soft scope past its hold draws the
    /// excess from its parent chain; a hard scope, or the hard ancestor the
    /// chain reaches, refuses with [`SpendRefused::OverCap`] and records
    /// nothing. A charge to a closed scope lands on its nearest open ancestor.
    pub fn charge_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        scope: &SpendScopeId,
        units: u64,
    ) -> std::result::Result<SpendRead, SpendRefused> {
        self.spend_in_txn(txn, scope, units, false)
    }

    /// [`Self::charge_in_txn`] in its own transaction.
    pub fn charge(
        &self,
        scope: &SpendScopeId,
        units: u64,
    ) -> std::result::Result<SpendRead, SpendRefused> {
        let mut txn = self.vault.store.env.write_txn()?;
        let read = self.charge_in_txn(&mut txn, scope, units)?;
        txn.commit()?;
        Ok(read)
    }

    /// A guard a host runs `scope`'s model calls under: its limit is what the
    /// scope may still spend, and it suspends at that limit. Built only from
    /// the existing guard API; record what it used with
    /// [`Self::record_guard_spend`].
    pub fn guard_for_scope(&self, scope: &SpendScopeId) -> Result<BudgetGuard> {
        let txn = self.vault.store.env.read_txn()?;
        let target = self.effective_scope_in_txn(&txn, scope)?;
        let available = self.available_from_in_txn(&txn, &target)?;
        Ok(BudgetGuard::new(
            scope.as_str(),
            available,
            BudgetExhaustionPolicy::Suspend,
        ))
    }

    /// Records what a guard from [`Self::guard_for_scope`] used, once, when
    /// the guard is done. The spend already happened, so it is recorded whole:
    /// the chain gives what it has, and any excess stays on `scope` past its
    /// cap. The signal tells the host to wrap up or that the cap is reached.
    pub fn record_guard_spend(
        &self,
        scope: &SpendScopeId,
        guard_used_units: u64,
    ) -> Result<SpendRead> {
        let mut txn = self.vault.store.env.write_txn()?;
        let read = self.spend_in_txn(&mut txn, scope, guard_used_units, true)?;
        txn.commit()?;
        Ok(read)
    }

    /// What `scope` may still spend, walking soft scopes up to the nearest
    /// hard ancestor.
    pub fn available_units(&self, scope: &SpendScopeId) -> Result<u64> {
        let txn = self.vault.store.env.read_txn()?;
        let target = self.effective_scope_in_txn(&txn, scope)?;
        self.available_from_in_txn(&txn, &target)
    }

    pub fn read_spend_scope(&self, scope: &SpendScopeId) -> Result<Option<SpendScope>> {
        let txn = self.vault.store.env.read_txn()?;
        SCOPE.get(&self.vault.store, &txn, &scope.0)
    }

    /// `scope` and the root it spends under, in the caller's snapshot; `None`
    /// when no such scope exists. The root's payer is the only consent a tree
    /// carries (OF-531): a cap or an open scope is none.
    pub(crate) fn scope_with_root_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        scope: &SpendScopeId,
    ) -> Result<Option<(SpendScope, SpendScope)>> {
        let Some(row) = SCOPE.get(&self.vault.store, txn, &scope.0)? else {
            return Ok(None);
        };
        let mut root = row.clone();
        for _ in 0..MAX_SPEND_DEPTH {
            let Some(parent) = root.parent.clone() else {
                return Ok(Some((row, root)));
            };
            root = SCOPE
                .get(&self.vault.store, txn, &parent.0)?
                .ok_or_else(|| invalid("spend scope ancestor is missing"))?;
        }
        Err(invalid("spend scope ancestor bound"))
    }

    /// The scope an attempt spends under. A retry spends under the scope of
    /// the try it retries: one logical launch, one lease. `None`: unmetered.
    pub fn spend_scope_for_attempt(&self, attempt: AttemptId) -> Result<Option<SpendScopeId>> {
        let txn = self.vault.store.env.read_txn()?;
        self.scope_for_attempt_in_txn(&txn, attempt)
    }

    /// Settles a child at its attempt's terminal: closes its scope, charges
    /// its spend to its parent, releases the unused hold, and folds one
    /// calibration sample for its agent. Idempotent. `None`: the attempt
    /// launched unmetered.
    pub fn settle_child_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        child: &AttemptId,
        now: u64,
    ) -> Result<Option<SpendSettlement>> {
        let Some(id) = self.scope_for_attempt_in_txn(txn, *child)? else {
            return Ok(None);
        };
        let mut scope = SCOPE
            .get(&self.vault.store, txn, &id.0)?
            .ok_or_else(|| invalid("spend scope is missing"))?;
        if scope.state == SpendState::Closed {
            return Ok(Some(SpendSettlement {
                scope: id,
                charged_to: None,
                spent_units: scope.spent_units,
                released_units: 0,
                already_settled: true,
            }));
        }
        let released = scope
            .cap_units
            .saturating_sub(scope.spent_units.saturating_add(scope.held_units));
        let charged_to = match &scope.parent {
            None => None,
            Some(_) => {
                let mut host = self.open_parent_in_txn(txn, &scope)?;
                // The host held this child's whole cap; it now holds the
                // child's own open children instead, and pays what it spent.
                host.held_units = host
                    .held_units
                    .saturating_sub(scope.cap_units)
                    .saturating_add(scope.held_units);
                host.spent_units = host.spent_units.saturating_add(scope.spent_units);
                SCOPE.put(&self.vault.store, txn, &host.scope.0, &host)?;
                Some(host.scope)
            }
        };
        scope.state = SpendState::Closed;
        scope.closed_at = Some(now);
        SCOPE.put(&self.vault.store, txn, &scope.scope.0, &scope)?;
        if let Some(agent) = scope.agent {
            self.fold_spend_sample_in_txn(txn, agent, &scope.unit, scope.spent_units, now)?;
        }
        Ok(Some(SpendSettlement {
            scope: id,
            charged_to,
            spent_units: scope.spent_units,
            released_units: released,
            already_settled: false,
        }))
    }

    /// [`Self::settle_child_in_txn`] in its own transaction.
    pub fn settle_child(&self, child: &AttemptId, now: u64) -> Result<Option<SpendSettlement>> {
        let mut txn = self.vault.store.env.write_txn()?;
        let settlement = self.settle_child_in_txn(&mut txn, child, now)?;
        txn.commit()?;
        Ok(settlement)
    }

    pub(super) fn scope_for_attempt_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        attempt: AttemptId,
    ) -> Result<Option<SpendScopeId>> {
        let queue = AttemptQueue::new(self.vault);
        let mut cursor = attempt;
        for _ in 0..1024 {
            let id = SpendScopeId::for_attempt(&cursor);
            if SCOPE.contains(&self.vault.store, txn, &id.0)? {
                return Ok(Some(id));
            }
            match queue.get_in_txn(txn, cursor)?.and_then(|row| row.retry_of) {
                Some(previous) => cursor = previous,
                None => return Ok(None),
            }
        }
        Err(invalid("spend scope retry lineage bound"))
    }

    /// The scope that books `scope`'s spend: itself when open, else its
    /// nearest open ancestor; when nothing above is open either, itself.
    pub(super) fn effective_scope_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        scope: &SpendScopeId,
    ) -> Result<SpendScope> {
        let row = SCOPE
            .get(&self.vault.store, txn, &scope.0)?
            .ok_or_else(|| invalid("spend scope is missing"))?;
        if row.state == SpendState::Open {
            return Ok(row);
        }
        Ok(self.nearest_open_above_in_txn(txn, &row)?.unwrap_or(row))
    }

    /// The scope that books for `scope`'s parent: its nearest open ancestor;
    /// when every ancestor is closed, the direct parent keeps the books.
    pub(super) fn open_parent_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        scope: &SpendScope,
    ) -> Result<SpendScope> {
        if let Some(open) = self.nearest_open_above_in_txn(txn, scope)? {
            return Ok(open);
        }
        let parent = scope
            .parent
            .as_ref()
            .ok_or_else(|| invalid("spend scope has no parent"))?;
        SCOPE
            .get(&self.vault.store, txn, &parent.0)?
            .ok_or_else(|| invalid("spend scope ancestor is missing"))
    }

    fn nearest_open_above_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        scope: &SpendScope,
    ) -> Result<Option<SpendScope>> {
        let mut cursor = scope.parent.clone();
        for _ in 0..MAX_SPEND_DEPTH {
            let Some(id) = cursor else {
                return Ok(None);
            };
            let row = SCOPE
                .get(&self.vault.store, txn, &id.0)?
                .ok_or_else(|| invalid("spend scope ancestor is missing"))?;
            if row.state == SpendState::Open {
                return Ok(Some(row));
            }
            cursor = row.parent;
        }
        Err(invalid("spend scope ancestor bound"))
    }

    /// What `scope` may spend: its own local units, plus, while it is soft,
    /// its open ancestors' up to and including the nearest hard one.
    pub(super) fn available_from_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        scope: &SpendScope,
    ) -> Result<u64> {
        let mut total = 0u64;
        let mut current = scope.clone();
        for _ in 0..MAX_SPEND_DEPTH {
            total = total.saturating_add(current.local_available());
            if current.hard || current.parent.is_none() {
                return Ok(total);
            }
            current = self.open_parent_in_txn(txn, &current)?;
        }
        Err(invalid("spend scope ancestor bound"))
    }

    /// The hard scope whose cap binds `scope`: itself when hard, else its
    /// nearest hard open ancestor.
    pub(super) fn binding_cap_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        scope: &SpendScope,
    ) -> Result<SpendScope> {
        let mut current = scope.clone();
        for _ in 0..MAX_SPEND_DEPTH {
            if current.hard || current.parent.is_none() {
                return Ok(current);
            }
            current = self.open_parent_in_txn(txn, &current)?;
        }
        Err(invalid("spend scope ancestor bound"))
    }

    fn spend_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        scope: &SpendScopeId,
        units: u64,
        record_whole: bool,
    ) -> std::result::Result<SpendRead, SpendRefused> {
        let target = self.effective_scope_in_txn(txn, scope)?;
        let drawn = if record_whole {
            units.min(self.available_from_in_txn(txn, &target)?)
        } else {
            units
        };
        let mut target = self.make_local_in_txn(txn, target, drawn)?;
        target.spent_units = target.spent_units.saturating_add(units);
        SCOPE.put(&self.vault.store, txn, &target.scope.0, &target)?;
        Ok(self.spend_read_in_txn(txn, &target)?)
    }

    fn spend_read_in_txn(&self, txn: &heed::RoTxn<'_>, scope: &SpendScope) -> Result<SpendRead> {
        let available = self.available_from_in_txn(txn, scope)?;
        let binding = self.binding_cap_in_txn(txn, scope)?;
        let signal = if available == 0 {
            Some(SpendSignal::AtCap {
                cap_units: binding.cap_units,
            })
        } else if u128::from(available) * 100 <= u128::from(binding.cap_units) * 5 {
            Some(SpendSignal::WrapUp {
                available_units: available,
                cap_units: binding.cap_units,
            })
        } else {
            None
        };
        Ok(SpendRead {
            scope: scope.scope.clone(),
            unit: scope.unit.clone(),
            spent_units: scope.spent_units,
            available_units: available,
            cap_scope: binding.scope,
            cap_units: binding.cap_units,
            signal,
        })
    }

    /// Makes `need` units local to `scope`, topping a soft scope up from its
    /// open ancestors, and returns it for the caller to spend or hold from and
    /// write. The ancestors' moves are written here, and only once the whole
    /// chain is known to cover `need`: a refusal writes nothing.
    fn make_local_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        scope: SpendScope,
        need: u64,
    ) -> std::result::Result<SpendScope, SpendRefused> {
        // Each entry draws its deficit from the next one up.
        let mut chain: Vec<(SpendScope, u64)> = Vec::new();
        let mut current = scope;
        let mut wanted = need;
        let mut reachable = 0u64;
        loop {
            let local = current.local_available();
            reachable = reachable.saturating_add(local);
            if local >= wanted {
                chain.push((current, 0));
                break;
            }
            if current.hard || current.parent.is_none() || chain.len() >= MAX_SPEND_DEPTH {
                return Err(SpendRefused::OverCap {
                    scope: current.scope,
                    available_units: reachable,
                    asked_units: need,
                });
            }
            let deficit = wanted - local;
            let parent = self.open_parent_in_txn(txn, &current)?;
            chain.push((current, deficit));
            current = parent;
            wanted = deficit;
        }
        for index in 0..chain.len() - 1 {
            let deficit = chain[index].1;
            chain[index].0.cap_units = chain[index].0.cap_units.saturating_add(deficit);
            chain[index + 1].0.held_units = chain[index + 1].0.held_units.saturating_add(deficit);
        }
        for (ancestor, _) in &chain[1..] {
            SCOPE.put(&self.vault.store, txn, &ancestor.scope.0, ancestor)?;
        }
        Ok(chain.swap_remove(0).0)
    }
}

/// Whether `payer`'s evidence binds its grantor to the payer: the payer is a
/// live PERSON, and the grantor is that PERSON or an actor whose stored
/// subject anchor names it. Read from stored bindings, never from labels.
pub(crate) fn payer_binds_in_txn(
    vault: &crate::Vault,
    txn: &heed::RoTxn<'_>,
    payer: &SpendPayer,
) -> Result<bool> {
    if !crate::consent::person_is_live_in_txn(vault, txn, &payer.party)? {
        return Ok(false);
    }
    let at = vault.store.clock.now_recorded_at();
    Ok(
        crate::workspace_roster::person_of_actor_in_txn(vault, txn, payer.granted_by, at)?
            == Some(payer.party),
    )
}
