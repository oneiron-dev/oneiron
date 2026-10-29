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
//! absorbed the closed parent's holds. A closed hard ancestor stays a cap
//! boundary for its subtree (FIX 9563): no more than its room is drawn
//! through it, and the child's settlement is tallied there too, while only
//! the open ancestor pays, so nothing is charged twice.

use crate::attempt_queue::AttemptId;
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::llm::run_admission::{DeclaredMaximum, JobMaximum, MaximumShown};
use crate::llm::{BudgetExhaustionPolicy, BudgetGuard};

use self::ancestry::{Host, ScopeWalk};
use super::AgentDispatcher;
use super::spend_record::{
    ChildSpend, SCOPE, SpendPayer, SpendRead, SpendRefused, SpendScope, SpendScopeId,
    SpendSettlement, SpendSignal, SpendState,
};
use super::widen_record::invalid;

mod ancestry;
mod closed_scope;

pub(super) use self::ancestry::observe as observe_spend_walk;

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

    /// Raises a persisted lease's hard maximum as its authenticated owner.
    /// The replacement cap makes a replay idempotent. A carved child's
    /// increase is reserved from its parent, never minted past an ancestor.
    pub fn top_up_spend_scope_as_owner(
        &self,
        owner: &crate::consent::AuthenticatedOwner,
        id: &SpendScopeId,
        expected_cap_units: u64,
        maximum: DeclaredMaximum,
        shown: MaximumShown,
    ) -> Result<SpendScope> {
        JobMaximum::start(id.as_str(), maximum.clone(), Some(shown))
            .map_err(|_| invalid("spend lease top-up requires a valid shown maximum"))?;
        let mut txn = self.vault.store.env.write_txn()?;
        let actor = owner.revalidate_in_txn(self.vault, &txn)?;
        let mut scope = SCOPE
            .get(&self.vault.store, &txn, &id.0)?
            .ok_or_else(|| invalid("spend scope is missing"))?;
        if scope.state != SpendState::Open || !scope.hard || scope.unit != maximum.unit {
            return Err(invalid("top up an open hard lease in its existing unit"));
        }
        if maximum.units <= expected_cap_units {
            return Err(invalid("a top-up raises the maximum the owner saw"));
        }
        if scope.cap_units == maximum.units {
            return Ok(scope);
        }
        if scope.cap_units != expected_cap_units {
            return Err(invalid("spend cap changed; read the lease again"));
        }
        if scope
            .payer
            .as_ref()
            .is_some_and(|payer| payer.party != actor)
        {
            return Err(invalid("only the payer may raise its accepted root cap"));
        }
        if let Some(payer) = &mut scope.payer {
            payer.granted_by = actor;
            payer.at_ms = shown.at_ms;
        }
        let additional = maximum.units - scope.cap_units;
        if scope.parent.is_some() {
            // FIX 10541: the increase holds at the booking host and once
            // through each closed hard scope on the way, no more than its room.
            let Host { host, boundaries } = self.host_in_txn(&txn, &scope)?;
            if let Some(refused) = closed_scope::boundary_refusal(&boundaries, additional) {
                return Err(refused.into());
            }
            let mut host = self.make_local_in_txn(&mut txn, host, additional)?;
            host.held_units = host
                .held_units
                .checked_add(additional)
                .ok_or(crate::Error::ArithmeticOverflow("spend lease top-up"))?;
            SCOPE.put(&self.vault.store, &mut txn, &host.scope.0, &host)?;
            closed_scope::hold_through(self, &mut txn, boundaries, additional)?;
        }
        scope.cap_units = maximum.units;
        scope.shown_at_ms = Some(shown.at_ms);
        SCOPE.put(&self.vault.store, &mut txn, &scope.scope.0, &scope)?;
        txn.commit()?;
        Ok(scope)
    }

    /// Reserves `child`'s scope under `parent` in one transaction: units move
    /// from the parent's available into its held units. Refuses only a carve
    /// the nearest hard ancestor cannot cover. A hold larger than what is
    /// available holds what is available; the cap is enforced at spend. The
    /// child keeps `parent` as its parent; a closed parent books at its
    /// nearest open ancestor, through each closed hard scope between, which
    /// holds the reservation too and bounds it to its room (FIX 10541).
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
        let booking = self.booking_in_txn(txn, parent)?;
        let available = self.available_through_in_txn(txn, &booking)?;
        let (amount, hard) = match ask {
            ChildSpend::Carve { cap_units } => {
                if cap_units > available {
                    return Err(SpendRefused::OverCap {
                        scope: closed_scope::refusing_scope(&booking, cap_units),
                        available_units: available,
                        asked_units: cap_units,
                    });
                }
                (cap_units, true)
            }
            ChildSpend::Hold { expected_units } => (expected_units.min(available), false),
        };
        let Host { host, boundaries } = booking;
        let mut host = self.make_local_in_txn(txn, host, amount)?;
        host.held_units = host.held_units.saturating_add(amount);
        SCOPE.put(&self.vault.store, txn, &host.scope.0, &host)?;
        closed_scope::hold_through(self, txn, boundaries, amount)?;
        let scope = SpendScope {
            scope: id,
            parent: Some(parent.clone()),
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
    /// nothing. A charge to a closed scope lands on its nearest open ancestor,
    /// which alone pays, and is tallied at each closed hard scope on the way
    /// (FIX 10541).
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
    /// the existing guard API; a live lease books what it used in parts with
    /// [`Self::record_guard_spend`], each look its part and the rest at the
    /// try's end.
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

    /// Records what a guard from [`Self::guard_for_scope`] used (FIX 11459):
    /// a live lease books each look's part through here, and the rest at the
    /// try's end (`book_rest`). The spend already happened, so each part is
    /// recorded whole: the chain gives what it has, and any excess stays on
    /// `scope` past its cap. The signal tells the host to wrap up or that
    /// the cap is reached.
    pub fn record_guard_spend(
        &self,
        scope: &SpendScopeId,
        guard_used_units: u64,
    ) -> Result<SpendRead> {
        let mut txn = self.vault.store.env.write_txn()?;
        let read = self.record_guard_spend_in_txn(&mut txn, scope, guard_used_units)?;
        txn.commit()?;
        Ok(read)
    }

    /// [`Self::record_guard_spend`] in the caller's transaction (FIX 4453):
    /// the caller's own keyed row, settled in the same commit, makes the
    /// record once-only, so a replay that finds its key gone records nothing.
    pub(crate) fn record_guard_spend_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        scope: &SpendScopeId,
        guard_used_units: u64,
    ) -> Result<SpendRead> {
        let read = self.spend_in_txn(txn, scope, guard_used_units, true)?;
        Ok(read)
    }

    /// Closes a root scope at its tree's end (FIX 4453: a free-time cycle's
    /// next boundary, or its owner clearing it). Nothing is released, since a
    /// root holds no parent's units; spend already made, and its open
    /// children's late spend, still land on it whole. Idempotent; a child
    /// scope is refused.
    pub(crate) fn close_root_spend_scope_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        root: &SpendScopeId,
        now: u64,
    ) -> Result<()> {
        let mut scope = SCOPE
            .get(&self.vault.store, txn, &root.0)?
            .ok_or_else(|| invalid("spend scope is missing"))?;
        if scope.parent.is_some() {
            return Err(invalid("only a root scope closes at its tree's end"));
        }
        if scope.state == SpendState::Closed {
            return Ok(());
        }
        scope.state = SpendState::Closed;
        scope.closed_at = Some(now);
        SCOPE.put(&self.vault.store, txn, &root.0, &scope)
    }

    /// What `scope` may still spend, walking soft scopes up to the nearest
    /// hard ancestor.
    pub fn available_units(&self, scope: &SpendScopeId) -> Result<u64> {
        let txn = self.vault.store.env.read_txn()?;
        let target = self.effective_scope_in_txn(&txn, scope)?;
        self.available_from_in_txn(&txn, &target)
    }

    /// `scope` as a spend would report it, without spending: what is left
    /// under the binding cap and the wrap-up or cap signal in force
    /// (OF-541's budget hold reads it before work starts).
    pub fn spend_read(&self, scope: &SpendScopeId) -> Result<SpendRead> {
        let txn = self.vault.store.env.read_txn()?;
        let target = self.effective_scope_in_txn(&txn, scope)?;
        self.spend_read_in_txn(&txn, &target)
    }

    /// [`Self::spend_read`] in the caller's snapshot.
    pub(crate) fn spend_read_at_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        scope: &SpendScopeId,
    ) -> Result<SpendRead> {
        let target = self.effective_scope_in_txn(txn, scope)?;
        self.spend_read_in_txn(txn, &target)
    }

    /// [`Self::available_units`] in the caller's snapshot.
    pub(crate) fn available_units_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        scope: &SpendScopeId,
    ) -> Result<u64> {
        let target = self.effective_scope_in_txn(txn, scope)?;
        self.available_from_in_txn(txn, &target)
    }

    pub fn read_spend_scope(&self, scope: &SpendScopeId) -> Result<Option<SpendScope>> {
        let txn = self.vault.store.env.read_txn()?;
        SCOPE.get(&self.vault.store, &txn, &scope.0)
    }

    /// The payer consent the root of `scope`'s tree carries (OF-531), with
    /// that root's id: the PERSON a call spending under `scope` bills. `None`
    /// when the root carries none, as a launch no room pays for. A missing
    /// scope or ancestor is an error, never a payer.
    pub fn root_payer(&self, scope: &SpendScopeId) -> Result<Option<(SpendScopeId, SpendPayer)>> {
        let txn = self.vault.store.env.read_txn()?;
        let (_, root) = self
            .scope_with_root_in_txn(&txn, scope)?
            .ok_or_else(|| invalid("spend scope is missing"))?;
        Ok(root.payer.map(|payer| (root.scope, payer)))
    }

    /// The scope an attempt spends under. A retry spends under the scope of
    /// the try it retries: one logical launch, one lease. `None`: unmetered.
    pub fn spend_scope_for_attempt(&self, attempt: AttemptId) -> Result<Option<SpendScopeId>> {
        let txn = self.vault.store.env.read_txn()?;
        self.scope_for_attempt_in_txn(&txn, attempt)
    }

    /// The scope row `attempt` spends under, in the caller's snapshot: a
    /// retry's is the try it retries. `None`: unmetered.
    pub(crate) fn attempt_spend_scope_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        attempt: AttemptId,
    ) -> Result<Option<SpendScope>> {
        match self.scope_for_attempt_in_txn(txn, attempt)? {
            Some(scope) => SCOPE.get(&self.vault.store, txn, &scope.0),
            None => Ok(None),
        }
    }

    /// Settles a child at its attempt's terminal: closes its scope, charges
    /// its spend to its parent, releases the unused hold, folds one
    /// calibration sample for its agent, and settles the exploration-slice
    /// charge of a run a skill trial routed. Idempotent. `None`: the attempt
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
                let Host {
                    mut host,
                    boundaries,
                } = self.host_in_txn(txn, &scope)?;
                // The host held this child's whole cap; it now holds the
                // child's own open children instead, and pays what it spent.
                host.held_units = host
                    .held_units
                    .saturating_sub(scope.cap_units)
                    .saturating_add(scope.held_units);
                host.spent_units = host.spent_units.saturating_add(scope.spent_units);
                SCOPE.put(&self.vault.store, txn, &host.scope.0, &host)?;
                // Each closed hard scope passed keeps its subtree's tally the
                // same way: the host alone pays, so nothing counts twice.
                for mut boundary in boundaries {
                    boundary.held_units = boundary
                        .held_units
                        .saturating_sub(scope.cap_units)
                        .saturating_add(scope.held_units);
                    boundary.spent_units = boundary.spent_units.saturating_add(scope.spent_units);
                    SCOPE.put(&self.vault.store, txn, &boundary.scope.0, &boundary)?;
                }
                Some(host.scope)
            }
        };
        scope.state = SpendState::Closed;
        scope.closed_at = Some(now);
        SCOPE.put(&self.vault.store, txn, &scope.scope.0, &scope)?;
        // A run an exploration trial routed is charged what it spent.
        crate::skill::settle_exploration_route_in_txn(
            self.vault,
            txn,
            *child,
            &scope.unit,
            scope.spent_units,
        )?;
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

    fn spend_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        scope: &SpendScopeId,
        units: u64,
        record_whole: bool,
    ) -> std::result::Result<SpendRead, SpendRefused> {
        let Host {
            host: target,
            boundaries,
        } = self.booking_in_txn(txn, scope)?;
        let drawn = if record_whole {
            units.min(self.available_from_in_txn(txn, &target)?)
        } else {
            units
        };
        let mut target = self.make_local_in_txn(txn, target, drawn)?;
        target.spent_units = target.spent_units.saturating_add(units);
        SCOPE.put(&self.vault.store, txn, &target.scope.0, &target)?;
        closed_scope::tally_through(self, txn, boundaries, units)?;
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
    /// open ancestors, no more through a closed hard scope than its room
    /// (FIX 9563), and returns it for the caller to spend or hold from and
    /// write. The ancestors' and boundaries' moves are written here, and only
    /// once the whole chain is known to cover `need`: a refusal writes
    /// nothing. The chain is read however long it is (rule 5).
    fn make_local_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        scope: SpendScope,
        need: u64,
    ) -> std::result::Result<SpendScope, SpendRefused> {
        // Each entry draws its deficit from the next one up, through the
        // closed hard scopes between them.
        let mut chain: Vec<(SpendScope, u64, Vec<SpendScope>)> = Vec::new();
        let from = scope.scope.clone();
        let mut hosts = std::collections::HashSet::from([from.clone()]);
        let mut walk = ScopeWalk::default();
        let mut current = scope;
        let mut wanted = need;
        let mut reachable = 0u64;
        let drawn = loop {
            let local = current.local_available();
            reachable = reachable.saturating_add(local);
            if local >= wanted {
                chain.push((current, 0, Vec::new()));
                break Ok(());
            }
            if current.hard || current.parent.is_none() {
                break Err(SpendRefused::OverCap {
                    scope: current.scope,
                    available_units: reachable,
                    asked_units: need,
                });
            }
            let deficit = wanted - local;
            let hop = match self.host_in_walk(txn, &current, &mut walk) {
                Ok(hop) => hop,
                Err(error) => break Err(error.into()),
            };
            if !hosts.insert(hop.host.scope.clone()) {
                break Err(invalid("spend scope ancestor cycle").into());
            }
            if let Some(boundary) = hop
                .boundaries
                .iter()
                .find(|boundary| boundary.local_available() < deficit)
            {
                break Err(SpendRefused::OverCap {
                    scope: boundary.scope.clone(),
                    available_units: reachable.saturating_add(boundary.local_available()),
                    asked_units: need,
                });
            }
            chain.push((current, deficit, hop.boundaries));
            current = hop.host;
            wanted = deficit;
        };
        walk.finish(&self.vault.store, txn, &from);
        drawn?;
        for index in 0..chain.len() - 1 {
            let deficit = chain[index].1;
            chain[index].0.cap_units = chain[index].0.cap_units.saturating_add(deficit);
            for boundary in &mut chain[index].2 {
                boundary.held_units = boundary.held_units.saturating_add(deficit);
            }
            chain[index + 1].0.held_units = chain[index + 1].0.held_units.saturating_add(deficit);
        }
        for (index, (scope, _, boundaries)) in chain.iter().enumerate() {
            if index > 0 {
                SCOPE.put(&self.vault.store, txn, &scope.scope.0, scope)?;
            }
            for boundary in boundaries {
                SCOPE.put(&self.vault.store, txn, &boundary.scope.0, boundary)?;
            }
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
