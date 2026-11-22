//! The spend a machine that takes over an agent run reserves for it, from
//! the launch statement the dispatch froze.

use super::*;

/// What a machine that takes over an agent run reserves for it (FIX 4747
/// slice 6).
enum HandedOverReserve {
    Reserve(LaunchReserve),
    /// This machine cannot fund the run as its launch was stated: it waits.
    Unfunded,
}

/// What an agent run another machine dispatched reserves on the machine that
/// takes it over, from the launch statement its dispatch froze (FIX 4747
/// slice 6) less what the machines that ran it committed of it (FIX 4889).
/// Engine call (CALLS, FIX 4747): a launch stated unmetered stays unmetered;
/// a pinned `budget` outside any tree pins what is left of its cap here; a
/// launch under a tree scope this machine holds open, or books at an open
/// ancestor (`tree_here`), reserves under it as the dispatch did, a carve of
/// its budget or a hold of its expected spend. Such a take keeps no open
/// scope of the run, so the carve is the budget less `committed_units`
/// (REVIEW-7890 round 2): a scope of the run that settled here, or one its
/// retry chain here does not reach, never stacks a second whole carve under
/// the tree, and a budget committed in full is unfunded. A tree scope this
/// machine does not hold lives on the machine that opened it, and nothing
/// of it is seeded here: the run gets a pinned hard scope of what its launch reserved
/// from that tree less what the machines that ran it committed of it
/// (`committed_units`, from the run TASK's carry: every scope's spend and
/// open children's holds, this machine's earlier scopes included), so the
/// run never spends past what its launch set aside, counted across the
/// machines that ran it. A launch that reserved nothing there, a room-bound
/// one, whose payer only that tree names, or one committed in full, is
/// unfunded here, and the take waits (canon CROSS-ARCH-0019 item 04: "If no
/// machine can take the run, it pauses").
fn handed_over_launch_reserve(
    statement: &LaunchStatement,
    tree_here: bool,
    room_bound: bool,
    committed_units: u64,
) -> HandedOverReserve {
    let Some(cap_units) = statement.cap_units else {
        return HandedOverReserve::Reserve(LaunchReserve::Unmetered);
    };
    let unit = statement.unit.clone();
    match &statement.parent_scope {
        None => {
            let remaining = cap_units.saturating_sub(committed_units);
            if remaining == 0 {
                HandedOverReserve::Unfunded
            } else {
                HandedOverReserve::Reserve(LaunchReserve::Pinned {
                    unit,
                    cap_units: remaining,
                })
            }
        }
        Some(parent) if tree_here => {
            let ask = if statement.hard {
                let remaining = cap_units.saturating_sub(committed_units);
                if remaining == 0 {
                    return HandedOverReserve::Unfunded;
                }
                ChildSpend::Carve {
                    cap_units: remaining,
                }
            } else {
                ChildSpend::Hold {
                    expected_units: statement.expected.units,
                }
            };
            HandedOverReserve::Reserve(LaunchReserve::Child {
                parent: parent.clone(),
                ask,
            })
        }
        Some(_) if room_bound || statement.reserved_units == 0 => HandedOverReserve::Unfunded,
        Some(_) => {
            let remaining = statement.reserved_units.saturating_sub(committed_units);
            if remaining == 0 {
                HandedOverReserve::Unfunded
            } else {
                HandedOverReserve::Reserve(LaunchReserve::Pinned {
                    unit,
                    cap_units: remaining,
                })
            }
        }
    }
}

impl AgentDispatcher<'_> {
    /// Reserves on this machine the spend of `attempt`, the try of an agent
    /// run this machine takes over, in the take's write (FIX 4747 slice 6),
    /// as `handed_over_launch_reserve` rules from the launch statement
    /// `input` froze, less what the machines that ran it committed of it
    /// (FIX 4889, from the run TASK's `carry`). A scope the run spends under
    /// here through its retry chain is kept when open. On the custody machine
    /// the kept scope folds the other machines' shares (FIX 4889); elsewhere
    /// a kept pinned scope is capped to the remainder. A pinned scope keeps
    /// the Grant `input` froze as its funding (FIX 7766), as the dispatch's
    /// own reserve did. A room-bound run proves its join again under the
    /// scope it reserves under, as its dispatch did. `Unfunded` when this
    /// machine cannot fund it: the take writes nothing, and the run waits.
    ///
    /// # Errors
    ///
    /// Storage errors.
    pub(in crate::agent_dispatch) fn reserve_handed_over_launch_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        attempt: AttemptId,
        input: &AgentDispatchInput,
        carry: Option<&AgentRunSpendCarry>,
        node: u64,
        now: u64,
    ) -> Result<HandedOverLaunchReserve> {
        match self.attempt_spend_scope_in_txn(txn, attempt)? {
            Some(kept) if kept.state == SpendState::Open => {
                return self.keep_handed_over_scope_in_txn(txn, attempt, kept, input, carry, node);
            }
            // A settled scope under the try's own id stands as it is, as
            // before FIX 4889: a second scope under that id is refused.
            Some(kept) if kept.scope == SpendScopeId::for_attempt(&attempt) => {
                return Ok(HandedOverLaunchReserve::Reserved { folded: 0 });
            }
            Some(_) | None => {}
        }
        let committed_units = carry.map_or(0, AgentRunSpendCarry::committed_units);
        let Some(statement) = input.launch.as_ref() else {
            return Ok(HandedOverLaunchReserve::Reserved { folded: 0 });
        };
        let tree_here = match &statement.parent_scope {
            Some(parent) => match SCOPE.get(&self.vault.store, txn, &parent.0)? {
                Some(row) if row.state == SpendState::Open => true,
                Some(_) => self.effective_scope_in_txn(txn, parent)?.state == SpendState::Open,
                None => false,
            },
            None => false,
        };
        let agent = input.target.agent_definition_ref()?;
        match handed_over_launch_reserve(
            statement,
            tree_here,
            input.room.is_some(),
            committed_units,
        ) {
            HandedOverReserve::Unfunded => return Ok(HandedOverLaunchReserve::Unfunded),
            HandedOverReserve::Reserve(LaunchReserve::Unmetered) => {}
            HandedOverReserve::Reserve(LaunchReserve::Pinned { unit, cap_units }) => {
                self.open_pinned_scope_in_txn(
                    txn,
                    &attempt,
                    Some(agent),
                    unit,
                    cap_units,
                    input.funding.clone(),
                    now,
                )?;
            }
            HandedOverReserve::Reserve(LaunchReserve::Child { parent, ask }) => {
                match self.reserve_agent_in_txn(txn, &parent, &attempt, Some(agent), ask, now) {
                    Ok(_) => {}
                    Err(SpendRefused::Engine(error)) => return Err(error),
                    Err(SpendRefused::OverCap { .. } | SpendRefused::Start(_)) => {
                        return Ok(HandedOverLaunchReserve::Unfunded);
                    }
                }
            }
        }
        if input.room.is_some() {
            match self.require_room_join_in_txn(
                txn,
                input.room.as_ref(),
                agent,
                statement.parent_scope.as_ref(),
            ) {
                Ok(_) => {}
                Err(Error::Claim(_) | Error::Artifact(_)) => {
                    return Ok(HandedOverLaunchReserve::Unfunded);
                }
                Err(error) => return Err(error),
            }
        }
        Ok(HandedOverLaunchReserve::Reserved { folded: 0 })
    }
}
