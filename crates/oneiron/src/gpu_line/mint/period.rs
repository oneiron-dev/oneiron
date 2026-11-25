//! One period's record: its pools, floors, tables and economic digest
//! (design pass 32, sections 3.2 and 4.1).

use std::collections::BTreeMap;

use serde::Serialize;
use sha2::{Digest, Sha256};

use super::policy::{BUILT_RULES, pools};
use super::rules::{even_split, payoff_share, posterior_sampling};
use crate::EntityId;
use crate::entity_id::bytes_to_hex_lower;
use crate::gpu_line::fold::{
    AllowanceRule, AllowanceTable, BudgetPolicy, FamilyFloor, FamilyPayoff, FamilySeat, GpuLine,
    GpuLinePeriod, PeriodAllocation, PinnedMode, RuleRef, SeatAtMint, Side, Track,
};
use crate::gpu_line::{ProposalMiss, TableProposal, TableSource, check_proposal};

/// What one family's rows inside the window say (section 4.3). Row M2-E
/// fills it from the line's arm rows and claims.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct SettledTally {
    /// Rungs confirmed a win.
    pub wins: u64,
    /// Rungs closed a loss.
    pub losses: u64,
    /// Seconds charged to the family's claims, invalid rungs left out.
    pub cost_secs: u64,
    /// Seconds charged to its rungs closed invalid. Box-lost and unattributed
    /// seconds are in no tally.
    pub invalid_secs: u64,
}

/// Why the mint wrote no record.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum MintError {
    #[error("period_out_of_range: the period's bounds do not fit the vault clock")]
    PeriodOutOfRange,
    #[error("the allowance rule {0} is not built yet")]
    RuleNotBuilt(RuleRef),
    /// The vault clock names a period before one this line already minted:
    /// a minted line never reopens an earlier period.
    #[error("period {index} is before period {newest}, which this line already minted")]
    BehindMintedPeriod { index: u32, newest: u32 },
    /// The seats' floors do not fit their side: the line admits nothing
    /// until the owner changes it, and the shortfall is never taken from the
    /// other side.
    #[error("mint_blocked: the {side:?} side cannot fund its seats' floors and reserve")]
    Blocked { side: Side },
    /// The record's pools do not sum to the allowance. Inside the bounds of
    /// a valid line this cannot happen.
    #[error("the period's pools do not sum to its allowance")]
    Unbalanced,
}

/// The id of the host allocation a line's wallet is installed as; its
/// generation is the period index plus one.
#[must_use]
pub fn line_allocation_id(project: &EntityId) -> String {
    format!("gpu-line:{}", project.to_hex())
}

/// Every field of a record the economic digest covers: all but the cohort
/// seed, its commit and `minted_at_ms`.
#[derive(Serialize)]
struct EconomicFields<'a> {
    project: &'a EntityId,
    index: u32,
    start_ms: u64,
    end_ms: u64,
    line_revision: u64,
    policy: &'a BudgetPolicy,
    seats: &'a [SeatAtMint],
    pinned_units: u64,
    unpinned_units: u64,
    floors: &'a [FamilyFloor],
    new_idea_pool: u64,
    reserve: (u64, u64),
    pinned_pool: u64,
    market_pool: u64,
    inputs: &'a [FamilyPayoff],
    inputs_cutoff_ms: u64,
    tables: &'a [AllowanceTable],
    split_remainder: u64,
    allocation: &'a PeriodAllocation,
}

/// sha256 (lower hex) of the record's economic fields as JSON, behind a
/// domain prefix.
#[must_use]
pub fn economic_digest(period: &GpuLinePeriod) -> String {
    let fields = EconomicFields {
        project: &period.project,
        index: period.index,
        start_ms: period.start_ms,
        end_ms: period.end_ms,
        line_revision: period.line_revision,
        policy: &period.policy,
        seats: &period.seats,
        pinned_units: period.pinned_units,
        unpinned_units: period.unpinned_units,
        floors: &period.floors,
        new_idea_pool: period.new_idea_pool,
        reserve: period.reserve,
        pinned_pool: period.pinned_pool,
        market_pool: period.market_pool,
        inputs: &period.inputs,
        inputs_cutoff_ms: period.inputs_cutoff_ms,
        tables: &period.tables,
        split_remainder: period.split_remainder,
        allocation: &period.allocation,
    };
    let mut hasher = Sha256::new();
    hasher.update(b"oneiron.gpu_line.period.economic:v1\n");
    hasher.update(serde_json::to_vec(&fields).expect("a period record serializes"));
    bytes_to_hex_lower(&hasher.finalize())
}

/// Whether `period`'s pools sum to its allowance (section 3.2).
#[must_use]
pub fn period_balances(period: &GpuLinePeriod) -> bool {
    let floors: u128 = period
        .floors
        .iter()
        .map(|floor| u128::from(floor.units))
        .sum();
    let tables: u128 = period
        .tables
        .iter()
        .map(|table| {
            table
                .ceilings
                .iter()
                .map(|(_, units)| u128::from(*units))
                .sum::<u128>()
                + u128::from(table.unallocated)
        })
        .sum();
    let pools = floors
        + u128::from(period.reserve.0)
        + u128::from(period.reserve.1)
        + u128::from(period.new_idea_pool)
        + u128::from(period.pinned_pool)
        + tables
        + u128::from(period.split_remainder);
    pools == u128::from(period.policy.allowance_units)
}

/// Mints the record of period `index` of `line`: the seats it funds, their
/// floors, the reserve, the new-idea pool, the pinned and market pools, and
/// one table of market ceilings per rule in force, each rule taking an equal
/// part of the market pool. `tallies` holds what the rows inside the window
/// say, by family; a family it does not name has none.
///
/// # Errors
///
/// [`MintError`]: the period does not fit the clock, a rule in force is not
/// built, the seats' floors do not fit their side (`mint_blocked`), or the
/// pools do not balance.
pub fn mint_period(
    line: &GpuLine,
    index: u32,
    tallies: &BTreeMap<EntityId, SettledTally>,
    minted_at_ms: u64,
) -> Result<GpuLinePeriod, MintError> {
    mint_period_with_proposal(line, index, tallies, None, minted_at_ms)
}

/// Mints a period, checking its standing proposal against the market pool
/// and seats. A missing or invalid proposal uses the line's fallback rule.
///
/// # Errors
///
/// The same [`MintError`]s as [`mint_period`].
pub fn mint_period_with_proposal(
    line: &GpuLine,
    index: u32,
    tallies: &BTreeMap<EntityId, SettledTally>,
    proposal: Option<&TableProposal>,
    minted_at_ms: u64,
) -> Result<GpuLinePeriod, MintError> {
    let (start_ms, end_ms) = line
        .period_bounds(index)
        .ok_or(MintError::PeriodOutOfRange)?;
    let policy = &line.budget;
    let mut funded: Vec<&FamilySeat> = line
        .families
        .iter()
        .filter(|seat| seat.funded_in(index, policy.new_idea_periods))
        .collect();
    funded.sort_by_key(|seat| seat.project);
    let floored = |seat: &&&FamilySeat| seat.track != Track::NewIdea;
    let pinned_seats = funded
        .iter()
        .filter(floored)
        .filter(|seat| policy.side_of(seat.track) == Side::Pinned)
        .count() as u64;
    let unpinned_seats = funded.iter().filter(floored).count() as u64 - pinned_seats;
    let pools =
        pools(policy, pinned_seats, unpinned_seats).map_err(|side| MintError::Blocked { side })?;
    let seats: Vec<SeatAtMint> = funded
        .iter()
        .map(|seat| SeatAtMint {
            seat: seat.seat,
            family: seat.project,
            track: seat.track,
        })
        .collect();
    let floors: Vec<FamilyFloor> = funded
        .iter()
        .filter(floored)
        .map(|seat| FamilyFloor {
            family: seat.project,
            track: seat.track,
            units: pools.floor_secs,
        })
        .collect();
    let inputs: Vec<FamilyPayoff> = funded
        .iter()
        .map(|seat| {
            let tally = tallies.get(&seat.project).copied().unwrap_or_default();
            FamilyPayoff {
                family: seat.project,
                wins: tally.wins,
                losses: tally.losses,
                cost_secs: tally.cost_secs,
                invalid_secs: tally.invalid_secs,
            }
        })
        .collect();
    // Under floor_plus_market every demand and interest seat shares the
    // market pool; under exclusive only the unpinned side's. A new idea
    // never does.
    let market_inputs: Vec<&FamilyPayoff> = funded
        .iter()
        .zip(&inputs)
        .filter(|(seat, _)| {
            seat.track != Track::NewIdea
                && (policy.pinned_mode == PinnedMode::FloorPlusMarket
                    || policy.side_of(seat.track) == Side::Unpinned)
        })
        .map(|(_, input)| input)
        .collect();
    let rules = policy.rules.len().max(1) as u64;
    let share = pools.market_pool / rules;
    let split_remainder = pools.market_pool % rules;
    let mut tables = Vec::with_capacity(policy.rules.len());
    for rule in &policy.rules {
        if !BUILT_RULES.contains(rule) {
            return Err(MintError::RuleNotBuilt(*rule));
        }
        if rule.rule == AllowanceRule::Proposed {
            tables.push(proposed_table(share, &market_inputs, line, index, proposal));
        } else {
            let (ceilings, unallocated) =
                deterministic_table(*rule, share, &market_inputs, policy, line, index);
            tables.push(AllowanceTable {
                rule: *rule,
                pool_units: share,
                ceilings,
                unallocated,
                source: None,
            });
        }
    }
    let mut record = GpuLinePeriod {
        project: line.project,
        index,
        start_ms,
        end_ms,
        line_revision: line.revision,
        policy: policy.clone(),
        seats,
        pinned_units: pools.pinned_units,
        unpinned_units: pools.unpinned_units,
        floors,
        new_idea_pool: pools.new_idea_pool,
        reserve: (pools.reserve_side, pools.reserve_side),
        pinned_pool: pools.pinned_pool,
        market_pool: pools.market_pool,
        inputs,
        inputs_cutoff_ms: start_ms,
        tables,
        split_remainder,
        cohort_seed_commit: None,
        cohort_seed: None,
        allocation: PeriodAllocation {
            wallet: line.wallet.clone(),
            id: line_allocation_id(&line.project),
            generation: u64::from(index) + 1,
            units: policy.allowance_units,
        },
        economic_digest: String::new(),
        minted_at_ms,
    };
    if !period_balances(&record) {
        return Err(MintError::Unbalanced);
    }
    record.economic_digest = economic_digest(&record);
    Ok(record)
}

fn deterministic_table(
    rule: RuleRef,
    share: u64,
    market_inputs: &[&FamilyPayoff],
    policy: &BudgetPolicy,
    line: &GpuLine,
    index: u32,
) -> (Vec<(EntityId, u64)>, u64) {
    match rule.rule {
        AllowanceRule::PayoffShare => payoff_share(
            share,
            market_inputs,
            policy.first_rung_secs(),
            policy.invalid_cost,
        ),
        AllowanceRule::EvenSplit => even_split(share, market_inputs),
        AllowanceRule::PosteriorSampling => {
            posterior_sampling(share, market_inputs, policy, &line.project, index, rule)
        }
        // A stored line cannot name proposed@1 as its deterministic fallback.
        AllowanceRule::Proposed => (Vec::new(), share),
    }
}

fn proposed_table(
    share: u64,
    market_inputs: &[&FamilyPayoff],
    line: &GpuLine,
    index: u32,
    proposal: Option<&TableProposal>,
) -> AllowanceTable {
    let (cause, note) = if let Some(proposal) =
        proposal.filter(|proposal| proposal.project == line.project && proposal.period == index)
    {
        let market: Vec<_> = market_inputs.iter().map(|input| input.family).collect();
        match check_proposal(proposal, share, &market) {
            Ok((ceilings, unallocated)) => {
                return AllowanceTable {
                    rule: RuleRef::PROPOSED_1,
                    pool_units: share,
                    ceilings,
                    unallocated,
                    source: Some(TableSource::Proposed {
                        proposal: proposal.note.clone(),
                    }),
                };
            }
            Err(cause) => (cause, Some(proposal.note.clone())),
        }
    } else {
        (ProposalMiss::NoneSubmitted, None)
    };
    let fallback = line.budget.proposal_fallback;
    let (ceilings, unallocated) =
        deterministic_table(fallback, share, market_inputs, &line.budget, line, index);
    AllowanceTable {
        rule: RuleRef::PROPOSED_1,
        pool_units: share,
        ceilings,
        unallocated,
        source: Some(TableSource::Replaced {
            by_rule: fallback,
            cause,
            proposal: note,
        }),
    }
}
