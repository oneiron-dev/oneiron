//! The planner's standing allocation proposal for the next period of a GPU
//! line (design pass 34, section 3.5).

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use super::doors::{GpuLineError, next_mint_index};
use super::doors_caller::{LineCaller, admit_in_txn};
use super::fold::{LineRole, RuleRef};
use super::intent::{IntentAsk, IntentStand};
use super::mint::mint_period_with_proposal;
use super::store::{line_in_txn, mint_first_in_txn};
use crate::consent::AuthenticatedOwner;
use crate::memory::Memory;
use crate::side_table::{self, Named, SideKey, SideTable};
use crate::{EntityId, Vault};

pub(crate) mod tables;

const PROPOSALS: SideTable<(EntityId, u32), TableProposal, Named> =
    SideTable::new(&side_table::GPU_LINE_PROPOSAL);

/// Who proposed a table.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case", tag = "kind")]
pub enum ProposalAuthor {
    Owner,
    Grant { grant: EntityId },
}

/// Who proposed a table, why, and when.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct ProposalNote {
    pub by: ProposalAuthor,
    pub why: String,
    pub submitted_at_ms: u64,
}

/// Why the mint did not use a proposed table.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ProposalMiss {
    NoneSubmitted,
    PoolMismatch,
    FamilyNotSeated,
    FamilyListedTwice,
    DoesNotConserve,
}

/// Where a `proposed@1` table came from.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case", tag = "source")]
pub enum TableSource {
    /// The planner's table, as proposed.
    Proposed { proposal: ProposalNote },
    /// The fallback rule's table: no proposal, or one that failed the check.
    Replaced {
        by_rule: RuleRef,
        cause: ProposalMiss,
        proposal: Option<ProposalNote>,
    },
}

/// The stored row: the standing proposal for one period.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct TableProposal {
    pub project: EntityId,
    pub period: u32,
    pub pool_units: u64,
    pub ceilings: Vec<(EntityId, u64)>,
    pub unallocated: u64,
    pub note: ProposalNote,
}

/// The mint checks that every family is seated, every ceiling is at least
/// zero, and the ceilings plus `unallocated` equal the pool. Returns ceilings
/// by family id, including zero for any market family not named, and what
/// was left unallocated.
///
/// # Errors
///
/// A family is named twice or is not seated in the market, the stated pool
/// differs from the rule's share, or the table does not conserve the pool.
pub fn check_proposal(
    proposal: &TableProposal,
    pool: u64,
    market: &[EntityId],
) -> Result<(Vec<(EntityId, u64)>, u64), ProposalMiss> {
    let mut ceilings = BTreeMap::new();
    for &(family, units) in &proposal.ceilings {
        if ceilings.insert(family, units).is_some() {
            return Err(ProposalMiss::FamilyListedTwice);
        }
    }
    if ceilings.keys().any(|family| !market.contains(family)) {
        return Err(ProposalMiss::FamilyNotSeated);
    }
    if proposal.pool_units != pool {
        return Err(ProposalMiss::PoolMismatch);
    }
    let given: u128 = ceilings.values().copied().map(u128::from).sum();
    if given + u128::from(proposal.unallocated) != u128::from(proposal.pool_units) {
        return Err(ProposalMiss::DoesNotConserve);
    }
    for &family in market {
        ceilings.entry(family).or_default();
    }
    Ok((ceilings.into_iter().collect(), proposal.unallocated))
}

pub(crate) fn proposal_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    project: &EntityId,
    period: u32,
) -> crate::Result<Option<TableProposal>> {
    PROPOSALS.get(&vault.store, txn, &(*project, period))
}

fn put_proposal_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    proposal: &TableProposal,
) -> crate::Result<()> {
    PROPOSALS.put(
        &vault.store,
        txn,
        &(proposal.project, proposal.period),
        proposal,
    )
}

/// Proposes the next period's table of market ceilings.
pub const VAULT_GPU_LINES_TABLES_PROPOSE: &str = "vault.gpu.lines.tables.propose";

/// `vault.gpu.lines.tables.propose`: set the standing table for the next mint.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct GpuLineTableProposeRequest {
    /// Names this ask. Repeating it answers the standing proposal for this period.
    pub intent_key: String,
    /// The lane project.
    pub project: EntityId,
    /// The next period's index.
    pub period: u32,
    /// The share of the market pool that `proposed@1` divides.
    pub pool_units: u64,
    /// The units each named market family may draw. Unnamed families get zero.
    pub ceilings: Vec<(EntityId, u64)>,
    /// The units the table leaves unspent.
    pub unallocated: u64,
    /// Why the planner or owner chose this division.
    pub why: String,
}

/// Why the proposal door refused a table.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum ProposalRefusal {
    #[error("rule_not_in_force: the line's rules do not include proposed@1")]
    RuleNotInForce,
    #[error("period_not_next: a table is proposed only for the next period, {next}")]
    PeriodNotNext { next: u32 },
    #[error("why_too_long: a proposal's reason is at most {max} bytes")]
    WhyTooLong { max: u32 },
    #[error("pool_mismatch: the next mint gives proposed@1 a pool of {expected}")]
    PoolMismatch { expected: u64 },
    #[error("family_not_seated: a named family has no market seat in the next period")]
    FamilyNotSeated,
    #[error("family_listed_twice: a proposed table names a family more than once")]
    FamilyListedTwice,
    #[error("does_not_conserve: the ceilings plus unallocated do not equal the pool")]
    DoesNotConserve,
    #[error("proposal_gone: the kept proposal is no longer stored")]
    Gone,
}

impl Memory<'_> {
    /// `vault.gpu.lines.tables.propose`: the planner or owner submits a table
    /// for the next period. The mint checks it again when that period begins.
    ///
    /// # Errors
    ///
    /// [`GpuLineError`]: a caller who is not the owner or a planner of this
    /// line, a refused intent key, no line, or a proposal that does not fit
    /// the next mint. The current period is minted first and stays minted.
    pub fn propose_gpu_line_table(
        &self,
        owner: Option<&AuthenticatedOwner>,
        request: &GpuLineTableProposeRequest,
        now_ms: u64,
    ) -> Result<TableProposal, GpuLineError> {
        let vault = self.vault();
        let ask = IntentAsk::new(
            self.actor(),
            VAULT_GPU_LINES_TABLES_PROPOSE,
            &request.intent_key,
            &(
                request.project,
                request.period,
                request.pool_units,
                &request.ceilings,
                request.unallocated,
                &request.why,
            ),
        )
        .map_err(GpuLineError::Intent)?;
        vault.with_write_txn_grouped(
            |txn| -> crate::Result<Result<TableProposal, GpuLineError>> {
                let caller = match admit_in_txn(
                    self,
                    txn,
                    owner,
                    VAULT_GPU_LINES_TABLES_PROPOSE,
                    request.project,
                ) {
                    Ok(caller) => caller,
                    Err(refusal) => return Ok(Err(GpuLineError::Caller(refusal))),
                };
                // Judge the caller's role on the stored line before allowing replay or mint.
                let Some(stored) = line_in_txn(vault, txn, &request.project)? else {
                    return Ok(Err(GpuLineError::NoLine));
                };
                if let Err(refusal) = caller.require_role(
                    &stored,
                    &[LineRole::Planner],
                    VAULT_GPU_LINES_TABLES_PROPOSE,
                ) {
                    return Ok(Err(GpuLineError::Caller(refusal)));
                }
                match ask.stand_in_txn(vault, txn)? {
                    Err(refused) => return Ok(Err(GpuLineError::Intent(refused))),
                    Ok(IntentStand::Replayed(_)) => {
                        return Ok(
                            proposal_in_txn(vault, txn, &request.project, request.period)?
                                .ok_or(GpuLineError::Proposal(ProposalRefusal::Gone)),
                        );
                    }
                    Ok(IntentStand::New) => {}
                }
                let minted = match mint_first_in_txn(vault, txn, &request.project, now_ms)? {
                    Ok(Some(minted)) => minted,
                    Ok(None) => return Ok(Err(GpuLineError::NoLine)),
                    Err(refusal) => return Ok(Err(GpuLineError::Mint(refusal))),
                };
                let next = match next_mint_index(&minted) {
                    Ok(next) => next,
                    Err(refusal) => return Ok(Err(refusal)),
                };
                if request.period != next {
                    return Ok(Err(ProposalRefusal::PeriodNotNext { next }.into()));
                }
                let line = minted.line;
                if !line.budget.rules.contains(&RuleRef::PROPOSED_1) {
                    return Ok(Err(ProposalRefusal::RuleNotInForce.into()));
                }
                let max = line.budget.proposal_why_max_bytes;
                if request.why.len() > max as usize {
                    return Ok(Err(ProposalRefusal::WhyTooLong { max }.into()));
                }
                let proposal = TableProposal {
                    project: request.project,
                    period: request.period,
                    pool_units: request.pool_units,
                    ceilings: request.ceilings.clone(),
                    unallocated: request.unallocated,
                    note: ProposalNote {
                        by: match caller {
                            LineCaller::Owner(_) => ProposalAuthor::Owner,
                            LineCaller::Agent { grant } => ProposalAuthor::Grant { grant },
                        },
                        why: request.why.clone(),
                        submitted_at_ms: now_ms,
                    },
                };
                // The pool and its market seats do not read the tallies.
                let preview = match mint_period_with_proposal(
                    &line,
                    next,
                    &BTreeMap::new(),
                    Some(&proposal),
                    now_ms,
                ) {
                    Ok(preview) => preview,
                    Err(refusal) => return Ok(Err(GpuLineError::Mint(refusal))),
                };
                let Some(table) = preview
                    .tables
                    .iter()
                    .find(|table| table.rule == RuleRef::PROPOSED_1)
                else {
                    return Ok(Err(ProposalRefusal::RuleNotInForce.into()));
                };
                if let Some(TableSource::Replaced { cause, .. }) = &table.source {
                    let refusal = match cause {
                        // The preview received the proposal for this exact line and period.
                        ProposalMiss::NoneSubmitted => ProposalRefusal::RuleNotInForce,
                        ProposalMiss::PoolMismatch => ProposalRefusal::PoolMismatch {
                            expected: table.pool_units,
                        },
                        ProposalMiss::FamilyNotSeated => ProposalRefusal::FamilyNotSeated,
                        ProposalMiss::FamilyListedTwice => ProposalRefusal::FamilyListedTwice,
                        ProposalMiss::DoesNotConserve => ProposalRefusal::DoesNotConserve,
                    };
                    return Ok(Err(refusal.into()));
                }
                put_proposal_in_txn(vault, txn, &proposal)?;
                let mut written = Vec::new();
                (proposal.project, proposal.period).encode_into(&mut written);
                ask.keep_in_txn(vault, txn, written, now_ms)?;
                Ok(Ok(proposal))
            },
        )?
    }
}
