//! The Dreamer's Steward grant and the strength archive, for integration
//! tests (untangle 6.3; X02's test pointed at a narrowed Steward grant).

use crate::attempt_queue::AttemptId;
use crate::dreamer_consolidation::strength::ConsolidationStrengthPolicy;
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::federation::grant_scope;
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

/// Stands `agent`'s Steward grant with `verbs` and marks it, as a first mint
/// leaves it; a later call stands a fresh grant that replaces it.
///
/// # Errors
///
/// The vault's.
pub fn stand_steward_grant(vault: &Vault, agent: EntityId, verbs: &[&str]) -> Result<EntityId> {
    vault.stand_steward_grant_for_test(agent, verbs)
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
