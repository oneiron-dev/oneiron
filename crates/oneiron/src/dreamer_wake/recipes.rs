//! Row-backed spending for the three wake recipes.

use serde::{Deserialize, Serialize};

use crate::conversation_dag::{ScopePath, ScopeSelector};
use crate::dreamer_runner::{DreamerAdmittedAttempt, DreamerRunnerStore};
use crate::scope_summary::{ScopeSummaryRequest, ScopeSummaryTarget};
use crate::side_table::{self, LegacyJson, SideTable};
use crate::{Error, Result, Vault};

use super::sieve;

const POLICY: SideTable<(), WakeRecipePolicy, LegacyJson> =
    SideTable::new(&side_table::DREAMER_WAKE_RECIPE_POLICY);

/// Per-receipt work budgets. Unspent interest stays in the queue.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct WakeRecipePolicy {
    pub continuous_rung_spans: u32,
    pub nightly_spans: u32,
    pub nightly_children: u32,
    pub rung_retry_secs: u64,
    /// Independent probability of sampling each retained rule span, in percent.
    pub audit_percent: u8,
    pub audit_spans: u32,
    /// Instructions are vault configuration, not Rust prompt constants.
    pub novelty_instruction: String,
    pub typing_instruction: String,
    pub narrative_instruction: String,
}

impl WakeRecipePolicy {
    fn validate(&self) -> Result<()> {
        if self.continuous_rung_spans == 0
            || self.nightly_spans == 0
            || self.nightly_children == 0
            || self.rung_retry_secs == 0
            || self.audit_percent > 100
            || self.novelty_instruction.trim().is_empty()
            || self.typing_instruction.trim().is_empty()
            || self.narrative_instruction.trim().is_empty()
        {
            return Err(Error::InvalidConfig("invalid Dreamer recipe policy".into()));
        }
        Ok(())
    }
}

pub(crate) fn policy_in_txn(vault: &Vault, txn: &heed::RoTxn<'_>) -> Result<WakeRecipePolicy> {
    let policy = match POLICY.get(&vault.store, txn, &())? {
        Some(policy) => policy,
        None => serde_json::from_str(include_str!("recipe_policy_defaults.json"))
            .map_err(|_| Error::InvalidConfig("invalid shipped Dreamer recipe policy".into()))?,
    };
    policy.validate()?;
    Ok(policy)
}

impl Vault {
    pub fn dreamer_recipe_policy(&self) -> Result<WakeRecipePolicy> {
        let txn = self.store.env.read_txn()?;
        policy_in_txn(self, &txn)
    }

    pub fn set_dreamer_recipe_policy(
        &self,
        owner: &crate::consent::AuthenticatedOwner,
        policy: WakeRecipePolicy,
    ) -> Result<()> {
        policy.validate()?;
        self.with_write_txn_grouped(|txn| {
            crate::dreamer_runner::maintenance::validate_owner_in_txn(self, txn, owner)?;
            POLICY.put(&self.store, txn, &(), &policy)
        })
    }
}

/// The summary executor reads retained source turns, never an earlier summary.
/// Source selection and the audit sample are durable children of this receipt.
pub(crate) fn weave_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    attempt: &DreamerAdmittedAttempt,
    now: u64,
) -> Result<()> {
    let requester = vault.dreamer_authority_in_txn(txn, now)?;
    for conversation in sieve::retained_conversations_in_txn(vault, txn)? {
        vault.request_scope_summary_in_txn(
            txn,
            &ScopeSummaryRequest {
                target: ScopeSummaryTarget::Scope {
                    scope: ScopeSelector {
                        conversation,
                        session: None,
                        path: ScopePath::Canonical,
                        include_forks: true,
                    },
                    land_on: None,
                    as_record: false,
                },
                requester,
            },
            Some(attempt.status.attempt.id),
            attempt.status.attempt.run_id.as_deref(),
            now,
        )?;
    }
    let policy = policy_in_txn(vault, txn)?;
    let store = DreamerRunnerStore::new(vault);
    for span in sieve::audit_sample_in_txn(vault, txn, attempt.status.attempt.id, &policy)? {
        sieve::enqueue_rungs_in_txn(&store, txn, &attempt.status, &span, true, now)?;
    }
    Ok(())
}
