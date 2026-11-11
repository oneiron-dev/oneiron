//! Row-backed spending for the three wake recipes.

use crate::conversation_dag::{ScopePath, ScopeSelector};
use crate::dreamer_runner::{DreamerAdmittedAttempt, DreamerRunnerStore};
use crate::scope_summary::{ScopeSummaryRequest, ScopeSummaryTarget};
use crate::side_table::{self, LegacyJson, SideTable};
use crate::{Error, Result, Vault};

use super::sieve;

const POLICY: SideTable<(), WakeRecipePolicy, LegacyJson> =
    SideTable::new(&side_table::DREAMER_WAKE_RECIPE_POLICY);

#[doc(hidden)]
pub use oneiron_wake_contract::dreamer_wake::recipes::WakeRecipePolicy;

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

/// The unflagged windows a weave for `attempt` audits, drawn on a read
/// snapshot of their own before the weave's write opens (FIX 7902): the draw
/// reads whole turn texts until it fills, which no write transaction holds.
/// Each window is read again at its own audit, so one the weave's commit
/// outdates is judged there, as any drawn window is.
pub(crate) fn weave_window_sample(
    vault: &Vault,
    attempt: &DreamerAdmittedAttempt,
) -> Result<Vec<sieve::SieveAuditWindow>> {
    let txn = vault.store.env.read_txn()?;
    let policy = policy_in_txn(vault, &txn)?;
    sieve::audit_window_sample_in_txn(vault, &txn, attempt.status.attempt.id, &policy)
}

/// The summary executor reads retained source turns, never an earlier summary.
/// Source selection and the audit sample are durable children of this receipt.
/// `windows` is [`weave_window_sample`], drawn before this write; `None`
/// draws it here, for a weave whose input was not there when the draw ran.
pub(crate) fn weave_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    attempt: &DreamerAdmittedAttempt,
    windows: Option<Vec<sieve::SieveAuditWindow>>,
    now: u64,
) -> Result<()> {
    let requester = vault.dreamer_authority_in_txn(txn, now)?;
    // An excluded conversation gets no fresh scope summary while it is
    // excluded; summaries it already has stand.
    let excluded = vault.dreamer_excluded_conversations_in_txn(txn)?;
    for conversation in sieve::retained_conversations_in_txn(vault, txn)? {
        if excluded.contains(&conversation) {
            continue;
        }
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
    // Unflagged windows go on top of the flagged sample (OF-498f).
    let windows = match windows {
        Some(windows) => windows,
        None => sieve::audit_window_sample_in_txn(vault, txn, attempt.status.attempt.id, &policy)?,
    };
    for window in windows {
        sieve::enqueue_window_audit_in_txn(&store, txn, &attempt.status, &window, &policy, now)?;
    }
    Ok(())
}
