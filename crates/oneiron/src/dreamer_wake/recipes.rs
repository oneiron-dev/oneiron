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
    /// Independent probability of sampling each retained rule span, and
    /// each unflagged window, in percent.
    pub audit_percent: u8,
    pub audit_spans: u32,
    /// Unflagged windows a weave audits on top of its `audit_spans`, in
    /// percent of them, rounded up (OF-498f); 0 draws none.
    pub audit_window_share: u8,
    /// Bytes of one unflagged window: a longer run of unflagged words is
    /// split into windows of at most this many, never cut short.
    pub audit_window_bytes: u32,
    /// Instructions are vault configuration, not Rust prompt constants.
    pub novelty_instruction: String,
    pub typing_instruction: String,
    pub narrative_instruction: String,
    /// The new lower-source statements an Arc's changed sittings must carry
    /// before it is written again ahead of its backstop (FIX 7509 P8). Zero
    /// writes on any changed source set; an unchanged set never writes.
    pub arc_min_new_statements: u32,
    /// The new part, review and rewrite model calls one Arc composed in
    /// parts makes in one wake before it checkpoints the rest (FIX 7509
    /// PR3): a pace, never a bound on the Arc. Above zero.
    pub arc_child_calls_per_wake: u32,
    /// What the expensive path is asked of an unflagged window.
    pub audit_window_instruction: String,
    /// Whether the sieve's follower session reads the owed novelty rung in
    /// batches over its cached log prefix (FIX 7510); false asks it one
    /// span at a time, as before.
    pub follower_enabled: bool,
    /// What the follower is asked of a suffix's spans: one reading each.
    pub follower_instruction: String,
    /// How the follower folds its retained frames into a keyframe.
    pub follower_keyframe_instruction: String,
    /// The follower's packing estimate of bytes per token: a sizing guess,
    /// never a tokenizer count.
    pub follower_sizing_bytes_per_token: u32,
    /// Whether a planned thing's branch runs as one scoped code-mode agent
    /// (FIX 7508): its slices go through the agent's lent extract and decide
    /// ports. A logical attempt that already ran as an agent keeps running
    /// as one when this is turned off; either way its slices are the same
    /// durable steps, so no checkpoint is lost to the switch.
    pub thing_child_code_mode: bool,
    /// What a thing's agent is asked to do with what it is lent.
    pub thing_child_instruction: String,
    /// The share of the agent model's input window one lent input piece may
    /// fill: one part in this many. A slice past it is split into pieces,
    /// every piece lent. At least one.
    pub thing_child_input_window_divisor: u32,
    /// The input window, in tokens, a thing's agent's inputs are packed by
    /// when its host lends no model window (FIX 9020); the host's real
    /// window wins whenever it lends one. Shipped at 32768. An unknown
    /// window is never a refusal.
    pub thing_child_fallback_window_tokens: u64,
}

impl WakeRecipePolicy {
    fn validate(&self) -> Result<()> {
        if self.continuous_rung_spans == 0
            || self.nightly_spans == 0
            || self.nightly_children == 0
            || self.rung_retry_secs == 0
            || self.arc_child_calls_per_wake == 0
            || self.audit_percent > 100
            || self.novelty_instruction.trim().is_empty()
            || self.typing_instruction.trim().is_empty()
            || self.narrative_instruction.trim().is_empty()
            || self.thing_child_instruction.trim().is_empty()
            || self.thing_child_input_window_divisor == 0
            || (self.audit_window_share > 0
                && (self.audit_window_bytes == 0
                    || self.audit_window_instruction.trim().is_empty()))
            || (self.follower_enabled
                && (self.follower_instruction.trim().is_empty()
                    || self.follower_keyframe_instruction.trim().is_empty()
                    || self.follower_sizing_bytes_per_token == 0))
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
    // Unflagged windows go on top of the flagged sample (OF-498f).
    for window in sieve::audit_window_sample_in_txn(vault, txn, attempt.status.attempt.id, &policy)?
    {
        sieve::enqueue_window_audit_in_txn(&store, txn, &attempt.status, &window, &policy, now)?;
    }
    Ok(())
}
