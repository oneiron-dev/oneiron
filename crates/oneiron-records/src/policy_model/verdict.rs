//! Moved from `crates/oneiron/src/policy_model/verdict.rs` (lib split R1: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use oneiron_policy_vocabulary::policy_model::pattern::PolicyPatternRole;
pub use oneiron_verb_wire::policy_model::verdict::PolicySkipReason;
use serde::Deserialize;
use serde::Serialize;

/// What a policy verdict can ask for. `Warn` and `Skipped` are the non-`Allow`
/// arms that still deliver the content, and they deliver it BYTE-IDENTICALLY —
/// there is deliberately no arm that returns rewritten content. `Reword`
/// withholds the original and asks its author for a fresh candidate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum PolicyClassifyDecision {
    Allow,
    Warn,
    /// Withhold this candidate and ask its author for a new one. The new
    /// candidate crosses the same policy door; this is never a permit.
    Reword,
    Block,
    RouteToHelp,
    Hold,
    /// The plane wanted a model answer and got none, so nothing examined the
    /// content. Not an `Allow`: an `Allow` is an answer. The owner's plane is
    /// sovereign, so its content still goes out, but the caller is told it
    /// went out unread.
    Skipped(PolicySkipReason),
}

impl PolicyClassifyDecision {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Allow => "allow",
            Self::Warn => "warn",
            Self::Reword => "reword",
            Self::Block => "block",
            Self::Hold => "hold",
            Self::RouteToHelp => "route-to-help",
            Self::Skipped(_) => "skipped",
        }
    }

    /// The ledger spelling, which is `snake_case` where [`Self::as_str`] is
    /// `kebab-case` (reason codes and outcomes never carry dashes).
    #[must_use]
    pub const fn ledger_str(self) -> &'static str {
        match self {
            Self::Allow => "allow",
            Self::Warn => "warn",
            Self::Reword => "reword",
            Self::Block => "block",
            Self::Hold => "hold",
            Self::RouteToHelp => "route_to_help",
            Self::Skipped(_) => "skipped",
        }
    }

    /// Why nothing examined the content, or `None` for an answered verdict.
    #[must_use]
    pub const fn skip_reason(self) -> Option<PolicySkipReason> {
        match self {
            Self::Skipped(reason) => Some(reason),
            _ => None,
        }
    }
}

/// Which plane the verdict came from, and enough of that plane's identity to
/// attribute it. An owner verdict names only the owner's row; a hosted-legal
/// verdict additionally names the jurisdiction and policy version it was
/// decided under, because the reader is owed the source of a rule they did
/// not write.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(tag = "category", content = "sub", rename_all = "snake_case")]
pub enum PolicyVerdictCategory {
    None,
    OwnerPolicy {
        row_ref: String,
    },
    HostedLegal {
        /// The host's own category label, as its policy registered it. The
        /// engine publishes no vocabulary of its own here — see
        /// [`HostedLegalRow::category`].
        ///
        /// [`HostedLegalRow::category`]: super::planes::HostedLegalRow::category
        category: String,
        jurisdiction: String,
        policy_version: String,
        row_ref: String,
        basis: super::planes::HostedLegalBasis,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PolicyHedgeBucket {
    Certain,
    High,
    Medium,
    Low,
}

#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct PolicyConfidence {
    pub calibrated: f32,
    pub hedge_bucket: PolicyHedgeBucket,
}

impl PolicyConfidence {
    pub const CERTAIN: Self = Self {
        calibrated: 1.0,
        hedge_bucket: PolicyHedgeBucket::Certain,
    };

    pub const HIGH: Self = Self {
        calibrated: 0.92,
        hedge_bucket: PolicyHedgeBucket::High,
    };

    pub const MEDIUM: Self = Self {
        calibrated: 0.75,
        hedge_bucket: PolicyHedgeBucket::Medium,
    };

    /// No confidence: nothing examined the content.
    pub const UNEXAMINED: Self = Self {
        calibrated: 0.0,
        hedge_bucket: PolicyHedgeBucket::Low,
    };
}

/// Serde skip predicate: a pass that dropped nothing says so by omission.
#[expect(
    clippy::trivially_copy_pass_by_ref,
    reason = "serde's skip_serializing_if hands the field by reference"
)]
pub fn is_zero(value: &usize) -> bool {
    *value == 0
}

/// Everything a pass learned on the way to its verdict, kept so the substrate
/// owner can improve the policy that produced it.
///
/// This is the loop the whole design turns on: patterns are unreliable, so the
/// engine records which ones fired and what the model said about them, and the
/// substrate owner reads that back. It carries IDS and the model's own words —
/// never a pattern's source text, and never the policy document.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct PolicyPassAudit {
    /// Every substrate-owner pattern rule that matched, in rule order — even
    /// the ones the model went on to overrule.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub matched_pattern_ids: Vec<String>,
    /// The role that governed once several rules matched.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub acting_pattern_role: Option<PolicyPatternRole>,
    /// Rule ids the MODEL named, under a rationale-bearing output contract,
    /// deduped and cut down to the rules the plane actually resolved. These
    /// are the policy document's own ids, not the pattern rules'.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub model_rule_ids: Vec<String>,
    /// How many ids the model cited that named no rule the plane resolved.
    ///
    /// A count, not the ids. Recording the strings would let one answer put
    /// unboundedly many rows in one ledger entry — the flood the engine used
    /// to hold off with a fixed cap on the whole array, which also threw away
    /// perfectly good citations once a model got talkative. What survives now
    /// is bounded by the plane's own rows; this is how the rest stays visible.
    #[serde(default, skip_serializing_if = "is_zero")]
    pub model_rule_ids_dropped: usize,
    /// The model's own confidence word, as its policy document asked for it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub model_confidence: Option<String>,
    /// The model's stated reason, bounded and otherwise untouched.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub model_rationale: Option<String>,
    /// The notes generation was already running when the read's one budget
    /// ran out, and was cut there (FIX 10531): the verdict stands without its
    /// notes, as it does on a failed notes call.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub model_notes_cut: bool,
    /// The guard refused the notes call because its budget was exhausted;
    /// the decided verdict stands without notes.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub model_notes_budget_exhausted: bool,
    /// Registered row questions and their shared-ladder receipts. These
    /// contain answers and hashes/ids, never the candidate or policy text.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub typed_decisions: Vec<oneiron_wake_contract::llm::decision::types::TypedDecision>,
    /// The typed fault that ended the safeguard read after its reply came
    /// back (FIX 1202). The verdict is the skip it was; the receipt names
    /// the fault.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub read_error: Option<PolicyReadError>,
}

/// A fault that ended a safeguard read after its reply came back, for the
/// receipt.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PolicyReadError {
    /// The guard could not settle the lease the admitted read went out on.
    SettlementInvariant,
}

impl PolicyReadError {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::SettlementInvariant => "settlement_invariant",
        }
    }
}

impl PolicyPassAudit {
    /// Whether this audit says anything at all. An empty audit is dropped
    /// rather than carried, so a verdict that learned nothing says so by
    /// having none.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.matched_pattern_ids.is_empty()
            && self.acting_pattern_role.is_none()
            && self.model_rule_ids.is_empty()
            && self.model_rule_ids_dropped == 0
            && self.model_confidence.is_none()
            && self.model_rationale.is_none()
            && !self.model_notes_budget_exhausted
            && self.typed_decisions.is_empty()
            && self.read_error.is_none()
    }
}
