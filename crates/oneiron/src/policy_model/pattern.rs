//! Substrate-owner pattern rules.
//!
//! The engine ships NO patterns. Every rule in this file's types is authored by
//! the substrate owner and reaches the engine through a plane's configuration
//! surface — a hosted service's registration, or the vault's own policy
//! manifest. The engine compiles them, matches them, resolves their roles and
//! receipts every id that fired; it never adds one of its own, and it never
//! records the pattern text.
//!
//! # Why a pattern is not a verdict
//!
//! A regular expression sees characters, not meaning. `porn` matches inside
//! `Agapornis`, `minor` inside `minority`, and `bomb` inside `bombproof` —
//! and the compounds that matter are unbounded, so no list of patterns is ever
//! complete either. A pattern is therefore an UNRELIABLE SIGNAL, which is why
//! [`PolicyPatternRole::Escalate`] is the default: a hit asks the safeguard
//! model to look, and the model's verdict wins. A pattern only decides on its
//! own where the substrate owner declared it a hard rule
//! ([`PolicyPatternRole::Decide`]), which is also the coverage that survives a
//! model outage.
//!
//! # Roles
//!
//! * [`Escalate`](PolicyPatternRole::Escalate) — the default. The hit triggers
//!   a safeguard-model call and never decides while a model verdict is
//!   obtainable. It is receipted EVEN when the model overrules it to `Allow`,
//!   because a pattern that keeps escalating clean content is exactly what the
//!   substrate owner needs to see to fix it.
//! * [`Decide`](PolicyPatternRole::Decide) — the hit IS the verdict. No model
//!   call is made, and the rule still decides while the model tier is down.
//! * [`Log`](PolicyPatternRole::Log) — record-only. It never gates, never
//!   triggers the model and never blocks; the content flows with an `Allow` and
//!   the id lands in the receipt.
//!
//! When several rules match the same content, the STRICTEST role acts
//! (`Decide` > `Escalate` > `Log`) and rule order breaks ties. Every matched id
//! is receipted regardless of which one acted.

use regex::Regex;
use serde::{Deserialize, Serialize};

/// Longest rule id the engine accepts. Ids ride into gate reason codes, so they
/// are bounded and tokenized rather than free text.
pub const POLICY_PATTERN_ID_MAX_LEN: usize = 64;

/// Longest pattern source the engine accepts, in bytes.
pub const POLICY_PATTERN_MAX_LEN: usize = 512;

/// Most rules one plane may carry.
pub const POLICY_PATTERN_RULES_MAX: usize = 256;

/// What a matching pattern is allowed to do. See the module doc for why
/// [`Self::Escalate`] is the default.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PolicyPatternRole {
    /// Trigger the safeguard model; never decide while a model verdict is
    /// obtainable.
    #[default]
    Escalate,
    /// The hit is the verdict.
    Decide,
    /// Record only.
    Log,
}

impl PolicyPatternRole {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Escalate => "escalate",
            Self::Decide => "decide",
            Self::Log => "log",
        }
    }

    /// Parses the wire spelling. Returns `None` for anything else, so a
    /// manifest naming a role the engine does not have fails closed rather
    /// than silently falling back to the default.
    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "escalate" => Some(Self::Escalate),
            "decide" => Some(Self::Decide),
            "log" => Some(Self::Log),
            _ => None,
        }
    }

    /// Ordering only — the numbers are never stored and never emitted. They
    /// exist so two roles can be compared when several rules match.
    const fn strictness(self) -> u8 {
        match self {
            Self::Log => 0,
            Self::Escalate => 1,
            Self::Decide => 2,
        }
    }
}

/// One substrate-owner pattern rule.
///
/// `category` must be a label the rule's own plane publishes: a hosted plane
/// accepts the categories its registered rows carry, and the owner plane
/// accepts the `row_ref` of one of the owner's own rows. That is what lets a
/// `Decide` hit resolve to an action without the engine inventing one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyPatternRule {
    pub id: String,
    pub pattern: String,
    pub category: String,
    pub role: PolicyPatternRole,
}

impl PolicyPatternRule {
    /// A rule in the default role, [`PolicyPatternRole::Escalate`].
    #[must_use]
    pub fn new(
        id: impl Into<String>,
        pattern: impl Into<String>,
        category: impl Into<String>,
    ) -> Self {
        Self {
            id: id.into(),
            pattern: pattern.into(),
            category: category.into(),
            role: PolicyPatternRole::Escalate,
        }
    }

    #[must_use]
    pub fn with_role(mut self, role: PolicyPatternRole) -> Self {
        self.role = role;
        self
    }
}

/// Why a set of pattern rules was refused. Field and reason are `'static` so a
/// caller can lift them into its own plane-shaped error without allocating.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct PatternRuleDefect {
    pub(crate) field: &'static str,
    pub(crate) reason: &'static str,
}

/// A compiled, validated rule set. Compilation happens once, where the rules
/// are registered — never on the hot path, and never on content.
#[derive(Debug, Clone, Default)]
pub(crate) struct CompiledPatternRules {
    rules: Vec<CompiledPatternRule>,
}

#[derive(Debug, Clone)]
pub(crate) struct CompiledPatternRule {
    id: String,
    category: String,
    role: PolicyPatternRole,
    regex: Regex,
}

impl CompiledPatternRule {
    pub(crate) fn category(&self) -> &str {
        &self.category
    }

    pub(crate) const fn role(&self) -> PolicyPatternRole {
        self.role
    }
}

/// What matching produced: every id that fired, and the one rule whose role
/// acts.
#[derive(Debug, Clone, Default)]
pub(crate) struct PatternEvaluation<'a> {
    /// Every matched rule id, in rule order. Ids only — the pattern text is
    /// never recorded.
    pub(crate) matched_ids: Vec<&'a str>,
    /// The strictest matching rule, or `None` when nothing matched.
    pub(crate) acting: Option<&'a CompiledPatternRule>,
}

impl PatternEvaluation<'_> {
    /// The role that governs this pass, or `None` when nothing matched.
    pub(crate) fn acting_role(&self) -> Option<PolicyPatternRole> {
        self.acting.map(CompiledPatternRule::role)
    }
}

impl CompiledPatternRules {
    /// Matches `content` against every rule. Ordering is rule order, so a tie
    /// on strictness resolves to the rule the substrate owner wrote first.
    ///
    /// `acts` is the plane's own reachability check: a rule whose category no
    /// longer resolves to a row on this pass — an owner row scoped out of this
    /// world, say — is still MATCHED and still receipted, but it cannot be the
    /// rule that acts, because the row it would act through is not in play.
    pub(crate) fn evaluate_where<'a>(
        &'a self,
        content: &str,
        acts: &dyn Fn(&CompiledPatternRule) -> bool,
    ) -> PatternEvaluation<'a> {
        let mut matched_ids = Vec::new();
        let mut acting: Option<&CompiledPatternRule> = None;
        for rule in &self.rules {
            if !rule.regex.is_match(content) {
                continue;
            }
            matched_ids.push(rule.id.as_str());
            if !acts(rule) {
                continue;
            }
            let stricter = acting
                .is_none_or(|current| rule.role.strictness() > current.role.strictness())
                .then_some(rule);
            if let Some(rule) = stricter {
                acting = Some(rule);
            }
        }
        PatternEvaluation {
            matched_ids,
            acting,
        }
    }
}

/// Validates and compiles a plane's rules.
///
/// `category_ok` is the plane's own vocabulary check — the engine has no
/// opinion about which labels are meaningful, only that a rule names one its
/// plane actually publishes.
pub(crate) fn compile_pattern_rules(
    rules: &[PolicyPatternRule],
    category_ok: &dyn Fn(&str) -> bool,
) -> Result<CompiledPatternRules, PatternRuleDefect> {
    if rules.len() > POLICY_PATTERN_RULES_MAX {
        return Err(PatternRuleDefect {
            field: "pattern_rules",
            reason: "carries more rules than one plane may hold",
        });
    }
    let mut compiled = Vec::with_capacity(rules.len());
    let mut seen: Vec<&str> = Vec::with_capacity(rules.len());
    for rule in rules {
        if rule.id.trim().is_empty() {
            return Err(PatternRuleDefect {
                field: "pattern_rule_id",
                reason: "must not be blank",
            });
        }
        if rule.id.len() > POLICY_PATTERN_ID_MAX_LEN {
            return Err(PatternRuleDefect {
                field: "pattern_rule_id",
                reason: "is longer than a receiptable rule id",
            });
        }
        // Ids become gate reason-code suffixes, so they stay tokenized. A rule
        // id carrying a space or a newline would split a ledger row's trace
        // into something no reader could key on.
        if !rule
            .id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.'))
        {
            return Err(PatternRuleDefect {
                field: "pattern_rule_id",
                reason: "must be ascii alphanumeric with `_`, `-` or `.`",
            });
        }
        if seen.contains(&rule.id.as_str()) {
            return Err(PatternRuleDefect {
                field: "pattern_rule_id",
                reason: "must be unique within a plane",
            });
        }
        if rule.pattern.is_empty() {
            return Err(PatternRuleDefect {
                field: "pattern_rule_pattern",
                reason: "must not be blank",
            });
        }
        if rule.pattern.len() > POLICY_PATTERN_MAX_LEN {
            return Err(PatternRuleDefect {
                field: "pattern_rule_pattern",
                reason: "is longer than a pattern may be",
            });
        }
        if !category_ok(&rule.category) {
            return Err(PatternRuleDefect {
                field: "pattern_rule_category",
                reason: "names a category this plane does not publish",
            });
        }
        let regex = Regex::new(&rule.pattern).map_err(|_| PatternRuleDefect {
            field: "pattern_rule_pattern",
            reason: "is not a valid regular expression",
        })?;
        seen.push(rule.id.as_str());
        compiled.push(CompiledPatternRule {
            id: rule.id.clone(),
            category: rule.category.clone(),
            role: rule.role,
            regex,
        });
    }
    Ok(CompiledPatternRules { rules: compiled })
}
