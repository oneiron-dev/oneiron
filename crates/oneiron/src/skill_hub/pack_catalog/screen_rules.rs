//! The rules of the connector tool screen, which of them the owner may lift
//! on one tool, and the owner's "install it anyway" that lifts them (FIX
//! SCREENING-PER-TOOL-SKIP, PR C; RULINGS SCREENING-SKIP-OVERRIDE-SCOPE = A
//! and SCREENING-SECRET-OVERRIDE = B, 16 Nov).
use super::PackObservedTool;
use super::screening::SkippedConnectorTool;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeSet;

/// One rule of the pack install screen that a listed connector tool can
/// trip. The order is the order the first-refusal screen tries them.
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    Serialize,
    Deserialize,
    schemars::JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum ScreenRule {
    /// A string shaped like a credential or key.
    SecretShapedString,
    /// One text past the screen's size bound.
    TextBound,
    /// A zero-width or right-to-left control character.
    InvisibleText,
    /// A word mixing Latin with Cyrillic or Greek letters.
    MixedScriptHomoglyph,
    /// A character whose compatibility form is an ASCII letter.
    CompatibilityHomoglyph,
    /// A hidden-instruction phrase of the install policy.
    HiddenInstructions,
    /// A known-bad pattern of the install policy.
    KnownBadPattern,
    /// A parameter-description injection phrase of the install policy.
    ParameterInjection,
    /// The input schema does not resolve, so no slate can hold the tool.
    UnresolvedSchema,
}

/// One row of [`SCREEN_RULES`].
#[derive(Debug, Clone, Copy)]
pub struct ScreenRuleRow {
    pub rule: ScreenRule,
    /// The reason the screen answers when the rule trips.
    pub reason: &'static str,
    /// The owner may install a tool that trips this rule anyway.
    pub owner_may_lift: bool,
}

/// Every screen rule, its reason and whether the owner may lift it on one
/// tool. The one table a later ruling changes: every instruction and
/// deception rule and the secret-shaped string may be lifted
/// (SCREENING-SKIP-OVERRIDE-SCOPE = A, SCREENING-SECRET-OVERRIDE = B); an
/// unresolved schema cannot install, and the text bound is a size limit
/// that becomes an owner Setting rather than a per-tool lift.
pub const SCREEN_RULES: [ScreenRuleRow; 9] = [
    ScreenRuleRow {
        rule: ScreenRule::SecretShapedString,
        reason: "secret-shaped string",
        owner_may_lift: true,
    },
    ScreenRuleRow {
        rule: ScreenRule::TextBound,
        reason: "manifest text bound exceeded",
        owner_may_lift: false,
    },
    ScreenRuleRow {
        rule: ScreenRule::InvisibleText,
        reason: "zero-width or RTL deception",
        owner_may_lift: true,
    },
    ScreenRuleRow {
        rule: ScreenRule::MixedScriptHomoglyph,
        reason: "mixed-script homoglyph deception",
        owner_may_lift: true,
    },
    ScreenRuleRow {
        rule: ScreenRule::CompatibilityHomoglyph,
        reason: "compatibility homoglyph deception",
        owner_may_lift: true,
    },
    ScreenRuleRow {
        rule: ScreenRule::HiddenInstructions,
        reason: "hidden instructions",
        owner_may_lift: true,
    },
    ScreenRuleRow {
        rule: ScreenRule::KnownBadPattern,
        reason: "known-bad pattern",
        owner_may_lift: true,
    },
    ScreenRuleRow {
        rule: ScreenRule::ParameterInjection,
        reason: "parameter-description injection",
        owner_may_lift: true,
    },
    ScreenRuleRow {
        rule: ScreenRule::UnresolvedSchema,
        reason: "input schema does not resolve",
        owner_may_lift: false,
    },
];

impl ScreenRule {
    fn row(self) -> &'static ScreenRuleRow {
        // Every rule has its row: the table lists each variant once.
        SCREEN_RULES
            .iter()
            .find(|row| row.rule == self)
            .unwrap_or(&SCREEN_RULES[SCREEN_RULES.len() - 1])
    }
    /// The reason the screen answers when this rule trips.
    pub fn reason(self) -> &'static str {
        self.row().reason
    }
    /// The owner may install a tool that trips this rule anyway.
    pub fn owner_may_lift(self) -> bool {
        self.row().owner_may_lift
    }
}

/// The digest of a listed tool's name, description and input schema (object
/// keys sorted): what an owner's "install it anyway" binds to. A tool that
/// changes any of them no longer matches, and the screen keeps it out again.
pub fn listed_tool_digest(tool: &PackObservedTool) -> String {
    let canonical = Value::Array(vec![
        Value::String(tool.name.clone()),
        Value::String(tool.description.clone()),
        sorted_keys(&tool.input_schema),
    ]);
    let digest = blake3::derive_key(
        "oneiron/connector-key/screened-tool/v1",
        canonical.to_string().as_bytes(),
    );
    blake3::Hash::from(digest).to_hex().to_string()
}

fn sorted_keys(value: &Value) -> Value {
    match value {
        Value::Object(map) => {
            let mut entries: Vec<_> = map.iter().collect();
            entries.sort_by(|left, right| left.0.cmp(right.0));
            Value::Object(
                entries
                    .into_iter()
                    .map(|(key, value)| (key.clone(), sorted_keys(value)))
                    .collect(),
            )
        }
        Value::Array(items) => Value::Array(items.iter().map(sorted_keys).collect()),
        other => other.clone(),
    }
}

/// The owner's "install it anyway" on one listed connector tool the screen
/// kept out, held in the slate manifest the owner stamps. It binds to the
/// tool as the owner saw it: while the tool keeps that digest and trips no
/// rule outside `rules`, the screen admits it; any change keeps it out
/// again.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct OwnerAcceptedScreen {
    /// [`listed_tool_digest`] of the tool the owner accepted.
    pub tool_digest: String,
    /// The rules it tripped then; the owner may lift every one.
    pub rules: BTreeSet<ScreenRule>,
}

impl OwnerAcceptedScreen {
    /// The owner's acceptance of `skipped`, which he saw at `seen_digest`.
    /// Refused when the tool changed since he saw it, or when it trips a
    /// rule the owner may not lift.
    pub fn accept(skipped: &SkippedConnectorTool, seen_digest: &str) -> Result<Self, String> {
        if skipped.digest != seen_digest {
            return Err(format!(
                "tool {} changed since the owner saw it",
                skipped.tool
            ));
        }
        if let Some(rule) = skipped.rules.iter().find(|rule| !rule.owner_may_lift()) {
            return Err(format!(
                "tool {}: {} cannot be installed anyway",
                skipped.tool,
                rule.reason()
            ));
        }
        Ok(Self {
            tool_digest: skipped.digest.clone(),
            rules: skipped.rules.iter().copied().collect(),
        })
    }
    /// This acceptance still covers `skipped`: the tool keeps the accepted
    /// digest and trips no rule outside the accepted ones.
    pub fn covers(&self, skipped: &SkippedConnectorTool) -> bool {
        self.tool_digest == skipped.digest
            && skipped.rules.iter().all(|rule| self.rules.contains(rule))
    }
    /// The tool's stored strings are public, owner-accepted at install: the
    /// owner accepted a secret-shaped string in them, so a secret scanner or
    /// an export redaction does not raise them again as a leak (RULING
    /// SCREENING-SECRET-OVERRIDE = B).
    pub fn public_secret_shape(&self) -> bool {
        self.rules.contains(&ScreenRule::SecretShapedString)
    }
}
