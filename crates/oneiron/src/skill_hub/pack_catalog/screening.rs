//! Bounded, source-bound install rules for connector tool manifests.
use super::screen_rules::{OwnerAcceptedScreen, ScreenRule, listed_tool_digest};
use super::tool_schema::{ResolvedToolSchema, TextRole};
use super::{PackKind, PackObservedTool, PackSource, invalid};
use crate::gate::{
    EffectivePackInstallPolicy, HolderInstallRow, PackInstallPolicyOverride, PackInstallRuleRow,
};
use crate::{Vault, consent::AuthenticatedOwner, error::Result, skill::SkillContentHash};
use icu_normalizer::ComposingNormalizer;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};
use unicode_script::{Script, UnicodeScript};

/// Owner-managed install prohibitions. A scan verdict is a signal, not a rule.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PackInstallRules {
    pub removed_hashes: Vec<String>,
    pub known_bad_patterns: Vec<String>,
}
impl Vault {
    /// Replace the local install rule set. This does not alter any staged source.
    pub fn set_pack_install_rules(
        &self,
        owner: &AuthenticatedOwner,
        rules: &PackInstallRules,
    ) -> Result<()> {
        if rules
            .removed_hashes
            .iter()
            .any(|h| SkillContentHash::parse_hex(h).is_err())
            || rules
                .known_bad_patterns
                .iter()
                .any(|p| p.trim().is_empty() || p.len() > 256)
        {
            return Err(invalid("invalid install rules"));
        }
        self.update_pack_install_policy(owner, |policy| {
            policy.owner.removed_hashes = rules.removed_hashes.clone();
            policy.owner.known_bad_patterns = rules.known_bad_patterns.clone();
            Ok(())
        })
    }
    /// Replace one owner-authored narrowing row in the vault policy manifest.
    /// A holder row may tighten but never widen its vault row; all operations
    /// remain capped by the analyzed grammar's immutable supported set.
    pub fn set_pack_install_policy_override(
        &self,
        owner: &AuthenticatedOwner,
        override_row: PackInstallPolicyOverride,
    ) -> Result<()> {
        self.update_pack_install_policy(owner, |policy| {
            let holder = override_row.holder_ref.clone();
            let row = PackInstallRuleRow::from(override_row);
            if let Some(holder_ref) = holder {
                if let Some(existing) = policy
                    .holders
                    .iter_mut()
                    .find(|item| item.holder_ref == holder_ref)
                {
                    existing.rules = row;
                } else {
                    policy.holders.push(HolderInstallRow {
                        holder_ref,
                        rules: row,
                    });
                }
            } else {
                policy.owner = row;
            }
            Ok(())
        })
    }
    /// Reuse content-keyed scan signals without treating any scanner as policy.
    pub(super) fn pack_scan_risk_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        hash: SkillContentHash,
    ) -> Result<Option<crate::skill_hub::ScanRiskLevel>> {
        let verdicts = crate::skill_hub::skill_scan_verdicts_for_content_hash_in_store(
            &self.store,
            txn,
            hash,
        )?;
        verdicts.iter().try_fold(None, |worst, body| {
            let risk = crate::skill_hub::scan_verdict_row_risk(body)?;
            Ok(Some(
                worst.map_or(risk, |prior: crate::skill_hub::ScanRiskLevel| {
                    prior.max(risk)
                }),
            ))
        })
    }
    pub(super) fn screen_pack_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        source: &PackSource,
        observed_tools: &[PackObservedTool],
        holder: &str,
    ) -> Result<Option<String>> {
        let resolution = crate::gate::resolve_policy_manifest(&self.store, txn)?;
        let Some(policy) = resolution.pack_install_policy() else {
            return Ok(Some("pack install policy unavailable".into()));
        };
        let rules = policy.effective(holder);
        if rules
            .removed_hashes
            .iter()
            .any(|h| h == &source.content_hash().to_hex())
        {
            return Ok(Some("removed content hash".into()));
        }
        for file in source.files() {
            let text =
                std::str::from_utf8(&file.content).map_err(|_| invalid("source is not UTF-8"))?;
            let lower = text.to_lowercase();
            if rules
                .known_bad_patterns
                .iter()
                .any(|pattern| lower.contains(&pattern.to_lowercase()))
            {
                return Ok(Some(format!("known-bad pattern in {}", file.path)));
            }
            if crate::batch::secret_scan::scan_file_content(&file.path, &file.content).is_some() {
                return Ok(Some(format!("secret-shaped string in {}", file.path)));
            }
            if file.path.starts_with("scripts/")
                && file.path.ends_with(".py")
                && let Some(reason) =
                    super::script_policy::screen_script(&file.path, text, &rules.allowed_calls)
            {
                return Ok(Some(format!("{reason} in {}", file.path)));
            }
            // The qualified code-mode JS sandbox adapter is not a host-side
            // Python interpreter. Its host-call boundary is its runtime plan.
        }
        if source.manifest().kind != PackKind::Connector {
            return Ok(None);
        }
        if let Some(pack) = source.files().iter().find(|file| file.path == "PACK.md") {
            let text =
                std::str::from_utf8(&pack.content).map_err(|_| invalid("PACK.md is not UTF-8"))?;
            for (field, decoded) in super::manifest::decoded_frontmatter(text)? {
                for value in decoded.strings.iter().chain(&decoded.run) {
                    if let Some(reason) = decoded_rule(value, &rules) {
                        return Ok(Some(format!("PACK.md {field}: {reason}")));
                    }
                }
            }
            if let Some(reason) = screen_text(text, &rules) {
                return Ok(Some(format!("PACK.md: {reason}")));
            }
        }
        let mut declared = BTreeMap::new();
        for file in source
            .files()
            .iter()
            .filter(|f| f.path.starts_with("knowledge/tools/") && f.path.ends_with(".json"))
        {
            let value: Value = serde_json::from_slice(&file.content)
                .map_err(|_| invalid("tool manifest is not JSON"))?;
            let name = value
                .get("name")
                .and_then(Value::as_str)
                .ok_or_else(|| invalid("tool name missing"))?;
            if file.path != format!("knowledge/tools/{name}.json")
                || name.is_empty()
                || name.len() > 128
                || declared.contains_key(name)
            {
                return Ok(Some("tool declaration path/name mismatch".into()));
            }
            let Some(description) = value.get("description").and_then(Value::as_str) else {
                return Ok(Some(format!("tool description absent: {name}")));
            };
            let Some(schema) = value.get("inputSchema") else {
                return Ok(Some(format!("tool input schema absent: {name}")));
            };
            let resolved = match ResolvedToolSchema::parse(schema) {
                Ok(schema) => schema,
                Err(reason) => return Ok(Some(format!("tool {name}: {reason}"))),
            };
            if let Some(reason) = decoded_rule(name, &rules)
                .or_else(|| decoded_rule(description, &rules))
                .map(str::to_owned)
                .or_else(|| screen_resolved_schema(&resolved, &rules))
            {
                return Ok(Some(format!("tool {name}: {reason}")));
            }
            declared.insert(
                name.to_owned(),
                (description.to_owned(), resolved.canonical().clone()),
            );
        }
        if declared.is_empty() && observed_tools.is_empty() {
            // A channel pack can expose no MCP tools. A nonempty observed
            // surface below still fails the exact declared/actual count.
            return Ok(None);
        }
        if declared.len() != observed_tools.len() {
            return Ok(Some("declared-vs-actual tool count mismatch".into()));
        }
        let mut seen = BTreeSet::new();
        for PackObservedTool {
            name,
            description,
            input_schema,
        } in observed_tools
        {
            if !seen.insert(name) {
                return Ok(Some(format!("duplicate observed tool: {name}")));
            }
            if crate::batch::secret_scan::scan_file_content(name, description.as_bytes()).is_some()
                || crate::batch::secret_scan::scan_file_content(
                    name,
                    input_schema.to_string().as_bytes(),
                )
                .is_some()
            {
                return Ok(Some(format!(
                    "secret-shaped string in observed tool {name}"
                )));
            }
            let Some((expected_description, expected_schema)) = declared.get(name) else {
                return Ok(Some(format!("undeclared observed tool: {name}")));
            };
            let observed = match ResolvedToolSchema::parse(input_schema) {
                Ok(schema) => schema,
                Err(reason) => return Ok(Some(format!("observed tool {name}: {reason}"))),
            };
            if let Some(reason) = decoded_rule(description, &rules)
                .map(str::to_owned)
                .or_else(|| screen_resolved_schema(&observed, &rules))
            {
                return Ok(Some(format!("observed tool {name}: {reason}")));
            }
            if description != expected_description || observed.canonical() != expected_schema {
                return Ok(Some(format!("declared-vs-actual mismatch for {name}")));
            }
        }
        Ok(None)
    }
}

/// One listed connector tool the install screen keeps out, and the rule it
/// tripped.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, schemars::JsonSchema)]
pub struct SkippedConnectorTool {
    /// The tool's listed name.
    pub tool: String,
    /// The first rule it tripped and where, e.g.
    /// `oneiron:tool-root#/properties/limit: parameter-description injection`.
    pub reason: String,
    /// Every rule it trips, on its name, its description and its schema.
    pub rules: BTreeSet<ScreenRule>,
    /// [`listed_tool_digest`] of the tool as listed: what the owner's
    /// "install it anyway" names (FIX SCREENING-PER-TOOL-SKIP, PR C).
    pub digest: String,
    /// The owner may install it anyway: it trips at least one rule and
    /// the owner may lift every rule it trips.
    pub owner_may_install: bool,
}

/// The pack install rules' verdict on a connector's listed tools, tool by
/// tool (FIX SCREENING-PER-TOOL-SKIP).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ConnectorToolScreen {
    /// A fault of the whole listing (no install policy, or a name listed
    /// twice): no tool installs.
    pub refused: Option<String>,
    /// Each tool whose name, description or input schema trips a rule, or
    /// whose schema does not resolve, in listed order. Every other listed
    /// tool passes.
    pub skipped: Vec<SkippedConnectorTool>,
    /// The tools that trip a rule but pass on the owner's "install it
    /// anyway", by name, with the acceptance their slate manifest holds
    /// (FIX SCREENING-PER-TOOL-SKIP, PR C).
    pub accepted: BTreeMap<String, OwnerAcceptedScreen>,
}
impl ConnectorToolScreen {
    /// The listed tool `name` passes: nothing refused the listing and the
    /// tool is not skipped.
    pub fn admits(&self, name: &str) -> bool {
        self.refused.is_none() && !self.skipped.iter().any(|skip| skip.tool == name)
    }
    /// Admits the skipped tool `tool` on the owner's "install it anyway",
    /// given as the digest he saw. Refused when it changed since he saw it,
    /// or when it trips a rule the owner may not lift
    /// ([`super::SCREEN_RULES`]). A tool the screen does not keep out needs
    /// no acceptance and is left as it is.
    pub fn accept_owner(&mut self, tool: &str, seen_digest: &str) -> Result<(), String> {
        let Some(at) = self.skipped.iter().position(|skip| skip.tool == tool) else {
            return Ok(());
        };
        let accepted = OwnerAcceptedScreen::accept(&self.skipped[at], seen_digest)?;
        self.skipped.remove(at);
        self.accepted.insert(tool.to_owned(), accepted);
        Ok(())
    }
    /// Admits each skipped tool that an acceptance the owner already
    /// stamped (`held`, by tool name) still covers. A tool whose name,
    /// description or schema changed, or which now trips another rule,
    /// stays skipped.
    pub fn keep_owner_accepted(&mut self, held: &BTreeMap<String, OwnerAcceptedScreen>) {
        let mut kept = Vec::with_capacity(self.skipped.len());
        for skip in std::mem::take(&mut self.skipped) {
            match held.get(&skip.tool) {
                Some(accepted) if accepted.covers(&skip) => {
                    self.accepted.insert(skip.tool, accepted.clone());
                }
                _ => kept.push(skip),
            }
        }
        self.skipped = kept;
    }
}

impl Vault {
    /// The pack install rules on a generic catalog connector's listed tools
    /// (OF-189): hidden instructions, zero-width, RTL and homoglyph
    /// deception, and parameter-description injection, read on each tool's
    /// name, its description and its resolved input schema, unused
    /// definitions included. `Some` names the first refusal.
    pub fn screen_connector_tools(
        &self,
        tools: &[PackObservedTool],
        holder: &str,
    ) -> Result<Option<String>> {
        let Some(rules) = self.connector_screen_rules(holder)? else {
            return Ok(Some(POLICY_UNAVAILABLE.into()));
        };
        let mut seen = BTreeSet::new();
        for tool in tools {
            if !seen.insert(&tool.name) {
                return Ok(Some(format!("duplicate listed tool: {}", tool.name)));
            }
            if let Some(reason) = screen_listed_tool(tool, &rules) {
                return Ok(Some(format!("tool {}: {reason}", tool.name)));
            }
        }
        Ok(None)
    }

    /// The same rules as [`Vault::screen_connector_tools`], answered tool by
    /// tool: a tripped tool is named in `skipped` and the rest pass
    /// (FIX SCREENING-PER-TOOL-SKIP). Only a fault of the whole listing
    /// refuses it all.
    pub fn screen_connector_tools_each(
        &self,
        tools: &[PackObservedTool],
        holder: &str,
    ) -> Result<ConnectorToolScreen> {
        let Some(rules) = self.connector_screen_rules(holder)? else {
            return Ok(ConnectorToolScreen {
                refused: Some(POLICY_UNAVAILABLE.into()),
                ..ConnectorToolScreen::default()
            });
        };
        let mut seen = BTreeSet::new();
        let mut skipped = Vec::new();
        for tool in tools {
            if !seen.insert(&tool.name) {
                return Ok(ConnectorToolScreen {
                    refused: Some(format!("duplicate listed tool: {}", tool.name)),
                    ..ConnectorToolScreen::default()
                });
            }
            if let Some(reason) = screen_listed_tool(tool, &rules) {
                let tripped = listed_tool_rules(tool, &rules);
                skipped.push(SkippedConnectorTool {
                    tool: tool.name.clone(),
                    reason,
                    owner_may_install: !tripped.is_empty()
                        && tripped.iter().all(|rule| rule.owner_may_lift()),
                    rules: tripped,
                    digest: listed_tool_digest(tool),
                });
            }
        }
        Ok(ConnectorToolScreen {
            refused: None,
            skipped,
            accepted: BTreeMap::new(),
        })
    }

    /// The pack install rules in force for `holder`, `None` when the policy
    /// manifest holds none.
    fn connector_screen_rules(&self, holder: &str) -> Result<Option<EffectivePackInstallPolicy>> {
        let txn = self.store.env.read_txn()?;
        let resolution = crate::gate::resolve_policy_manifest(&self.store, &txn)?;
        Ok(resolution
            .pack_install_policy()
            .map(|policy| policy.effective(holder)))
    }
}

const POLICY_UNAVAILABLE: &str = "pack install policy unavailable";

/// The first rule one listed tool trips, on its name, its description and
/// its resolved input schema; `None` when it passes.
fn screen_listed_tool(
    tool: &PackObservedTool,
    rules: &EffectivePackInstallPolicy,
) -> Option<String> {
    let resolved = match ResolvedToolSchema::parse(&tool.input_schema) {
        Ok(schema) => schema,
        Err(reason) => return Some(reason),
    };
    decoded_rule(&tool.name, rules)
        .or_else(|| decoded_rule(&tool.description, rules))
        .map(str::to_owned)
        .or_else(|| screen_resolved_schema(&resolved, rules))
}

/// Every rule one listed tool trips, on its name, its description and each
/// text of its resolved input schema: the same rules
/// [`screen_listed_tool`] stops at the first of.
fn listed_tool_rules(
    tool: &PackObservedTool,
    rules: &EffectivePackInstallPolicy,
) -> BTreeSet<ScreenRule> {
    let mut tripped: BTreeSet<ScreenRule> = decoded_rules(&tool.name, rules).into_iter().collect();
    tripped.extend(decoded_rules(&tool.description, rules));
    match ResolvedToolSchema::parse(&tool.input_schema).and_then(|schema| schema.text()) {
        Ok(fields) => {
            for field in fields {
                tripped.extend(decoded_rules(&field.text, rules));
                if field.role == TextRole::ParameterDescription
                    && screen_parameter(&field.text, rules).is_some()
                {
                    tripped.insert(ScreenRule::ParameterInjection);
                }
            }
        }
        Err(_) => {
            tripped.insert(ScreenRule::UnresolvedSchema);
        }
    }
    tripped
}

fn screen_resolved_schema(
    schema: &ResolvedToolSchema,
    rules: &EffectivePackInstallPolicy,
) -> Option<String> {
    let fields = match schema.text() {
        Ok(fields) => fields,
        Err(reason) => return Some(reason),
    };
    for field in fields {
        let reason = decoded_rule(&field.text, rules).or_else(|| {
            (field.role == TextRole::ParameterDescription)
                .then(|| screen_parameter(&field.text, rules))
                .flatten()
        });
        if let Some(reason) = reason {
            return Some(format!("{}: {reason}", field.location));
        }
    }
    None
}
fn decoded_rule(text: &str, rules: &EffectivePackInstallPolicy) -> Option<&'static str> {
    decoded_rules(text, rules).first().map(|rule| rule.reason())
}
/// Every rule `text` trips: the secret shape, then [`text_rules`], then the
/// known-bad patterns, the order [`decoded_rule`] answers the first of.
fn decoded_rules(text: &str, rules: &EffectivePackInstallPolicy) -> Vec<ScreenRule> {
    let normalized = ComposingNormalizer::new_nfkc().normalize(text);
    let mut tripped = Vec::new();
    if crate::batch::secret_scan::scan_file_content("", normalized.as_bytes()).is_some() {
        tripped.push(ScreenRule::SecretShapedString);
    }
    tripped.extend(text_rules(text, rules));
    if known_bad(text, rules).is_some() {
        tripped.push(ScreenRule::KnownBadPattern);
    }
    tripped
}
fn known_bad(text: &str, rules: &EffectivePackInstallPolicy) -> Option<&'static str> {
    let lower = ComposingNormalizer::new_nfkc()
        .normalize(text)
        .to_lowercase();
    rules
        .known_bad_patterns
        .iter()
        .any(|pattern| lower.contains(&pattern.to_lowercase()))
        .then_some("known-bad pattern")
}
fn screen_parameter(text: &str, rules: &EffectivePackInstallPolicy) -> Option<&'static str> {
    let lower = ComposingNormalizer::new_nfkc()
        .normalize(text)
        .to_lowercase();
    rules
        .parameter_injection
        .iter()
        .any(|pattern| lower.contains(&pattern.to_lowercase()))
        .then_some("parameter-description injection")
}
fn screen_text(text: &str, rules: &EffectivePackInstallPolicy) -> Option<&'static str> {
    text_rules(text, rules).first().map(|rule| rule.reason())
}
/// The size bound of one screened text, in bytes.
const TEXT_MAX_BYTES: usize = 16384;
/// Every size, deception and hidden-instruction rule `text` trips, in the
/// order [`screen_text`] answers the first of.
fn text_rules(text: &str, rules: &EffectivePackInstallPolicy) -> Vec<ScreenRule> {
    let mut tripped = Vec::new();
    if text.len() > TEXT_MAX_BYTES {
        tripped.push(ScreenRule::TextBound);
    }
    if text.chars().any(|c| matches!(c, '\u{00ad}' | '\u{034f}' | '\u{061c}' | '\u{180e}' | '\u{200b}'..='\u{200f}' | '\u{202a}'..='\u{202e}' | '\u{2060}'..='\u{2069}' | '\u{feff}')) {
        tripped.push(ScreenRule::InvisibleText);
    }
    // Mixed Latin/Cyrillic or Latin/Greek text admits the whole confusable
    // repertoire, not a manually maintained set of code points.
    if text.split(|c: char| !c.is_alphabetic()).any(|word| {
        word.chars().any(|c| c.script() == Script::Latin)
            && word
                .chars()
                .any(|c| matches!(c.script(), Script::Cyrillic | Script::Greek))
    }) {
        tripped.push(ScreenRule::MixedScriptHomoglyph);
    }
    let normalized = ComposingNormalizer::new_nfkc().normalize(text);
    if text.chars().any(|c| {
        !c.is_ascii()
            && ComposingNormalizer::new_nfkc()
                .normalize(&c.to_string())
                .chars()
                .any(|normalized| normalized.is_ascii_alphabetic())
    }) {
        tripped.push(ScreenRule::CompatibilityHomoglyph);
    }
    let lower = normalized.to_lowercase();
    if rules
        .hidden_instructions
        .iter()
        .any(|pattern| lower.contains(&pattern.to_lowercase()))
    {
        tripped.push(ScreenRule::HiddenInstructions);
    }
    tripped
}
