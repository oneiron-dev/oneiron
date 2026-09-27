//! Bounded, source-bound install rules for connector tool manifests.
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
        if rules.removed_hashes.len() > 1024
            || rules.known_bad_patterns.len() > 128
            || rules
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
        let manifest = source.manifest();
        let mut decoded = vec![
            ("name", manifest.name.as_str()),
            ("description", manifest.description.as_str()),
            ("version", manifest.version.as_str()),
        ];
        if let Some(license) = &manifest.license {
            decoded.push(("license", license));
        }
        if let Some(adapter) = &manifest.adapter {
            match adapter {
                super::PackAdapter::Builtin(value) | super::PackAdapter::Script(value) => {
                    decoded.push(("adapter", value));
                }
            }
        }
        for (field, values) in [
            ("predicates", &manifest.predicates),
            ("kinds", &manifest.kinds),
            ("grants", &manifest.requested_grants),
            ("wakes", &manifest.wake_subscriptions),
        ] {
            decoded.extend(values.iter().map(|value| (field, value.as_str())));
        }
        for (field, text) in decoded {
            if let Some(reason) = decoded_rule(text, &rules) {
                return Ok(Some(format!("PACK.md {field}: {reason}")));
            }
        }
        if let Some(pack) = source.files().iter().find(|file| file.path == "PACK.md") {
            let text =
                std::str::from_utf8(&pack.content).map_err(|_| invalid("PACK.md is not UTF-8"))?;
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
    let normalized = ComposingNormalizer::new_nfkc().normalize(text);
    if crate::batch::secret_scan::scan_file_content("", normalized.as_bytes()).is_some() {
        return Some("secret-shaped string");
    }
    screen_text(text, rules).or_else(|| known_bad(text, rules))
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
    if text.len() > 16384 {
        return Some("manifest text bound exceeded");
    }
    if text.chars().any(|c| matches!(c, '\u{00ad}' | '\u{034f}' | '\u{061c}' | '\u{180e}' | '\u{200b}'..='\u{200f}' | '\u{202a}'..='\u{202e}' | '\u{2060}'..='\u{2069}' | '\u{feff}')) {
        return Some("zero-width or RTL deception");
    }
    // Mixed Latin/Cyrillic or Latin/Greek text admits the whole confusable
    // repertoire, not a manually maintained set of code points.
    for word in text.split(|c: char| !c.is_alphabetic()) {
        if word.chars().any(|c| c.script() == Script::Latin)
            && word
                .chars()
                .any(|c| matches!(c.script(), Script::Cyrillic | Script::Greek))
        {
            return Some("mixed-script homoglyph deception");
        }
    }
    let normalized = ComposingNormalizer::new_nfkc().normalize(text);
    if text.chars().any(|c| {
        !c.is_ascii()
            && ComposingNormalizer::new_nfkc()
                .normalize(&c.to_string())
                .chars()
                .any(|normalized| normalized.is_ascii_alphabetic())
    }) {
        return Some("compatibility homoglyph deception");
    }
    let lower = normalized.to_lowercase();
    rules
        .hidden_instructions
        .iter()
        .any(|pattern| lower.contains(&pattern.to_lowercase()))
        .then_some("hidden instructions")
}
