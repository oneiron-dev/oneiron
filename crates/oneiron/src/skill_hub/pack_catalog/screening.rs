//! Bounded, source-bound install rules for connector tool manifests.
use super::{PackKind, PackObservedTool, PackQualification, PackSource, invalid};
use crate::{Vault, consent::AuthenticatedOwner, error::Result, skill::SkillContentHash};
use icu_normalizer::ComposingNormalizer;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use std::collections::{BTreeMap, BTreeSet};
use unicode_script::{Script, UnicodeScript};

const RULES_KEY: &[u8] = b"pack.install.rules.v1";
const MAX_NODES: usize = 8192;
const MAX_DEPTH: usize = 32;

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
        self.with_write_txn(|txn| {
            owner.revalidate_in_txn(self, txn)?;
            let bytes = serde_json::to_vec(rules).map_err(|_| invalid("install rules encoding"))?;
            self.store.vault_meta.put(txn, RULES_KEY, &bytes)?;
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
        qualification: &PackQualification,
    ) -> Result<Option<String>> {
        let rules: PackInstallRules = self
            .store
            .vault_meta
            .get(txn, RULES_KEY)?
            .map(|raw| serde_json::from_slice(&raw).map_err(|_| invalid("install rules corrupt")))
            .transpose()?
            .unwrap_or_default();
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
                && let Some(reason) = super::script_screen::screen_script(&file.path, text)
            {
                return Ok(Some(format!("{reason} in {}", file.path)));
            }
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
            if let Some(reason) = screen_text(text) {
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
            let mut budget = MAX_NODES;
            let resolved = match resolve(schema, schema, 0, &mut budget) {
                Ok(resolved) => resolved,
                Err(reason) => return Ok(Some(format!("tool {name}: {reason}"))),
            };
            if !resolved.is_object() {
                return Ok(Some(format!("tool {name}: schema must be an object")));
            }
            if let Some(reason) = screen_text(name)
                .or_else(|| screen_text(description))
                .or_else(|| screen_schema(&resolved, false))
                .or_else(|| known_bad_value(&resolved, &rules))
                .or_else(|| known_bad(name, &rules))
                .or_else(|| known_bad(description, &rules))
            {
                return Ok(Some(format!("tool {name}: {reason}")));
            }
            declared.insert(name.to_owned(), (description.to_owned(), resolved));
        }
        if declared.is_empty() {
            return Ok(Some("connector has no declared tool manifest".into()));
        }
        if declared.len() != qualification.observed_tools.len() {
            return Ok(Some("declared-vs-actual tool count mismatch".into()));
        }
        let mut seen = BTreeSet::new();
        for PackObservedTool {
            name,
            description,
            input_schema,
        } in &qualification.observed_tools
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
            let mut budget = MAX_NODES;
            let observed = match resolve(input_schema, input_schema, 0, &mut budget) {
                Ok(resolved) => resolved,
                Err(reason) => return Ok(Some(format!("observed tool {name}: {reason}"))),
            };
            if let Some(reason) = screen_text(description)
                .or_else(|| screen_schema(&observed, false))
                .or_else(|| known_bad_value(&observed, &rules))
                .or_else(|| known_bad(description, &rules))
            {
                return Ok(Some(format!("observed tool {name}: {reason}")));
            }
            if description != expected_description || &observed != expected_schema {
                return Ok(Some(format!("declared-vs-actual mismatch for {name}")));
            }
        }
        Ok(None)
    }
}

// Resolve LOCAL JSON pointers against the entire tool document. No remote fetch,
// unresolved/cyclic references, oversized graph or unchecked composition branch.
fn resolve(
    value: &Value,
    root: &Value,
    depth: usize,
    budget: &mut usize,
) -> std::result::Result<Value, &'static str> {
    if depth > MAX_DEPTH || *budget == 0 {
        return Err("schema resolution bound exceeded");
    }
    *budget -= 1;
    match value {
        Value::Object(fields) => {
            let mut result = Map::new();
            let reference_target = if let Some(reference) = fields.get("$ref") {
                let pointer = reference
                    .as_str()
                    .and_then(|s| s.strip_prefix('#'))
                    .filter(|p| p.is_empty() || p.starts_with('/'))
                    .ok_or("external or invalid schema ref")?;
                let target = root.pointer(pointer).ok_or("unresolved schema ref")?;
                let resolved = resolve(target, root, depth + 1, budget)?;
                if !resolved.is_object() {
                    return Err("ref must resolve to an object");
                }
                Some(resolved)
            } else {
                None
            };
            for (key, child) in fields {
                if key == "$ref" {
                    continue;
                }
                if key == "allOf" {
                    let branches = child
                        .as_array()
                        .filter(|b| !b.is_empty())
                        .ok_or("empty composition")?;
                    let mut combined = Vec::new();
                    // Never union constraints from distinct branches: branch-local
                    // additionalProperties/unevaluatedProperties would change meaning.
                    for branch in branches {
                        let resolved = resolve(branch, root, depth + 1, budget)?;
                        if !resolved.is_object() {
                            return Err("composition must contain objects");
                        }
                        if !combined.contains(&resolved) {
                            combined.push(resolved);
                        }
                    }
                    if result.insert(key.clone(), Value::Array(combined)).is_some() {
                        return Err("conflicting composition");
                    }
                } else if key == "anyOf" || key == "oneOf" {
                    let branches = child
                        .as_array()
                        .filter(|b| !b.is_empty())
                        .ok_or("empty composition")?;
                    let mut resolved = Vec::new();
                    for branch in branches {
                        let value = resolve(branch, root, depth + 1, budget)?;
                        if !value.is_object() {
                            return Err("composition must contain objects");
                        }
                        resolved.push(value);
                    }
                    if result.insert(key.clone(), Value::Array(resolved)).is_some() {
                        return Err("conflicting composition");
                    }
                } else {
                    let resolved = resolve(child, root, depth + 1, budget)?;
                    if result
                        .insert(key.clone(), resolved.clone())
                        .is_some_and(|old| old != resolved)
                    {
                        return Err("conflicting ref sibling");
                    }
                }
            }
            // A ref plus sibling keywords is an intersection, not a map union.
            // Even one allOf branch must keep its own evaluation scope:
            // additionalProperties in that branch cannot see parent properties.
            if let Some(target) = reference_target {
                if result.is_empty() {
                    return Ok(target);
                }
                return Ok(serde_json::json!({"allOf": [target, Value::Object(result)]}));
            }
            Ok(Value::Object(result))
        }
        Value::Array(items) => items
            .iter()
            .map(|item| resolve(item, root, depth + 1, budget))
            .collect(),
        _ => Ok(value.clone()),
    }
}
fn screen_schema(value: &Value, parameter: bool) -> Option<&'static str> {
    match value {
        Value::Object(fields) => fields.iter().find_map(|(key, value)| {
            screen_text(key).or_else(|| match (key.as_str(), value) {
                // A property called "description" is a schema, not an annotation.
                ("description", Value::String(text)) => screen_text(text)
                    .or_else(|| parameter.then(|| screen_parameter(text)).flatten()),
                ("properties" | "patternProperties", Value::Object(properties)) => {
                    properties.iter().find_map(|(name, schema)| {
                        screen_text(name).or_else(|| screen_schema(schema, true))
                    })
                }
                (_, child) => screen_schema(child, parameter),
            })
        }),
        Value::Array(values) => values.iter().find_map(|v| screen_schema(v, parameter)),
        Value::String(s) => screen_text(s),
        _ => None,
    }
}
fn decoded_rule(text: &str, rules: &PackInstallRules) -> Option<&'static str> {
    let normalized = ComposingNormalizer::new_nfkc().normalize(text);
    if crate::batch::secret_scan::scan_file_content("", normalized.as_bytes()).is_some() {
        return Some("secret-shaped string");
    }
    screen_text(text).or_else(|| known_bad(text, rules))
}
fn known_bad(text: &str, rules: &PackInstallRules) -> Option<&'static str> {
    let lower = ComposingNormalizer::new_nfkc()
        .normalize(text)
        .to_lowercase();
    rules
        .known_bad_patterns
        .iter()
        .any(|pattern| lower.contains(&pattern.to_lowercase()))
        .then_some("known-bad pattern")
}
fn known_bad_value(value: &Value, rules: &PackInstallRules) -> Option<&'static str> {
    match value {
        Value::Object(fields) => fields.iter().find_map(|(key, value)| {
            known_bad(key, rules).or_else(|| known_bad_value(value, rules))
        }),
        Value::Array(items) => items.iter().find_map(|item| known_bad_value(item, rules)),
        Value::String(text) => known_bad(text, rules),
        _ => None,
    }
}
fn screen_parameter(text: &str) -> Option<&'static str> {
    let lower = ComposingNormalizer::new_nfkc()
        .normalize(text)
        .to_lowercase();
    [
        "ignore",
        "instruction",
        "system prompt",
        "developer message",
        "exfiltrat",
        "send secrets",
    ]
    .iter()
    .any(|pattern| lower.contains(pattern))
    .then_some("parameter-description injection")
}
fn screen_text(text: &str) -> Option<&'static str> {
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
    [
        "ignore previous",
        "ignore all",
        "override instructions",
        "act as system",
        "system prompt",
        "developer message",
        "do not tell",
        "reveal secret",
    ]
    .iter()
    .any(|pattern| lower.contains(pattern))
    .then_some("hidden instructions")
}
