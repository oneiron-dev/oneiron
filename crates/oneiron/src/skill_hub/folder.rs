//! Strict portable SKILL.md frontmatter subset used by real hub transports.
use super::package_codec::invalid;
use super::{HubFile, HubPackage, SkillCapabilitySurface, SkillPackageFormat};
use crate::claim::{ClaimApprovalStatus, ClaimSource};
use crate::error::Result;
use crate::skill::{SkillCallContract, SkillLifecycle, SkillRecord, SkillRole};
use std::collections::BTreeMap;

/// Reads the common scalar frontmatter subset. Complex YAML is refused, not guessed.
/// Hosts can normalize richer YAML before publication, without changing this parser's trust floor.
pub(super) fn package_from_files(files: Vec<HubFile>) -> Result<HubPackage> {
    validate_source_files(&files)?;
    let front = source_frontmatter(instruction_text(&files)?)?
        .ok_or_else(|| invalid("SKILL.md needs frontmatter"))?;
    let (fields, caps, role, call) = frontmatter_fields(front)?;
    let scalar = |key: &str| -> Result<String> {
        let value = *fields
            .get(key)
            .ok_or_else(|| invalid("missing required frontmatter scalar"))?;
        if value.starts_with('"') {
            return serde_json::from_str(value)
                .map_err(|_| invalid("invalid quoted frontmatter scalar"));
        }
        if value.is_empty()
            || value
                .chars()
                .any(|c| matches!(c, '\'' | '&' | '*' | '!' | '{' | '[' | '|' | '>' | '#'))
        {
            return Err(invalid("unsupported YAML scalar"));
        }
        Ok(value.to_owned())
    };
    let record = SkillRecord::new(
        scalar("name")?,
        scalar("description")?,
        scalar("version")?,
        ClaimApprovalStatus::Proposed,
        SkillLifecycle::Candidate,
        ClaimSource::Imported,
        0.5,
        false,
        true,
        vec![],
        rmpv::Value::Map(vec![(
            rmpv::Value::from("source"),
            rmpv::Value::from("hub-folder"),
        )]),
    )
    .with_role(role, call);
    crate::skill::encode_skill_record(&record)?;
    if let Some(call) = &record.call
        && !files
            .iter()
            .any(|file| file.path == call.reference && std::str::from_utf8(&file.content).is_ok())
    {
        return Err(invalid(
            "call reference must name a UTF-8 file in the exact skill tree",
        ));
    }
    let mut package = HubPackage::new(record, files, caps);
    package.record.content_hash = Some(package.content_hash()?);
    Ok(package)
}

type ParsedFrontmatter<'a> = (
    BTreeMap<&'a str, &'a str>,
    SkillCapabilitySurface,
    SkillRole,
    Option<SkillCallContract>,
);

fn frontmatter_fields(front: &str) -> Result<ParsedFrontmatter<'_>> {
    let mut fields = BTreeMap::new();
    let mut caps = SkillCapabilitySurface::default();
    let mut call_fields = serde_json::Map::new();
    let mut in_call = false;
    for line in front.lines() {
        if line.trim().is_empty() || line.starts_with('#') {
            continue;
        }
        if line.starts_with(char::is_whitespace) {
            if !in_call || !line.starts_with("  ") || line.starts_with("   ") {
                return Err(invalid("unsupported nested YAML frontmatter"));
            }
            let (key, value) = line
                .trim_start()
                .split_once(':')
                .ok_or_else(|| invalid("invalid call field"))?;
            if !matches!(key, "reference" | "arguments" | "returns")
                || call_fields
                    .insert(key.to_owned(), call_field_value(value.trim())?)
                    .is_some()
            {
                return Err(invalid(
                    "call must have unique reference, arguments and returns fields",
                ));
            }
            continue;
        }
        in_call = false;
        let (key, value) = line
            .split_once(':')
            .ok_or_else(|| invalid("invalid frontmatter field"))?;
        let value = value.trim();
        if fields.insert(key, value).is_some() {
            return Err(invalid("duplicate frontmatter field"));
        }
        match key {
            "name" | "description" | "version" | "license" | "compatibility" | "role" => {}
            "call" => {
                if value.is_empty() {
                    in_call = true;
                } else {
                    let serde_json::Value::Object(object) =
                        serde_json::from_str(value).map_err(|_| {
                            invalid("call requires a JSON flow-map or three nested fields")
                        })?
                    else {
                        return Err(invalid("call must be a map"));
                    };
                    call_fields = object;
                }
            }
            "metadata" => {
                let _: BTreeMap<String, String> = serde_json::from_str(value)
                    .map_err(|_| invalid("metadata requires a JSON string map"))?;
            }
            // These are JSON arrays, a closed YAML flow-sequence subset. No expansion, aliases or tags.
            "allowed-tools" | "requires-bins" | "requires-env" | "requires-mcp" => {
                let entries: Vec<String> = serde_json::from_str(value)
                    .map_err(|_| invalid("capabilities require a JSON string array"))?;
                let set = match key {
                    "allowed-tools" => &mut caps.allowed_tools,
                    "requires-bins" => &mut caps.bins,
                    "requires-env" => &mut caps.env,
                    _ => &mut caps.mcp,
                };
                for entry in entries {
                    if !set.insert(entry) {
                        return Err(invalid("duplicate capability"));
                    }
                }
            }
            _ => {
                return Err(invalid(
                    "unsupported frontmatter field; normalize before import",
                ));
            }
        }
    }
    let role = fields
        .get("role")
        .map(|value| {
            SkillRole::parse(value)
                .ok_or_else(|| invalid("role must be knowledge|workflow|callable"))
        })
        .transpose()?
        .unwrap_or(SkillRole::Knowledge);
    let call = if fields.contains_key("call") {
        let value = serde_json::Value::Object(call_fields);
        Some(
            serde_json::from_value::<CallFields>(value)
                .map_err(|_| invalid("call requires reference, arguments and returns only"))?
                .into_contract(),
        )
    } else {
        None
    };
    Ok((fields, caps, role, call))
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct CallFields {
    reference: String,
    arguments: serde_json::Value,
    returns: serde_json::Value,
}

impl CallFields {
    fn into_contract(self) -> SkillCallContract {
        SkillCallContract {
            reference: self.reference,
            arguments: self.arguments,
            returns: self.returns,
        }
    }
}

fn call_field_value(value: &str) -> Result<serde_json::Value> {
    if let Ok(parsed) = serde_json::from_str(value) {
        return Ok(parsed);
    }
    if value.is_empty() || value.contains(['#', '\n', '\r']) {
        return Err(invalid("invalid call field"));
    }
    Ok(serde_json::Value::String(value.to_owned()))
}

/// Reconstructs an untrusted package without changing one byte of its source.
/// Native metadata is not SKILL.md frontmatter: content-named conversion versions
/// cannot be inserted into their own preimage. The format is not an authority claim.
pub(crate) fn package_from_source(
    record: &SkillRecord,
    files: Vec<HubFile>,
    format: SkillPackageFormat,
) -> Result<HubPackage> {
    let mut package = match format {
        SkillPackageFormat::Folder => {
            let package = package_from_files(files)?;
            if record.skill_id != package.record.skill_id
                || record.desc != package.record.desc
                || record.version != package.record.version
                || record.role != package.record.role
                || record.call != package.record.call
            {
                return Err(invalid("source frontmatter differs from native skill"));
            }
            package
        }
        SkillPackageFormat::Native => {
            validate_source_files(&files)?;
            let parsed = source_frontmatter(instruction_text(&files)?)?
                .map(frontmatter_fields)
                .transpose()?;
            if record.role == SkillRole::Callable
                && !parsed.as_ref().is_some_and(|(_, _, role, call)| {
                    *role == SkillRole::Callable && call == &record.call
                })
            {
                return Err(invalid(
                    "callable source frontmatter must match its native call contract",
                ));
            }
            if let Some((fields, _, role, call)) = &parsed
                && ((fields.contains_key("role") && *role != record.role)
                    || (fields.contains_key("call") && call != &record.call))
            {
                return Err(invalid(
                    "native skill role/call differs from declared frontmatter",
                ));
            }
            let caps = parsed.map(|(_, caps, _, _)| caps).unwrap_or_default();
            let mut package = HubPackage::new(record.clone(), files, caps);
            package.format = SkillPackageFormat::Native;
            package
        }
    };
    if let Some(call) = &record.call
        && !package
            .files
            .iter()
            .any(|file| file.path == call.reference && std::str::from_utf8(&file.content).is_ok())
    {
        return Err(invalid(
            "call reference must name a UTF-8 file in the exact skill tree",
        ));
    }
    if record.content_hash != Some(package.content_hash()?) {
        return Err(invalid("source tree differs from native skill hash"));
    }
    crate::skill::encode_skill_record(record)?;
    package.record = record.clone();
    Ok(package)
}

fn validate_source_files(files: &[HubFile]) -> Result<()> {
    crate::skill::canonical_skill_tree_hash(
        files
            .iter()
            .map(|file| (file.path.as_str(), file.content.as_slice())),
    )?;
    for file in files {
        if file
            .path
            .split('/')
            .any(|part| part.eq_ignore_ascii_case(".git"))
        {
            return Err(invalid("repository metadata cannot enter a skill folder"));
        }
        crate::batch::secret_scan::scan_metadata_field(&String::from_utf8_lossy(&file.content))?;
    }
    Ok(())
}

pub(super) fn instruction_text(files: &[HubFile]) -> Result<&str> {
    let raw = files
        .iter()
        .find(|file| file.path == "SKILL.md")
        .ok_or_else(|| invalid("package requires SKILL.md"))?;
    std::str::from_utf8(&raw.content).map_err(|_| invalid("SKILL.md is not UTF-8"))
}

pub(super) fn source_frontmatter(text: &str) -> Result<Option<&str>> {
    let Some(front) = text.strip_prefix("---\n") else {
        if text.lines().next().is_some_and(|line| line.trim() == "---") {
            return Err(invalid("unsupported SKILL.md frontmatter delimiter"));
        }
        return Ok(None);
    };
    let end = front
        .find("\n---\n")
        .ok_or_else(|| invalid("unclosed SKILL.md frontmatter"))?;
    if end > 64 * 1024 {
        return Err(invalid("SKILL.md frontmatter exceeds bound"));
    }
    Ok(Some(&front[..end]))
}
