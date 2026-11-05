//! Strict portable SKILL.md frontmatter subset used by real hub transports.
use crate::skill_package::codec::invalid;
use crate::skill_package::package::HubPackage;
use crate::skill_package::package::SkillCapabilitySurface;
use crate::write_envelope::skill_record::SkillCallContract;
use crate::write_envelope::skill_record::SkillLifecycle;
use crate::write_envelope::skill_record::SkillRecord;
use crate::write_envelope::skill_record::SkillRole;
use crate::write_envelope::skill_source::HubFile;
use crate::write_envelope::skill_source::SkillPackageFormat;
use oneiron_base::error::Result;
use oneiron_contracts::claim::{ClaimApprovalStatus, ClaimSource};
use std::collections::BTreeMap;

pub fn frontmatter_scalar(value: &str) -> Result<String> {
    if value.starts_with('"') {
        return serde_json::from_str(value)
            .map_err(|_| invalid("invalid quoted frontmatter scalar"));
    }
    if let Some(quoted) = value.strip_prefix('\'') {
        let inner = quoted
            .strip_suffix('\'')
            .ok_or_else(|| invalid("unterminated single-quoted frontmatter scalar"))?;
        let mut decoded = String::with_capacity(inner.len());
        let mut chars = inner.chars();
        while let Some(c) = chars.next() {
            if c == '\'' && chars.next() != Some('\'') {
                return Err(invalid("single quote must be doubled in a quoted scalar"));
            }
            decoded.push(c);
        }
        if decoded.is_empty() {
            return Err(invalid("empty frontmatter scalar"));
        }
        return Ok(decoded);
    }
    if value.is_empty()
        || value
            .chars()
            .any(|c| matches!(c, '&' | '*' | '!' | '{' | '[' | '|' | '>' | '#'))
    {
        return Err(invalid("unsupported YAML scalar"));
    }
    Ok(value.to_owned())
}

type ParsedFrontmatter<'a> = (
    BTreeMap<&'a str, &'a str>,
    SkillCapabilitySurface,
    SkillRole,
    Option<SkillCallContract>,
    // `metadata.version`, for a source whose frontmatter names no version.
    Option<String>,
);

pub fn frontmatter_fields(front: &str) -> Result<ParsedFrontmatter<'_>> {
    let mut fields = BTreeMap::new();
    let mut caps = SkillCapabilitySurface::default();
    let mut call_fields = serde_json::Map::new();
    let mut in_call = false;
    let mut metadata_block = false;
    let mut requires_block = false;
    let mut metadata_version = None;
    let mut metadata_keys = std::collections::BTreeSet::new();
    for line in front.lines() {
        if line.trim().is_empty() || line.starts_with('#') {
            continue;
        }
        if requires_block
            && let Some(requirement) = line
                .strip_prefix("    ")
                .filter(|rest| !rest.starts_with(char::is_whitespace))
        {
            let (key, value) = requirement
                .split_once(':')
                .ok_or_else(|| invalid("invalid metadata requirement"))?;
            let entries = capability_list(value.trim())?
                .into_iter()
                .map(serde_json::Value::String)
                .collect();
            let block =
                serde_json::Map::from_iter([(key.to_owned(), serde_json::Value::Array(entries))]);
            add_requirements(&block, &mut caps)?;
            continue;
        }
        requires_block = false;
        if line.starts_with(char::is_whitespace) {
            let nested = line
                .strip_prefix("  ")
                .filter(|rest| !rest.starts_with(char::is_whitespace))
                .ok_or_else(|| invalid("unsupported nested YAML frontmatter"))?;
            let (key, value) = nested
                .split_once(':')
                .ok_or_else(|| invalid("invalid nested frontmatter field"))?;
            if in_call {
                if !matches!(key, "reference" | "arguments" | "returns")
                    || call_fields
                        .insert(key.to_owned(), call_field_value(value.trim())?)
                        .is_some()
                {
                    return Err(invalid(
                        "call must have unique reference, arguments and returns fields",
                    ));
                }
            } else if metadata_block && key == "requires" && value.trim().is_empty() {
                if !metadata_keys.insert(key) {
                    return Err(invalid("unsupported metadata scalar"));
                }
                requires_block = true;
            } else if metadata_block && value.trim_start().starts_with('{') {
                // A vendor's map (ClawHub: `openclaw: {"requires": …}`) is read
                // only for its precondition block.
                let serde_json::Value::Object(vendor) = serde_json::from_str(value.trim())
                    .map_err(|_| invalid("metadata map requires a JSON object"))?
                else {
                    return Err(invalid("metadata map requires a JSON object"));
                };
                if !metadata_keys.insert(key) {
                    return Err(invalid("unsupported metadata scalar"));
                }
                metadata_requirements(
                    &serde_json::Map::from_iter([(
                        key.to_owned(),
                        serde_json::Value::Object(vendor),
                    )]),
                    &mut caps,
                )?;
            } else if metadata_block {
                if key == "version" {
                    metadata_version = Some(frontmatter_scalar(value.trim())?);
                }
                if key.is_empty()
                    || !key
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b"_-".contains(&b))
                    || value.trim().is_empty()
                    || value
                        .trim_start()
                        .chars()
                        .next()
                        .is_some_and(|c| matches!(c, '[' | '{' | '!' | '&' | '*' | '|' | '>'))
                    || !metadata_keys.insert(key)
                {
                    return Err(invalid("unsupported metadata scalar"));
                }
            } else {
                return Err(invalid("nested YAML requires call or metadata block"));
            }
            continue;
        }
        in_call = false;
        metadata_block = false;
        let (key, value) = line
            .split_once(':')
            .ok_or_else(|| invalid("invalid frontmatter field"))?;
        let value = value.trim();
        if fields.insert(key, value).is_some() {
            return Err(invalid("duplicate frontmatter field"));
        }
        match key {
            "name" | "description" | "version" | "license" | "compatibility" | "role" => {}
            // Claude Code's invocation hints: read as inert, never a capability.
            "homepage"
            | "model"
            | "argument-hint"
            | "user-invocable"
            | "disable-model-invocation" => {}
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
            "metadata" if value.is_empty() => metadata_block = true,
            "metadata" => {
                let serde_json::Value::Object(metadata) = serde_json::from_str(value)
                    .map_err(|_| invalid("metadata requires a JSON object"))?
                else {
                    return Err(invalid("metadata requires a JSON object"));
                };
                metadata_version = match metadata.get("version") {
                    None => None,
                    Some(serde_json::Value::String(version)) if !version.is_empty() => {
                        Some(version.clone())
                    }
                    Some(_) => return Err(invalid("metadata version must be a string")),
                };
                metadata_requirements(&metadata, &mut caps)?;
            }
            // A JSON array (a closed YAML flow-sequence subset; no expansion,
            // aliases or tags) or a plain delimited list.
            "allowed-tools" | "requires-bins" | "requires-env" | "requires-mcp" => {
                let entries = capability_list(value)?;
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
            SkillRole::parse(&frontmatter_scalar(value)?)
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
    Ok((fields, caps, role, call, metadata_version))
}

/// A capability list: a JSON string array, or the plain list agentskills.io
/// (space-delimited) and Claude Code (comma-delimited) write. A separator inside
/// parentheses belongs to its entry, as in `Bash(git add:*)`.
fn capability_list(value: &str) -> Result<Vec<String>> {
    if value.starts_with('[') {
        return serde_json::from_str(value)
            .map_err(|_| invalid("capabilities require a JSON string array"));
    }
    let value = if value.starts_with(['"', '\'']) {
        frontmatter_scalar(value)?
    } else {
        value.to_owned()
    };
    let mut entries = Vec::new();
    let mut entry = String::new();
    let mut depth = 0usize;
    for c in value.chars() {
        match c {
            ',' | ' ' | '\t' if depth == 0 => {
                if !entry.is_empty() {
                    entries.push(std::mem::take(&mut entry));
                }
            }
            '(' => {
                depth += 1;
                entry.push(c);
            }
            ')' => {
                depth = depth
                    .checked_sub(1)
                    .ok_or_else(|| invalid("unbalanced capability list"))?;
                entry.push(c);
            }
            _ => entry.push(c),
        }
    }
    if depth != 0 {
        return Err(invalid("unbalanced capability list"));
    }
    if !entry.is_empty() {
        entries.push(entry);
    }
    if entries.is_empty() {
        return Err(invalid("empty capability list"));
    }
    Ok(entries)
}

/// The `requires` block of a metadata map, top-level or under one vendor key.
fn metadata_requirements(
    metadata: &serde_json::Map<String, serde_json::Value>,
    caps: &mut SkillCapabilitySurface,
) -> Result<()> {
    let vendors = metadata
        .values()
        .filter_map(|value| value.as_object()?.get("requires"));
    for block in metadata.get("requires").into_iter().chain(vendors) {
        let serde_json::Value::Object(block) = block else {
            return Err(invalid("metadata requires must be a map"));
        };
        add_requirements(block, caps)?;
    }
    Ok(())
}

/// Adds declared requirements to the surface. Any-of binaries count as all of
/// them, the wider reading; an OS filter or a config key asks for nothing the
/// surface tracks. Anything else is normalized before import.
fn add_requirements(
    block: &serde_json::Map<String, serde_json::Value>,
    caps: &mut SkillCapabilitySurface,
) -> Result<()> {
    for (kind, entries) in block {
        let set = match kind.as_str() {
            "bins" | "anyBins" => &mut caps.bins,
            "env" => &mut caps.env,
            "mcp" => &mut caps.mcp,
            "os" | "config" => continue,
            _ => return Err(invalid("unknown requirement kind; normalize before import")),
        };
        let serde_json::Value::Array(entries) = entries else {
            return Err(invalid("requirements must be a string array"));
        };
        for entry in entries {
            match entry {
                serde_json::Value::String(entry) if !entry.is_empty() => {
                    set.insert(entry.clone());
                }
                _ => return Err(invalid("requirements must be a string array")),
            }
        }
    }
    Ok(())
}

/// The version of a source that names none (agentskills.io makes it optional),
/// named by its content so the same tree always reads the same version.
pub fn content_version(files: &[HubFile]) -> Result<String> {
    let hash = crate::write_envelope::skill_record::canonical_skill_tree_hash(
        files
            .iter()
            .map(|file| (file.path.as_str(), file.content.as_slice())),
    )?;
    Ok(format!("0.0.0+{}", &hash.to_hex()[..12]))
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

/// Reads any declared role/call from an authored source tree. Absence stays
/// absence: a merge inherits its target rather than silently downgrading it.
pub fn declared_role_call(
    files: &[HubFile],
) -> Result<(Option<SkillRole>, Option<SkillCallContract>)> {
    let Some(front) = source_frontmatter(instruction_text(files)?)? else {
        return Ok((None, None));
    };
    let (fields, _, role, call, _) = frontmatter_fields(front)?;
    Ok((fields.contains_key("role").then_some(role), call))
}

/// The licence a source tree's SKILL.md frontmatter declares. A tree with
/// no frontmatter, or one that does not read, declares none.
pub fn declared_license(files: &[HubFile]) -> Option<String> {
    let front = source_frontmatter(instruction_text(files).ok()?).ok()??;
    let (fields, _, _, _, _) = frontmatter_fields(front).ok()?;
    frontmatter_scalar(fields.get("license")?).ok()
}

pub fn instruction_text(files: &[HubFile]) -> Result<&str> {
    let raw = files
        .iter()
        .find(|file| file.path == "SKILL.md")
        .ok_or_else(|| invalid("package requires SKILL.md"))?;
    std::str::from_utf8(&raw.content).map_err(|_| invalid("SKILL.md is not UTF-8"))
}

pub fn source_frontmatter(text: &str) -> Result<Option<&str>> {
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
