//! Strict portable SKILL.md frontmatter subset used by real hub transports.
use super::package_codec::invalid;
use super::{HubFile, HubPackage, SkillCapabilitySurface, SkillPackageFormat};
use crate::claim::{ClaimApprovalStatus, ClaimSource};
use crate::error::Result;
use crate::skill::{SkillLifecycle, SkillRecord};
use std::collections::BTreeMap;

/// Reads the common scalar frontmatter subset. Complex YAML is refused, not guessed.
/// Hosts can normalize richer YAML before publication, without changing this parser's trust floor.
pub(super) fn package_from_files(files: Vec<HubFile>) -> Result<HubPackage> {
    validate_source_files(&files)?;
    let front = source_frontmatter(instruction_text(&files)?)?
        .ok_or_else(|| invalid("SKILL.md needs frontmatter"))?;
    let (fields, caps) = frontmatter_fields(front)?;
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
                .any(|c| matches!(c, '&' | '*' | '!' | '{' | '[' | '|' | '>' | '#'))
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
    );
    crate::skill::encode_skill_record(&record)?;
    let mut package = HubPackage::new(record, files, caps);
    package.record.content_hash = Some(package.content_hash()?);
    Ok(package)
}

fn frontmatter_fields(front: &str) -> Result<(BTreeMap<&str, &str>, SkillCapabilitySurface)> {
    let mut fields = BTreeMap::new();
    let mut caps = SkillCapabilitySurface::default();
    let mut metadata_block = false;
    let mut metadata_keys = std::collections::BTreeSet::new();
    for line in front.lines() {
        if line.trim().is_empty() || line.starts_with('#') {
            continue;
        }
        if line.starts_with(char::is_whitespace) {
            // The shipped hub uses the plain YAML scalar-map spelling of
            // metadata. It is inert attribution, not parsed as capabilities.
            let nested = line
                .strip_prefix("  ")
                .ok_or_else(|| invalid("invalid metadata indent"))?;
            let (key, value) = nested
                .split_once(':')
                .ok_or_else(|| invalid("invalid metadata field"))?;
            if !metadata_block
                || key.is_empty()
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
            continue;
        }
        metadata_block = false;
        let (key, value) = line
            .split_once(':')
            .ok_or_else(|| invalid("invalid frontmatter field"))?;
        let value = value.trim();
        if fields.insert(key, value).is_some() {
            return Err(invalid("duplicate frontmatter field"));
        }
        match key {
            "name" | "description" | "version" | "license" | "compatibility" => {}
            "metadata" if value.is_empty() => metadata_block = true,
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
    Ok((fields, caps))
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
            {
                return Err(invalid("source frontmatter differs from native skill"));
            }
            package
        }
        SkillPackageFormat::Native => {
            validate_source_files(&files)?;
            let caps = source_frontmatter(instruction_text(&files)?)?
                .map(frontmatter_fields)
                .transpose()?
                .map(|(_, caps)| caps)
                .unwrap_or_default();
            let mut package = HubPackage::new(record.clone(), files, caps);
            package.format = SkillPackageFormat::Native;
            package
        }
    };
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
