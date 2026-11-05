//! Core half of `store::skill_package::folder`: its store-layer items live in `oneiron_store::skill_package::folder` and are
//! re-exported here; the items below stay in the engine.

pub(crate) use oneiron_store::skill_package::folder::*;

use super::codec::invalid;
use super::{HubFile, HubPackage, SkillCapabilitySurface, SkillPackageFormat};
use crate::error::Result;
use crate::write_envelope::skill_record::{
    SkillCallContract, SkillLifecycle, SkillRecord, SkillRole,
};
use oneiron_contracts::claim::{ClaimApprovalStatus, ClaimSource};
use std::collections::BTreeMap;

/// Reads the common scalar frontmatter subset. Complex YAML is refused, not guessed.
/// Hosts can normalize richer YAML before publication, without changing this parser's trust floor.
///
/// The marketplaces' own shapes map here at ingress (ARCH-0053 §7: any git repo
/// or static index is a hub, so a marketplace needs no adapter of its own):
/// agentskills.io's optional `version` falls back to `metadata.version`, then to
/// a version named by the tree's content; `allowed-tools` may be its plain
/// space- or comma-delimited list; the `metadata.requires.{bins,env,mcp}`
/// precondition block, top-level or under one vendor key (ClawHub's
/// `openclaw`), joins the capability surface; and Claude Code's invocation
/// hints are read as inert.
pub(crate) fn package_from_files(files: Vec<HubFile>) -> Result<HubPackage> {
    validate_source_files(&files)?;
    let front = source_frontmatter(instruction_text(&files)?)?
        .ok_or_else(|| invalid("SKILL.md needs frontmatter"))?;
    let (fields, caps, role, call, metadata_version) = frontmatter_fields(front)?;
    let scalar = |key: &str| -> Result<String> {
        let value = *fields
            .get(key)
            .ok_or_else(|| invalid("missing required frontmatter scalar"))?;
        frontmatter_scalar(value)
    };
    let version = match (fields.contains_key("version"), metadata_version) {
        (true, _) => scalar("version")?,
        (false, Some(version)) => version,
        (false, None) => content_version(&files)?,
    };
    // A site skill's origins, routes and seeds that do not read are named
    // on its provenance (CUA E10); the import goes on all the same.
    let mut provenance = vec![(rmpv::Value::from("source"), rmpv::Value::from("hub-folder"))];
    let site_notes = super::site_folder::import_notes(&files);
    if !site_notes.is_empty() {
        provenance.push((
            rmpv::Value::from(super::site_folder::SITE_NOTES_KEY),
            rmpv::Value::Array(site_notes.into_iter().map(rmpv::Value::from).collect()),
        ));
    }
    let record = SkillRecord::new(
        scalar("name")?,
        scalar("description")?,
        version,
        ClaimApprovalStatus::Proposed,
        SkillLifecycle::Candidate,
        ClaimSource::Imported,
        0.5,
        false,
        true,
        vec![],
        rmpv::Value::Map(provenance),
    )
    .with_role(role, call);
    crate::write_envelope::skill_record::encode_skill_record(&record)?;
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
                && !parsed.as_ref().is_some_and(|(_, _, role, call, _)| {
                    *role == SkillRole::Callable && call == &record.call
                })
            {
                return Err(invalid(
                    "callable source frontmatter must match its native call contract",
                ));
            }
            if let Some((fields, _, role, call, _)) = &parsed
                && ((fields.contains_key("role") && *role != record.role)
                    || (fields.contains_key("call") && call != &record.call))
            {
                return Err(invalid(
                    "native skill role/call differs from declared frontmatter",
                ));
            }
            let caps = parsed.map(|(_, caps, _, _, _)| caps).unwrap_or_default();
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
    crate::write_envelope::skill_record::encode_skill_record(record)?;
    // A site skill's origins, routes and seeds that do not read are named on
    // its provenance in either format, as `package_from_files` names them.
    package.record = with_site_notes(record.clone(), &package.files);
    crate::write_envelope::skill_record::encode_skill_record(&package.record)?;
    Ok(package)
}

/// `record` with the site notes `files` give on its provenance under
/// [`super::site_folder::SITE_NOTES_KEY`], in place of any it held there.
/// A tree with no notes, or a provenance that is neither a map nor empty,
/// leaves the record as it was.
fn with_site_notes(mut record: SkillRecord, files: &[HubFile]) -> SkillRecord {
    let notes = super::site_folder::import_notes(files);
    if notes.is_empty() {
        return record;
    }
    if record.provenance.is_nil() {
        record.provenance = rmpv::Value::Map(Vec::new());
    }
    if let rmpv::Value::Map(entries) = &mut record.provenance {
        entries.retain(|(key, _)| key.as_str() != Some(super::site_folder::SITE_NOTES_KEY));
        entries.push((
            rmpv::Value::from(super::site_folder::SITE_NOTES_KEY),
            rmpv::Value::Array(notes.into_iter().map(rmpv::Value::from).collect()),
        ));
    }
    record
}

fn validate_source_files(files: &[HubFile]) -> Result<()> {
    crate::write_envelope::skill_record::canonical_skill_tree_hash(
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
