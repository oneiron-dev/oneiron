//! OF-063 record assertions in saved skill text (FIX 1230): the prose an
//! agent saves or forks into a skill is read for `oneiron://` links its
//! writer cannot resolve, as every other AI-written text is
//! ([`unlinked_prose_links`]), and each one is receipted once the skill
//! lands. A code sample in a fenced, indented or inline code block cites
//! nothing (the prose parser skips it), and a source file that is not
//! Markdown is a script, never prose. The read refuses no save; a human
//! writer's text is not read.

use std::path::Path;

use serde::Serialize;

use crate::Vault;
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::gate::record_references::unlinked_prose_links;
use crate::memory::{Memory, MemoryResult};
use crate::receipt::ReferenceRefusalFacts;
use crate::skill_hub::HubFile;

use super::record::SkillRecord;

/// The verb row a saved skill's unlinked links are receipted under.
const SKILL_SAVE_ROW: &str = "self.skills.save";
/// The verb row a forked skill's unlinked links are receipted under.
const SKILL_FORK_ROW: &str = "self.skills.fork";
/// The extension of a source file whose text is prose; any other file is a
/// script or data and cites nothing.
const PROSE_EXTENSION: &str = "md";
/// The slots of [`SkillProse`] the prose read takes.
const PROSE_POINTERS: &[&str] = &["/desc", "/files/*/text"];

/// The prose a saved skill carries: its description and its Markdown files.
#[derive(Serialize)]
struct SkillProse<'a> {
    desc: &'a str,
    files: Vec<ProseFile<'a>>,
}

/// One Markdown source file's text, by its path.
#[derive(Serialize)]
struct ProseFile<'a> {
    path: &'a str,
    text: &'a str,
}

impl<'a> SkillProse<'a> {
    fn of(record: &'a SkillRecord, files: &'a [HubFile]) -> Self {
        let files = files
            .iter()
            .filter(|file| {
                Path::new(&file.path)
                    .extension()
                    .is_some_and(|extension| extension.eq_ignore_ascii_case(PROSE_EXTENSION))
            })
            .filter_map(|file| {
                Some(ProseFile {
                    path: &file.path,
                    text: std::str::from_utf8(&file.content).ok()?,
                })
            })
            .collect();
        Self {
            desc: &record.desc,
            files,
        }
    }
}

/// The `unlinked` facts the text a skill save lands earns its writer:
/// `record`'s description and each Markdown file in `files`. Read before the
/// save's writer opens; its caller receipts them once the save has landed.
///
/// # Errors
///
/// The prose read's errors.
pub(crate) fn saved_skill_prose_links(
    memory: &Memory<'_>,
    record: &SkillRecord,
    files: &[HubFile],
) -> MemoryResult<Vec<ReferenceRefusalFacts>> {
    unlinked_prose_links(
        memory,
        SKILL_SAVE_ROW,
        &SkillProse::of(record, files),
        PROSE_POINTERS,
    )
}

/// [`saved_skill_prose_links`] for a fork of `parent`: the fork saves its
/// parent's description and source under its writer's name, so that text is
/// read for the forker. A parent this read cannot open yields no facts: the
/// fork's own transaction answers for it.
///
/// # Errors
///
/// The prose read's errors.
pub(crate) fn forked_skill_prose_links(
    memory: &Memory<'_>,
    vault: &Vault,
    parent: &EntityId,
) -> MemoryResult<Vec<ReferenceRefusalFacts>> {
    let Ok((record, files)) = parent_text(vault, parent) else {
        return Ok(Vec::new());
    };
    unlinked_prose_links(
        memory,
        SKILL_FORK_ROW,
        &SkillProse::of(&record, &files),
        PROSE_POINTERS,
    )
}

/// `parent`'s record and the source files a fork of it copies.
fn parent_text(vault: &Vault, parent: &EntityId) -> Result<(SkillRecord, Vec<HubFile>)> {
    let rtxn = vault.store.env.read_txn()?;
    let record = vault.read_skill_record_in_txn(&rtxn, parent)?;
    let files = vault
        .runtime_skill_package_in_txn(&rtxn, parent, &record)?
        .map(|package| package.files)
        .unwrap_or_default();
    Ok((record, files))
}
