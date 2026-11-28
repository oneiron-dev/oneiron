//! A team-shape package with its task-type tree replaced: the head's files,
//! the tree file swapped and SKILL.md's `name:` and `version:` lines set, every
//! other byte kept. Project forks, promote forks, the owner's pin and the
//! owner's promoted revision all build their package this way.

use crate::error::{ArtifactError, Error, Result};
use crate::skill_hub::{HubFile, HubPackage};

use super::TASK_TYPE_TREE_FILE;

/// The head's files with the tree replaced by `tree` and SKILL.md's `name:`
/// and `version:` lines set to `name` and `version`.
pub(crate) fn fork_files(
    head: &HubPackage,
    name: &str,
    version: &str,
    tree: &[u8],
) -> Result<Vec<HubFile>> {
    let mut files = Vec::with_capacity(head.files.len() + 1);
    for file in &head.files {
        if file.path == TASK_TYPE_TREE_FILE {
            continue;
        }
        if file.path == "SKILL.md" {
            let instructions = fork_instructions(&file.content, name, version)?;
            files.push(HubFile::new("SKILL.md", instructions));
        } else {
            files.push(file.clone());
        }
    }
    files.push(HubFile::new(TASK_TYPE_TREE_FILE, tree));
    Ok(files)
}

/// `head`, a SKILL.md, with its frontmatter `name:` and `version:` lines set
/// to `name` and `version` (a missing `version:` line is added last) and
/// every other byte kept.
fn fork_instructions(head: &[u8], name: &str, version: &str) -> Result<Vec<u8>> {
    let text =
        std::str::from_utf8(head).map_err(|_| refused("the team-shape SKILL.md is not UTF-8"))?;
    let (front, body) = text
        .strip_prefix("---\n")
        .and_then(|rest| rest.split_once("\n---\n"))
        .ok_or_else(|| refused("the team-shape SKILL.md has no frontmatter"))?;
    let line = |key: &str, value: &str| -> Result<String> {
        serde_json::to_string(value)
            .map(|value| format!("{key}: {value}\n"))
            .map_err(|_| refused("a fork's name or version does not encode"))
    };
    let mut out = String::from("---\n");
    let mut versioned = false;
    for entry in front.split('\n') {
        if entry.starts_with("name:") {
            out.push_str(&line("name", name)?);
        } else if entry.starts_with("version:") {
            versioned = true;
            out.push_str(&line("version", version)?);
        } else {
            out.push_str(entry);
            out.push('\n');
        }
    }
    if !versioned {
        out.push_str(&line("version", version)?);
    }
    out.push_str("---\n");
    out.push_str(body);
    Ok(out.into_bytes())
}

/// The version a changed fork package takes: past its own, and never the
/// head's.
pub(crate) fn next_version(current: &str, head: &str) -> String {
    let mut next = current
        .parse::<u64>()
        .map_or(1, |version| version.wrapping_add(1));
    loop {
        let version = next.to_string();
        if version != current && version != head {
            return version;
        }
        next = next.wrapping_add(1);
    }
}

/// A refusal of a package this module cannot edit.
fn refused(reason: &'static str) -> Error {
    Error::Artifact(ArtifactError::InvalidSkillBody(reason))
}
