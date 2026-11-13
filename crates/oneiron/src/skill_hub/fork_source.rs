//! A fork copies real files and edits source identity before hashing the new tree.
use super::{HubFile, HubPackage, SkillPackageFormat, folder, package_codec::invalid};
use crate::skill::health_review::REVIEWER_POLICY_FILE;
use crate::skill::team_shape_catalog::{TASK_TYPE_TREE_FILE, TEAM_SHAPE_SKILL_NAME};
use crate::skill_optimize::SkillFileEdit;
use crate::store::skill_package::site_folder::{PROGRAMS_DIR, SITE_FILE};
use crate::{Vault, entity_id::EntityId, error::Result, skill::SkillRecord};
use std::collections::BTreeMap;

/// The instruction file of a skill's tree.
const INSTRUCTION_FILE: &str = "SKILL.md";

/// Extensions of the text and data files a skill_optimize draft may replace
/// whole (census L9-02, Engine ruling 13 Nov 22:39: existing text and data
/// files, no scripts). Any other file is code, or bytes a draft cannot read.
const DRAFTABLE_EXTENSIONS: [&str; 10] = [
    "md", "markdown", "txt", "json", "jsonl", "yaml", "yml", "toml", "csv", "tsv",
];

/// Whether a skill_optimize draft may replace `record`'s file at `path`
/// whole (census L9-02): a text or data file by its extension, and never a
/// script or hook, the callable's entry, a site skill's `site.json` and
/// seed programs, which declare what the skill may reach, or the team-shape
/// skill's task-type tree, which its own loop revises and its own gate judge
/// reads. `SKILL.md` stands for its body below the engine-written
/// frontmatter; a workflow skill's body is its `desc`, so a draft moves it
/// through `desc` instead.
pub(crate) fn draftable_skill_file(record: &SkillRecord, path: &str) -> bool {
    if record
        .call
        .as_ref()
        .is_some_and(|call| call.reference == path)
    {
        return false;
    }
    if path == INSTRUCTION_FILE {
        return record.role != crate::skill::SkillRole::Workflow;
    }
    let text_or_data = path.rsplit_once('.').is_some_and(|(_, extension)| {
        DRAFTABLE_EXTENSIONS
            .iter()
            .any(|draftable| extension.eq_ignore_ascii_case(draftable))
    });
    text_or_data
        && !super::pack_catalog::is_script_or_hook_path(path)
        && path != SITE_FILE
        && !path.starts_with(PROGRAMS_DIR)
        && !(record.skill_id == TEAM_SHAPE_SKILL_NAME && path == TASK_TYPE_TREE_FILE)
}

/// Each file of `files` a draft may replace ([`draftable_skill_file`]) with
/// its whole UTF-8 text, path-sorted; `SKILL.md` as its body below the
/// frontmatter. A file that is not UTF-8 is not text and is left out.
///
/// # Errors
///
/// A `SKILL.md` whose frontmatter does not read.
pub(crate) fn draftable_skill_texts(
    record: &SkillRecord,
    files: &[HubFile],
) -> Result<Vec<(String, String)>> {
    let mut texts = Vec::new();
    for file in files {
        if !draftable_skill_file(record, &file.path) {
            continue;
        }
        let Ok(text) = std::str::from_utf8(&file.content) else {
            continue;
        };
        let text = if file.path == INSTRUCTION_FILE {
            instruction_body(text)?
        } else {
            text
        };
        texts.push((file.path.clone(), text.to_owned()));
    }
    texts.sort();
    Ok(texts)
}

/// `SKILL.md`'s text below its frontmatter; the whole text when it has none.
fn instruction_body(text: &str) -> Result<&str> {
    Ok(folder::source_frontmatter(text)?.map_or(text, |front| &text[4 + front.len() + 5..]))
}

impl Vault {
    pub(crate) fn fork_skill_package_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        parent_id: &EntityId,
        parent: &SkillRecord,
        fork: &mut SkillRecord,
    ) -> Result<Option<HubPackage>> {
        let Some(mut package) = self.runtime_skill_package_in_txn(txn, parent_id, parent)? else {
            // No historical source can be reconstructed from metadata. This fork
            // remains source-unavailable too; never pretend the description is a file.
            return Ok(None);
        };
        let text = folder::instruction_text(&package.files)?;
        let front = folder::source_frontmatter(text)?;
        let mut replacements = BTreeMap::new();
        for (key, value) in [("name", &fork.skill_id), ("version", &fork.version)] {
            replacements.insert(
                key,
                serde_json::to_string(value)
                    .map_err(|_| invalid("fork identity encoding failed"))?,
            );
        }
        // Capabilities can also arrive through the typed hub adapter. Re-declare
        // the actual stored surface in the fork source so archive import derives
        // the same requirements without trusting an envelope's capability grant.
        for (key, values) in [
            ("requires-bins", &package.capabilities.bins),
            ("requires-env", &package.capabilities.env),
            ("requires-mcp", &package.capabilities.mcp),
            ("allowed-tools", &package.capabilities.allowed_tools),
        ] {
            replacements.insert(
                key,
                serde_json::to_string(values)
                    .map_err(|_| invalid("fork capabilities encoding failed"))?,
            );
        }
        let mut changed = String::from("---\n");
        if let Some(front) = front {
            for line in front.split_inclusive('\n') {
                if line
                    .split_once(':')
                    .is_some_and(|(key, _)| replacements.contains_key(key))
                {
                    continue;
                }
                changed.push_str(line);
                if !line.ends_with('\n') {
                    changed.push('\n');
                }
            }
        }
        for (key, value) in replacements {
            changed.push_str(&format!("{key}: {value}\n"));
        }
        changed.push_str("---\n");
        // Delimiters account for the opening 4 and closing 5 bytes. Everything
        // after frontmatter, and every companion/script file, stays byte-exact.
        changed.push_str(front.map_or(text, |front| &text[4 + front.len() + 5..]));
        package
            .files
            .iter_mut()
            .find(|file| file.path == "SKILL.md")
            .ok_or_else(|| invalid("fork source has no instructions"))?
            .content = changed.into_bytes();
        package.format = SkillPackageFormat::Native;
        fork.content_hash = Some(package.content_hash()?);
        package.record = fork.clone();
        let package = folder::package_from_source(fork, package.files, package.format)?;
        Ok(Some(package))
    }
}

impl Vault {
    /// Carry the exact skill tree into an improver revision. The edit changes
    /// the descriptive recipe text, and replaces whole each text or data file
    /// `files` names (census L9-02); companion scripts/capabilities stay
    /// byte-exact, so a callable never silently loses its executable file.
    /// A rule skill's `policy.json` is re-derived from the improved text: a
    /// dial the text names with a number takes it (FIX 10878), unless the
    /// draft replaces the file itself.
    pub(crate) fn optimized_skill_package_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        parent_id: &EntityId,
        parent: &SkillRecord,
        proposed: &mut SkillRecord,
        files: &[SkillFileEdit],
    ) -> Result<Option<HubPackage>> {
        let Some(mut package) = self.fork_skill_package_in_txn(txn, parent_id, parent, proposed)?
        else {
            if parent.content_hash.is_some() {
                return Err(invalid(
                    "source-backed optimized skill has no recoverable source",
                ));
            }
            if !files.is_empty() {
                return Err(invalid(
                    "a drafted file edit needs the target's recoverable source",
                ));
            }
            return Ok(None);
        };
        let text = folder::instruction_text(&package.files)?;
        let front = folder::source_frontmatter(text)?;
        let description = serde_json::to_string(&proposed.desc)
            .map_err(|_| invalid("optimized description cannot be encoded"))?;
        let changed = if let Some(front) = front {
            let mut changed = String::from("---\n");
            for line in front.lines() {
                if !line.starts_with("description:") {
                    changed.push_str(line);
                    changed.push('\n');
                }
            }
            changed.push_str(&format!("description: {description}\n---\n"));
            // Workflow recipes are their own load-order/effort instructions:
            // the improver's replacement text must become what the next pack
            // loads, not merely a metadata edit to an unchanged old body.
            if proposed.role == crate::skill::SkillRole::Workflow {
                changed.push_str(&proposed.desc);
                changed.push('\n');
            } else {
                changed.push_str(&text[4 + front.len() + 5..]);
            }
            changed
        } else {
            // Native source without frontmatter: the record carries metadata.
            // Preserve scripts and rewrite only the workflow instruction body.
            if proposed.role == crate::skill::SkillRole::Workflow {
                format!("{}\n", proposed.desc)
            } else {
                text.to_owned()
            }
        };
        package
            .files
            .iter_mut()
            .find(|file| file.path == "SKILL.md")
            .ok_or_else(|| invalid("optimized source has no SKILL.md"))?
            .content = changed.into_bytes();
        // The dials the rule's reader seeds from move with the rule text.
        if let Some(policy) = package
            .files
            .iter_mut()
            .find(|file| file.path == REVIEWER_POLICY_FILE)
            && let Some(derived) = rederived_rule_policy(&policy.content, &proposed.desc)
        {
            policy.content = derived;
        }
        for edit in files {
            replace_drafted_file(proposed, &mut package.files, edit)?;
        }
        proposed.content_hash = Some(package.content_hash()?);
        package.record = proposed.clone();
        folder::package_from_source(proposed, package.files, SkillPackageFormat::Native).map(Some)
    }
}

/// Replaces the file `edit` names in `files` with its text whole: for
/// `SKILL.md`, the body below the frontmatter this revision already wrote.
/// Only a file a draft may replace ([`draftable_skill_file`]) that the tree
/// holds as text: never a new path.
fn replace_drafted_file(
    record: &SkillRecord,
    files: &mut [HubFile],
    edit: &SkillFileEdit,
) -> Result<()> {
    if !draftable_skill_file(record, &edit.path) {
        return Err(invalid(
            "a drafted file edit names a file a draft may not replace",
        ));
    }
    let file = files
        .iter_mut()
        .find(|file| file.path == edit.path)
        .ok_or_else(|| {
            invalid("a drafted file edit names a path the skill's tree does not hold")
        })?;
    let text = std::str::from_utf8(&file.content)
        .map_err(|_| invalid("a drafted file edit names a file that is not text"))?;
    let content = if edit.path == INSTRUCTION_FILE {
        let body = instruction_body(text)?;
        format!("{}{}", &text[..text.len() - body.len()], edit.content).into_bytes()
    } else {
        edit.content.clone().into_bytes()
    };
    file.content = content;
    Ok(())
}

/// A rule skill's `policy.json` re-derived from its improved rule `text`
/// (FIX 10878): each key of the file the text names with a number right
/// after it (`key: 4`, `key = 0.5`, `` `key` at 4 ``) takes that number,
/// and every other key keeps its value. `None` when the file is not one
/// JSON object or the text moves no key, so an unmoved file stays
/// byte-exact.
fn rederived_rule_policy(policy: &[u8], text: &str) -> Option<Vec<u8>> {
    let Ok(serde_json::Value::Object(mut entries)) =
        serde_json::from_slice::<serde_json::Value>(policy)
    else {
        return None;
    };
    let mut moved = false;
    for (key, value) in &mut entries {
        let Some(number) = named_number(text, key) else {
            continue;
        };
        if value.as_f64() != number.as_f64() {
            *value = serde_json::Value::Number(number);
            moved = true;
        }
    }
    if !moved {
        return None;
    }
    let mut bytes = serde_json::to_vec_pretty(&serde_json::Value::Object(entries)).ok()?;
    bytes.push(b'\n');
    Some(bytes)
}

/// The number `text` names right after a mention of `key`: the first
/// mention that names one.
fn named_number(text: &str, key: &str) -> Option<serde_json::Number> {
    text.match_indices(key).find_map(|(at, _)| {
        let rest = text[at + key.len()..]
            .trim_start_matches(|c: char| matches!(c, '`' | '"' | '\''))
            .trim_start();
        let rest = ["=", ":", "at ", "to ", "is ", "of "]
            .into_iter()
            .find_map(|joint| rest.strip_prefix(joint))
            .unwrap_or(rest)
            .trim_start();
        let end = rest
            .find(|c: char| !(c.is_ascii_digit() || c == '.' || c == '-'))
            .unwrap_or(rest.len());
        match serde_json::from_str::<serde_json::Value>(rest[..end].trim_end_matches('.')) {
            Ok(serde_json::Value::Number(number)) => Some(number),
            _ => None,
        }
    })
}
