//! A fork copies real files and edits source identity before hashing the new tree.
use super::{HubPackage, SkillPackageFormat, folder, package_codec::invalid};
use crate::{Vault, entity_id::EntityId, error::Result, skill::SkillRecord};
use std::collections::BTreeMap;

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
    /// only the descriptive recipe text; companion scripts/capabilities stay
    /// byte-exact, so a callable never silently loses its executable file.
    pub(crate) fn optimized_skill_package_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        parent_id: &EntityId,
        parent: &SkillRecord,
        proposed: &mut SkillRecord,
    ) -> Result<Option<HubPackage>> {
        let Some(mut package) = self.fork_skill_package_in_txn(txn, parent_id, parent, proposed)?
        else {
            if parent.content_hash.is_some() {
                return Err(invalid(
                    "source-backed optimized skill has no recoverable source",
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
        proposed.content_hash = Some(package.content_hash()?);
        package.record = proposed.clone();
        folder::package_from_source(proposed, package.files, SkillPackageFormat::Native).map(Some)
    }
}
