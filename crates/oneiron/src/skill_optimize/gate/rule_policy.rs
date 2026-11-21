//! The instructions the gate compares for a rule skill (FIX 10878): its
//! description, then the dial seeds the agent-health reviewer (T1) reads
//! from the revision's `policy.json`, decoded as T1 decodes them. So an
//! improvement that moves a dial is judged on the dial the reviewer would
//! run, and one that only rewords the rule is judged as rewording.

use crate::dreamer_runner::maintenance::agent_health::reviewer_policy_seeds;
use crate::skill::SkillRecord;
use crate::skill::health_review::AGENT_HEALTH_REVIEW_SKILL_ID;
use crate::skill::health_review::REVIEWER_POLICY_FILE;
use crate::skill_optimize::PROVENANCE_OPTIMIZE_EDITED_FILES_KEY;
use crate::{EntityId, Vault};
use std::collections::BTreeMap;

/// `record`'s instructions as the gate's judge reads them: its description,
/// and for a reviewer revision whose package carries `policy.json`, the
/// seeds T1 reads from it. A package that does not read leaves the
/// description alone, as T1 itself falls back rather than fail.
pub(super) fn gate_instructions_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    entity: &EntityId,
    record: &SkillRecord,
) -> String {
    gate_instructions_sourced_in_txn(vault, txn, entity, record).0
}

/// The instructions the gate's judge reads for `current`, the target, and
/// `staged`, its proposal: each one's [`gate_instructions_in_txn`], then
/// each file the draft replaced (its birth provenance's
/// [`PROVENANCE_OPTIMIZE_EDITED_FILES_KEY`], census L9-02), each side with
/// its own text. A proposal that names no file, an instructions-only draft
/// or a Coach package revision, is judged on the pair it was judged on
/// before. A tree that does not read shows no file, as the instruction read
/// falls back.
pub(super) fn gate_instruction_pair_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    target: &EntityId,
    current: &SkillRecord,
    proposal: &EntityId,
    staged: &SkillRecord,
) -> (String, String) {
    let mut before = gate_instructions_in_txn(vault, txn, target, current);
    let mut after = gate_instructions_in_txn(vault, txn, proposal, staged);
    let edited = edited_paths(staged);
    if edited.is_empty() {
        return (before, after);
    }
    let texts = |entity: &EntityId, record: &SkillRecord| -> BTreeMap<String, String> {
        let files = match vault.runtime_skill_package_in_txn(txn, entity, record) {
            Ok(Some(package)) => package.files,
            Ok(None) => return BTreeMap::new(),
            Err(error) => {
                tracing::debug!(kind = ?error.kind(), "a gated revision's package is unreadable");
                return BTreeMap::new();
            }
        };
        crate::skill_hub::draftable_skill_texts(record, &files)
            .map(|texts| texts.into_iter().collect())
            .unwrap_or_default()
    };
    let (old, new) = (texts(target, current), texts(proposal, staged));
    for path in &edited {
        // The reviewer's policy already reaches the judge as its seeds.
        if current.skill_id == AGENT_HEALTH_REVIEW_SKILL_ID && path == REVIEWER_POLICY_FILE {
            continue;
        }
        let (was, is) = (old.get(path), new.get(path));
        if was == is {
            continue;
        }
        for (text, file) in [(&mut before, was), (&mut after, is)] {
            text.push_str("\n\nFile `");
            text.push_str(path);
            text.push_str("`:\n");
            text.push_str(file.map_or("(no such file)", String::as_str));
        }
    }
    (before, after)
}

/// The paths `record`'s birth provenance names as the files its draft
/// replaced, in the draft's order; none when it names none.
fn edited_paths(record: &SkillRecord) -> Vec<String> {
    let rmpv::Value::Map(fields) = &record.provenance else {
        return Vec::new();
    };
    fields
        .iter()
        .find(|(key, _)| key.as_str() == Some(PROVENANCE_OPTIMIZE_EDITED_FILES_KEY))
        .and_then(|(_, paths)| paths.as_array())
        .map(|paths| {
            paths
                .iter()
                .filter_map(|path| path.as_str().map(str::to_owned))
                .collect()
        })
        .unwrap_or_default()
}

/// The same instruction read, carrying its native package sources even on fallback.
pub(super) fn gate_instructions_sourced_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    entity: &EntityId,
    record: &SkillRecord,
) -> (String, Option<Vec<EntityId>>) {
    let mut text = record.desc.clone();
    if record.skill_id != AGENT_HEALTH_REVIEW_SKILL_ID {
        return (text, Some(Vec::new()));
    }
    let (package, sources) = match vault.runtime_skill_package_sourced_in_txn(txn, entity, record) {
        Ok(result) => result,
        Err(error) => {
            tracing::debug!(kind = ?error.kind(), "a reviewer revision's package is unreadable");
            (None, None)
        }
    };
    let policy = match package {
        Some(package) => package
            .files
            .into_iter()
            .find(|file| file.path == REVIEWER_POLICY_FILE),
        None => None,
    };
    let Some(policy) = policy else {
        return (text, sources);
    };
    if let Ok(seeds) = serde_json::to_string(&reviewer_policy_seeds(&policy.content)) {
        text.push_str("\n\npolicy.json, as the agent-health reviewer reads it: ");
        text.push_str(&seeds);
    }
    (text, sources)
}
