//! The instructions the gate compares for a rule skill (FIX 10878): its
//! description, then the dial seeds the agent-health reviewer (T1) reads
//! from the revision's `policy.json`, decoded as T1 decodes them. So an
//! improvement that moves a dial is judged on the dial the reviewer would
//! run, and one that only rewords the rule is judged as rewording.

use crate::dreamer_runner::maintenance::agent_health::{
    AGENT_HEALTH_REVIEW_SKILL_ID, REVIEWER_POLICY_FILE, reviewer_policy_seeds,
};
use crate::skill::SkillRecord;
use crate::{EntityId, Vault};

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
    let mut text = record.desc.clone();
    if record.skill_id != AGENT_HEALTH_REVIEW_SKILL_ID {
        return text;
    }
    let policy = match vault.runtime_skill_package_in_txn(txn, entity, record) {
        Ok(Some(package)) => package
            .files
            .into_iter()
            .find(|file| file.path == REVIEWER_POLICY_FILE),
        Ok(None) => None,
        Err(error) => {
            tracing::debug!(kind = ?error.kind(), "a reviewer revision's package is unreadable");
            None
        }
    };
    let Some(policy) = policy else {
        return text;
    };
    if let Ok(seeds) = serde_json::to_string(&reviewer_policy_seeds(&policy.content)) {
        text.push_str("\n\npolicy.json, as the agent-health reviewer reads it: ");
        text.push_str(&seeds);
    }
    text
}
