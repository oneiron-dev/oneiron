//! A human-authored Standard skill for skill-gate integration fixtures.
use crate::claim::{ClaimApprovalStatus, ClaimSource};
use crate::error::Result;
use crate::skill::{SkillGovernanceTier, SkillLifecycle, SkillRecord};
use crate::{EntityId, TimeRange, Vault};

/// Write an approved Standard candidate and activate it through the human update door.
/// # Errors
/// Skill-record validation or storage failures.
pub fn write_skill(vault: &Vault, skill_id: &str) -> Result<EntityId> {
    let id = EntityId::now();
    let record = SkillRecord::new(
        skill_id,
        "Skill gate fixture",
        "1.0.0",
        ClaimApprovalStatus::Approved,
        SkillLifecycle::Candidate,
        ClaimSource::UserStated,
        0.5,
        false,
        true,
        Vec::new(),
        rmpv::Value::Map(vec![(
            rmpv::Value::from("source"),
            rmpv::Value::from("skill-gate-fixture"),
        )]),
    )
    .with_governance_tier(SkillGovernanceTier::Standard);
    vault.put_skill_record(&id, &record, TimeRange { start: 10, end: 10 }, 11)?;
    let mut active = record.clone();
    active.lifecycle_status = SkillLifecycle::Active;
    vault.update_skill_record(&id, &active, TimeRange { start: 12, end: 12 }, 13)?;
    Ok(id)
}
