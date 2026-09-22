//! Real ledger lifecycle and skill-body observations for the session board.
use super::*;
use crate::claim::{
    ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus, ClaimSource, ClaimSubject,
    ScopedReadActorKey,
};
use crate::skill::{SkillLifecycle, SkillRecord};
use crate::{Result, TimeRange};

#[test]
fn served_snapshot_resolves_real_supersession_and_loaded_requires_a_body() -> Result<()> {
    let (_dir, vault) = crate::test_util::open_test_vault_with(crate::VaultConfig::default());
    let subject = crate::test_util::entity(221);
    let first = crate::test_util::entity(222);
    let next = crate::test_util::entity(223);
    let skill_id = crate::test_util::entity(224);
    vault.put_entity(
        &subject,
        crate::registry::ENTITY_TYPE_PERSON,
        TimeRange { start: 1, end: 1 },
        1,
        b"person",
    )?;
    for (id, value) in [(first, "tea"), (next, "coffee")] {
        vault.put_claim(
            &id,
            &ClaimBody::new(
                "profile.likes",
                ClaimSubject::Entity(subject),
                rmpv::Value::from(value),
                0.8,
                ClaimApprovalStatus::Approved,
                ClaimLifecycleStatus::Active,
            ),
            TimeRange { start: 1, end: 1 },
            1,
        )?;
    }
    let read = vault.scoped_read(ScopedReadActorKey::new("viewer").unwrap());
    let mut session = SessionReadSet::default();
    let crate::claim::ScopedReadResult {
        value,
        receipt: _receipt,
    } = read.get_entity_parts_with_receipt(&first, None)?;
    let (kind, _, body) = value.expect("readable claim");
    session.observe_snapshot(&read, first, kind, &body, false)?;
    assert!(session.refresh(&read, 1)?.rows.is_empty());
    vault.supersede_claim(&next, &first, 3)?;
    let hidden = crate::EntityId::from_bytes([0x12; 16]).unwrap();
    vault.put_claim(
        &hidden,
        &ClaimBody::new(
            "profile.likes",
            ClaimSubject::Entity(subject),
            "unapproved".into(),
            0.8,
            ClaimApprovalStatus::Proposed,
            ClaimLifecycleStatus::Active,
        ),
        TimeRange { start: 1, end: 1 },
        1,
    )?;
    vault.put_edge(&hidden, crate::EdgeKind::Supersedes, &first, 1.0)?;
    vault.put_edge(&subject, crate::EdgeKind::Supersedes, &first, 1.0)?;
    let changed = session.refresh(&read, 1)?;
    assert_eq!(
        changed.rows,
        vec![(first.to_hex(), ServedLifecycle::Superseded(next.to_hex()))]
    );
    assert!(changed.ride(None).is_none());
    let record = SkillRecord::new(
        "skill.sample",
        "fixture",
        "v2",
        ClaimApprovalStatus::Approved,
        SkillLifecycle::Active,
        ClaimSource::UserStated,
        1.0,
        false,
        true,
        vec![],
        rmpv::Value::Map(vec![(
            rmpv::Value::from("source"),
            rmpv::Value::from("fixture"),
        )]),
    );
    let bytes = crate::skill::encode_skill_record(&record)?;
    session.observe_snapshot(
        &read,
        skill_id,
        crate::registry::ENTITY_TYPE_SKILL,
        &bytes,
        false,
    )?;
    assert_eq!(session.loaded_skills().count(), 0);
    session.observe_snapshot(
        &read,
        skill_id,
        crate::registry::ENTITY_TYPE_SKILL,
        &bytes,
        true,
    )?;
    assert_eq!(
        session.loaded_skills().collect::<Vec<_>>(),
        vec![(skill_id.to_hex().as_str(), "v2")]
    );
    Ok(())
}
