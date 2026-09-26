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
            )?,
            TimeRange { start: 1, end: 1 },
            1,
        )?;
    }
    crate::test_util::authorize_readers(&vault, &["viewer"]);
    let read = vault.scoped_read(ScopedReadActorKey::new("viewer").unwrap());
    let mut session = SessionReadSet::default();
    let row = read
        .read(&[crate::claim::PointRead::id(first)], None)?
        .single()
        .value
        .expect("readable claim");
    let (kind, body) = (row.entity_type, row.body.expect("live body"));
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
        )?,
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

#[test]
fn board_observations_keep_their_read_receipt() -> Result<()> {
    let (_dir, vault) = crate::test_util::open_test_vault_with(crate::VaultConfig::default());
    let subject = crate::EntityId::now();
    let (served, hidden, old) = (
        crate::EntityId::now(),
        crate::EntityId::now(),
        crate::EntityId::now(),
    );
    vault.put_entity(
        &subject,
        crate::registry::ENTITY_TYPE_PERSON,
        TimeRange { start: 1, end: 1 },
        1,
        b"person",
    )?;
    let body = |value: &str, approval, lifecycle| {
        ClaimBody::new(
            "profile.likes",
            ClaimSubject::Entity(subject),
            rmpv::Value::from(value),
            0.8,
            approval,
            lifecycle,
        )
        .unwrap()
    };
    for (id, value, approval) in [
        (served, "tea", ClaimApprovalStatus::Approved),
        (old, "water", ClaimApprovalStatus::Approved),
        // Stored, but an unapproved row is never this reader's to see.
        (hidden, "unapproved", ClaimApprovalStatus::Proposed),
    ] {
        vault.put_claim(
            &id,
            &body(value, approval, ClaimLifecycleStatus::Active),
            TimeRange { start: 1, end: 1 },
            1,
        )?;
    }
    crate::test_util::authorize_readers(&vault, &["viewer"]);
    let read = vault.scoped_read(ScopedReadActorKey::new("viewer").unwrap());
    let mut session = SessionReadSet::default();

    // Re-reading the served rows counts the one this reader cannot see.
    let observed = session.observe_rows(&read, &[served, hidden])?;
    assert_eq!(observed.suppressed_count, 1);
    assert!(observed.narrowed_axes.contains(&"row_authority".to_owned()));

    // A superseded row whose only successor is withheld records no successor,
    // and the successor read's receipt says why.
    vault.put_edge(&hidden, crate::EdgeKind::Supersedes, &old, 1.0)?;
    let superseded = crate::claim::encode_claim_body(&body(
        "water",
        ClaimApprovalStatus::Approved,
        ClaimLifecycleStatus::Superseded,
    ))?;
    let successor = session
        .observe_snapshot(
            &read,
            old,
            crate::registry::ENTITY_TYPE_CLAIM,
            &superseded,
            false,
        )?
        .expect("the successor lookup returns its receipt");
    assert_eq!(successor.suppressed_count, 1);
    assert!(session.refresh(&read, 8)?.rows.is_empty());
    Ok(())
}
