//! Imported Active fixtures traverse the same consent and held-out doors as a host.
use super::*;
use crate::{
    Vault,
    claim::{ClaimApprovalStatus, ClaimSource},
    entity_id::EntityId,
    error::Result,
    skill::{SkillLifecycle, SkillRecord},
    skill_optimize::{HeldOutReplayCase, HeldOutReplayScorer},
    temporal::TimeRange,
};
fn at(time: u64) -> TimeRange {
    TimeRange {
        start: time,
        end: time,
    }
}

pub(crate) fn admitted_import(vault: &Vault, id: &EntityId, record: SkillRecord) -> SkillRecord {
    assert_eq!(record.source, ClaimSource::Imported);
    let contents = format!(
        "---\nname: {}\ndescription: {}\nversion: {}\n---\nCheck the fixture result.\n",
        record.skill_id, record.desc, record.version
    );
    let mut imported = record;
    imported.content_hash = None;
    imported.lifecycle_status = SkillLifecycle::Candidate;
    let package = HubPackage::new(
        imported,
        vec![HubFile::new("SKILL.md", contents.into_bytes())],
        SkillCapabilitySurface::default(),
    );
    let source = HubRef::new(
        EntityId::now(),
        "fixture",
        HubPin::ContentHash(package.content_hash().expect("hash").to_hex()),
    )
    .expect("ref");
    assert_eq!(
        vault
            .import_skill_from_hub_with_id(&source, &package, *id, at(10), 10)
            .expect("import"),
        *id
    );
    admit_installed(vault, id, &source)
}

pub(crate) fn admit_installed(vault: &Vault, id: &EntityId, source: &HubRef) -> SkillRecord {
    let owner_id = EntityId::now();
    vault
        .put_entity(
            &owner_id,
            crate::registry::ENTITY_TYPE_PERSON,
            at(1),
            1,
            b"fixture owner",
        )
        .expect("person");
    let owner = vault
        .authenticate_owner(
            owner_id,
            "principal:fixture-owner",
            true,
            crate::store::GateDecisionId::now(),
        )
        .expect("owner");
    let baseline = EntityId::now();
    let mut base = SkillRecord::new(
        format!("fixture.baseline.{}", baseline.to_hex()),
        "baseline instructions",
        "1",
        ClaimApprovalStatus::Approved,
        SkillLifecycle::Candidate,
        ClaimSource::UserStated,
        1.0,
        false,
        true,
        Vec::new(),
        rmpv::Value::Map(vec![(
            rmpv::Value::from("source"),
            rmpv::Value::from("admission fixture"),
        )]),
    );
    vault
        .put_skill_record(&baseline, &base, at(2), 2)
        .expect("baseline");
    base.lifecycle_status = SkillLifecycle::Active;
    vault
        .update_skill_record(&baseline, &base, at(3), 3)
        .expect("authored baseline");
    reserve(vault, &baseline, &base.skill_id);
    let hub = source.hub_id;
    let hub_record = SkillHubRecord::new(
        SkillHubKind::HttpIndex,
        "https://example.invalid/index.json",
        SkillHubTrustTier::Community,
        HubSyncPolicy::ContentHashFrozen,
    )
    .expect("hub");
    vault
        .configure_skill_hub(&owner, &hub, &hub_record, at(4), 4)
        .expect("configure");
    let publisher = vault
        .admit_skill_publisher(&owner, "publisher:fixture", hub)
        .expect("publisher");
    let ask = vault
        .prepare_marketplace_activation(*id, source, &publisher, baseline)
        .expect("ask");
    vault
        .approve_marketplace_activation(&ask, &owner)
        .expect("human consent");
    let HubAdmissionDisposition::Ruled(receipt) = vault
        .admit_marketplace_skill(&ask, &FixtureReplay, at(12), 13)
        .expect("held-out")
    else {
        panic!("consented fixture")
    };
    assert!(receipt.accepted);
    vault.get_skill_record(id).expect("read").expect("admitted")
}
struct FixtureReplay;
impl HeldOutReplayScorer for FixtureReplay {
    fn score(&self, case: &HeldOutReplayCase<'_>) -> Result<f32> {
        assert!(!case.held_out_receipts.is_empty());
        Ok(if case.instructions.contains("Check the fixture result.") {
            0.9
        } else {
            0.2
        })
    }
}
/// Real terminal attempt receipts, attributed through the production reliability door.
pub(crate) fn reserve(vault: &Vault, skill: &EntityId, skill_id: &str) {
    use crate::attempt_queue::{
        AttemptQueue, ClaimAttempt, ClaimOutcome, CompleteAttempt, CompleteOutcome, EnqueueAttempt,
        EnqueueOutcome, ManifestEntry, ManifestKind,
    };
    let queue = AttemptQueue::new(vault);
    for index in 0..200 {
        let now = 100 + index * 10;
        let EnqueueOutcome::Enqueued(attempt) = queue
            .enqueue(EnqueueAttempt {
                kind: "hub.fixture".to_owned(),
                payload: vec![],
                dedupe_key: None,
                run_id: None,
                now,
            })
            .expect("enqueue")
        else {
            panic!("fresh attempt");
        };
        queue
            .append_manifest_entry(
                attempt.id,
                ManifestEntry::new(ManifestKind::Skill, skill_id, "1", now),
            )
            .expect("manifest");
        let ClaimOutcome::Claimed(leased) = queue
            .claim(ClaimAttempt {
                lease_owner: "fixture".to_owned(),
                now: now + 1,
            })
            .expect("claim")
        else {
            panic!("claimable attempt");
        };
        assert!(matches!(
            queue
                .complete(CompleteAttempt {
                    id: attempt.id,
                    lease_owner: "fixture".to_owned(),
                    attempt_count: leased.attempt_count,
                    now: now + 2
                })
                .expect("complete"),
            CompleteOutcome::Completed(_)
        ));
        let receipt = crate::receipt::attempt_pack_receipt_id(&attempt.id);
        crate::skill_reliability::record_skill_contributing_win(vault, skill, &receipt, now + 3)
            .expect("attribute");
        if !crate::skill_optimize::held_out_receipts(vault, skill)
            .expect("reserve")
            .is_empty()
        {
            return;
        }
    }
    panic!("fixture did not obtain held-out evidence");
}
