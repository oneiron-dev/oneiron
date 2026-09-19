//! Real marketplace admission for the plugin rendering fixtures.
use oneiron::claim::{ClaimApprovalStatus, ClaimSource};
use oneiron::consent::AuthenticatedOwner;
use oneiron::skill::{SkillLifecycle, SkillRecord};
use oneiron::skill_hub::{
    ForeignSkillPublisher, HubAdmissionDisposition, HubPackage, HubPin, HubRef, HubSyncPolicy,
    SkillHubKind, SkillHubRecord, SkillHubTrustTier,
};
use oneiron::skill_optimize::{HeldOutReplayCase, HeldOutReplayScorer};
use oneiron::{EntityId, TimeRange, Vault};

pub(super) struct Admission {
    owner: AuthenticatedOwner,
    publisher: ForeignSkillPublisher,
    baseline: EntityId,
    source: HubRef,
}
fn at(now: u64) -> TimeRange {
    TimeRange {
        start: now,
        end: now,
    }
}
impl Admission {
    pub(super) fn new(vault: &Vault, hub: EntityId, package: &HubPackage) -> Self {
        let owner_id = EntityId::now();
        vault
            .put_entity(
                &owner_id,
                oneiron::registry::ENTITY_TYPE_PERSON,
                at(1),
                1,
                b"owner",
            )
            .expect("owner person");
        let owner = vault
            .authenticate_owner(
                owner_id,
                "principal:plugin-fixture",
                true,
                oneiron::store::GateDecisionId::now(),
            )
            .expect("authenticated owner");
        let baseline = EntityId::now();
        let mut record = SkillRecord::new(
            "plugin.fixture.baseline",
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
                rmpv::Value::from("fixture"),
            )]),
        );
        vault
            .put_skill_record(&baseline, &record, at(2), 2)
            .expect("native baseline");
        record.lifecycle_status = SkillLifecycle::Active;
        vault
            .update_skill_record(&baseline, &record, at(3), 3)
            .expect("activate native baseline");
        reserve(vault, &baseline, &record.skill_id);
        let configuration = SkillHubRecord::new(
            SkillHubKind::LocalDir,
            "/fixture/crm",
            SkillHubTrustTier::Community,
            HubSyncPolicy::ContentHashFrozen,
        )
        .expect("hub configuration");
        vault
            .configure_skill_hub(&owner, &hub, &configuration, at(4), 4)
            .expect("configure hub");
        let publisher = vault
            .admit_skill_publisher(&owner, "publisher:plugin-fixture", hub)
            .expect("foreign publisher");
        let source = HubRef::new(
            hub,
            "crm-pack@1.0.0",
            HubPin::ContentHash(package.content_hash().expect("hash").to_hex()),
        )
        .expect("source");
        Self {
            owner,
            publisher,
            baseline,
            source,
        }
    }
    pub(super) fn activate(
        &self,
        vault: &Vault,
        skill: EntityId,
        now: u64,
    ) -> oneiron::error::Result<SkillRecord> {
        let ask = vault.prepare_marketplace_activation(
            skill,
            &self.source,
            &self.publisher,
            self.baseline,
        )?;
        vault.approve_marketplace_activation(&ask, &self.owner)?;
        let HubAdmissionDisposition::Ruled(receipt) =
            vault.admit_marketplace_skill(&ask, &Replay, at(now), now)?
        else {
            panic!("confirmed admission must rule")
        };
        assert!(receipt.accepted);
        Ok(vault.get_skill_record(&skill)?.expect("admitted skill"))
    }
}
struct Replay;
impl HeldOutReplayScorer for Replay {
    fn score(&self, case: &HeldOutReplayCase<'_>) -> oneiron::error::Result<f32> {
        assert!(!case.held_out_receipts.is_empty());
        Ok(if case.instructions.contains("CRM contact") {
            0.9
        } else {
            0.2
        })
    }
}
fn reserve(vault: &Vault, skill: &EntityId, skill_id: &str) {
    use oneiron::attempt_queue::{
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
        let receipt = oneiron::receipt::attempt_pack_receipt_id(&attempt.id);
        oneiron::skill_reliability::record_skill_contributing_win(vault, skill, &receipt, now + 3)
            .expect("attribute");
        if !oneiron::skill_optimize::held_out_receipts(vault, skill)
            .expect("reserve")
            .is_empty()
        {
            return;
        }
    }
    panic!("fixture did not obtain held-out evidence");
}
