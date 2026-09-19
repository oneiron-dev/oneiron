use super::*;
use crate::agent_dispatch::{AgentDispatchOutcome, AgentDispatcher};

#[test]
fn terminal_receipt_keeps_index_pull_and_actor_claim_in_load_order() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let actor = put_actor(&vault)?;
    let skill = put_skill(&vault, "pack.loaded")?;
    let claim = write_actor_claim(
        &vault,
        ActorClaimRow::Lesson {
            actor,
            text: "read the source".to_owned(),
        },
        &task_evidence(&vault, 30),
    )?;
    let dispatcher = AgentDispatcher::new(&vault);
    let AgentDispatchOutcome::Dispatched(status) = dispatcher.dispatch_default_base(
        None,
        Some("pack-run".to_owned()),
        Some("pack-run".to_owned()),
        40,
    )?
    else {
        panic!("new dispatch")
    };
    assert_eq!(status.attempt.manifest.len(), 1);
    assert_eq!(status.attempt.manifest[0].kind, ManifestKind::SkillIndex);
    let AgentDispatchOutcome::Existing(existing) = dispatcher.dispatch_default_base(
        None,
        Some("pack-run".to_owned()),
        Some("pack-run".to_owned()),
        40,
    )?
    else {
        panic!("deduped dispatch")
    };
    assert_eq!(existing.attempt.manifest, status.attempt.manifest);
    let loaded = vault.load_attempt_skill(status.attempt.id, &skill, 41)?;
    assert_eq!(loaded.skill_id, "pack.loaded");
    assert_eq!(
        vault
            .load_attempt_actor_claim(status.attempt.id, &claim, 42)?
            .predicate,
        PREDICATE_ACTOR_LESSON
    );
    let queue = AttemptQueue::new(&vault);
    let ClaimOutcome::Claimed(leased) = queue.claim_kind(
        "dreamer",
        ClaimAttempt {
            lease_owner: "pack-worker".to_owned(),
            now: 43,
        },
    )?
    else {
        panic!("claim dispatch")
    };
    assert_eq!(leased.id, status.attempt.id);
    queue.complete(CompleteAttempt {
        id: leased.id,
        lease_owner: "pack-worker".to_owned(),
        attempt_count: leased.attempt_count,
        now: 44,
    })?;
    let receipt =
        crate::receipt::attempt_pack_receipt(&vault, &attempt_pack_receipt_id(&leased.id))?
            .unwrap();
    let entries = receipt.pack_manifest_entries().unwrap();
    assert_eq!(
        entries.iter().map(|entry| entry.kind).collect::<Vec<_>>(),
        vec![
            ManifestKind::SkillIndex,
            ManifestKind::Skill,
            ManifestKind::ActorClaim
        ]
    );
    assert_eq!(
        entries.iter().map(|entry| entry.at).collect::<Vec<_>>(),
        vec![40, 41, 42]
    );
    assert_eq!(entries[2].reference, claim.to_hex());
    assert_eq!(entries, queue.get(leased.id)?.unwrap().manifest);
    assert_eq!(
        receipt.pack_manifest_skills(),
        Some(vec!["pack.loaded@1.0.0".to_owned()])
    );
    assert!(vault.load_attempt_skill(leased.id, &skill, 45).is_err());
    assert_eq!(
        crate::receipt::attempt_pack_receipt(&vault, &receipt.receipt_id)?.unwrap(),
        receipt
    );
    Ok(())
}
