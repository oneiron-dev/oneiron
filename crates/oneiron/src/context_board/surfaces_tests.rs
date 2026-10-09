//! Acceptance fixtures for scope, read-set freshness, and capability shedding.

use super::*;
use crate::{
    EntityId,
    pipeline::{ResolvedWorldAuthority, WorldAuthoritySet},
};

fn id(byte: u8) -> EntityId {
    EntityId::from_bytes([byte; 16]).unwrap()
}

#[test]
fn worlds_filter_before_projection_and_counting() {
    let worlds = [1, 2, 3, 4].map(|n| WorldPresence {
        id: id(n),
        label: format!("world-{n}"),
        trust: "trusted".into(),
    });
    let authority = ResolvedWorldAuthority {
        allowed_set: WorldAuthoritySet::new(false, [id(1), id(2), id(3)]).unwrap(),
        default_subset: WorldAuthoritySet::new(false, [id(1)]).unwrap(),
        active_set: WorldAuthoritySet::new(false, [id(1)]).unwrap(),
        allowed_claim_ids: vec![],
        default_claim_id: None,
    };
    let projected = WorldsSection::project(&worlds, &authority, 1);
    assert_eq!((projected.active_count, projected.off_count), (1, 2));
    assert!(projected.rows[0].contains("ACTIVE trusted world-1"));
    assert!(projected.rows[1].starts_with("off:"));
    assert!(projected.rows[1].ends_with("+1"));
    assert!(!projected.rows.join(" ").contains("world-4"));
    let allowed_only = WorldsSection::project(&worlds[..3], &authority, 1);
    assert_eq!(projected, allowed_only);
    let section = projected.board_section().unwrap();
    assert_eq!(section.policy().shed_rank, Some(ShedRank::WorldsToCounts));
    assert_eq!(section.count_rows(), ["active: 1 off: 2"]);
}

/// The rider stays inside the board's row-byte limit whatever a restored
/// session checkpoint holds: every row, and the one row a STREAM delta joins.
#[test]
fn a_restored_checkpoint_cannot_push_the_rider_past_the_row_byte_limit() {
    let (_dir, vault) = crate::test_util::open_test_vault_with(crate::VaultConfig::default());
    let huge = "m".repeat(MAX_BOARD_ROW_BYTES * 2);
    let prefix: serde_json::Map<String, serde_json::Value> = (0..40)
        .map(|n| {
            (
                format!("{n}{huge}"),
                serde_json::json!({"key": huge, "fingerprint": huge}),
            )
        })
        .collect();
    let session: SessionReadSet = serde_json::from_value(serde_json::json!({
        "rows": {},
        "loaded_skills": {},
        "proposal_count": 0,
        "own_proposals": [format!("claim:{huge}")],
        "prefix_connectors": prefix,
    }))
    .unwrap();
    let mut line = ChangedLine {
        rows: vec![(huge.clone(), ServedLifecycle::Superseded(huge))],
        ..ChangedLine::default()
    };
    session
        .fold_own_changes(&vault, Some(id(7)), &mut line, 16)
        .unwrap();
    assert!(!line.events.is_empty());
    let rows = line.render();
    assert!(rows.iter().all(|row| row.len() <= MAX_BOARD_ROW_BYTES));
    assert!(rows.join(" ").len() <= MAX_BOARD_ROW_BYTES);
    let delta = line
        .ride(Some(BoardStreamFrame {
            epoch: 1,
            kind: FrameKind::Delta(Vec::new()),
        }))
        .unwrap();
    let FrameKind::Delta(delta) = delta.kind else {
        panic!("delta")
    };
    assert!(delta[0].line.len() <= MAX_BOARD_ROW_BYTES);
}

/// A settled proposal is answered by the receipt that settled it. A later
/// write under the same id that the gate refused leaves the body as it was,
/// so its rule and diagnostic never ride as the answer.
#[test]
fn a_refused_later_write_never_answers_for_a_settled_proposal() -> crate::Result<()> {
    use crate::claim::{ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus, ClaimSubject};
    use crate::store::{GateDecisionId, GateDecisionRecord};
    let (_dir, vault) = crate::test_util::open_test_vault_with(crate::VaultConfig::default());
    let claim = id(0x21);
    vault.put_entity(
        &id(0x22),
        crate::registry::ENTITY_TYPE_PERSON,
        crate::TimeRange { start: 1, end: 1 },
        1,
        b"subject",
    )?;
    let body = ClaimBody::new(
        "note.topic",
        ClaimSubject::Entity(id(0x22)),
        rmpv::Value::from("harbor"),
        1.0,
        ClaimApprovalStatus::Rejected,
        ClaimLifecycleStatus::Active,
    )?;
    vault.put_claim(&claim, &body, crate::TimeRange { start: 1, end: 1 }, 1)?;
    let decision = |outcome: &str, reason: &str, grant: Option<&str>, row: Option<&str>| {
        Ok::<_, crate::Error>(GateDecisionRecord {
            version: 0,
            decision_id: GateDecisionId::from_bytes(vault.store.clock.ulid()?),
            created_at: 2,
            outcome: outcome.to_owned(),
            reason_codes: vec![reason.to_owned()],
            receipt_reasons: row
                .map(|row| format!("policy_row_{row}"))
                .into_iter()
                .collect(),
            system_notices: Vec::new(),
            actor_class: "agent".to_owned(),
            actor_ref: Some(id(7).to_hex()),
            content_kind: "claim".to_owned(),
            policy_manifest_version: "v0".to_owned(),
            claim_id: Some(*claim.as_bytes()),
            grant_ref: grant.map(str::to_owned),
            diff_handle: vec![0xA5],
            read_frontier_hash: [0; 32],
            redacted_at: None,
        })
    };
    let declined = decision(
        "rejected",
        "gate.consent.bundle.reject",
        Some("bundle:declined"),
        None,
    )?;
    let refused = decision("deny", "gate.deny.actor_ceiling", None, Some("later"))?;
    vault.with_write_txn(|wtxn| {
        vault.store.append_gate_decision_in_txn(wtxn, &declined)?;
        vault.store.append_gate_decision_in_txn(wtxn, &refused)
    })?;

    let session: SessionReadSet = serde_json::from_value(serde_json::json!({
        "rows": {},
        "loaded_skills": {},
        "proposal_count": 0,
        "own_proposals": [format!("claim:{}", claim.to_hex())],
    }))
    .unwrap();
    let mut line = ChangedLine::default();
    session.fold_own_changes(&vault, Some(id(7)), &mut line, 16)?;
    let [ChangedEvent::Proposal { change, .. }] = line.events.as_slice() else {
        panic!("one settled proposal rides: {:?}", line.events);
    };
    assert_eq!(change.to, "rejected");
    assert_eq!(
        change.reason,
        Some(ProposalReason::PersonWord("bundle:declined".to_owned()))
    );
    assert_eq!(
        change.diagnostic.as_deref(),
        Some("gate.consent.bundle.reject")
    );
    Ok(())
}

/// A full watch stops the submission cursor. An outcome delivered past it
/// covers every receipt of its proposal that the fold read, so it rides once;
/// a later submission under the same id is owed once more, and then never
/// again.
#[test]
fn an_outcome_delivered_past_a_full_watch_rides_once_per_submission() -> crate::Result<()> {
    use crate::claim::{ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus, ClaimSubject};
    use crate::gate::proposal_observation::{ProposalPolicySource, observe_submission_in_txn};
    let (_dir, vault) = crate::test_util::open_test_vault_with(crate::VaultConfig::default());
    let actor = id(7);
    vault.put_entity(
        &id(0x32),
        crate::registry::ENTITY_TYPE_PERSON,
        crate::TimeRange { start: 1, end: 1 },
        1,
        b"subject",
    )?;
    let (open, declined) = (id(0x33), id(0x34));
    for (claim, approval) in [
        (open, ClaimApprovalStatus::Proposed),
        (declined, ClaimApprovalStatus::Rejected),
    ] {
        let body = ClaimBody::new(
            "note.topic",
            ClaimSubject::Entity(id(0x32)),
            rmpv::Value::from("harbor"),
            1.0,
            approval,
            ClaimLifecycleStatus::Active,
        )?;
        vault.put_claim(&claim, &body, crate::TimeRange { start: 1, end: 1 }, 1)?;
    }
    let submit = |claim: EntityId| {
        vault.with_write_txn(|txn| {
            observe_submission_in_txn(
                &vault.store,
                txn,
                actor,
                &format!("claim:{}", claim.to_hex()),
                ProposalPolicySource {
                    threshold: u64::MAX,
                    deciding_row: None,
                    precedence_row: None,
                    shipped_default_precedence: true,
                },
                true,
            )
        })
    };
    let wake = |session: &mut SessionReadSet| -> crate::Result<usize> {
        let mut line = ChangedLine::default();
        session.fold_own_changes(&vault, Some(actor), &mut line, 16)?;
        session.acknowledge(&line);
        Ok(line.events.len())
    };
    let watched: Vec<String> = (0..1024).map(|n| format!("claim:held{n}")).collect();
    let mut session: SessionReadSet = serde_json::from_value(serde_json::json!({
        "rows": {},
        "loaded_skills": {},
        "proposal_count": 0,
        "own_proposals": watched,
    }))
    .unwrap();
    // The open proposal finds no room in the watch, so the cursor stops
    // before it. The declined one, submitted twice past it, rides once.
    submit(open)?;
    submit(declined)?;
    submit(declined)?;
    assert_eq!(wake(&mut session)?, 1);
    assert_eq!(wake(&mut session)?, 0);
    submit(declined)?;
    assert_eq!(wake(&mut session)?, 1);
    assert_eq!(wake(&mut session)?, 0);
    assert_eq!(wake(&mut session)?, 0);
    Ok(())
}
