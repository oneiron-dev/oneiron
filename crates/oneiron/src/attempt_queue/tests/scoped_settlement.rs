//! ONE-1904 × ONE-1876: caller-owned settlement keeps actor-scoped index ownership.

use super::*;

const KIND: &str = "scoped-settlement";
const KEY: &str = "shared";
const ACTOR_A: &str = "actor-a";
const ACTOR_B: &str = "actor-b";

fn enqueue_actor(vault: &Vault, queue: &AttemptQueue<'_>, actor: &str) -> Result<AttemptRecord> {
    let mut wtxn = vault.store.env.write_txn()?;
    let EnqueueOutcome::Enqueued(record) = queue.enqueue_with_task_ref_and_dedupe_actor_in_txn(
        &mut wtxn,
        enqueue(KIND, Some(KEY), 10),
        None,
        Some(actor),
    )?
    else {
        panic!("expected a new actor-scoped row");
    };
    wtxn.commit()?;
    Ok(record)
}

fn claim_with_neighbors(
    vault: &Vault,
    queue: &AttemptQueue<'_>,
) -> Result<(AttemptRecord, AttemptRecord, AttemptRecord)> {
    let source = enqueue_actor(vault, queue, ACTOR_A)?;
    let ClaimOutcome::Claimed(claim) = queue.claim(ClaimAttempt {
        lease_owner: "worker-a".to_owned(),
        now: 11,
    })?
    else {
        panic!("expected a claim");
    };
    assert_eq!(claim.id, source.id);
    let other = enqueue_actor(vault, queue, ACTOR_B)?;
    let EnqueueOutcome::Enqueued(legacy) = queue.enqueue(enqueue(KIND, Some(KEY), 12))? else {
        panic!("actorless enqueue must not coalesce with either actor");
    };
    // Both actorless families can still belong to a live legacy chain. Neither
    // may be deleted while settling an unrelated actor-scoped row.
    let mut wtxn = vault.store.env.write_txn()?;
    vault.store.attempt_dedupe.put(
        &mut wtxn,
        &legacy_dedupe_index_key(KIND, KEY),
        legacy.id.as_bytes(),
    )?;
    wtxn.commit()?;
    Ok((claim, other, legacy))
}

fn assert_index_owners(
    vault: &Vault,
    own: Option<AttemptId>,
    other: AttemptId,
    legacy: AttemptId,
) -> Result<()> {
    let rtxn = vault.store.env.read_txn()?;
    for (key, expected) in [
        (dedupe_index_key_v2(KIND, ACTOR_A, KEY).to_vec(), own),
        (
            dedupe_index_key_v2(KIND, ACTOR_B, KEY).to_vec(),
            Some(other),
        ),
        (dedupe_index_key(KIND, KEY).to_vec(), Some(legacy)),
        (legacy_dedupe_index_key(KIND, KEY), Some(legacy)),
    ] {
        let actual = vault
            .store
            .attempt_dedupe
            .get(&rtxn, &key)?
            .map(|raw| AttemptId::from_bytes(&raw))
            .transpose()?;
        assert_eq!(actual, expected);
    }
    Ok(())
}

#[test]
fn result_and_settlement_atomically_retire_only_the_owning_actor_index() -> Result<()> {
    for state in [
        AttemptState::Completed,
        AttemptState::Failed,
        AttemptState::Abandoned,
    ] {
        let (_dir, vault) = open_queue();
        let queue = AttemptQueue::new(&vault);
        let (claim, other, legacy) = claim_with_neighbors(&vault, &queue)?;
        let before = queue.append_manifest_entry(claim.id, skill_entry("index", "1", 12))?;
        let output = result_ref("blob-artifact:aa@1");
        let receipt_id = crate::receipt::attempt_pack_receipt_id(&claim.id);

        // First abort, then commit the same composed operation. Result, terminal
        // state, PACK receipt, and the v2 deletion must move together.
        for commit in [false, true] {
            let mut wtxn = vault.store.env.write_txn()?;
            queue.set_result_in_txn(
                &mut wtxn,
                SetAttemptResult {
                    id: claim.id,
                    lease_owner: "worker-a".to_owned(),
                    attempt_count: claim.attempt_count,
                    result_ref: output.clone(),
                    now: 13,
                },
            )?;
            match state {
                AttemptState::Completed => {
                    queue.complete_in_txn(
                        &mut wtxn,
                        CompleteAttempt {
                            id: claim.id,
                            lease_owner: "worker-a".to_owned(),
                            attempt_count: claim.attempt_count,
                            now: 14,
                        },
                    )?;
                }
                AttemptState::Failed => {
                    queue.fail_in_txn(
                        &mut wtxn,
                        FailAttempt {
                            id: claim.id,
                            lease_owner: "worker-a".to_owned(),
                            attempt_count: claim.attempt_count,
                            reason: "stopped".to_owned(),
                            now: 14,
                        },
                    )?;
                }
                AttemptState::Abandoned => {
                    queue.abandon_in_txn(
                        &mut wtxn,
                        AbandonAttempt {
                            id: claim.id,
                            lease_owner: "worker-a".to_owned(),
                            attempt_count: claim.attempt_count,
                            result_ref: output.clone(),
                            reason: "stopped".to_owned(),
                            now: 14,
                        },
                    )?;
                }
                _ => unreachable!(),
            }
            let settled = queue
                .get_in_write_txn(&wtxn, claim.id)?
                .expect("settled row");
            assert_eq!(settled.state, state);
            assert_eq!(settled.result_ref(), Some(&output));
            if commit {
                wtxn.commit()?;
                assert_eq!(queue.get(claim.id)?.expect("committed row"), settled);
                assert_index_owners(&vault, None, other.id, legacy.id)?;
                let receipt = crate::receipt::attempt_pack_receipt(&vault, &receipt_id)?
                    .expect("settlement stamps its PACK receipt");
                assert_eq!(receipt.outcome, state.as_str());
                assert_eq!(receipt.actor.as_deref(), Some("worker-a"));
                assert_eq!(
                    receipt.pack_manifest_skills(),
                    Some(vec!["index@1".to_owned()])
                );
            } else {
                drop(wtxn);
                assert_eq!(queue.get(claim.id)?.expect("original row"), before);
                assert_index_owners(&vault, Some(claim.id), other.id, legacy.id)?;
                assert!(crate::receipt::attempt_pack_receipt(&vault, &receipt_id)?.is_none());
            }
            assert_eq!(queue.get(other.id)?.expect("other actor"), other);
            assert_eq!(queue.get(legacy.id)?.expect("legacy chain"), legacy);
        }
    }
    Ok(())
}

#[test]
fn landing_handoff_atomically_moves_actor_scope_but_not_the_result() -> Result<()> {
    let (_dir, vault) = open_queue();
    let queue = AttemptQueue::new(&vault);
    let (claim, other, legacy) = claim_with_neighbors(&vault, &queue)?;
    queue.append_manifest_entry(claim.id, skill_entry("index", "1", 12))?;
    queue.request_cancel(soft_request(claim.id, "peer-1", CancelStanding::PeerAgent))?;
    let landing = accept_landing_at(&queue, &claim, LandingTrigger::CancelRequest, 13)?;
    let before = queue.record_resume_point(RecordAttemptResumePoint {
        id: landing.id,
        lease_owner: "worker-a".to_owned(),
        attempt_count: landing.attempt_count,
        resume_point: AttemptResumePoint::new("step-2", 14),
        now: 14,
    })?;
    let output = result_ref("blob-artifact:aa@1");
    let receipt_id = crate::receipt::attempt_pack_receipt_id(&claim.id);
    for commit in [false, true] {
        let mut wtxn = vault.store.env.write_txn()?;
        queue.set_result_in_txn(
            &mut wtxn,
            SetAttemptResult {
                id: claim.id,
                lease_owner: "worker-a".to_owned(),
                attempt_count: claim.attempt_count,
                result_ref: output.clone(),
                now: 15,
            },
        )?;
        let FinishLandingOutcome::HandedOff { landed, successor } = queue.finish_landing_in_txn(
            &mut wtxn,
            FinishAttemptLanding {
                id: claim.id,
                lease_owner: "worker-a".to_owned(),
                attempt_count: claim.attempt_count,
                hand_off: true,
                scheduled_at: Some(100),
                now: 16,
            },
        )?
        else {
            panic!("expected a successor");
        };
        assert_eq!(landed.state, AttemptState::Cancelled);
        assert_eq!(landed.result_ref(), Some(&output));
        assert_eq!(successor.state, AttemptState::Scheduled);
        assert_eq!(successor.scheduled_at, Some(100));
        assert_eq!(successor.retry_of, Some(claim.id));
        assert_eq!(successor.dedupe_actor_ref.as_deref(), Some(ACTOR_A));
        assert_eq!(successor.result_ref(), None);
        assert_eq!(
            successor.cancel_state.resume_point,
            before.cancel_state.resume_point
        );
        assert_eq!(successor.run_id, before.run_id);
        assert_eq!(successor.payload, before.payload);
        assert!(successor.manifest().is_empty());
        if commit {
            wtxn.commit()?;
            assert_eq!(queue.get(claim.id)?.expect("landed row"), landed);
            assert_eq!(queue.get(successor.id)?.expect("successor"), successor);
            assert_index_owners(&vault, Some(successor.id), other.id, legacy.id)?;
            let receipt = crate::receipt::attempt_pack_receipt(&vault, &receipt_id)?
                .expect("handoff stamps the landed PACK receipt");
            assert_eq!(receipt.outcome, "cancelled");
        } else {
            drop(wtxn);
            assert_eq!(queue.get(claim.id)?.expect("original landing"), before);
            assert!(queue.get(successor.id)?.is_none());
            assert_index_owners(&vault, Some(claim.id), other.id, legacy.id)?;
            assert!(crate::receipt::attempt_pack_receipt(&vault, &receipt_id)?.is_none());
        }
        let rtxn = vault.store.env.read_txn()?;
        let ready = vault
            .store
            .attempt_ready
            .get(&rtxn, &ready_key(100, successor.id))?;
        assert_eq!(ready.is_some(), commit);
        drop(rtxn);
        let run = queue.list_run(before.run_id.as_deref().expect("run id"))?;
        assert_eq!(run.iter().any(|row| row.id == successor.id), commit);
        assert_eq!(queue.get(other.id)?.expect("other actor"), other);
        assert_eq!(queue.get(legacy.id)?.expect("legacy chain"), legacy);
    }
    Ok(())
}
