//! Successor Qodo regressions for terminal custody and runtime attribution.

mod stop_reasons;

use super::*;
use crate::attempt_queue::{
    AcceptAttemptLanding, AttemptCancelReceiptKind, CancelMode, CancelStanding, ForceAttemptCancel,
    ForceCancelAuthority, ForceCancelOutcome, LandingOutcome, LandingTrigger, ManifestEntry,
    ManifestKind, RequestAttemptCancel,
};
use crate::error::ArtifactError;

fn claimed_with_manifest(
    vault: &Vault,
    dispatcher: &mut ByoaDispatcher<'_, StubFactory, DenyAllEgress>,
    landing: bool,
) -> AttemptRecord {
    let dispatched = dispatcher
        .dispatch(DispatchByoa {
            connector: ByoaConnectorSpec::CliSandbox(cli_spec()),
            task_ref: None,
            parent_attempt_id: None,
            run_id: Some("terminal-custody".to_owned()),
            dedupe_key: Some("terminal-custody".to_owned()),
            now: 10,
        })
        .expect("dispatch");
    let queue = AttemptQueue::new(vault);
    let ClaimOutcome::Claimed(attempt) = queue
        .claim_kind(
            BYOA_ATTEMPT_KIND,
            ClaimAttempt {
                lease_owner: "worker".to_owned(),
                now: 20,
            },
        )
        .expect("claim")
    else {
        panic!("expected claim");
    };
    assert_eq!(attempt.id, dispatched.status().attempt.id);
    queue
        .append_manifest_entry(
            attempt.id,
            ManifestEntry::new(ManifestKind::Skill, "skill.capture", "1", 21),
        )
        .expect("manifest");
    if landing {
        queue
            .request_cancel(RequestAttemptCancel {
                id: attempt.id,
                actor: "owner".to_owned(),
                standing: CancelStanding::Authority,
                trigger: LandingTrigger::CancelRequest,
                reason: Some("stop requested".to_owned()),
                now: 24,
            })
            .expect("soft request");
        let LandingOutcome::Landing(landed) = queue
            .accept_landing(AcceptAttemptLanding {
                id: attempt.id,
                lease_owner: "worker".to_owned(),
                attempt_count: attempt.attempt_count,
                trigger: LandingTrigger::BudgetWarning,
                status: Some("stopping".to_owned()),
                resume_point: None,
                request_sequence: None,
                now: 25,
            })
            .expect("accept landing")
        else {
            panic!("expected fresh landing");
        };
        assert_eq!(
            landed.landing().expect("landing").trigger,
            LandingTrigger::CancelRequest
        );
        return landed;
    }
    queue.get(attempt.id).expect("row").expect("attempt")
}

fn force_cancel_request(attempt: &AttemptRecord) -> ForceAttemptCancel {
    ForceAttemptCancel {
        id: attempt.id,
        authority: ForceCancelAuthority::owner("owner").expect("verified owner"),
        reason: Some("owner stopped the executor".to_owned()),
        now: 31,
    }
}

#[test]
fn terminal_capture_commits_disposition_receipts_and_dedupe_release_together() {
    for (landing, disposition) in [
        (false, ByoaTerminalDisposition::Completed),
        (false, ByoaTerminalDisposition::Failed),
        (true, ByoaTerminalDisposition::Cancelled),
        (false, ByoaTerminalDisposition::Abandoned),
        (true, ByoaTerminalDisposition::Abandoned),
    ] {
        let (_dir, vault) = open_vault();
        let mut dispatcher = dispatcher(&vault);
        let attempt = claimed_with_manifest(&vault, &mut dispatcher, landing);
        let request = capture_request(&attempt, disposition);
        let first = dispatcher
            .capture_terminal_exhaust(request.clone())
            .expect("capture");
        let queue = AttemptQueue::new(&vault);
        assert!(disposition_matches_state(disposition, first.attempt.state));
        assert_eq!(first.attempt.lease_owner, None);
        assert_eq!(first.attempt.updated_at, request.now);
        assert_eq!(first.attempt.result_ref, Some(first.result_ref.clone()));
        assert_eq!(
            queue.get(attempt.id).expect("row"),
            Some(first.attempt.clone())
        );
        assert_eq!(
            queue.list().expect("attempts").len(),
            1,
            "capture never hands off"
        );
        let bytes = vault
            .read_blob_artifact_version(&first.artifact_id, 1)
            .expect("read exhaust")
            .expect("exhaust");
        assert_eq!(decode_byoa_exhaust(&bytes).expect("decode").1, disposition);
        let pack = crate::receipt::attempt_pack_receipt(
            &vault,
            &crate::receipt::attempt_pack_receipt_id(&attempt.id),
        )
        .expect("pack receipt")
        .expect("terminal manifest must be stamped");
        assert_eq!(pack.outcome, first.attempt.state.as_str());
        assert_eq!(pack.occurred_at, request.now);
        assert_eq!(pack.actor.as_deref(), Some("worker"));
        if disposition == ByoaTerminalDisposition::Cancelled {
            let cancellation = first.attempt.cancellation().expect("cancel receipt");
            assert_eq!(cancellation.mode, CancelMode::Landed);
            assert_eq!(
                cancellation.grounds, None,
                "capture cannot mint force authority"
            );
            assert_eq!(cancellation.actor, "worker");
            assert_eq!(cancellation.trigger, Some(LandingTrigger::CancelRequest));
            assert_eq!(first.attempt.landing(), attempt.landing());
            assert_eq!(
                first
                    .attempt
                    .cancel_receipts()
                    .last()
                    .expect("landed receipt")
                    .kind,
                AttemptCancelReceiptKind::Landed
            );
        }
        if disposition == ByoaTerminalDisposition::Failed
            || disposition == ByoaTerminalDisposition::Abandoned
        {
            assert_eq!(first.attempt.last_error, request.reason);
        }
        let before = custody_snapshot(&vault);
        let forced = queue
            .force_cancel(force_cancel_request(&attempt))
            .expect("late force");
        match forced {
            ForceCancelOutcome::AlreadyCancelled(record) => {
                assert_eq!(disposition, ByoaTerminalDisposition::Cancelled);
                assert_eq!(record, first.attempt);
            }
            ForceCancelOutcome::AlreadySettled(record) => assert_eq!(record, first.attempt),
            other => panic!("capture must already be terminal: {other:?}"),
        }
        if disposition != ByoaTerminalDisposition::Completed {
            assert!(
                queue
                    .complete(CompleteAttempt {
                        id: attempt.id,
                        lease_owner: "worker".to_owned(),
                        attempt_count: attempt.attempt_count,
                        now: 32,
                    })
                    .is_err()
            );
        }
        if disposition != ByoaTerminalDisposition::Failed {
            assert!(
                queue
                    .fail(FailAttempt {
                        id: attempt.id,
                        lease_owner: "worker".to_owned(),
                        attempt_count: attempt.attempt_count,
                        reason: "different settlement".to_owned(),
                        now: 32,
                    })
                    .is_err()
            );
        }
        for other in [
            ByoaTerminalDisposition::Completed,
            ByoaTerminalDisposition::Failed,
            ByoaTerminalDisposition::Cancelled,
            ByoaTerminalDisposition::Abandoned,
        ] {
            if other != disposition {
                assert!(
                    dispatcher
                        .capture_terminal_exhaust(capture_request(&attempt, other))
                        .is_err()
                );
            }
        }
        for change in ["owner", "generation"] {
            let mut changed = request.clone();
            if change == "owner" {
                changed.lease_owner = "intruder".to_owned();
            } else {
                changed.attempt_count += 1;
            }
            assert!(
                dispatcher.capture_terminal_exhaust(changed).is_err(),
                "{change}"
            );
        }
        assert_eq!(
            dispatcher
                .capture_terminal_exhaust(request)
                .expect("canonical retry"),
            first
        );
        assert_eq!(
            custody_snapshot(&vault),
            before,
            "late settlement and retry are read-only"
        );
        let next = dispatcher
            .dispatch(DispatchByoa {
                connector: ByoaConnectorSpec::CliSandbox(cli_spec()),
                task_ref: None,
                parent_attempt_id: None,
                run_id: Some("terminal-custody".to_owned()),
                dedupe_key: Some("terminal-custody".to_owned()),
                now: 40,
            })
            .expect("redispatch");
        assert!(matches!(next, ByoaDispatchOutcome::Dispatched(_)));
        assert_ne!(
            next.status().attempt.id,
            attempt.id,
            "settlement releases dedupe"
        );
    }
}

#[test]
fn capture_preserves_landing_state_and_lease_gates_without_residual_writes() {
    for (landing, disposition) in [
        (false, ByoaTerminalDisposition::Cancelled),
        (true, ByoaTerminalDisposition::Completed),
        (true, ByoaTerminalDisposition::Failed),
    ] {
        let (_dir, vault) = open_vault();
        let mut dispatcher = dispatcher(&vault);
        let attempt = claimed_with_manifest(&vault, &mut dispatcher, landing);
        let before = custody_snapshot(&vault);
        assert!(
            dispatcher
                .capture_terminal_exhaust(capture_request(&attempt, disposition))
                .is_err()
        );
        assert_eq!(
            custody_snapshot(&vault),
            before,
            "{landing} / {disposition:?}"
        );
        assert_eq!(
            AttemptQueue::new(&vault).get(attempt.id).expect("row"),
            Some(attempt)
        );
    }
    let (_dir, vault) = open_vault();
    let mut dispatcher = dispatcher(&vault);
    let attempt = claimed_with_manifest(&vault, &mut dispatcher, true);
    for change in ["owner", "generation"] {
        let mut request = capture_request(&attempt, ByoaTerminalDisposition::Cancelled);
        if change == "owner" {
            request.lease_owner = "intruder".to_owned();
        } else {
            request.attempt_count += 1;
        }
        let before = custody_snapshot(&vault);
        assert!(dispatcher.capture_terminal_exhaust(request).is_err());
        assert_eq!(custody_snapshot(&vault), before, "{change}");
    }
}

#[test]
fn generic_result_attachment_cannot_authorize_a_running_canonical_retry() {
    let (_dir, vault) = open_vault();
    let mut dispatcher = dispatcher(&vault);
    let attempt = claimed_with_manifest(&vault, &mut dispatcher, false);
    let artifact = byoa_exhaust_artifact_id(attempt.id).expect("artifact");
    let occurred = TimeRange { start: 25, end: 25 };
    let actor = vault
        .try_with_write_txn(|wtxn| ensure_byoa_runtime_actor(&vault, wtxn, occurred, 25))
        .expect("canonical actor");
    vault
        .put_blob_artifact(
            &artifact,
            &BlobArtifactBody::new(
                byoa_exhaust_artifact_name(attempt.id),
                BYOA_EXHAUST_MEDIA_TYPE,
            ),
            occurred,
            25,
        )
        .expect("caller-created canonical metadata");
    let bytes = encode_exhaust_envelope(&ByoaExhaustEnvelope {
        schema_version: BYOA_CONNECTOR_SCHEMA_VERSION,
        attempt_id: *attempt.id.as_bytes(),
        lease_owner: "worker".to_owned(),
        attempt_count: attempt.attempt_count,
        disposition: ByoaTerminalDisposition::Completed,
        exhaust: sample_exhaust(),
    })
    .expect("caller-created envelope");
    vault
        .append_blob_artifact_version(
            &artifact,
            &bytes,
            &BlobVersionProvenance::AgentRun {
                run_ref: attempt.run_id.clone().expect("run id"),
            },
            actor,
            occurred,
            25,
        )
        .expect("caller-created version");
    let attached = AttemptQueue::new(&vault)
        .set_result(SetAttemptResult {
            id: attempt.id,
            lease_owner: "worker".to_owned(),
            attempt_count: attempt.attempt_count,
            result_ref: byoa_result_ref(&artifact, 1).expect("result ref"),
            now: 26,
        })
        .expect("generic attachment");
    let before = custody_snapshot(&vault);
    let error = dispatcher
        .capture_terminal_exhaust(capture_request(
            &attempt,
            ByoaTerminalDisposition::Completed,
        ))
        .expect_err("only an atomically settled capture authorizes canonical retry");
    assert!(matches!(
        error,
        ByoaError::Store(Error::Artifact(ArtifactError::InvalidAgentDispatchInput(
            ERR_CAPTURE_CONFLICT
        )))
    ));
    assert_eq!(custody_snapshot(&vault), before);
    assert_eq!(attached.state, AttemptState::Leased);
    assert_eq!(
        AttemptQueue::new(&vault).get(attempt.id).expect("row"),
        Some(attached)
    );
}

#[test]
fn failure_reason_validation_rolls_back_attachment_and_defaults_when_absent() {
    let (_dir, vault) = open_vault();
    let mut dispatcher = dispatcher(&vault);
    let attempt = claimed_with_manifest(&vault, &mut dispatcher, false);
    for reason in [String::new(), "x".repeat(2049)] {
        let mut request = capture_request(&attempt, ByoaTerminalDisposition::Failed);
        request.reason = Some(reason);
        let before = custody_snapshot(&vault);
        assert!(dispatcher.capture_terminal_exhaust(request).is_err());
        assert_eq!(custody_snapshot(&vault), before);
    }
    let mut request = capture_request(&attempt, ByoaTerminalDisposition::Failed);
    request.reason = None;
    let receipt = dispatcher
        .capture_terminal_exhaust(request)
        .expect("default failure reason");
    assert_eq!(receipt.attempt.state, AttemptState::Failed);
    assert_eq!(
        receipt.attempt.last_error.as_deref(),
        Some(BYOA_DEFAULT_FAILURE_REASON)
    );
}

#[test]
fn capture_after_force_cancel_is_refused_without_new_evidence() {
    for landing in [false, true] {
        let (_dir, vault) = open_vault();
        let mut dispatcher = dispatcher(&vault);
        let attempt = claimed_with_manifest(&vault, &mut dispatcher, landing);
        AttemptQueue::new(&vault)
            .force_cancel(force_cancel_request(&attempt))
            .expect("force first");
        let before = custody_snapshot(&vault);
        for disposition in [
            ByoaTerminalDisposition::Completed,
            ByoaTerminalDisposition::Failed,
            ByoaTerminalDisposition::Cancelled,
            ByoaTerminalDisposition::Abandoned,
        ] {
            assert!(
                dispatcher
                    .capture_terminal_exhaust(capture_request(&attempt, disposition))
                    .is_err()
            );
            assert_eq!(custody_snapshot(&vault), before);
        }
    }
}

#[test]
fn capture_racing_force_cancel_cannot_publish_a_contradictory_disposition() {
    for disposition in [
        ByoaTerminalDisposition::Completed,
        ByoaTerminalDisposition::Failed,
    ] {
        let (_dir, vault) = open_vault();
        let mut initial = dispatcher(&vault);
        let attempt = claimed_with_manifest(&vault, &mut initial, false);
        let barrier = std::sync::Barrier::new(2);
        let (captured, forced) = std::thread::scope(|scope| {
            let captured = scope.spawn(|| {
                barrier.wait();
                dispatcher(&vault).capture_terminal_exhaust(capture_request(&attempt, disposition))
            });
            let forced = scope.spawn(|| {
                barrier.wait();
                AttemptQueue::new(&vault).force_cancel(force_cancel_request(&attempt))
            });
            (
                captured.join().expect("capture worker"),
                forced.join().expect("force worker"),
            )
        });
        let record = AttemptQueue::new(&vault)
            .get(attempt.id)
            .expect("row")
            .expect("attempt");
        let before = custody_snapshot(&vault);
        match captured {
            Ok(receipt) => {
                assert!(matches!(
                    forced.expect("force result"),
                    ForceCancelOutcome::AlreadySettled(_)
                ));
                assert!(disposition_matches_state(disposition, record.state));
                assert_eq!(record, receipt.attempt);
                assert_eq!(
                    initial
                        .capture_terminal_exhaust(capture_request(&attempt, disposition))
                        .expect("canonical retry after race"),
                    receipt
                );
                assert_eq!(
                    vault
                        .blob_artifact_versions(&receipt.artifact_id)
                        .expect("versions")
                        .len(),
                    1
                );
            }
            Err(_) => {
                assert!(matches!(
                    forced.expect("force result"),
                    ForceCancelOutcome::Cancelled(_)
                ));
                assert_eq!(record.state, AttemptState::Cancelled);
                assert_eq!(record.result_ref, None);
                let artifact = byoa_exhaust_artifact_id(attempt.id).expect("artifact");
                assert!(
                    vault
                        .get_blob_artifact(&artifact)
                        .expect("artifact body")
                        .is_none()
                );
                assert!(
                    vault
                        .blob_artifact_versions(&artifact)
                        .expect("versions")
                        .is_empty()
                );
                assert!(
                    vault
                        .get_raw(&byoa_runtime_actor().expect("actor").entity_ref())
                        .expect("actor body")
                        .is_none()
                );
            }
        }
        assert_eq!(custody_snapshot(&vault), before);
    }
}

#[test]
fn abort_after_terminal_capture_rolls_back_settlement_pack_and_artifact() {
    for disposition in [
        ByoaTerminalDisposition::Completed,
        ByoaTerminalDisposition::Failed,
        ByoaTerminalDisposition::Cancelled,
    ] {
        let (_dir, vault) = open_vault();
        let mut dispatcher = dispatcher(&vault);
        let attempt = claimed_with_manifest(
            &vault,
            &mut dispatcher,
            disposition == ByoaTerminalDisposition::Cancelled,
        );
        let before = custody_snapshot(&vault);
        let aborted: ByoaResult<()> = vault.try_with_write_txn(|wtxn| {
            let receipt = dispatcher
                .capture_terminal_exhaust_in_txn(wtxn, capture_request(&attempt, disposition))?;
            let staged = AttemptQueue::new(&vault)
                .get_in_write_txn(wtxn, attempt.id)?
                .expect("staged attempt");
            assert_eq!(staged, receipt.attempt);
            assert!(disposition_matches_state(disposition, staged.state));
            assert!(
                read_blob_artifact_head_in_txn(&vault.store, wtxn, &receipt.artifact_id)?.is_some()
            );
            Err(invalid("injected failure after terminal capture"))
        });
        assert!(aborted.is_err());
        assert_eq!(custody_snapshot(&vault), before);
        let retry = dispatcher
            .capture_terminal_exhaust(capture_request(&attempt, disposition))
            .expect("retry after abort");
        assert!(disposition_matches_state(disposition, retry.attempt.state));
        assert_eq!(retry.artifact_version, 1);
    }
}

#[test]
fn compatible_person_collision_rejects_capture_without_overwrite_or_settlement() {
    for body in [
        Vec::new(),
        b"caller-controlled person".to_vec(),
        BYOA_RUNTIME_ACTOR_DOMAIN[..BYOA_RUNTIME_ACTOR_DOMAIN.len() - 1].to_vec(),
        [BYOA_RUNTIME_ACTOR_DOMAIN, b"-caller"].concat(),
    ] {
        for disposition in [
            ByoaTerminalDisposition::Completed,
            ByoaTerminalDisposition::Failed,
            ByoaTerminalDisposition::Cancelled,
            ByoaTerminalDisposition::Abandoned,
        ] {
            let (_dir, vault) = open_vault();
            let actor = byoa_runtime_actor().expect("actor");
            vault
                .put_entity(
                    &actor.entity_ref(),
                    crate::registry::ENTITY_TYPE_PERSON,
                    TimeRange { start: 5, end: 5 },
                    5,
                    &body,
                )
                .expect("preclaimed person");
            let original = vault.get_raw(&actor.entity_ref()).expect("original actor");
            let mut dispatcher = dispatcher(&vault);
            let attempt = claimed_with_manifest(
                &vault,
                &mut dispatcher,
                disposition == ByoaTerminalDisposition::Cancelled,
            );
            let before = custody_snapshot(&vault);
            let error = dispatcher
                .capture_terminal_exhaust(capture_request(&attempt, disposition))
                .expect_err("an agent-compatible person is not necessarily the runtime");
            assert!(matches!(
                error,
                ByoaError::Store(Error::Artifact(ArtifactError::InvalidAgentDispatchInput(
                    ERR_RUNTIME_ACTOR_COLLISION
                )))
            ));
            assert_eq!(custody_snapshot(&vault), before);
            assert_eq!(
                vault
                    .get_raw(&actor.entity_ref())
                    .expect("actor after rejection"),
                original
            );
            assert_eq!(
                AttemptQueue::new(&vault).get(attempt.id).expect("row"),
                Some(attempt)
            );
        }
    }
}

#[test]
fn exact_canonical_runtime_body_is_reused_without_rewriting_actor_metadata() {
    let (_dir, vault) = open_vault();
    let actor = byoa_runtime_actor().expect("actor");
    vault
        .put_entity(
            &actor.entity_ref(),
            crate::registry::ENTITY_TYPE_PERSON,
            TimeRange { start: 5, end: 7 },
            8,
            BYOA_RUNTIME_ACTOR_DOMAIN,
        )
        .expect("canonical runtime actor");
    let original = vault.get_raw(&actor.entity_ref()).expect("original actor");
    let mut dispatcher = dispatcher(&vault);
    for _ in 0..2 {
        let attempt = dispatch_and_claim(
            &vault,
            &mut dispatcher,
            ByoaConnectorSpec::CliSandbox(cli_spec()),
            "worker",
        );
        let request = capture_request(&attempt, ByoaTerminalDisposition::Completed);
        let first = dispatcher
            .capture_terminal_exhaust(request.clone())
            .expect("canonical actor reused");
        assert_eq!(first.attempt.state, AttemptState::Completed);
        assert_eq!(
            vault.get_raw(&actor.entity_ref()).expect("unchanged actor"),
            original
        );
        let before = custody_snapshot(&vault);
        assert_eq!(
            dispatcher
                .capture_terminal_exhaust(request)
                .expect("canonical retry"),
            first
        );
        assert_eq!(custody_snapshot(&vault), before);
    }
}
