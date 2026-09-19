use std::panic::{AssertUnwindSafe, catch_unwind};

use super::*;
use crate::artifact_hosting::tests::{publisher, test_config};
use crate::error::ErrorKind;
use crate::outbound::OutboundExecutionOutcomeKind;
use crate::outbound_chokepoint::{
    OutboundEffectCommand, OutboundTransport, execute_outbound_effect,
};
use crate::outbound_consent::OutboundBindingAuthority;
use crate::outbound_intent_ledger::{
    FrozenOutboundCall, IntentState, OutboundSendOutcome, RecordedOutboundOutcome,
    intent_ledger_records, read_intent_record,
};
use crate::receipt::{ReceiptKind, ReceiptQuery};
use crate::temporal::TimeRange;

type TestResult = std::result::Result<(), Box<dyn std::error::Error>>;

struct CrashAfterCommit<'a>(PublishSink<'a>);
impl OutboundExecutionSink for CrashAfterCommit<'_> {
    fn execute(&mut self, execution: &OutboundExecutionRequest<'_>) -> OutboundExecutionOutcome {
        let outcome = self.0.execute(execution);
        assert_eq!(
            outcome.kind,
            OutboundExecutionOutcomeKind::DeliveredToChannel
        );
        // Model loss of the process after the effect is durable but before the
        // transport adapter can return Acked and transition the ledger to Done.
        self.0
            .vault
            .store
            .env
            .force_sync()
            .expect("persist local publish");
        panic!("crash after pointer and share receipt commit");
    }
}

struct CrashBeforeCommit;
impl OutboundExecutionSink for CrashBeforeCommit {
    fn execute(&mut self, _: &OutboundExecutionRequest<'_>) -> OutboundExecutionOutcome {
        panic!("crash after admission but before publish");
    }
}

struct NoTransport;
impl OutboundTransport for NoTransport {
    fn send(&mut self, _: &FrozenOutboundCall) -> OutboundSendOutcome {
        panic!("committed publication recovery must not execute transport");
    }
}

fn publication(vault: &Vault, actor: EntityId) -> Result<ArtifactPublishVerbRequest> {
    let id = EntityId::now();
    vault.put_blob_artifact(
        &id,
        &crate::blob_artifact::BlobArtifactBody::new("report.pdf", "application/pdf"),
        TimeRange { start: 1, end: 1 },
        1,
    )?;
    for (at, bytes) in [(2, b"export-one".as_slice()), (3, b"export-two".as_slice())] {
        vault.append_blob_artifact_version(
            &id,
            bytes,
            &crate::blob_artifact::BlobVersionProvenance::UserUpload,
            crate::write_envelope::WriteActor::new(actor, crate::edge::EdgeActorClass::Human),
            TimeRange { start: at, end: at },
            at,
        )?;
    }
    Ok(ArtifactPublishVerbRequest::new(
        "report",
        ArtifactPointerChannel::Published,
        ArtifactPinnedVersion::Blob {
            artifact_id: id,
            version: 1,
        },
        OutboundDispatchActor::agent(actor),
        "intent:publish-crash",
        10,
    ))
}

#[test]
fn publish_commit_crash_reopens_and_recovers_without_restoring_pointer() -> TestResult {
    // Exercise both live dispatch retry and the existing Resume command. Each
    // must close the same durable boundary after both kinds of later mutation.
    for (unpublish, resume) in [(false, false), (true, false), (false, true), (true, true)] {
        let (dir, vault) = crate::test_util::open_test_vault_with(test_config());
        let actor = publisher(&vault)?;
        let mut request = publication(&vault, actor)?;
        let owner = vault.authenticate_owner(
            actor,
            &actor.to_hex(),
            true,
            crate::store::GateDecisionId::now(),
        )?;
        vault.approve_artifact_publish(&owner, &request)?;
        let dispatch = request.dispatch_request()?;
        let mut sink = CrashAfterCommit(PublishSink {
            vault: &vault,
            request: &request,
            intent: dispatch.intent.clone(),
        });
        assert!(
            catch_unwind(AssertUnwindSafe(|| {
                vault.dispatch_outbound_intent(dispatch, &mut sink)
            }))
            .is_err()
        );
        let listing = intent_ledger_records(&vault)?;
        assert!(listing.corrupt.is_empty());
        assert_eq!(listing.len(), 1);
        let pending = listing.records.into_iter().next().unwrap();
        assert_eq!(pending.state, IntentState::Pending);
        assert_eq!(pending.recorded_outcome, None);
        let share = vault.committed_artifact_publication(&request)?.unwrap();
        assert_eq!(share.receipt_kind, ReceiptKind::Share);
        assert_eq!(share.outcome, "published");
        assert_eq!(share.fields["outbound_intent_id"], pending.idempotency_key);
        assert_eq!(
            vault
                .approve_artifact_publish(&owner, &request)
                .unwrap_err()
                .kind(),
            ErrorKind::ConsentApproveOnceSpent,
        );
        assert_eq!(
            vault
                .artifact_pointer(&request.artifact, request.channel)?
                .unwrap()
                .version,
            request.version,
        );
        if unpublish {
            assert!(vault.unpublish_artifact_pointer(&request.artifact, request.channel)?);
        } else {
            let mut newer = request.clone();
            newer.intent_ref = "intent:publish-newer".into();
            let ArtifactPinnedVersion::Blob { artifact_id, .. } = request.version else {
                unreachable!();
            };
            newer.version = ArtifactPinnedVersion::Blob {
                artifact_id,
                version: 2,
            };
            vault.approve_artifact_publish(&owner, &newer)?;
            assert_eq!(
                vault.request_artifact_publish(&newer)?.status,
                ArtifactPublishVerbStatus::Published,
            );
        }
        let later_pointer = vault.artifact_pointer(&request.artifact, request.channel)?;
        let shares = vault.receipts(ReceiptQuery::new(100).with_kind(ReceiptKind::Share))?;
        let gates = vault.receipts(ReceiptQuery::new(100).with_kind(ReceiptKind::Gate))?;
        drop(vault);
        let vault = Vault::open(dir.path(), test_config())?;
        request.occurred_at = 30;
        let mut changed = request.clone();
        changed.actor.actor_entity_ref = None;
        assert!(vault.request_artifact_publish(&changed).is_err());
        changed = request.clone();
        changed.channel = ArtifactPointerChannel::Preview;
        assert!(vault.request_artifact_publish(&changed).is_err());
        assert_eq!(
            read_intent_record(&vault, &pending.id)?.unwrap().state,
            IntentState::Pending
        );

        if resume {
            let result = execute_outbound_effect(
                &vault,
                &OutboundBindingAuthority::for_vault(&vault)?,
                OutboundEffectCommand::Resume(pending.id),
                request.occurred_at,
                &mut NoTransport,
            )?;
            assert_eq!(result.dispatch.state, Some(IntentState::Done));
            assert_eq!(
                result.dispatch.send_outcome,
                Some(OutboundSendOutcome::Acked)
            );
            assert!(result.dispatch.replayed);
            assert!(result.gate_decision_id.is_none());
            assert!(result.budget_charge.is_none());
        }
        let recovered = vault.request_artifact_publish(&request)?;
        assert_eq!(recovered.status, ArtifactPublishVerbStatus::Published);
        assert_eq!(recovered.receipt.receipt_kind, ReceiptKind::Outbound);
        assert_eq!(recovered.receipt.outcome, "delivered_to_channel");
        assert_eq!(recovered.receipt.fields["intent_state"], "done");
        assert_eq!(recovered.share_receipt, Some(share.clone()));
        assert_eq!(
            vault.artifact_pointer(&request.artifact, request.channel)?,
            later_pointer
        );
        assert_eq!(
            vault.receipts(ReceiptQuery::new(100).with_kind(ReceiptKind::Share))?,
            shares,
        );
        assert_eq!(
            vault.receipts(ReceiptQuery::new(100).with_kind(ReceiptKind::Gate))?,
            gates,
        );
        let done = read_intent_record(&vault, &pending.id)?.unwrap();
        assert_eq!(done.state, IntentState::Done);
        assert_eq!(done.recorded_outcome, Some(RecordedOutboundOutcome::Acked));
        assert_eq!(done.budget_accounting, pending.budget_accounting);
        assert!(vault.active_standing_consent_grants()?.is_empty());
        assert!(
            vault
                .entities_by_type(crate::registry::ENTITY_TYPE_OUTBOUND_GRANT)?
                .is_empty()
        );
        drop(vault);
        let vault = Vault::open(dir.path(), test_config())?;
        assert_eq!(
            vault.request_artifact_publish(&request)?.share_receipt,
            Some(share)
        );
        assert_eq!(
            vault.artifact_pointer(&request.artifact, request.channel)?,
            later_pointer
        );
    }
    Ok(())
}

#[test]
fn publish_pending_without_committed_receipt_does_not_reuse_spent_approval() -> TestResult {
    let (dir, vault) = crate::test_util::open_test_vault_with(test_config());
    let actor = publisher(&vault)?;
    let mut request = publication(&vault, actor)?;
    let owner = vault.authenticate_owner(
        actor,
        &actor.to_hex(),
        true,
        crate::store::GateDecisionId::now(),
    )?;
    // A prior successful publication of the same pointer is not evidence that
    // a different admitted intent committed its effect.
    let mut earlier = request.clone();
    earlier.intent_ref = "intent:earlier-publication".into();
    vault.approve_artifact_publish(&owner, &earlier)?;
    let prior_share = vault
        .request_artifact_publish(&earlier)?
        .share_receipt
        .unwrap();
    assert!(vault.unpublish_artifact_pointer(&request.artifact, request.channel)?);
    vault.approve_artifact_publish(&owner, &request)?;
    assert!(
        catch_unwind(AssertUnwindSafe(|| {
            vault.dispatch_outbound_intent(
                request.dispatch_request().unwrap(),
                &mut CrashBeforeCommit,
            )
        }))
        .is_err()
    );
    assert_eq!(
        vault
            .approve_artifact_publish(&owner, &request)
            .unwrap_err()
            .kind(),
        ErrorKind::ConsentApproveOnceSpent,
    );
    assert!(vault.committed_artifact_publication(&request)?.is_none());
    drop(vault);
    let vault = Vault::open(dir.path(), test_config())?;
    request.occurred_at = 20;
    assert!(vault.request_artifact_publish(&request).is_err());
    assert!(
        vault
            .artifact_pointer(&request.artifact, request.channel)?
            .is_none()
    );
    assert_eq!(
        vault.receipts(ReceiptQuery::new(100).with_kind(ReceiptKind::Share))?,
        vec![prior_share],
    );
    let pending = intent_ledger_records(&vault)?
        .records
        .into_iter()
        .filter(|record| record.state == IntentState::Pending)
        .collect::<Vec<_>>();
    assert_eq!(pending.len(), 1);
    assert_eq!(pending[0].recorded_outcome, None);
    Ok(())
}

#[test]
fn publish_receipt_cannot_complete_a_different_admitted_ledger_identity() -> TestResult {
    let (dir, vault) = crate::test_util::open_test_vault_with(test_config());
    let actor = publisher(&vault)?;
    let request = publication(&vault, actor)?;
    vault
        .memory(actor, crate::edge::EdgeActorClass::Human)
        .grant_artifact_publish(&request.artifact, actor, 5)?;
    let share = vault
        .request_artifact_publish(&request)?
        .share_receipt
        .unwrap();
    assert!(vault.unpublish_artifact_pointer(&request.artifact, request.channel)?);
    // The trigger and all frozen payload bytes match, but this is another
    // admitted logical attempt. Its Pending row has no committed effect.
    let mut dispatch = request.dispatch_request()?;
    dispatch.ledger_identity_ref = Some("different-publish-attempt".into());
    assert!(
        catch_unwind(AssertUnwindSafe(|| {
            vault.dispatch_outbound_intent(dispatch, &mut CrashBeforeCommit)
        }))
        .is_err()
    );
    let pending = intent_ledger_records(&vault)?
        .records
        .into_iter()
        .find(|record| record.state == IntentState::Pending)
        .unwrap();
    assert_ne!(pending.idempotency_key, share.fields["outbound_intent_id"]);
    drop(vault);
    let vault = Vault::open(dir.path(), test_config())?;
    let error = execute_outbound_effect(
        &vault,
        &OutboundBindingAuthority::for_vault(&vault)?,
        OutboundEffectCommand::Resume(pending.id),
        30,
        &mut NoTransport,
    )
    .expect_err("a shared trigger is not a completion proof");
    assert!(matches!(
        error,
        crate::outbound_intent_ledger::IntentLedgerError::Engine(Error::InvalidConfig(_))
    ));
    assert_eq!(
        read_intent_record(&vault, &pending.id)?.unwrap().state,
        IntentState::Pending
    );
    assert!(
        vault
            .artifact_pointer(&request.artifact, request.channel)?
            .is_none()
    );
    assert_eq!(
        vault.receipts(ReceiptQuery::new(100).with_kind(ReceiptKind::Share))?,
        vec![share],
    );
    Ok(())
}
