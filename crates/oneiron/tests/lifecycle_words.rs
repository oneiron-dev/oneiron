//! UC-15: each stored lifecycle status keeps its stored spelling byte for byte (STORED-CHANGE-RULE: keep), and declares the edges its writers take.

use oneiron::calendar::CalendarWriteOutboxState;
use oneiron::checkout::CheckoutLeaseState;
use oneiron::code_run::{ReaderJobState, ReaderJobStatus};
use oneiron::ingest::history::{HostedImportState, HostedImportStatus};
use oneiron::outbound_intent_ledger::IntentState;
use oneiron::secret_lease::SecretLeaseStatus;
use oneiron_contracts::lifecycle::{Lifecycle, LifecycleWords};

type TestResult = Result<(), Box<dyn std::error::Error>>;

#[test]
fn intent_state_keeps_its_words_and_declares_its_edges() {
    for (state, word) in [
        (IntentState::Pending, "pending"),
        (IntentState::Done, "done"),
        (IntentState::Abandoned, "abandoned"),
        (IntentState::Deferred, "deferred"),
    ] {
        assert_eq!(state.word(), word);
        assert_eq!(IntentState::kind_from_word(word), Some(state));
    }
    assert_eq!(IntentState::kind_from_word(""), None);
    assert_eq!(
        IntentState::next_kinds(IntentState::Pending),
        &[
            IntentState::Done,
            IntentState::Abandoned,
            IntentState::Deferred
        ]
    );
    assert_eq!(
        IntentState::next_kinds(IntentState::Deferred),
        &[IntentState::Done, IntentState::Abandoned]
    );
    assert_eq!(IntentState::next_kinds(IntentState::Done), &[]);
    assert_eq!(IntentState::next_kinds(IntentState::Abandoned), &[]);
}

#[test]
fn checkout_lease_state_keeps_its_words_and_declares_its_edges() {
    for (state, word) in [
        (CheckoutLeaseState::Active, "active"),
        (CheckoutLeaseState::Settling, "settling"),
        (CheckoutLeaseState::Settled, "settled"),
        (CheckoutLeaseState::Retained, "retained"),
    ] {
        assert_eq!(state.word(), word);
        assert_eq!(CheckoutLeaseState::kind_from_word(word), Some(state));
    }
    assert_eq!(CheckoutLeaseState::kind_from_word(""), None);
    assert_eq!(
        CheckoutLeaseState::next_kinds(CheckoutLeaseState::Active),
        &[
            CheckoutLeaseState::Settled,
            CheckoutLeaseState::Settling,
            CheckoutLeaseState::Retained
        ]
    );
    assert_eq!(
        CheckoutLeaseState::next_kinds(CheckoutLeaseState::Retained),
        &[CheckoutLeaseState::Settled, CheckoutLeaseState::Settling]
    );
    assert_eq!(
        CheckoutLeaseState::next_kinds(CheckoutLeaseState::Settled),
        &[CheckoutLeaseState::Settling, CheckoutLeaseState::Retained]
    );
    assert_eq!(
        CheckoutLeaseState::next_kinds(CheckoutLeaseState::Settling),
        &[]
    );
}

#[test]
fn reader_job_state_keeps_its_words_serde_and_edges() -> TestResult {
    for (state, word) in [
        (ReaderJobState::Queued, "queued"),
        (ReaderJobState::Active, "active"),
        (ReaderJobState::Done, "done"),
        (ReaderJobState::Partial { reason: "r".into() }, "partial"),
        (ReaderJobState::Failed { reason: "r".into() }, "failed"),
    ] {
        assert_eq!(state.word(), word);
        assert_eq!(ReaderJobState::kind_from_word(word), Some(state.kind()));
    }
    assert_eq!(ReaderJobState::kind_from_word(""), None);
    assert_eq!(
        serde_json::to_value(ReaderJobState::Queued)?,
        serde_json::json!({"state": "queued"})
    );
    assert_eq!(
        serde_json::to_value(ReaderJobState::Active)?,
        serde_json::json!({"state": "active"})
    );
    assert_eq!(
        serde_json::to_value(ReaderJobState::Done)?,
        serde_json::json!({"state": "done"})
    );
    assert_eq!(
        serde_json::to_value(ReaderJobState::Partial { reason: "r".into() })?,
        serde_json::json!({"state": "partial", "reason": "r"})
    );
    assert_eq!(
        serde_json::to_value(ReaderJobState::Failed { reason: "r".into() })?,
        serde_json::json!({"state": "failed", "reason": "r"})
    );
    assert_eq!(
        ReaderJobState::next_kinds(ReaderJobStatus::Queued),
        &[
            ReaderJobStatus::Active,
            ReaderJobStatus::Done,
            ReaderJobStatus::Partial,
            ReaderJobStatus::Failed
        ]
    );
    assert_eq!(
        ReaderJobState::next_kinds(ReaderJobStatus::Active),
        &[
            ReaderJobStatus::Queued,
            ReaderJobStatus::Done,
            ReaderJobStatus::Partial,
            ReaderJobStatus::Failed
        ]
    );
    assert_eq!(ReaderJobState::next_kinds(ReaderJobStatus::Done), &[]);
    assert_eq!(ReaderJobState::next_kinds(ReaderJobStatus::Partial), &[]);
    assert_eq!(ReaderJobState::next_kinds(ReaderJobStatus::Failed), &[]);
    Ok(())
}

#[test]
fn calendar_write_outbox_state_keeps_its_serde_and_declares_its_edges() -> TestResult {
    assert_eq!(
        serde_json::to_value(CalendarWriteOutboxState::Prepared)?,
        serde_json::json!("prepared")
    );
    assert_eq!(
        serde_json::to_value(CalendarWriteOutboxState::RemoteApplied)?,
        serde_json::json!("remote_applied")
    );
    assert_eq!(
        serde_json::to_value(CalendarWriteOutboxState::ReconcileRequired)?,
        serde_json::json!("reconcile_required")
    );
    assert_eq!(
        serde_json::to_value(CalendarWriteOutboxState::Committed)?,
        serde_json::json!("committed")
    );
    assert_eq!(
        CalendarWriteOutboxState::next_kinds(CalendarWriteOutboxState::Prepared),
        &[
            CalendarWriteOutboxState::RemoteApplied,
            CalendarWriteOutboxState::ReconcileRequired
        ]
    );
    assert_eq!(
        CalendarWriteOutboxState::next_kinds(CalendarWriteOutboxState::RemoteApplied),
        &[CalendarWriteOutboxState::Committed]
    );
    assert_eq!(
        CalendarWriteOutboxState::next_kinds(CalendarWriteOutboxState::Committed),
        &[CalendarWriteOutboxState::Prepared]
    );
    assert_eq!(
        CalendarWriteOutboxState::next_kinds(CalendarWriteOutboxState::ReconcileRequired),
        &[]
    );
    Ok(())
}

#[test]
fn hosted_import_state_pins_its_kinds_and_declares_its_edges() {
    assert_eq!(HostedImportState::Staged.kind(), HostedImportStatus::Staged);
    assert_eq!(
        HostedImportState::Landing.kind(),
        HostedImportStatus::Landing
    );
    assert_eq!(HostedImportState::Landed.kind(), HostedImportStatus::Landed);
    assert_eq!(
        HostedImportState::Failed("r".into()).kind(),
        HostedImportStatus::Failed
    );
    assert_eq!(
        HostedImportState::Cancelling.kind(),
        HostedImportStatus::Cancelling
    );
    assert_eq!(
        HostedImportState::Cancelled.kind(),
        HostedImportStatus::Cancelled
    );
    assert_eq!(
        HostedImportState::next_kinds(HostedImportStatus::Staged),
        &[
            HostedImportStatus::Landing,
            HostedImportStatus::Landed,
            HostedImportStatus::Failed,
            HostedImportStatus::Cancelling
        ]
    );
    assert_eq!(
        HostedImportState::next_kinds(HostedImportStatus::Landing),
        &[
            HostedImportStatus::Landed,
            HostedImportStatus::Failed,
            HostedImportStatus::Cancelling
        ]
    );
    assert_eq!(
        HostedImportState::next_kinds(HostedImportStatus::Cancelling),
        &[
            HostedImportStatus::Landed,
            HostedImportStatus::Failed,
            HostedImportStatus::Cancelled
        ]
    );
    assert_eq!(
        HostedImportState::next_kinds(HostedImportStatus::Landed),
        &[]
    );
    assert_eq!(
        HostedImportState::next_kinds(HostedImportStatus::Failed),
        &[]
    );
    assert_eq!(
        HostedImportState::next_kinds(HostedImportStatus::Cancelled),
        &[]
    );
}

#[test]
fn secret_lease_status_keeps_its_wire_bytes_and_declares_its_edges() {
    assert_eq!(SecretLeaseStatus::Active.as_wire_byte(), 0x01);
    assert_eq!(SecretLeaseStatus::Expired.as_wire_byte(), 0x02);
    assert_eq!(SecretLeaseStatus::Revoked.as_wire_byte(), 0x03);
    assert_eq!(
        SecretLeaseStatus::next_kinds(SecretLeaseStatus::Active),
        &[SecretLeaseStatus::Expired, SecretLeaseStatus::Revoked]
    );
    assert_eq!(
        SecretLeaseStatus::next_kinds(SecretLeaseStatus::Expired),
        &[SecretLeaseStatus::Revoked]
    );
    assert_eq!(
        SecretLeaseStatus::next_kinds(SecretLeaseStatus::Revoked),
        &[]
    );
}
