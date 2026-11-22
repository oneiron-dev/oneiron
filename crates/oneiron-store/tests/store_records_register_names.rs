//! The names of 11 name lists in `oneiron-store`, one line per row, generated from
//! `scripts/ratchet/hand_name_tables.py --names --only <file>` before each list became a Register
//! (Fable pass 25, the Register wave): the names each hand table wrote. Green on the hand tables and
//! on the derive, so no stored or sent name changed (M-1 keep). Each name is also pinned to the one
//! serde reads and writes, and each kept reverse fn to its rows.
//!
//! - `crates/oneiron-store/src/attempt_inputs.rs`
//! - `crates/oneiron-store/src/diagnostic_record/event.rs`
//! - `crates/oneiron-store/src/merge_queue/tested_types.rs`
//! - `crates/oneiron-store/src/model_step_record.rs`
//! - `crates/oneiron-store/src/origin/lfs/policy.rs`
//! - `crates/oneiron-store/src/origin/mirror_strategy.rs`
//! - `crates/oneiron-store/src/origin/secret_publication.rs`
//! - `crates/oneiron-store/src/own_rate_record.rs`
//! - `crates/oneiron-store/src/vault_cleanup/cleanup_types.rs`

use oneiron_store::attempt_inputs::AttemptInterventionKind;
use oneiron_store::diagnostic_record::event::AgentHealthSignal;
use oneiron_store::merge_queue::tested_types::QueueExportHoldReason;
use oneiron_store::model_step_record::StepProgression;
use oneiron_store::origin::lfs::policy::LfsAssetClass;
use oneiron_store::origin::mirror_strategy::OriginMirrorSyncStrategy;
use oneiron_store::origin::secret_publication::RepoDestinationRole;
use oneiron_store::origin::secret_publication::RepoDestinationVisibility;
use oneiron_store::own_rate_record::OwnRateKind;
use oneiron_store::vault_cleanup::cleanup_types::CleanupKind;
use oneiron_store::vault_cleanup::cleanup_types::CleanupPosture;
use serde_json::Value;

/// Every row of `AttemptInterventionKind`, as its hand table spelled it.
const ATTEMPT_INTERVENTION_KIND_ROWS: [(AttemptInterventionKind, &str); 5] = [
    (AttemptInterventionKind::Interrupt, "interrupt"),
    (AttemptInterventionKind::Pause, "pause"),
    (AttemptInterventionKind::Resume, "resume"),
    (AttemptInterventionKind::Cancel, "cancel"),
    (AttemptInterventionKind::Redirect, "redirect"),
];

#[test]
fn every_attempt_intervention_kind_keeps_its_name() {
    assert_eq!(AttemptInterventionKind::Interrupt.as_str(), "interrupt");
    assert_eq!(AttemptInterventionKind::Pause.as_str(), "pause");
    assert_eq!(AttemptInterventionKind::Resume.as_str(), "resume");
    assert_eq!(AttemptInterventionKind::Cancel.as_str(), "cancel");
    assert_eq!(AttemptInterventionKind::Redirect.as_str(), "redirect");
}

#[test]
fn every_attempt_intervention_kind_name_is_its_serde_name() {
    for (row, name) in ATTEMPT_INTERVENTION_KIND_ROWS {
        let written = serde_json::to_value(row).expect("a row serializes");
        assert_eq!(written, Value::String(name.to_owned()), "{row:?}");
        let read: AttemptInterventionKind =
            serde_json::from_value(Value::String(name.to_owned())).expect("serde reads the name");
        assert_eq!(read, row, "{name}");
    }
}

/// Every row of `AgentHealthSignal`, as its hand table spelled it.
const AGENT_HEALTH_SIGNAL_ROWS: [(AgentHealthSignal, &str); 8] = [
    (AgentHealthSignal::Loop, "loop"),
    (AgentHealthSignal::FailedCheckRepeat, "failed_check_repeat"),
    (AgentHealthSignal::CostSpike, "cost_spike"),
    (AgentHealthSignal::LongWait, "long_wait"),
    (AgentHealthSignal::Silent, "silent"),
    (AgentHealthSignal::DuplicateWork, "duplicate_work"),
    (AgentHealthSignal::UnsupportedDone, "unsupported_done"),
    (AgentHealthSignal::Misalignment, "misalignment"),
];

#[test]
fn every_agent_health_signal_keeps_its_name() {
    assert_eq!(AgentHealthSignal::Loop.as_str(), "loop");
    assert_eq!(
        AgentHealthSignal::FailedCheckRepeat.as_str(),
        "failed_check_repeat"
    );
    assert_eq!(AgentHealthSignal::CostSpike.as_str(), "cost_spike");
    assert_eq!(AgentHealthSignal::LongWait.as_str(), "long_wait");
    assert_eq!(AgentHealthSignal::Silent.as_str(), "silent");
    assert_eq!(AgentHealthSignal::DuplicateWork.as_str(), "duplicate_work");
    assert_eq!(
        AgentHealthSignal::UnsupportedDone.as_str(),
        "unsupported_done"
    );
    assert_eq!(AgentHealthSignal::Misalignment.as_str(), "misalignment");
}

#[test]
fn every_agent_health_signal_name_is_its_serde_name() {
    for (row, name) in AGENT_HEALTH_SIGNAL_ROWS {
        let written = serde_json::to_value(row).expect("a row serializes");
        assert_eq!(written, Value::String(name.to_owned()), "{row:?}");
        let read: AgentHealthSignal =
            serde_json::from_value(Value::String(name.to_owned())).expect("serde reads the name");
        assert_eq!(read, row, "{name}");
    }
}

/// Every row of `QueueExportHoldReason`, as its hand table spelled it.
const QUEUE_EXPORT_HOLD_REASON_ROWS: [(QueueExportHoldReason, &str); 12] = [
    (QueueExportHoldReason::SealPending, "seal_pending"),
    (
        QueueExportHoldReason::HeldSealAncestor,
        "held_seal_ancestor",
    ),
    (QueueExportHoldReason::HeldBinding, "held_binding"),
    (QueueExportHoldReason::HeldObject, "held_object"),
    (
        QueueExportHoldReason::HeldUnsupportedTree,
        "held_unsupported_tree",
    ),
    (
        QueueExportHoldReason::HeldUnreviewedChange,
        "held_unreviewed_change",
    ),
    (QueueExportHoldReason::HeldStore, "held_store"),
    (
        QueueExportHoldReason::HeldUntouchedPromotion,
        "held_untouched_promotion",
    ),
    (QueueExportHoldReason::AuthorErased, "author_erased"),
    (
        QueueExportHoldReason::AuthorUnavailable,
        "author_unavailable",
    ),
    (QueueExportHoldReason::Unenrolled, "unenrolled"),
    (QueueExportHoldReason::Unavailable, "unavailable"),
];

#[test]
fn every_queue_export_hold_reason_keeps_its_name() {
    assert_eq!(QueueExportHoldReason::SealPending.as_str(), "seal_pending");
    assert_eq!(
        QueueExportHoldReason::HeldSealAncestor.as_str(),
        "held_seal_ancestor"
    );
    assert_eq!(QueueExportHoldReason::HeldBinding.as_str(), "held_binding");
    assert_eq!(QueueExportHoldReason::HeldObject.as_str(), "held_object");
    assert_eq!(
        QueueExportHoldReason::HeldUnsupportedTree.as_str(),
        "held_unsupported_tree"
    );
    assert_eq!(
        QueueExportHoldReason::HeldUnreviewedChange.as_str(),
        "held_unreviewed_change"
    );
    assert_eq!(QueueExportHoldReason::HeldStore.as_str(), "held_store");
    assert_eq!(
        QueueExportHoldReason::HeldUntouchedPromotion.as_str(),
        "held_untouched_promotion"
    );
    assert_eq!(
        QueueExportHoldReason::AuthorErased.as_str(),
        "author_erased"
    );
    assert_eq!(
        QueueExportHoldReason::AuthorUnavailable.as_str(),
        "author_unavailable"
    );
    assert_eq!(QueueExportHoldReason::Unenrolled.as_str(), "unenrolled");
    assert_eq!(QueueExportHoldReason::Unavailable.as_str(), "unavailable");
}

#[test]
fn every_queue_export_hold_reason_name_is_its_serde_name() {
    for (row, name) in QUEUE_EXPORT_HOLD_REASON_ROWS {
        let written = serde_json::to_value(row).expect("a row serializes");
        assert_eq!(written, Value::String(name.to_owned()), "{row:?}");
        let read: QueueExportHoldReason =
            serde_json::from_value(Value::String(name.to_owned())).expect("serde reads the name");
        assert_eq!(read, row, "{name}");
    }
}

/// Every row of `StepProgression`, as its hand table spelled it.
const STEP_PROGRESSION_ROWS: [(StepProgression, &str); 4] = [
    (StepProgression::Started, "started"),
    (StepProgression::ResponseReceived, "response_received"),
    (StepProgression::Logged, "logged"),
    (StepProgression::Finished, "finished"),
];

#[test]
fn every_step_progression_keeps_its_name() {
    assert_eq!(StepProgression::Started.as_str(), "started");
    assert_eq!(
        StepProgression::ResponseReceived.as_str(),
        "response_received"
    );
    assert_eq!(StepProgression::Logged.as_str(), "logged");
    assert_eq!(StepProgression::Finished.as_str(), "finished");
}

#[test]
fn every_step_progression_name_is_its_serde_name() {
    for (row, name) in STEP_PROGRESSION_ROWS {
        let written = serde_json::to_value(row).expect("a row serializes");
        assert_eq!(written, Value::String(name.to_owned()), "{row:?}");
        let read: StepProgression =
            serde_json::from_value(Value::String(name.to_owned())).expect("serde reads the name");
        assert_eq!(read, row, "{name}");
    }
}

/// Every row of `LfsAssetClass`, as its hand table spelled it.
const LFS_ASSET_CLASS_ROWS: [(LfsAssetClass, &str); 2] = [
    (LfsAssetClass::RepositoryLarge, "repository-large"),
    (LfsAssetClass::BuildRequired, "build-required"),
];

#[test]
fn every_lfs_asset_class_keeps_its_name() {
    assert_eq!(LfsAssetClass::RepositoryLarge.as_str(), "repository-large");
    assert_eq!(LfsAssetClass::BuildRequired.as_str(), "build-required");
}

#[test]
fn every_lfs_asset_class_name_is_its_serde_name() {
    for (row, name) in LFS_ASSET_CLASS_ROWS {
        let written = serde_json::to_value(row).expect("a row serializes");
        assert_eq!(written, Value::String(name.to_owned()), "{row:?}");
        let read: LfsAssetClass =
            serde_json::from_value(Value::String(name.to_owned())).expect("serde reads the name");
        assert_eq!(read, row, "{name}");
    }
}

/// Every row of `OriginMirrorSyncStrategy`, as its hand table spelled it.
const ORIGIN_MIRROR_SYNC_STRATEGY_ROWS: [(OriginMirrorSyncStrategy, &str); 3] = [
    (OriginMirrorSyncStrategy::AskMe, "ask_me"),
    (OriginMirrorSyncStrategy::Schedule, "schedule"),
    (OriginMirrorSyncStrategy::FullAuto, "full_auto"),
];

#[test]
fn every_origin_mirror_sync_strategy_keeps_its_name() {
    assert_eq!(OriginMirrorSyncStrategy::AskMe.as_str(), "ask_me");
    assert_eq!(OriginMirrorSyncStrategy::Schedule.as_str(), "schedule");
    assert_eq!(OriginMirrorSyncStrategy::FullAuto.as_str(), "full_auto");
}

#[test]
fn every_origin_mirror_sync_strategy_name_is_its_serde_name() {
    for (row, name) in ORIGIN_MIRROR_SYNC_STRATEGY_ROWS {
        let written = serde_json::to_value(row).expect("a row serializes");
        assert_eq!(written, Value::String(name.to_owned()), "{row:?}");
        let read: OriginMirrorSyncStrategy =
            serde_json::from_value(Value::String(name.to_owned())).expect("serde reads the name");
        assert_eq!(read, row, "{name}");
    }
}

/// Every row of `RepoDestinationVisibility`, as its hand table spelled it.
const REPO_DESTINATION_VISIBILITY_ROWS: [(RepoDestinationVisibility, &str); 3] = [
    (RepoDestinationVisibility::Public, "public"),
    (RepoDestinationVisibility::Private, "private"),
    (RepoDestinationVisibility::Unknown, "unknown"),
];

#[test]
fn every_repo_destination_visibility_keeps_its_name() {
    assert_eq!(RepoDestinationVisibility::Public.as_str(), "public");
    assert_eq!(RepoDestinationVisibility::Private.as_str(), "private");
    assert_eq!(RepoDestinationVisibility::Unknown.as_str(), "unknown");
}

#[test]
fn every_repo_destination_visibility_name_is_its_serde_name() {
    for (row, name) in REPO_DESTINATION_VISIBILITY_ROWS {
        let written = serde_json::to_value(row).expect("a row serializes");
        assert_eq!(written, Value::String(name.to_owned()), "{row:?}");
        let read: RepoDestinationVisibility =
            serde_json::from_value(Value::String(name.to_owned())).expect("serde reads the name");
        assert_eq!(read, row, "{name}");
    }
}

/// Every row of `RepoDestinationRole`, as its hand table spelled it.
const REPO_DESTINATION_ROLE_ROWS: [(RepoDestinationRole, &str); 2] = [
    (RepoDestinationRole::Mirror, "mirror"),
    (RepoDestinationRole::OriginalSource, "original_source"),
];

#[test]
fn every_repo_destination_role_keeps_its_name() {
    assert_eq!(RepoDestinationRole::Mirror.as_str(), "mirror");
    assert_eq!(
        RepoDestinationRole::OriginalSource.as_str(),
        "original_source"
    );
}

#[test]
fn every_repo_destination_role_name_is_its_serde_name() {
    for (row, name) in REPO_DESTINATION_ROLE_ROWS {
        let written = serde_json::to_value(row).expect("a row serializes");
        assert_eq!(written, Value::String(name.to_owned()), "{row:?}");
        let read: RepoDestinationRole =
            serde_json::from_value(Value::String(name.to_owned())).expect("serde reads the name");
        assert_eq!(read, row, "{name}");
    }
}

/// Every row of `OwnRateKind`, as its hand table spelled it.
const OWN_RATE_KIND_ROWS: [(OwnRateKind, &str); 4] = [
    (OwnRateKind::TaskCreate, "task_create"),
    (OwnRateKind::AutoWrite, "auto_write"),
    (OwnRateKind::WeaveCorrection, "weave_correction"),
    (OwnRateKind::ConsultFanout, "consult_fanout"),
];

#[test]
fn every_own_rate_kind_keeps_its_name() {
    assert_eq!(OwnRateKind::TaskCreate.token(), "task_create");
    assert_eq!(OwnRateKind::AutoWrite.token(), "auto_write");
    assert_eq!(OwnRateKind::WeaveCorrection.token(), "weave_correction");
    assert_eq!(OwnRateKind::ConsultFanout.token(), "consult_fanout");
}

#[test]
fn every_own_rate_kind_name_is_its_serde_name() {
    for (row, name) in OWN_RATE_KIND_ROWS {
        let written = serde_json::to_value(row).expect("a row serializes");
        assert_eq!(written, Value::String(name.to_owned()), "{row:?}");
        let read: OwnRateKind =
            serde_json::from_value(Value::String(name.to_owned())).expect("serde reads the name");
        assert_eq!(read, row, "{name}");
    }
}

/// Every row of `CleanupKind`, as its hand table spelled it.
const CLEANUP_KIND_ROWS: [(CleanupKind, &str); 5] = [
    (
        CleanupKind::ClaimlessExtractionPerson,
        "claimless_extraction_person",
    ),
    (CleanupKind::EmptySummary, "empty_summary"),
    (CleanupKind::CompletedTask, "completed_task"),
    (CleanupKind::CompletedAttempt, "completed_attempt"),
    (CleanupKind::RetainedNote, "retained_note"),
];

#[test]
fn every_cleanup_kind_keeps_its_name() {
    assert_eq!(
        CleanupKind::ClaimlessExtractionPerson.as_str(),
        "claimless_extraction_person"
    );
    assert_eq!(CleanupKind::EmptySummary.as_str(), "empty_summary");
    assert_eq!(CleanupKind::CompletedTask.as_str(), "completed_task");
    assert_eq!(CleanupKind::CompletedAttempt.as_str(), "completed_attempt");
    assert_eq!(CleanupKind::RetainedNote.as_str(), "retained_note");
}

#[test]
fn every_cleanup_kind_name_is_its_serde_name() {
    for (row, name) in CLEANUP_KIND_ROWS {
        let written = serde_json::to_value(row).expect("a row serializes");
        assert_eq!(written, Value::String(name.to_owned()), "{row:?}");
        let read: CleanupKind =
            serde_json::from_value(Value::String(name.to_owned())).expect("serde reads the name");
        assert_eq!(read, row, "{name}");
    }
}

#[test]
fn cleanup_kind_parse_reads_each_name_back() {
    for (row, name) in CLEANUP_KIND_ROWS {
        assert_eq!(CleanupKind::parse(name), Some(row), "{name}");
    }
    assert_eq!(CleanupKind::parse("not.a.row"), None);
}

/// Every row of `CleanupPosture`, as its hand table spelled it.
const CLEANUP_POSTURE_ROWS: [(CleanupPosture, &str); 2] = [
    (CleanupPosture::ProposeFirst, "propose_first"),
    (CleanupPosture::AutoWithDigest, "auto_with_digest"),
];

#[test]
fn every_cleanup_posture_keeps_its_name() {
    assert_eq!(CleanupPosture::ProposeFirst.as_str(), "propose_first");
    assert_eq!(CleanupPosture::AutoWithDigest.as_str(), "auto_with_digest");
}

#[test]
fn every_cleanup_posture_name_is_its_serde_name() {
    for (row, name) in CLEANUP_POSTURE_ROWS {
        let written = serde_json::to_value(row).expect("a row serializes");
        assert_eq!(written, Value::String(name.to_owned()), "{row:?}");
        let read: CleanupPosture =
            serde_json::from_value(Value::String(name.to_owned())).expect("serde reads the name");
        assert_eq!(read, row, "{name}");
    }
}

#[test]
fn cleanup_posture_parse_reads_each_name_back() {
    for (row, name) in CLEANUP_POSTURE_ROWS {
        assert_eq!(CleanupPosture::parse(name), Some(row), "{name}");
    }
    assert_eq!(CleanupPosture::parse("not.a.row"), None);
}
