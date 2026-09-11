//! Stop reasons are part of failed and abandoned capture idempotency.

use super::*;
use crate::error::ArtifactError;

const STOP_CASES: [(bool, ByoaTerminalDisposition, &str); 3] = [
    (
        false,
        ByoaTerminalDisposition::Failed,
        BYOA_DEFAULT_FAILURE_REASON,
    ),
    (
        false,
        ByoaTerminalDisposition::Abandoned,
        BYOA_DEFAULT_ABANDON_REASON,
    ),
    (
        true,
        ByoaTerminalDisposition::Abandoned,
        BYOA_DEFAULT_ABANDON_REASON,
    ),
];

fn invalid_stop_reasons() -> [(String, &'static str); 3] {
    [
        (String::new(), ERR_STOP_REASON_EMPTY),
        ("x".repeat(2049), ERR_STOP_REASON_TOO_LONG),
        ("é".repeat(1025), ERR_STOP_REASON_TOO_LONG),
    ]
}

#[test]
fn stop_reason_bounds_and_changes_are_rejected_without_custody_writes() {
    for (landing, disposition, default) in STOP_CASES {
        for reason in ["x".to_owned(), "x".repeat(2048), "é".repeat(1024)] {
            let (_dir, vault) = open_vault();
            let mut dispatcher = dispatcher(&vault);
            let attempt = claimed_with_manifest(&vault, &mut dispatcher, landing);
            let mut request = capture_request(&attempt, disposition);
            request.reason = Some(reason.clone());
            let before = custody_snapshot(&vault);
            for (invalid_reason, expected) in invalid_stop_reasons() {
                let mut rejected = request.clone();
                rejected.reason = Some(invalid_reason);
                let error = dispatcher
                    .capture_terminal_exhaust(rejected)
                    .expect_err("invalid initial reason");
                assert!(matches!(
                    error,
                    ByoaError::Store(Error::Artifact(ArtifactError::InvalidAttemptQueueRecord(message)))
                        if message == expected
                ));
                assert_eq!(custody_snapshot(&vault), before);
            }
            let first = dispatcher
                .capture_terminal_exhaust(request.clone())
                .expect("reason at the queue byte bounds");
            assert_eq!(first.attempt.last_error.as_deref(), Some(reason.as_str()));
            request.now += 1;
            let before = custody_snapshot(&vault);
            assert_eq!(
                dispatcher
                    .capture_terminal_exhaust(request.clone())
                    .expect("matching reason retry"),
                first
            );
            assert_eq!(custody_snapshot(&vault), before);
            for (invalid_reason, expected) in invalid_stop_reasons() {
                let mut rejected = request.clone();
                rejected.reason = Some(invalid_reason);
                let error = dispatcher
                    .capture_terminal_exhaust(rejected)
                    .expect_err("invalid retry reason");
                assert!(matches!(
                    error,
                    ByoaError::Store(Error::Artifact(ArtifactError::InvalidAttemptQueueRecord(message)))
                        if message == expected
                ));
                assert_eq!(custody_snapshot(&vault), before);
            }
            for changed in [
                None,
                Some(default.to_owned()),
                Some("changed reason".to_owned()),
            ] {
                let mut rejected = request.clone();
                rejected.reason = changed;
                let error = dispatcher
                    .capture_terminal_exhaust(rejected)
                    .expect_err("a valid but different reason is not a canonical retry");
                assert!(matches!(
                    error,
                    ByoaError::Store(Error::Artifact(ArtifactError::InvalidAgentDispatchInput(
                        ERR_CAPTURE_CONFLICT
                    )))
                ));
                assert_eq!(custody_snapshot(&vault), before);
            }
        }
    }
}

#[test]
fn omitted_and_explicit_default_stop_reasons_are_equivalent_on_retry() {
    for (landing, disposition, default) in STOP_CASES {
        for initial in [None, Some(default.to_owned())] {
            let (_dir, vault) = open_vault();
            let mut dispatcher = dispatcher(&vault);
            let attempt = claimed_with_manifest(&vault, &mut dispatcher, landing);
            let mut request = capture_request(&attempt, disposition);
            request.reason = initial;
            let first = dispatcher
                .capture_terminal_exhaust(request.clone())
                .expect("default stop reason");
            assert_eq!(first.attempt.last_error.as_deref(), Some(default));
            request.now += 1;
            let before = custody_snapshot(&vault);
            for repeated in [None, Some(default.to_owned())] {
                request.reason = repeated;
                assert_eq!(
                    dispatcher
                        .capture_terminal_exhaust(request.clone())
                        .expect("normalized default retry"),
                    first
                );
                assert_eq!(custody_snapshot(&vault), before);
            }
            request.reason = Some("changed reason".to_owned());
            let error = dispatcher
                .capture_terminal_exhaust(request)
                .expect_err("a custom reason cannot replace the stored default");
            assert!(matches!(
                error,
                ByoaError::Store(Error::Artifact(ArtifactError::InvalidAgentDispatchInput(
                    ERR_CAPTURE_CONFLICT
                )))
            ));
            assert_eq!(custody_snapshot(&vault), before);
        }
    }
}

#[test]
fn completed_and_cancelled_reasons_remain_advisory_on_capture_and_retry() {
    for (landing, disposition) in [
        (false, ByoaTerminalDisposition::Completed),
        (true, ByoaTerminalDisposition::Cancelled),
    ] {
        let advisory_reasons = [
            None,
            Some(String::new()),
            Some("x".repeat(2049)),
            Some("changed advisory reason".to_owned()),
        ];
        for initial in &advisory_reasons {
            let (_dir, vault) = open_vault();
            let mut dispatcher = dispatcher(&vault);
            let attempt = claimed_with_manifest(&vault, &mut dispatcher, landing);
            let mut request = capture_request(&attempt, disposition);
            request.reason = initial.clone();
            let first = dispatcher
                .capture_terminal_exhaust(request.clone())
                .expect("advisory reason does not gate settlement");
            assert_eq!(first.attempt.last_error, attempt.last_error);
            request.now += 1;
            let before = custody_snapshot(&vault);
            for repeated in &advisory_reasons {
                request.reason = repeated.clone();
                assert_eq!(
                    dispatcher
                        .capture_terminal_exhaust(request.clone())
                        .expect("advisory reason does not gate retry"),
                    first
                );
                assert_eq!(custody_snapshot(&vault), before);
            }
        }
    }
}
