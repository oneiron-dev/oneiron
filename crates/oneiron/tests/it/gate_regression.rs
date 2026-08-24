use crate::common::entity as test_id;
use oneiron::error::{GateDenialOutcome, GateDenialReason};
use oneiron::registry::{ENTITY_TYPE_PERSON, ENTITY_TYPE_POLICY_MANIFEST};
use oneiron::{
    ClaimApprovalStatus, ClaimCandidate, ClaimSource, ClaimSubject, EdgeActorClass, EntityId,
    Error, Result, TimeRange, Vault, VaultConfig, WriteActor, WriteEnvelope, WriteProvenance,
};
use rmpv::Value;

fn test_time(ts: u64) -> TimeRange {
    TimeRange { start: ts, end: ts }
}

fn temp_vault() -> (tempfile::TempDir, Vault) {
    let tmp = tempfile::tempdir().expect("temp dir");
    let vault = Vault::open(tmp.path(), VaultConfig::default()).expect("open vault");
    (tmp, vault)
}

fn put_person(vault: &Vault, id: &EntityId) -> Result<()> {
    vault.put_entity(
        id,
        ENTITY_TYPE_PERSON,
        test_time(1),
        1,
        b"gate regression person",
    )
}

fn claim_candidate(subject: EntityId, predicate: &'static str) -> ClaimCandidate {
    ClaimCandidate::new(
        predicate,
        ClaimSubject::Entity(subject),
        Value::from("Ada"),
        1.0,
    )
}

fn write_envelope(
    actor: EntityId,
    source: ClaimSource,
    approval: ClaimApprovalStatus,
) -> Result<WriteEnvelope> {
    Ok(WriteEnvelope::new(
        WriteActor::new(actor, EdgeActorClass::Human),
        source,
        WriteProvenance::new(Value::from("gate-regression"))?,
        approval,
    ))
}

#[derive(Clone, Copy)]
enum Presence {
    Present,
    Missing,
}

#[derive(Clone, Copy)]
enum ExpectedError {
    EntityNotFound,
    GateWriteRejected {
        outcome: &'static str,
        reason_codes: &'static [&'static str],
    },
    MaintenanceKindNotWritable(u8),
}

struct DeniedClaimCase {
    name: &'static str,
    seed: u8,
    actor: Presence,
    subject: Presence,
    source: ClaimSource,
    approval: ClaimApprovalStatus,
    predicate: &'static str,
    expected: ExpectedError,
}

fn assert_expected_error(err: Error, expected: ExpectedError) {
    match expected {
        ExpectedError::EntityNotFound => {
            assert!(matches!(err, Error::EntityNotFound), "got {err:?}");
        }
        ExpectedError::GateWriteRejected {
            outcome,
            reason_codes,
        } => {
            assert!(
                matches!(
                    err,
                    Error::GateWriteRejected {
                        outcome: got_outcome,
                        reason_codes: ref got
                    } if got_outcome == outcome && got == reason_codes
                ),
                "expected GateWriteRejected({outcome}, {reason_codes:?}), got {err:?}",
            );
        }
        ExpectedError::MaintenanceKindNotWritable(kind) => {
            assert!(
                matches!(err, Error::MaintenanceKindNotWritable(got) if got == kind),
                "expected MaintenanceKindNotWritable({kind}), got {err:?}",
            );
        }
    }
}

fn run_denied_claim_case(case: &DeniedClaimCase) -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let actor_id = test_id(case.seed);
    let subject_id = test_id(case.seed + 1);
    let prior_id = test_id(case.seed + 2);
    let claim_id = test_id(case.seed + 3);

    if matches!(case.actor, Presence::Present) {
        put_person(&vault, &actor_id)?;
    }
    if matches!(case.subject, Presence::Present) {
        put_person(&vault, &subject_id)?;
    }

    let candidate = claim_candidate(subject_id, case.predicate);
    let envelope = write_envelope(actor_id, case.source, case.approval)?;
    let err = vault
        .batch()
        .put(&prior_id, ENTITY_TYPE_PERSON, test_time(11), 11, b"prior")
        .claim_candidate(&claim_id, candidate, &envelope, test_time(11), 11)
        .commit()
        .expect_err(case.name);

    assert_expected_error(err, case.expected);
    assert!(
        vault.get_raw(&prior_id)?.is_none(),
        "{}: denied batch must not commit earlier put",
        case.name
    );
    assert!(
        vault.get_raw(&claim_id)?.is_none(),
        "{}: denied batch must not commit claim",
        case.name
    );
    Ok(())
}

#[test]
fn gate_regression_denial_taxonomy_is_typed_and_stable() {
    assert_eq!(
        GateDenialOutcome::parse("pending"),
        Some(GateDenialOutcome::Pending)
    );
    assert_eq!(
        GateDenialOutcome::parse("deny"),
        Some(GateDenialOutcome::Deny)
    );
    assert_eq!(GateDenialOutcome::parse("allow"), None);

    let cases = [
        (
            GateDenialReason::DenyMissingActorClass,
            GateDenialOutcome::Deny,
            "gate.deny.missing_actor_class",
        ),
        (
            GateDenialReason::DenyMissingActorProvenance,
            GateDenialOutcome::Deny,
            "gate.deny.missing_actor_provenance",
        ),
        (
            GateDenialReason::DenyMissingPolicyManifestVersion,
            GateDenialOutcome::Deny,
            "gate.deny.missing_policy_manifest_version",
        ),
        (
            GateDenialReason::DenyPolicyFailClosed,
            GateDenialOutcome::Deny,
            "gate.deny.policy_fail_closed",
        ),
        (
            GateDenialReason::PendingActorCeiling,
            GateDenialOutcome::Pending,
            "gate.pending.actor_ceiling",
        ),
        (
            GateDenialReason::PendingSourceTrust,
            GateDenialOutcome::Pending,
            "gate.pending.source_trust",
        ),
        (
            GateDenialReason::PendingCriticalityFloor,
            GateDenialOutcome::Pending,
            "gate.pending.criticality_floor",
        ),
        (
            GateDenialReason::PendingPolicyManifestAuthority,
            GateDenialOutcome::Pending,
            "gate.pending.policy_manifest_authority",
        ),
        (
            GateDenialReason::PendingExternalEffectAuthority,
            GateDenialOutcome::Pending,
            "gate.pending.external_effect_authority",
        ),
    ];

    for (reason, outcome, code) in cases {
        assert_eq!(reason.as_str(), code);
        assert_eq!(reason.outcome(), outcome);
        assert_eq!(GateDenialReason::from_code(code), Some(reason));

        let err = Error::GateWriteRejected {
            outcome: outcome.as_str(),
            reason_codes: vec![code],
        };
        let typed = err.gate_denial().expect("stable Gate code must parse");
        assert_eq!(typed.outcome(), outcome);
        assert_eq!(typed.reason_codes(), &[reason]);
    }

    assert_eq!(GateDenialReason::from_code("gate.allow"), None);
    let inconsistent = Error::GateWriteRejected {
        outcome: "pending",
        reason_codes: vec!["gate.deny.policy_fail_closed"],
    };
    assert!(inconsistent.gate_denial().is_none());
}

#[test]
fn gate_regression_denied_claim_matrix_leaves_no_committed_side_effects() -> Result<()> {
    let cases = [
        DeniedClaimCase {
            name: "missing actor entity",
            seed: 0xC0,
            actor: Presence::Missing,
            subject: Presence::Present,
            source: ClaimSource::UserStated,
            approval: ClaimApprovalStatus::Auto,
            predicate: "profile.name",
            expected: ExpectedError::EntityNotFound,
        },
        DeniedClaimCase {
            name: "missing subject entity",
            seed: 0xC4,
            actor: Presence::Present,
            subject: Presence::Missing,
            source: ClaimSource::UserStated,
            approval: ClaimApprovalStatus::Auto,
            predicate: "profile.name",
            expected: ExpectedError::EntityNotFound,
        },
        // Deliberate gate consequence of the ONE-1645 provenance floor:
        // unstamped ToolOutput queues for consent under the default manifest.
        // This candidate carries no `sensitivity` scope, so post-floor it reads
        // band 2 and trips the default manifest's ToolOutput
        // `max_auto_sensitivity: 0` ceiling IN ADDITION to the critical
        // predicate's floor. Both reasons are correct and both are reported;
        // the case's subject — a denied batch commits no side effects — is
        // unchanged.
        DeniedClaimCase {
            name: "tool output criticality floor denial",
            seed: 0xC8,
            actor: Presence::Present,
            subject: Presence::Present,
            source: ClaimSource::ToolOutput,
            approval: ClaimApprovalStatus::Auto,
            predicate: "health.allergy",
            expected: ExpectedError::GateWriteRejected {
                outcome: "pending",
                reason_codes: &[
                    "gate.pending.source_trust",
                    "gate.pending.criticality_floor",
                ],
            },
        },
        DeniedClaimCase {
            name: "imported default source trust denial",
            seed: 0xCC,
            actor: Presence::Present,
            subject: Presence::Present,
            source: ClaimSource::Imported,
            approval: ClaimApprovalStatus::Auto,
            predicate: "profile.name",
            expected: ExpectedError::GateWriteRejected {
                outcome: "pending",
                reason_codes: &["gate.pending.source_trust"],
            },
        },
        DeniedClaimCase {
            name: "generated default source trust denial",
            seed: 0xD0,
            actor: Presence::Present,
            subject: Presence::Present,
            source: ClaimSource::Generated,
            approval: ClaimApprovalStatus::Auto,
            predicate: "profile.name",
            expected: ExpectedError::GateWriteRejected {
                outcome: "pending",
                reason_codes: &["gate.pending.source_trust"],
            },
        },
    ];

    for case in &cases {
        run_denied_claim_case(case)?;
    }

    Ok(())
}

#[test]
fn gate_regression_public_policy_manifest_rejection_leaves_no_committed_side_effects() -> Result<()>
{
    let (_tmp, vault) = temp_vault();
    let prior_id = test_id(0xD0);
    let policy_id = test_id(0xD1);

    let err = vault
        .batch()
        .put(&prior_id, ENTITY_TYPE_PERSON, test_time(11), 11, b"prior")
        .put(
            &policy_id,
            ENTITY_TYPE_POLICY_MANIFEST,
            test_time(11),
            11,
            b"not-msgpack",
        )
        .commit()
        .expect_err("public policy manifest put must be rejected");

    assert_expected_error(
        err,
        ExpectedError::MaintenanceKindNotWritable(ENTITY_TYPE_POLICY_MANIFEST),
    );
    assert!(vault.get_raw(&prior_id)?.is_none());
    assert!(vault.get_raw(&policy_id)?.is_none());
    Ok(())
}
