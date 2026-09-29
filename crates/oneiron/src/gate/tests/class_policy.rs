//! `wait_policy` / `act_policy` manifest parse and resolution tests.

use super::*;

use crate::gate::class_policy::{ActPosture, ClassPolicyPrecedence, WaitResolution};
use crate::gate::constants::{
    ACT_POLICY_CLASS_KEY, ACT_POLICY_POSTURE_KEY, ACT_POLICY_SUBJECT_CLASS_KEY,
    CLASS_POLICY_HOLDER_REF_KEY, CLASS_POLICY_PRECEDENCE_KEY, POLICY_ACT_POLICY_KEY,
    POLICY_WAIT_POLICY_KEY, WAIT_POLICY_CLASS_KEY, WAIT_POLICY_MAX_SECS_KEY,
    WAIT_POLICY_MIN_SECS_KEY,
};

const WAIT_CLASS: &str = "channel_identity.quarantine";
const ACT_CLASS: &str = "channel_identity.outbound_send";
const SUBJECT: &str = "delegated_grant";
const DAY: u64 = 24 * 60 * 60;

fn map(entries: Vec<(&str, Value)>) -> Value {
    Value::Map(
        entries
            .into_iter()
            .map(|(key, value)| (Value::from(key), value))
            .collect(),
    )
}

fn wait_row(min_secs: u64, max_secs: Option<u64>, holder: Option<&str>) -> Value {
    let mut entries = vec![
        (WAIT_POLICY_CLASS_KEY, Value::from(WAIT_CLASS)),
        (WAIT_POLICY_MIN_SECS_KEY, Value::from(min_secs)),
    ];
    if let Some(max_secs) = max_secs {
        entries.push((WAIT_POLICY_MAX_SECS_KEY, Value::from(max_secs)));
    }
    if let Some(holder) = holder {
        entries.push((CLASS_POLICY_HOLDER_REF_KEY, Value::from(holder)));
    }
    map(entries)
}

fn act_row(posture: ActPosture, holder: Option<&str>) -> Value {
    let mut entries = vec![
        (ACT_POLICY_CLASS_KEY, Value::from(ACT_CLASS)),
        (ACT_POLICY_SUBJECT_CLASS_KEY, Value::from(SUBJECT)),
        (ACT_POLICY_POSTURE_KEY, Value::from(posture.as_str())),
    ];
    if let Some(holder) = holder {
        entries.push((CLASS_POLICY_HOLDER_REF_KEY, Value::from(holder)));
    }
    map(entries)
}

fn resolved(entries: Vec<(Value, Value)>) -> Result<PolicyManifestResolution> {
    let (_tmp, vault) = temp_vault();
    put_policy_manifest_bytes(&vault, test_id(0x40), &encode_policy_manifest(entries))?;
    resolve(&vault)
}

fn waits(rows: Vec<Value>) -> Result<PolicyManifestResolution> {
    resolved(vec![(
        Value::from(POLICY_WAIT_POLICY_KEY),
        Value::Array(rows),
    )])
}

fn acts(rows: Vec<Value>) -> Result<PolicyManifestResolution> {
    resolved(vec![(
        Value::from(POLICY_ACT_POLICY_KEY),
        Value::Array(rows),
    )])
}

#[test]
fn an_unnamed_wait_class_is_ungoverned_and_a_named_one_resolves() -> Result<()> {
    let policy = waits(vec![wait_row(30 * DAY, None, None)])?;
    assert_eq!(
        policy.resolved_wait("some.other.wait", None),
        WaitResolution::Ungoverned
    );
    let WaitResolution::Resolved(wait) = policy.resolved_wait(WAIT_CLASS, None) else {
        panic!("vault row resolves");
    };
    assert_eq!(wait.min_secs, 30 * DAY);
    assert_eq!(wait.max_secs, None);
    Ok(())
}

#[test]
fn wait_rows_merge_most_restrictively_across_packs() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    put_policy_manifest_bytes(
        &vault,
        test_id(0x41),
        &encode_policy_manifest(vec![(
            Value::from(POLICY_WAIT_POLICY_KEY),
            Value::Array(vec![wait_row(30 * DAY, Some(400 * DAY), None)]),
        )]),
    )?;
    put_policy_manifest_bytes(
        &vault,
        test_id(0x52),
        &encode_policy_manifest(vec![(
            Value::from(POLICY_WAIT_POLICY_KEY),
            Value::Array(vec![wait_row(60 * DAY, Some(200 * DAY), None)]),
        )]),
    )?;
    let WaitResolution::Resolved(wait) = resolve(&vault)?.resolved_wait(WAIT_CLASS, None) else {
        panic!("two packs resolve");
    };
    // The LONGEST floor and the TIGHTEST ceiling: restrictive on both bounds.
    assert_eq!(wait.min_secs, 60 * DAY);
    assert_eq!(wait.max_secs, Some(200 * DAY));
    Ok(())
}

#[test]
fn a_holder_row_raises_the_floor_but_never_lowers_it() -> Result<()> {
    let holder = test_id(0x43);
    let policy = waits(vec![
        wait_row(30 * DAY, None, None),
        wait_row(90 * DAY, None, Some(&holder.to_hex())),
    ])?;
    let WaitResolution::Resolved(narrowed) = policy.resolved_wait(WAIT_CLASS, Some(holder)) else {
        panic!("holder row resolves");
    };
    assert_eq!(narrowed.min_secs, 90 * DAY);
    // Another holder, and the vault answer itself, are untouched by it.
    let WaitResolution::Resolved(other) = policy.resolved_wait(WAIT_CLASS, Some(test_id(0x44)))
    else {
        panic!("unnamed holder resolves");
    };
    assert_eq!(other.min_secs, 30 * DAY);

    let lowering = waits(vec![
        wait_row(30 * DAY, None, None),
        wait_row(DAY, None, Some(&holder.to_hex())),
    ])?;
    let WaitResolution::Resolved(clamped) = lowering.resolved_wait(WAIT_CLASS, Some(holder)) else {
        panic!("lowering holder row resolves");
    };
    // Narrowing only: a holder asking for LESS keeps the vault's floor.
    assert_eq!(clamped.min_secs, 30 * DAY);
    Ok(())
}

#[test]
fn a_holder_row_is_capped_by_the_vault_ceiling() -> Result<()> {
    let holder = test_id(0x45);
    let policy = waits(vec![
        wait_row(30 * DAY, Some(120 * DAY), None),
        wait_row(365 * DAY, None, Some(&holder.to_hex())),
    ])?;
    let WaitResolution::Resolved(wait) = policy.resolved_wait(WAIT_CLASS, Some(holder)) else {
        panic!("capped holder row resolves");
    };
    // The holder asked past the vault's ceiling and is clamped back to it.
    assert_eq!(wait.min_secs, 120 * DAY);
    assert_eq!(wait.max_secs, Some(120 * DAY));
    Ok(())
}

#[test]
fn vault_only_precedence_turns_holder_rows_off() -> Result<()> {
    let holder = test_id(0x46);
    let mut vault_row = wait_row(30 * DAY, None, None);
    if let Value::Map(entries) = &mut vault_row {
        entries.push((
            Value::from(CLASS_POLICY_PRECEDENCE_KEY),
            Value::from(ClassPolicyPrecedence::VaultOnly.as_str()),
        ));
    }
    let policy = waits(vec![
        vault_row,
        wait_row(90 * DAY, None, Some(&holder.to_hex())),
    ])?;
    let WaitResolution::Resolved(wait) = policy.resolved_wait(WAIT_CLASS, Some(holder)) else {
        panic!("vault-only row resolves");
    };
    assert_eq!(wait.min_secs, 30 * DAY);
    Ok(())
}

#[test]
fn contradictory_wait_bounds_across_packs_fail_closed() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    put_policy_manifest_bytes(
        &vault,
        test_id(0x57),
        &encode_policy_manifest(vec![(
            Value::from(POLICY_WAIT_POLICY_KEY),
            Value::Array(vec![wait_row(300 * DAY, None, None)]),
        )]),
    )?;
    put_policy_manifest_bytes(
        &vault,
        test_id(0x48),
        &encode_policy_manifest(vec![(
            Value::from(POLICY_WAIT_POLICY_KEY),
            Value::Array(vec![wait_row(DAY, Some(30 * DAY), None)]),
        )]),
    )?;
    // Floor above ceiling: no window satisfies it, and picking either bound
    // would be the engine inventing policy.
    assert_eq!(
        resolve(&vault)?.resolved_wait(WAIT_CLASS, None),
        WaitResolution::Contradictory
    );
    Ok(())
}

#[test]
fn an_unnamed_act_pairing_resolves_to_no_row() -> Result<()> {
    let policy = acts(vec![act_row(ActPosture::RequireCapability, None)])?;
    assert_eq!(
        policy.resolved_act_posture(ACT_CLASS, "self_held", None),
        None
    );
    assert_eq!(
        policy.resolved_act_posture(ACT_CLASS, SUBJECT, None),
        Some(ActPosture::RequireCapability)
    );
    Ok(())
}

#[test]
fn act_postures_merge_restrictively_and_holders_only_narrow() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    put_policy_manifest_bytes(
        &vault,
        test_id(0x49),
        &encode_policy_manifest(vec![(
            Value::from(POLICY_ACT_POLICY_KEY),
            Value::Array(vec![act_row(ActPosture::RequireCapability, None)]),
        )]),
    )?;
    put_policy_manifest_bytes(
        &vault,
        test_id(0x4A),
        &encode_policy_manifest(vec![(
            Value::from(POLICY_ACT_POLICY_KEY),
            Value::Array(vec![act_row(ActPosture::Deny, None)]),
        )]),
    )?;
    // Any `deny` wins across packs.
    assert_eq!(
        resolve(&vault)?.resolved_act_posture(ACT_CLASS, SUBJECT, None),
        Some(ActPosture::Deny)
    );

    let holder = test_id(0x4B);
    let narrowing = acts(vec![
        act_row(ActPosture::RequireCapability, None),
        act_row(ActPosture::Deny, Some(&holder.to_hex())),
    ])?;
    assert_eq!(
        narrowing.resolved_act_posture(ACT_CLASS, SUBJECT, Some(holder)),
        Some(ActPosture::Deny)
    );
    assert_eq!(
        narrowing.resolved_act_posture(ACT_CLASS, SUBJECT, None),
        Some(ActPosture::RequireCapability)
    );

    // A holder cannot open what the vault denied.
    let widening = acts(vec![
        act_row(ActPosture::Deny, None),
        act_row(ActPosture::RequireCapability, Some(&holder.to_hex())),
    ])?;
    assert_eq!(
        widening.resolved_act_posture(ACT_CLASS, SUBJECT, Some(holder)),
        Some(ActPosture::Deny)
    );
    Ok(())
}

#[test]
fn malformed_class_rows_fail_the_whole_manifest_closed() -> Result<()> {
    // Unreadable posture, unknown key, a row whose own floor is above its own
    // ceiling, a duplicate key, and a holder row naming its own precedence.
    // Each drops the whole manifest, which fails the gate closed rather than
    // resolving to the permissive arm or the shorter wait.
    let unreadable_posture = map(vec![
        (ACT_POLICY_CLASS_KEY, Value::from(ACT_CLASS)),
        (ACT_POLICY_SUBJECT_CLASS_KEY, Value::from(SUBJECT)),
        (ACT_POLICY_POSTURE_KEY, Value::from("allow")),
    ]);
    assert!(acts(vec![unreadable_posture])?.is_fail_closed());

    let unknown_key = map(vec![
        (WAIT_POLICY_CLASS_KEY, Value::from(WAIT_CLASS)),
        (WAIT_POLICY_MIN_SECS_KEY, Value::from(DAY)),
        ("min_secs_typo", Value::from(DAY)),
    ]);
    assert!(waits(vec![unknown_key])?.is_fail_closed());

    assert!(waits(vec![wait_row(90 * DAY, Some(DAY), None)])?.is_fail_closed());

    assert!(
        waits(vec![
            wait_row(DAY, None, None),
            wait_row(2 * DAY, None, None)
        ])?
        .is_fail_closed()
    );

    let holder_naming_precedence = map(vec![
        (WAIT_POLICY_CLASS_KEY, Value::from(WAIT_CLASS)),
        (WAIT_POLICY_MIN_SECS_KEY, Value::from(DAY)),
        (
            CLASS_POLICY_HOLDER_REF_KEY,
            Value::from(test_id(0x4C).to_hex()),
        ),
        (
            CLASS_POLICY_PRECEDENCE_KEY,
            Value::from(ClassPolicyPrecedence::VaultOnly.as_str()),
        ),
    ]);
    assert!(waits(vec![holder_naming_precedence])?.is_fail_closed());
    Ok(())
}

#[test]
fn a_fail_closed_manifest_never_reads_as_a_shorter_wait_or_a_permit() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    put_policy_manifest_bytes(&vault, test_id(0x4D), b"not-a-manifest")?;
    let policy = resolve(&vault)?;
    assert!(policy.is_fail_closed());
    assert_eq!(
        policy.resolved_wait(WAIT_CLASS, None),
        WaitResolution::Contradictory
    );
    assert_eq!(
        policy.resolved_act_posture(ACT_CLASS, SUBJECT, None),
        Some(ActPosture::Deny)
    );
    Ok(())
}

#[test]
fn class_policy_tokens_round_trip() {
    for posture in [ActPosture::Deny, ActPosture::RequireCapability] {
        assert_eq!(ActPosture::parse(posture.as_str()), Some(posture));
    }
    for precedence in [
        ClassPolicyPrecedence::NestedNarrowing,
        ClassPolicyPrecedence::VaultOnly,
    ] {
        assert_eq!(
            ClassPolicyPrecedence::parse(precedence.as_str()),
            Some(precedence)
        );
    }
    assert_eq!(ActPosture::default(), ActPosture::Deny);
    assert_eq!(
        ClassPolicyPrecedence::default(),
        ClassPolicyPrecedence::NestedNarrowing
    );
}

#[test]
fn the_shipped_default_manifest_carries_both_class_rows() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    put_policy_manifest_bytes(
        &vault,
        crate::gate::default_policy_manifest_id()?,
        &crate::gate::default_policy_manifest().unwrap(),
    )?;
    let policy = resolve(&vault)?;
    // GATE-009: the restrictive starting values are DATA in the vault, not
    // engine constants. The delegated ban is a row an owner can edit.
    let WaitResolution::Resolved(wait) = policy.resolved_wait(WAIT_CLASS, None) else {
        panic!("the default manifest names the quarantine wait");
    };
    assert_eq!(
        wait.min_secs,
        crate::channel_identity::DEFAULT_CHANNEL_IDENTITY_QUARANTINE_MIN_SECS
    );
    assert_eq!(
        policy.resolved_act_posture(ACT_CLASS, SUBJECT, None),
        Some(ActPosture::Deny)
    );
    assert_eq!(
        policy.resolved_act_posture(ACT_CLASS, "self_held", None),
        Some(ActPosture::RequireCapability)
    );
    Ok(())
}
