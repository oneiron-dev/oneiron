//! Public-door policy-row proof independent of unrelated lib-test compilation.
use oneiron::policy_model::{PolicyRowAction, PolicyRowChange, PolicyRowScope};
use oneiron::store::GateDecisionId;
use oneiron::{EntityId, Vault, VaultConfig};

type TestResult = Result<(), Box<dyn std::error::Error>>;

#[test]
fn owner_edits_are_immediate_receipted_and_reversible() -> TestResult {
    let dir = tempfile::tempdir()?;
    let vault = Vault::open(dir.path(), VaultConfig::default())?;
    let owner = vault.ensure_embedded_owner_actor()?;
    let auth = vault.authenticate_owner(owner, &owner.to_hex(), true, GateDecisionId::now())?;
    let add = PolicyRowChange::Add {
        row_ref: "mine".into(),
        text: "Let me know".into(),
        action: PolicyRowAction::Warn,
        scope: PolicyRowScope::Vault,
    };
    let r1 = vault.change_policy_row(&auth, add, 10)?;
    for (at, action) in [
        (11, PolicyRowAction::Block),
        (12, PolicyRowAction::Warn),
        (13, PolicyRowAction::Block),
    ] {
        vault.change_policy_row(
            &auth,
            PolicyRowChange::Edit {
                row_ref: "mine".into(),
                text: "Let me know".into(),
                action,
                scope: PolicyRowScope::Vault,
            },
            at,
        )?;
    }
    assert_eq!(vault.policy_row_change_log()?.len(), 4);
    assert_eq!(vault.policy_changed_events()?.len(), 4);
    assert_eq!(
        vault.policy_row_change_log()?[1]
            .previous_receipt_id
            .as_deref(),
        Some(r1.receipt_id.as_str())
    );
    vault.change_policy_row(
        &auth,
        PolicyRowChange::Remove {
            row_ref: "mine".into(),
            scope: PolicyRowScope::Vault,
        },
        14,
    )?;
    assert_eq!(vault.policy_row_change_log()?.len(), 5);
    Ok(())
}

#[test]
fn non_owner_cannot_land_a_row_by_presenting_an_authenticated_person() -> TestResult {
    let dir = tempfile::tempdir()?;
    let vault = Vault::open(dir.path(), VaultConfig::default())?;
    let id = EntityId::now();
    vault.put_entity(
        &id,
        oneiron::registry::ENTITY_TYPE_PERSON,
        oneiron::TimeRange { start: 1, end: 1 },
        1,
        b"person",
    )?;
    let actor = vault.authenticate_owner(id, &id.to_hex(), true, GateDecisionId::now())?;
    assert!(
        vault
            .change_policy_row(
                &actor,
                PolicyRowChange::Add {
                    row_ref: "mine".into(),
                    text: "No".into(),
                    action: PolicyRowAction::Block,
                    scope: PolicyRowScope::Vault
                },
                10
            )
            .is_err()
    );
    assert!(vault.policy_row_change_log()?.is_empty());
    Ok(())
}

/// The benchmark door: a host builds a vault with the secret scan off through
/// public calls only, and the switch survives a reopen (and a copied fork).
#[test]
fn a_host_turns_the_secret_scan_off_through_the_public_owner_door() -> TestResult {
    use oneiron::policy_model::SecretScanMode;
    use oneiron::registry::ENTITY_TYPE_TURN as TURN;
    let dir = tempfile::tempdir()?;
    let token = ["gh", "p_", "0123456789abcdefghijklmnopqrstuvwxyz"].concat();
    let turn = format!("user: the token is {token}");
    let id = EntityId::now();
    {
        let vault = Vault::open(dir.path(), VaultConfig::default())?;
        assert!(
            vault
                .put_entity(
                    &id,
                    TURN,
                    oneiron::TimeRange { start: 1, end: 1 },
                    1,
                    turn.as_bytes()
                )
                .is_err()
        );
        let owner = vault.ensure_embedded_owner_actor()?;
        let auth = vault.authenticate_owner(owner, &owner.to_hex(), true, GateDecisionId::now())?;
        let receipt = vault.set_secret_scan_mode(&auth, SecretScanMode::Off, 10)?;
        assert_eq!(receipt.mode, SecretScanMode::Off);
    }
    let vault = Vault::open(dir.path(), VaultConfig::default())?;
    assert_eq!(vault.secret_scan_mode()?, SecretScanMode::Off);
    vault.put_entity(
        &id,
        TURN,
        oneiron::TimeRange { start: 1, end: 1 },
        1,
        turn.as_bytes(),
    )?;
    assert_eq!(vault.get(&id)?, Some(turn.into_bytes()));
    assert_eq!(vault.secret_scan_change_log()?.len(), 1);
    Ok(())
}
