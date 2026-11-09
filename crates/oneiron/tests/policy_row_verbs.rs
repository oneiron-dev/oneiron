//! Public-door policy-row proof independent of unrelated lib-test compilation.
use oneiron::policy_model::{PolicyRowAction, PolicyRowChange, PolicyRowScope};
use oneiron::store::GateDecisionId;
use oneiron::{EntityId, Vault, VaultConfig};

type TestResult = Result<(), Box<dyn std::error::Error>>;

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
    let masked = EntityId::now();
    let id = EntityId::now();
    {
        let vault = Vault::open(dir.path(), VaultConfig::default())?;
        // Scan on (the default): the token never lands. Since mask on write
        // (#1811, OF-560 slice 1, owner ruling G04 = A) the write lands with
        // the token in secret custody and its handle in its place.
        vault.put_entity(
            &masked,
            TURN,
            oneiron::TimeRange { start: 1, end: 1 },
            1,
            turn.as_bytes(),
        )?;
        let stored = String::from_utf8(vault.get(&masked)?.expect("the masked TURN"))?;
        assert!(!stored.contains(&token), "the token landed: {stored}");
        assert!(
            stored.starts_with("user: the token is [secret sc") && stored.ends_with(']'),
            "the token's custody handle is not in its place: {stored}"
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
