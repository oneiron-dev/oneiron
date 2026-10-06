use super::*;
use crate::registry::{ENTITY_TYPE_PERSON, ENTITY_TYPE_TURN};
use crate::store::GateDecisionId;
use crate::{EntityId, TimeRange, VaultConfig};

type TestResult = std::result::Result<(), Box<dyn std::error::Error>>;

fn open() -> Result<(tempfile::TempDir, Vault, AuthenticatedOwner)> {
    let dir = tempfile::tempdir()?;
    let vault = Vault::open(dir.path(), VaultConfig::default())?;
    let id = crate::vault::embedded_owner_actor_id()?;
    let owner = vault.authenticate_owner(id, &id.to_hex(), true, GateDecisionId::now())?;
    Ok((dir, vault, owner))
}

/// A GitHub-token-shaped value, assembled at run time so no literal in the
/// source matches a provider pattern.
fn token_shaped() -> String {
    ["gh", "p_", "0123456789abcdefghijklmnopqrstuvwxyz"].concat()
}

fn write_turn(vault: &Vault, id: &EntityId, text: &str) -> Result<()> {
    vault
        .batch()
        .put(
            id,
            ENTITY_TYPE_TURN,
            TimeRange { start: 1, end: 1 },
            1,
            text.as_bytes(),
        )
        .text(id, &[("body", text)])
        .commit()
}

#[test]
fn switch_off_stores_a_real_shaped_token_and_switch_on_rejects_it() -> TestResult {
    let (_dir, vault, owner) = open()?;
    let turn = format!("user: my deploy token is {} for now", token_shaped());
    assert_eq!(vault.secret_scan_mode()?, SecretScanMode::On);

    let refused = EntityId::now();
    let error = write_turn(&vault, &refused, &turn).expect_err("on by default");
    crate::test_util::assert_secret_scan_rejected(error, "gate.secret_scan.github_token");
    assert!(vault.get(&refused)?.is_none());

    vault.set_secret_scan_mode(&owner, SecretScanMode::Off, 10)?;
    let stored = EntityId::now();
    write_turn(&vault, &stored, &turn)?;
    assert_eq!(vault.get(&stored)?, Some(turn.as_bytes().to_vec()));
    let hits = vault.search_text("deploy token", 10)?;
    assert!(hits.iter().any(|hit| hit.id == stored));
    // Staged sources follow the batch door.
    crate::batch::secret_scan::scan_staged_payload(&vault.store, turn.as_bytes())?;

    vault.set_secret_scan_mode(&owner, SecretScanMode::On, 11)?;
    let error = write_turn(&vault, &EntityId::now(), &turn).expect_err("on again");
    crate::test_util::assert_secret_scan_rejected(error, "gate.secret_scan.github_token");
    let error = crate::batch::secret_scan::scan_staged_payload(&vault.store, turn.as_bytes())
        .expect_err("staged source scans while on");
    crate::test_util::assert_secret_scan_rejected(error, "gate.secret_scan.github_token");
    // The row stored while off stays; switching on never rewrites history.
    assert!(vault.get(&stored)?.is_some());
    Ok(())
}

#[test]
fn a_non_owner_cannot_flip_the_switch_and_an_owner_flip_writes_a_receipt() -> TestResult {
    let (_dir, vault, owner) = open()?;
    let person = EntityId::from_bytes([0x5a; 16])?;
    vault.put_entity(
        &person,
        ENTITY_TYPE_PERSON,
        TimeRange { start: 1, end: 1 },
        1,
        b"person",
    )?;
    let not_owner =
        vault.authenticate_owner(person, &person.to_hex(), true, GateDecisionId::now())?;
    let error = vault
        .set_secret_scan_mode(&not_owner, SecretScanMode::Off, 10)
        .expect_err("a live person who is not the owner");
    assert!(matches!(
        error,
        Error::Gate(GateError::ConsentOwnerNotAuthenticated(_))
    ));
    assert_eq!(vault.secret_scan_mode()?, SecretScanMode::On);
    assert!(vault.secret_scan_change_log()?.is_empty());
    assert!(vault.policy_changed_events()?.is_empty());

    let off = vault.set_secret_scan_mode(&owner, SecretScanMode::Off, 20)?;
    assert_eq!(
        (off.revision, off.previous, off.mode, off.at),
        (1, SecretScanMode::On, SecretScanMode::Off, 20)
    );
    assert_eq!(off.author, owner.actor().to_hex());
    assert_eq!(vault.secret_scan_mode()?, SecretScanMode::Off);
    let on = vault.set_secret_scan_mode(&owner, SecretScanMode::On, 21)?;
    assert_eq!(
        (on.revision, on.previous, on.mode),
        (2, SecretScanMode::Off, SecretScanMode::On)
    );
    assert_eq!(
        vault.secret_scan_change_log()?,
        vec![off.clone(), on.clone()]
    );

    let events = vault.policy_changed_events()?;
    assert_eq!(events.len(), 2);
    for (event, receipt) in events.iter().zip([&off, &on]) {
        assert_eq!(event.kind, "policy.secret_scan.changed");
        assert_eq!(event.receipt_id, receipt.receipt_id);
        assert_eq!(event.author, receipt.author);
        assert_eq!(event.scope, Some(PolicyRowScope::Vault));
    }
    // The non-owner is still refused after the owner acted.
    assert!(
        vault
            .set_secret_scan_mode(&not_owner, SecretScanMode::Off, 22)
            .is_err()
    );
    assert_eq!(vault.secret_scan_change_log()?.len(), 2);
    Ok(())
}
