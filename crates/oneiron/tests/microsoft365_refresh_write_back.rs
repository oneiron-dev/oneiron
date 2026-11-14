//! The engine stores Microsoft's newer refresh token in place of the grant a
//! credential door read ([MICROSOFT365-OAUTH-EXCHANGE] B; RULING
//! MICROSOFT365-REFRESH-WRITEBACK, 14 Nov 07:00). The record keeps its name
//! and bindings and moves to the next generation; the door reads the newer
//! grant and never the old one; the receipt's cause is `provider_refresh`.
//! Nothing is written for a record the owner revoked or rotated since the
//! door read it, or for a portable record, and at most one write-back lands
//! per day. A pack setup check that held for the grant the door read still
//! holds for the newer one, and shows the newer grant's issued-at (RULING
//! MICROSOFT365-WRITEBACK-CHECK-STALE, 14 Nov 07:34); a check that no longer
//! held stays stale.
//!
//! Fleet: `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron --all-features --test microsoft365_refresh_write_back`

use std::sync::Arc;

use oneiron::authority::ActSurface;
use oneiron::connector_key::{
    MICROSOFT365_ME_CHECK, PackConnectionCheck, PackConnectionEvidence, PackConnectionVerifier,
};
use oneiron::consent::AuthenticatedOwner;
use oneiron::secret_custody::{
    CustodyClass, CustodyTier, OwnerSecretRegistration, RequestedBinding,
};
use oneiron::secret_lease::DoorInjectionReceipt;
use oneiron::secret_rotation::{RotationCause, RotationKind};
use oneiron::skill_hub::pack_catalog::{
    PackInstallStatus, PackSetupAnswer, PackSetupAuth, PackSetupCheck, PackSetupConnectionState,
    PackSetupView,
};
use oneiron::store::GateDecisionId;
use oneiron::test_doors::microsoft_token::store_refreshed_grant;
use oneiron::{Vault, VaultConfig};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

const GRANT_NAME: &str = "microsoft365.oauth";
const GRANT_EFFECTOR: &str = "connector:microsoft365";
/// When the owner's exchange stored the grant.
const STORED_AT: u64 = 1_800_000_000;
const DAY_SECS: u64 = 24 * 60 * 60;
const STORED_GRANT: &[u8] = br#"{"access_token":"at-1","refresh_token":"rt-1","client_id":"client-1","tenant":"organizations"}"#;
const SUCCESSOR_GRANT: &[u8] = br#"{"access_token":"at-2","refresh_token":"rt-2","client_id":"client-1","tenant":"organizations"}"#;
const LATER_GRANT: &[u8] = br#"{"access_token":"at-3","refresh_token":"rt-3","client_id":"client-1","tenant":"organizations"}"#;
const PACK: &str = "oneiron.microsoft365";
const CONNECTION: &str = "microsoft365";
const EXCEL_WRITE: &str = "excel.write";
const FILES_READ_WRITE: &str = "https://graph.microsoft.com/Files.ReadWrite";
const ACCOUNT: &str = "owen@example.com";

struct WriteBackFixture {
    vault: Vault,
    owner: AuthenticatedOwner,
    _dir: tempfile::TempDir,
}

/// A vault whose owner stored the Microsoft grant as the exchange does:
/// bound with read to the Microsoft 365 connector, the door rung, no
/// manifest; of `class`, with the "this device only" dial `device_only`.
fn write_back_fixture(class: CustodyClass, device_only: bool) -> TestResult<WriteBackFixture> {
    let dir = tempfile::tempdir()?;
    let vault = Vault::open(dir.path(), VaultConfig::device())?;
    vault.install_device_keystore(Arc::new(oneiron_keystore::MemoryKeystore::new()));
    vault.prepare_install_signing()?;
    let actor = vault.ensure_embedded_owner_actor()?;
    let owner = vault.authenticate_owner(actor, &actor.to_hex(), true, GateDecisionId::now())?;
    vault.register_secret_as_owner(
        &owner,
        &OwnerSecretRegistration {
            name: GRANT_NAME,
            class,
            device_only,
            rung: CustodyTier::T0Doored,
            bindings: vec![RequestedBinding {
                effector: GRANT_EFFECTOR.to_owned(),
                tier_ceiling: None,
                scopes: vec!["read".to_owned()],
            }],
            manifest: None,
            value: STORED_GRANT,
        },
        STORED_AT,
    )?;
    Ok(WriteBackFixture {
        vault,
        owner,
        _dir: dir,
    })
}

/// What the connector's door reads now, and the door's receipt.
fn door_read(vault: &Vault) -> TestResult<(Vec<u8>, DoorInjectionReceipt)> {
    let mut read = Vec::new();
    let door = vault.inject_secret_at_door(GRANT_NAME, GRANT_EFFECTOR, &mut |value: &[u8]| {
        read = value.to_vec();
        Ok(())
    })?;
    Ok((read, door))
}

#[test]
fn a_device_record_takes_the_newer_grant_with_a_provider_refresh_receipt() -> TestResult {
    let fixture = write_back_fixture(CustodyClass::CustodyDeviceBound, true)?;
    let (read, door) = door_read(&fixture.vault)?;
    assert_eq!(read, STORED_GRANT);
    let at = STORED_AT + DAY_SECS + 1;
    let receipt = store_refreshed_grant(&fixture.vault, &door, SUCCESSOR_GRANT, at)?
        .ok_or("the write-back lands for the record the door read")?;
    assert_eq!(receipt.secret_ref, GRANT_NAME);
    assert_eq!(receipt.from_generation, door.value_generation);
    assert_eq!(receipt.to_generation, door.value_generation + 1);
    assert_eq!(receipt.rotated_at, at);
    assert_eq!(receipt.kind, RotationKind::Rotated);
    assert_eq!(receipt.cause, RotationCause::ProviderRefresh);
    // The receipt row reads back with its cause.
    assert_eq!(
        fixture.vault.rotation_receipt(&receipt.receipt_id)?,
        Some(receipt.clone())
    );
    // The door reads the newer grant at the next generation; the old one is
    // gone from the record.
    let (read, after) = door_read(&fixture.vault)?;
    assert_eq!(read, SUCCESSOR_GRANT);
    assert_eq!(after.value_generation, receipt.to_generation);
    // The door that read the old generation writes nothing more.
    assert_eq!(
        store_refreshed_grant(&fixture.vault, &door, LATER_GRANT, at + DAY_SECS + 1)?,
        None
    );
    assert_eq!(door_read(&fixture.vault)?.0, SUCCESSOR_GRANT);
    Ok(())
}

#[test]
fn at_most_one_write_back_lands_a_day() -> TestResult {
    let fixture = write_back_fixture(CustodyClass::CustodyDeviceBound, true)?;
    let (_, door) = door_read(&fixture.vault)?;
    // The exchange stored the grant within the day: nothing is written.
    assert_eq!(
        store_refreshed_grant(&fixture.vault, &door, SUCCESSOR_GRANT, STORED_AT + 60)?,
        None
    );
    assert_eq!(door_read(&fixture.vault)?.0, STORED_GRANT);
    let landed = STORED_AT + DAY_SECS;
    assert!(store_refreshed_grant(&fixture.vault, &door, SUCCESSOR_GRANT, landed)?.is_some());
    let (_, door) = door_read(&fixture.vault)?;
    assert_eq!(
        store_refreshed_grant(&fixture.vault, &door, LATER_GRANT, landed + DAY_SECS - 1)?,
        None
    );
    assert!(
        store_refreshed_grant(&fixture.vault, &door, LATER_GRANT, landed + DAY_SECS)?.is_some()
    );
    assert_eq!(door_read(&fixture.vault)?.0, LATER_GRANT);
    Ok(())
}

#[test]
fn a_revoked_or_owner_rotated_record_takes_no_write_back() -> TestResult {
    // Past the day since either owner act, so only the act refuses.
    let at = STORED_AT + 2 * DAY_SECS;
    // The owner rotated the grant after the door read it.
    let fixture = write_back_fixture(CustodyClass::CustodyDeviceBound, true)?;
    let (_, door) = door_read(&fixture.vault)?;
    fixture.vault.rotate_secret_as_owner(
        &fixture.owner,
        GRANT_NAME,
        LATER_GRANT,
        STORED_AT + 10,
    )?;
    assert_eq!(
        store_refreshed_grant(&fixture.vault, &door, SUCCESSOR_GRANT, at)?,
        None
    );
    assert_eq!(door_read(&fixture.vault)?.0, LATER_GRANT);
    // The owner revoked the grant after the door read it.
    let fixture = write_back_fixture(CustodyClass::CustodyDeviceBound, true)?;
    let (_, door) = door_read(&fixture.vault)?;
    fixture.vault.revoke_secret_as_owner(
        &fixture.owner,
        ActSurface::ThisInstall,
        GRANT_NAME,
        STORED_AT + 10,
    )?;
    assert_eq!(
        store_refreshed_grant(&fixture.vault, &door, SUCCESSOR_GRANT, at)?,
        None
    );
    assert!(
        door_read(&fixture.vault).is_err(),
        "a revoked grant opens no door"
    );
    Ok(())
}

#[test]
fn a_portable_record_takes_no_write_back() -> TestResult {
    let fixture = write_back_fixture(CustodyClass::CustodyPortable, false)?;
    let (_, door) = door_read(&fixture.vault)?;
    assert_eq!(
        store_refreshed_grant(
            &fixture.vault,
            &door,
            SUCCESSOR_GRANT,
            STORED_AT + DAY_SECS + 1
        )?,
        None
    );
    assert_eq!(door_read(&fixture.vault)?.0, STORED_GRANT);
    Ok(())
}

/// The `microsoft365.me` check, offline: the provider boundary of the pack's
/// setup. Custody, grants and qualification still run through the engine's
/// own doors. The account and the evidence are synthetic.
struct FixtureMicrosoft365Me;

impl PackConnectionVerifier for FixtureMicrosoft365Me {
    fn verify(
        &self,
        _vault: &Vault,
        check: &PackConnectionCheck<'_>,
    ) -> Result<PackConnectionEvidence, String> {
        assert_eq!(check.pack, PACK);
        assert_eq!(check.connection, CONNECTION);
        assert_eq!(check.check, MICROSOFT365_ME_CHECK);
        assert_eq!(check.auth, PackSetupAuth::Oauth);
        assert_eq!(
            check.allowed_scopes,
            [FILES_READ_WRITE.to_owned()].as_slice()
        );
        Ok(PackConnectionEvidence {
            account: ACCOUNT.to_owned(),
            provider_account: Some("fixture-graph-user".to_owned()),
            scopes: vec![FILES_READ_WRITE.to_owned()],
            evidence: "fixture-microsoft365-me".to_owned(),
        })
    }
}

fn connection(view: &PackSetupView) -> TestResult<&PackSetupConnectionState> {
    view.connections
        .iter()
        .find(|state| state.id == CONNECTION)
        .ok_or_else(|| "the Microsoft 365 connection is missing from the setup view".into())
}

fn grant_issued_at(state: &PackSetupConnectionState) -> Option<u64> {
    state
        .secrets
        .iter()
        .find(|secret| secret.name == GRANT_NAME)
        .and_then(|secret| secret.issued_at)
}

/// The owner sets up the Microsoft 365 pack over the stored grant: Excel
/// allowed and the connection checked, so the built-in turns Active. Returns
/// the setup's content hash.
fn checked_setup(fixture: &WriteBackFixture) -> TestResult<String> {
    let setup = fixture
        .vault
        .prepare_pack_setup(&fixture.owner, PACK, None)?;
    assert_eq!(setup.status, PackInstallStatus::Candidate);
    fixture.vault.answer_pack_setup(
        &fixture.owner,
        PACK,
        Some(&setup.content_hash),
        &PackSetupAnswer::Allow {
            connection: CONNECTION.to_owned(),
            permissions: vec![EXCEL_WRITE.to_owned()],
        },
    )?;
    let checked = fixture.vault.verify_pack_connection(
        &fixture.owner,
        PACK,
        Some(&setup.content_hash),
        CONNECTION,
        &FixtureMicrosoft365Me,
    )?;
    assert!(checked.ready);
    assert_eq!(checked.status, PackInstallStatus::Active);
    let state = connection(&checked)?;
    assert!(
        matches!(state.check, PackSetupCheck::Verified { .. }),
        "the fixture check verifies: {:?}",
        state.check
    );
    assert_eq!(grant_issued_at(state), Some(STORED_AT));
    Ok(setup.content_hash)
}

#[test]
fn a_checked_setup_stays_verified_across_a_write_back() -> TestResult {
    let fixture = write_back_fixture(CustodyClass::CustodyDeviceBound, true)?;
    let content_hash = checked_setup(&fixture)?;
    let (_, door) = door_read(&fixture.vault)?;
    let at = STORED_AT + DAY_SECS + 1;
    let receipt = store_refreshed_grant(&fixture.vault, &door, SUCCESSOR_GRANT, at)?
        .ok_or("the write-back lands for the record the door read")?;
    assert_eq!(receipt.cause, RotationCause::ProviderRefresh);
    let after = fixture
        .vault
        .pack_setup(&fixture.owner, PACK, Some(&content_hash))?;
    let state = connection(&after)?;
    match &state.check {
        PackSetupCheck::Verified { account, .. } => assert_eq!(account, ACCOUNT),
        other => return Err(format!("the write-back staled the check: {other:?}").into()),
    }
    assert!(state.ready);
    assert!(after.ready);
    assert_eq!(after.status, PackInstallStatus::Active);
    // The setup view shows the newer grant's age.
    assert_eq!(grant_issued_at(state), Some(at));
    Ok(())
}

#[test]
fn a_check_the_owner_staled_stays_stale_after_a_write_back() -> TestResult {
    let fixture = write_back_fixture(CustodyClass::CustodyDeviceBound, true)?;
    let content_hash = checked_setup(&fixture)?;
    // The owner rotates the grant after the check: the check no longer holds.
    let rotated_at = STORED_AT + 10;
    fixture
        .vault
        .rotate_secret_as_owner(&fixture.owner, GRANT_NAME, LATER_GRANT, rotated_at)?;
    let stale = fixture
        .vault
        .pack_setup(&fixture.owner, PACK, Some(&content_hash))?;
    assert!(
        matches!(connection(&stale)?.check, PackSetupCheck::Stale { .. }),
        "an owner rotation stales the check: {:?}",
        connection(&stale)?.check
    );
    let (read, door) = door_read(&fixture.vault)?;
    assert_eq!(read, LATER_GRANT);
    let at = rotated_at + DAY_SECS;
    assert!(store_refreshed_grant(&fixture.vault, &door, SUCCESSOR_GRANT, at)?.is_some());
    // The write-back keeps only a check that held; this one stays stale.
    let after = fixture
        .vault
        .pack_setup(&fixture.owner, PACK, Some(&content_hash))?;
    let state = connection(&after)?;
    assert!(
        matches!(state.check, PackSetupCheck::Stale { .. }),
        "a stale check stays stale across a write-back: {:?}",
        state.check
    );
    assert!(!state.ready);
    assert_eq!(grant_issued_at(state), Some(at));
    Ok(())
}
