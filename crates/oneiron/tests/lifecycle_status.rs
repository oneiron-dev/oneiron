//! UC-15 (census FD-06): a stored lifecycle status declares its edges and
//! its terminal states once, and a door that takes its caller's target state
//! refuses one the declaration does not allow, leaving the row as it was.
//!
//! Every path is public, so this target needs no cfg flag. It builds on a
//! base without the declarations too, where the refused moves are written
//! and the tests fail on their assertions.

use std::path::Path;

use oneiron::ingest::history::{
    HistorySource, HostedImportId, HostedImportStaged, HostedImportState,
};
use oneiron::store::GateDecisionId;
use oneiron::{Vault, VaultConfig};

type TestResult = Result<(), Box<dyn std::error::Error>>;

/// A process-owned vault at `dir`, as `serve` opens it: this process holds
/// its writer lease, so its embedded owner may import.
fn open_vault(dir: &Path) -> Result<Vault, Box<dyn std::error::Error>> {
    let mut config = VaultConfig::device();
    config.map_size = 64 * 1024 * 1024;
    config.dimensions = 4;
    config.embedding_model = None;
    Ok(Vault::open_owned(dir, config)?)
}

/// A Staged hosted import of an empty export, made by the vault's owner.
fn staged_import(vault: &Vault) -> Result<HostedImportId, Box<dyn std::error::Error>> {
    let owner = vault.ensure_embedded_owner_actor()?;
    let proof = vault.authenticate_owner(owner, &owner.to_hex(), true, GateDecisionId::now())?;
    let id = HostedImportId::generate();
    let row = vault.hosted_import_create(
        &proof,
        id,
        HistorySource::Chatgpt,
        HostedImportStaged {
            bytes: 2,
            blake3: *blake3::hash(b"[]").as_bytes(),
        },
        1_780_000_000,
    )?;
    assert_eq!(row.state, HostedImportState::Staged);
    Ok(id)
}

fn state_of(
    vault: &Vault,
    id: HostedImportId,
) -> Result<HostedImportState, Box<dyn std::error::Error>> {
    Ok(vault
        .hosted_import(id)?
        .ok_or("the hosted import row is gone")?
        .state)
}

/// `hosted_import_end` ends a job: Landed, Failed or Cancelled. A live
/// target is no end, so it is refused and the job stays Staged.
#[test]
fn a_hosted_import_ended_into_a_live_state_is_refused() -> TestResult {
    let dir = tempfile::tempdir()?;
    let vault = open_vault(dir.path())?;
    let id = staged_import(&vault)?;

    let ended = vault.hosted_import_end(id, HostedImportState::Landing, 0);

    assert!(
        ended.is_err(),
        "FAILBEFORE: a Staged job ended as Landing is written: {ended:?}"
    );
    assert_eq!(state_of(&vault, id)?, HostedImportState::Staged);
    Ok(())
}

/// A job ends Cancelled only once a cancel has marked it Cancelling, so a
/// Staged job ended as Cancelled is refused and stays Staged.
#[test]
fn a_staged_hosted_import_ended_as_cancelled_is_refused() -> TestResult {
    let dir = tempfile::tempdir()?;
    let vault = open_vault(dir.path())?;
    let id = staged_import(&vault)?;

    let ended = vault.hosted_import_end(id, HostedImportState::Cancelled, 0);

    assert!(
        ended.is_err(),
        "FAILBEFORE: a Staged job ended as Cancelled is written: {ended:?}"
    );
    assert_eq!(state_of(&vault, id)?, HostedImportState::Staged);
    Ok(())
}

/// Guard: the ends the job's writers take stay allowed. A Staged job with
/// nothing to land ends Landed, and an ended job is left as it is.
#[test]
fn a_staged_hosted_import_ends_landed_and_stays_ended() -> TestResult {
    let dir = tempfile::tempdir()?;
    let vault = open_vault(dir.path())?;
    let id = staged_import(&vault)?;

    let ended = vault.hosted_import_end(id, HostedImportState::Landed, 0)?;
    assert_eq!(ended.map(|row| row.state), Some(HostedImportState::Landed));

    let again = vault.hosted_import_end(id, HostedImportState::Failed("late".into()), 0)?;
    assert_eq!(again.map(|row| row.state), Some(HostedImportState::Landed));
    assert_eq!(state_of(&vault, id)?, HostedImportState::Landed);
    Ok(())
}
