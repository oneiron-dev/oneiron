#![cfg(oneiron_test_support)]
//! Fix list row 17645, slice 3: a drafted reply carries files, each one
//! exact version of an artifact the drafter reads, frozen with the draft.
//!
//! `reply_draft_pins_artifact_version` (a Google mailbox, slice 3a) is red on
//! origin/main: a draft request that names a file is refused (the request
//! has no `attachments` field, and `mail_pack/reply.rs` refuses files), so
//! its first check, that the draft lands, fails. On the head the draft
//! lands, and its row names the manifest of the version it pinned.
//! `graph_reply_draft_pins_artifact_version` (a Microsoft 365 mailbox, slice
//! 3b) is red on slice 3a, which refuses files from any mailbox but a
//! Google one. `imap_reply_with_files_waits_for_the_size_check_runner`
//! (an IMAP mailbox, slice 3c) is red on slice 3b, which refuses files from
//! an IMAP mailbox outright, without asking its submission server.

use std::sync::Arc;

use oneiron::authority::{HostSlipIssuer, MachineRole};
use oneiron::test_doors::reply_attachments as doors;
use oneiron::{Vault, VaultConfig};

type TestResult = Result<(), Box<dyn std::error::Error>>;

/// The artifact's two versions: the reply pins the first, while the
/// second is the head.
const FIRST_VERSION: &[u8] = b"Quarterly report, first draft.\n";
const SECOND_VERSION: &[u8] = b"Quarterly report, second draft.\n";

/// A vault as a self-hosted server starts it: owned, with the process
/// keystore, rooted under the host and this install profiled.
fn open_vault(path: &std::path::Path) -> Result<Vault, Box<dyn std::error::Error>> {
    let vault = Vault::open_owned(path, VaultConfig::default())?;
    let _owner = vault.ensure_embedded_owner_actor()?;
    let issuer = HostSlipIssuer::from_secret(b"reply attachments test host")?;
    vault.install_device_keystore(Arc::new(oneiron_keystore::MemoryKeystore::default()));
    vault.ensure_host_root_slip(&issuer)?;
    vault.ensure_serving_install_profile(&issuer, MachineRole::Unanswered)?;
    Ok(vault)
}

fn now_sec() -> Result<u64, Box<dyn std::error::Error>> {
    Ok(std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_secs())
}

/// Checks that `drafted` is a draft of `artifact`'s version 1 alone, with
/// version 1's stored bytes, its manifest named by the draft's row and the
/// exact message it sends.
fn assert_pins_first_version(
    drafted: Result<doors::DraftedReply, String>,
    artifact: oneiron::EntityId,
) {
    let drafted = match drafted {
        Ok(drafted) => drafted,
        Err(refusal) => {
            panic!("a reply naming one artifact version is drafted, not refused: {refusal}")
        }
    };
    assert!(
        drafted.manifest_digest.is_some(),
        "the draft's row names the manifest of the files it froze"
    );
    let files = &drafted.files;
    assert_eq!(files.len(), 1, "the draft carries the one file it named");
    assert_eq!(files[0].artifact_ref, artifact.to_hex());
    assert_eq!(files[0].version, 1, "the pinned version, never the head");
    assert_eq!(
        files[0].stored_version_blake3,
        blake3::hash(FIRST_VERSION).to_hex().to_string(),
        "the file is version 1's stored bytes"
    );
    assert!(
        drafted.message_octets.is_some() && drafted.message_blake3.is_some(),
        "the draft names the exact message it sends"
    );
}

/// A Gmail reply that names version 1 of an artifact whose head is version
/// 2 lands as a draft that pins version 1: the draft's row names its
/// manifest by digest, and its reader sees the one file at version 1, with
/// version 1's stored bytes, and the exact message it sends.
#[test]
fn reply_draft_pins_artifact_version() -> TestResult {
    let directory = tempfile::tempdir()?;
    let vault = open_vault(directory.path())?;
    let seeded = doors::seed_gmail_thread(&vault, now_sec()?)?;
    let artifact = doors::seed_artifact(&vault, seeded.owner, &[FIRST_VERSION, SECOND_VERSION])?;

    let drafted =
        doors::draft_reply_with_file(&vault, seeded.owner, &seeded.thread_ref, artifact, 1);

    assert_pins_first_version(drafted, artifact);
    Ok(())
}

/// The same reply from a Microsoft 365 mailbox lands the same way: Graph
/// carries files too, and the draft's row names only the manifest's digest.
#[test]
fn graph_reply_draft_pins_artifact_version() -> TestResult {
    let directory = tempfile::tempdir()?;
    let vault = open_vault(directory.path())?;
    let seeded = doors::seed_microsoft_thread(&vault, now_sec()?)?;
    let artifact = doors::seed_artifact(&vault, seeded.owner, &[FIRST_VERSION, SECOND_VERSION])?;

    let drafted =
        doors::draft_reply_with_file(&vault, seeded.owner, &seeded.thread_ref, artifact, 1);

    assert_pins_first_version(drafted, artifact);
    Ok(())
}

/// The same reply from an IMAP mailbox asks the mailbox's submission server
/// the size it takes before any file is read. A test host installs no
/// runner for that blocking check, so the draft is refused by that name:
/// it never lands unchecked, and never on the stored limit alone.
#[test]
fn imap_reply_with_files_waits_for_the_size_check_runner() -> TestResult {
    let directory = tempfile::tempdir()?;
    let vault = open_vault(directory.path())?;
    let seeded = doors::seed_imap_thread(&vault, now_sec()?)?;
    let artifact = doors::seed_artifact(&vault, seeded.owner, &[FIRST_VERSION, SECOND_VERSION])?;

    let drafted =
        doors::draft_reply_with_file(&vault, seeded.owner, &seeded.thread_ref, artifact, 1);

    let Err(refusal) = drafted else {
        panic!("an IMAP reply with files is not drafted before its size check runs");
    };
    assert!(
        refusal.contains("mail_blocking_runner_missing"),
        "the refusal names the missing size check runner: {refusal}"
    );
    Ok(())
}
