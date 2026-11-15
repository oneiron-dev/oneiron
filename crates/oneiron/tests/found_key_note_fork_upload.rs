//! REVIEW-7904 second commit F2: the owner's "not a secret" answer on a
//! NOTE's own key puts the value back into a pending declared rewrite that
//! keeps its handle, and the rewrite's own operations still edit its text
//! alone and add its own authorship entry alone. An own device sends such a
//! fork to the NOTE's authority, which refuses any other fork for good
//! (`note/fork_upload.rs`), so a ruling on the device before the upload
//! sends must not cost the fork its upload.
//!
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron --all-features --test found_key_note_fork_upload`.

use std::sync::Arc;

use oneiron::authority::{ActSurface, HostSlipIssuer, MachineRole};
use oneiron::note::{NoteForkReadRequest, NoteProgramEdit};
use oneiron::store::GateDecisionId;
use oneiron::test_doors::note_fork_upload::fork_upload_refusal;
use oneiron::{EdgeActorClass, EntityId, Vault, VaultConfig, WriteActor};

type TestResult = Result<(), Box<dyn std::error::Error>>;

/// A GitHub token the door's text rules place by its span.
const TOKEN: &str = "ghp_0123456789abcdefghijklmnopqrstuvwxyz";

/// How a found key's handle opens where the mask left it in a text.
const HANDLE_OPEN: &str = "[secret ";

/// A vault with a device keystore, its embedded owner and this install's
/// live machine profile (the `found_key_note_fork_restore.rs` fixture).
fn open_vault() -> Result<(tempfile::TempDir, Vault, EntityId), Box<dyn std::error::Error>> {
    let dir = tempfile::tempdir()?;
    let vault = Vault::open(dir.path(), VaultConfig::default())?;
    vault.install_device_keystore(Arc::new(oneiron_keystore::MemoryKeystore::default()));
    let owner = vault.ensure_embedded_owner_actor()?;
    let issuer = HostSlipIssuer::from_secret(b"found key note fork upload host")?;
    vault.ensure_host_root_slip(&issuer)?;
    vault.ensure_serving_install_profile(&issuer, MachineRole::Unanswered)?;
    Ok((dir, vault, owner))
}

fn as_owner(owner: EntityId) -> WriteActor {
    WriteActor::new(owner, EdgeActorClass::Human)
}

/// The pending fork's markdown as the owner reads it.
fn fork_markdown(
    vault: &Vault,
    owner: EntityId,
    note: EntityId,
    fork: EntityId,
) -> Result<String, Box<dyn std::error::Error>> {
    Ok(vault
        .memory(owner, EdgeActorClass::Human)
        .read_note_fork(&NoteForkReadRequest {
            note_ref: note.to_hex(),
            fork_ref: fork.to_hex(),
            reason: None,
        })
        .map_err(|error| format!("FIXTURE: the fork reads: {error:?}"))?
        .value
        .and_then(|view| view.markdown)
        .ok_or("FIXTURE: the pending fork has a text")?)
}

#[test]
fn a_ruling_on_the_notes_own_key_keeps_a_rewrite_uploadable() -> TestResult {
    let (_dir, vault, owner) = open_vault()?;
    let proof = vault.authenticate_owner(owner, &owner.to_hex(), true, GateDecisionId::now())?;
    let note = vault
        .create_note(
            "research",
            &format!("Release notes. Deploy with token={TOKEN}."),
            as_owner(owner),
        )
        .map_err(|error| format!("FIXTURE: the NOTE is written: {error:?}"))?;
    let live = vault
        .read_note(&note)?
        .ok_or("FIXTURE: the NOTE reads")?
        .markdown;
    assert!(
        live.contains(HANDLE_OPEN) && !live.contains(TOKEN),
        "FIXTURE: the NOTE holds the key's handle: {live}"
    );
    let handle = vault
        .found_keys(&proof, true, 10)?
        .into_iter()
        .find(|notice| notice.record == note)
        .and_then(|notice| notice.keys.into_iter().next())
        .map(|key| key.handle)
        .ok_or("FIXTURE: the mask lifted the token into a found key")?;
    let edit = NoteProgramEdit::Rewrite {
        text: format!("{live} Ship it."),
    };
    let fork = vault
        .fork_note(note, &edit, as_owner(owner))
        .map_err(|error| format!("FIXTURE: the rewrite is opened: {error:?}"))?;
    assert_eq!(
        fork_upload_refusal(&vault, note, fork)?,
        None,
        "FIXTURE: the rewrite as opened makes an upload its authority admits"
    );
    vault.rule_found_key_not_a_secret(&proof, ActSurface::ThisInstall, &handle)?;
    let pending = fork_markdown(&vault, owner, note, fork)?;
    assert!(
        pending.contains(TOKEN) && !pending.contains(HANDLE_OPEN),
        "the pending rewrite reads the value: {pending}"
    );
    assert_eq!(
        fork_upload_refusal(&vault, note, fork)?,
        None,
        "the restored rewrite still edits its text alone and adds its own authorship entry alone"
    );
    Ok(())
}
