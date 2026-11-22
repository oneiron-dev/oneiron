//! FIX [NOTE-PROPOSAL-FORK-RULING-KEEPS-HANDLE] (Engine RULING 14 Nov 14:55,
//! NEXT-ROW-22 C): a NOTE proposal fork's text is admitted under the fork
//! head's id, so a key the mask lifts out of it names the head, which is no
//! entity. The owner's "not a secret" answer puts the value back into the
//! pending fork; a land after it carries the value into the NOTE, by merge
//! or by switch; and an answer after a land puts it back into the NOTE. An
//! answer on the NOTE's own key reaches a pending fork that keeps its handle
//! too: a merge fork still merges (REVIEW-7904 F1), and a declared rewrite
//! switches in with the value (REVIEW-7904 F2).
//!
//! A merge the write gate holds moves none of the fork's keys to the NOTE,
//! so no key of text that never landed names the NOTE (REVIEW-9471 F2). A
//! handle a merge fork wrote on its own, of a key the owner ruled, lands as
//! the value (REVIEW-9471 F3).
//!
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron --all-features --test found_key_note_fork_restore`.

use std::sync::Arc;

use oneiron::authority::{ActSurface, HostSlipIssuer, MachineRole};
use oneiron::consent::AuthenticatedOwner;
use oneiron::note::{NoteForkReadRequest, NoteProgramEdit, NoteSpanResolution, NoteVerdict};
use oneiron::store::GateDecisionId;
use oneiron::{
    ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus, ClaimSource, ClaimSubject,
    EdgeActorClass, EntityId, TimeRange, Vault, VaultConfig, WriteActor,
};

type TestResult = Result<(), Box<dyn std::error::Error>>;

/// A GitHub token the door's text rules place by its span.
const TOKEN: &str = "ghp_0123456789abcdefghijklmnopqrstuvwxyz";

/// A second GitHub token, which a fork adds to a NOTE that holds the first.
const SECOND_TOKEN: &str = "ghp_zyxwvutsrqponmlkjihgfedcba9876543210";

/// How a found key's handle opens where the mask left it in a text.
const HANDLE_OPEN: &str = "[secret ";

/// The NOTE's text before any fork: no key in it.
const WRITTEN: &str = "Release notes.";

/// A vault with a device keystore, its embedded owner and this install's
/// live machine profile, so a ruling carries its revoke to the owner's
/// other machines (the `found_key_note_restore.rs` fixture).
fn open_vault() -> Result<(tempfile::TempDir, Vault, EntityId), Box<dyn std::error::Error>> {
    let dir = tempfile::tempdir()?;
    let vault = Vault::open(dir.path(), VaultConfig::default())?;
    vault.install_device_keystore(Arc::new(oneiron_keystore::MemoryKeystore::default()));
    let owner = vault.ensure_embedded_owner_actor()?;
    let issuer = HostSlipIssuer::from_secret(b"found key note fork restore host")?;
    vault.ensure_host_root_slip(&issuer)?;
    vault.ensure_serving_install_profile(&issuer, MachineRole::Unanswered)?;
    Ok((dir, vault, owner))
}

/// The owner's proof.
fn proof_of(
    vault: &Vault,
    owner: EntityId,
) -> Result<AuthenticatedOwner, Box<dyn std::error::Error>> {
    Ok(vault.authenticate_owner(owner, &owner.to_hex(), true, GateDecisionId::now())?)
}

fn as_owner(owner: EntityId) -> WriteActor {
    WriteActor::new(owner, EdgeActorClass::Human)
}

/// A NOTE the owner writes with no key in it, and the owner's pending fork
/// of it whose whole text adds the token: a merge fork, or a declared
/// rewrite, which only a switch lands.
fn note_and_fork(
    vault: &Vault,
    owner: EntityId,
    rewrite: bool,
) -> Result<(EntityId, EntityId), Box<dyn std::error::Error>> {
    let note = vault
        .create_note("research", WRITTEN, as_owner(owner))
        .map_err(|error| format!("FIXTURE: the NOTE is written: {error:?}"))?;
    let text = format!("{WRITTEN} Deploy with token={TOKEN}.");
    let edit = if rewrite {
        NoteProgramEdit::Rewrite { text }
    } else {
        let base = vault
            .note_program_document(note)?
            .ok_or("FIXTURE: the NOTE has a document")?
            .version();
        NoteProgramEdit::WholeText {
            text,
            timeout_ms: 1_000,
            base: Some(base),
        }
    };
    let fork = vault
        .fork_note(note, &edit, as_owner(owner))
        .map_err(|error| format!("FIXTURE: the fork is opened: {error:?}"))?;
    Ok((note, fork))
}

/// A NOTE the owner writes with the token in it, whose key names the NOTE,
/// and its markdown, which holds the key's handle.
fn note_with_token(
    vault: &Vault,
    owner: EntityId,
) -> Result<(EntityId, String), Box<dyn std::error::Error>> {
    let note = vault
        .create_note(
            "research",
            &format!("{WRITTEN} Deploy with token={TOKEN}."),
            as_owner(owner),
        )
        .map_err(|error| format!("FIXTURE: the NOTE is written: {error:?}"))?;
    let [live, _] = markdown_reads(vault, note)?;
    assert!(
        handled(&live),
        "FIXTURE: the NOTE holds the key's handle: {live}"
    );
    Ok((note, live))
}

/// The handle of the key the mask lifted out of `record`, from the owner's
/// found-key list.
fn found_handle(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    record: &EntityId,
) -> Result<String, Box<dyn std::error::Error>> {
    Ok(vault
        .found_keys(owner, true, 10)?
        .into_iter()
        .find(|notice| notice.record == *record)
        .and_then(|notice| notice.keys.into_iter().next())
        .map(|key| key.handle)
        .ok_or("FIXTURE: the mask lifted the token into a found key")?)
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

/// The NOTE's markdown as `Vault::read_note` and `Vault::note_document`
/// serve it: both read its document.
fn markdown_reads(
    vault: &Vault,
    note: EntityId,
) -> Result<[String; 2], Box<dyn std::error::Error>> {
    let read = vault
        .read_note(&note)?
        .ok_or("FIXTURE: the NOTE reads")?
        .markdown;
    Ok([read, vault.note_document(note)?.markdown])
}

/// Whether `text` holds a key's handle where the token was written.
fn handled(text: &str) -> bool {
    text.contains(HANDLE_OPEN) && !text.contains(TOKEN)
}

/// Whether `text` holds the token itself and no handle.
fn valued(text: &str) -> bool {
    text.contains(TOKEN) && !text.contains(HANDLE_OPEN)
}

/// The owner opens a proposal of `fork` and lands it: a merge fork lands at
/// once (the owner holds the grant), a rewrite by the owner's switch.
fn land(
    vault: &Vault,
    owner: EntityId,
    fork: EntityId,
    rewrite: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut bundle = vault
        .open_note_proposal(&[fork], "deploy notes", as_owner(owner))
        .map_err(|error| format!("FIXTURE: the proposal opens: {error:?}"))?;
    if rewrite {
        assert!(
            bundle.landed.is_empty(),
            "FIXTURE: a declared rewrite waits for a switch"
        );
        bundle = vault
            .review_note_proposal(bundle.id, NoteVerdict::Switch, as_owner(owner))
            .map_err(|error| format!("FIXTURE: the switch lands: {error:?}"))?;
    }
    assert_eq!(bundle.landed.len(), 1, "FIXTURE: the fork lands");
    Ok(())
}

#[test]
fn a_pending_fork_ruled_not_a_secret_reads_back_with_its_value() -> TestResult {
    let (_dir, vault, owner) = open_vault()?;
    let proof = proof_of(&vault, owner)?;
    let (note, fork) = note_and_fork(&vault, owner, false)?;
    let before = fork_markdown(&vault, owner, note, fork)?;
    assert!(
        handled(&before),
        "FIXTURE: the fork holds the key's handle: {before}"
    );
    let handle = found_handle(&vault, &proof, &fork)?;
    vault.rule_found_key_not_a_secret(&proof, ActSurface::ThisInstall, &handle)?;
    let after = fork_markdown(&vault, owner, note, fork)?;
    assert!(valued(&after), "the pending fork reads the value: {after}");
    for markdown in markdown_reads(&vault, note)? {
        assert!(
            !markdown.contains("token="),
            "the NOTE itself is not edited: {markdown}"
        );
    }
    Ok(())
}

#[test]
fn a_fork_ruled_then_merged_lands_its_value_in_the_note() -> TestResult {
    let (_dir, vault, owner) = open_vault()?;
    let proof = proof_of(&vault, owner)?;
    let (note, fork) = note_and_fork(&vault, owner, false)?;
    let handle = found_handle(&vault, &proof, &fork)?;
    vault.rule_found_key_not_a_secret(&proof, ActSurface::ThisInstall, &handle)?;
    land(&vault, owner, fork, false)?;
    for markdown in markdown_reads(&vault, note)? {
        assert!(
            valued(&markdown),
            "the merged NOTE reads the value: {markdown}"
        );
    }
    Ok(())
}

#[test]
fn a_fork_merged_then_ruled_puts_the_value_back_in_the_note() -> TestResult {
    let (_dir, vault, owner) = open_vault()?;
    let proof = proof_of(&vault, owner)?;
    let (note, fork) = note_and_fork(&vault, owner, false)?;
    let handle = found_handle(&vault, &proof, &fork)?;
    land(&vault, owner, fork, false)?;
    for markdown in markdown_reads(&vault, note)? {
        assert!(
            handled(&markdown),
            "FIXTURE: the merged NOTE holds the handle: {markdown}"
        );
    }
    vault.rule_found_key_not_a_secret(&proof, ActSurface::ThisInstall, &handle)?;
    for markdown in markdown_reads(&vault, note)? {
        assert!(
            valued(&markdown),
            "the answer after the land reaches the NOTE: {markdown}"
        );
    }
    Ok(())
}

#[test]
fn a_rewrite_fork_ruled_then_switched_lands_its_value_in_the_note() -> TestResult {
    let (_dir, vault, owner) = open_vault()?;
    let proof = proof_of(&vault, owner)?;
    let (note, fork) = note_and_fork(&vault, owner, true)?;
    let handle = found_handle(&vault, &proof, &fork)?;
    vault.rule_found_key_not_a_secret(&proof, ActSurface::ThisInstall, &handle)?;
    land(&vault, owner, fork, true)?;
    for markdown in markdown_reads(&vault, note)? {
        assert!(
            valued(&markdown),
            "the switched NOTE reads the value: {markdown}"
        );
    }
    Ok(())
}

#[test]
fn a_ruling_on_the_notes_own_key_lets_a_fork_that_keeps_its_handle_merge() -> TestResult {
    let (_dir, vault, owner) = open_vault()?;
    let proof = proof_of(&vault, owner)?;
    let (note, live) = note_with_token(&vault, owner)?;
    let handle = found_handle(&vault, &proof, &note)?;
    let base = vault
        .note_program_document(note)?
        .ok_or("FIXTURE: the NOTE has a document")?
        .version();
    let edit = NoteProgramEdit::WholeText {
        text: format!("{live} Rotate with token={SECOND_TOKEN}."),
        timeout_ms: 1_000,
        base: Some(base),
    };
    let fork = vault
        .fork_note(note, &edit, as_owner(owner))
        .map_err(|error| format!("FIXTURE: the fork is opened: {error:?}"))?;
    vault.rule_found_key_not_a_secret(&proof, ActSurface::ThisInstall, &handle)?;
    let pending = fork_markdown(&vault, owner, note, fork)?;
    assert!(
        pending.contains(TOKEN) && !pending.contains(&handle),
        "the pending fork reads the NOTE's ruled value: {pending}"
    );
    let bundle = vault
        .open_note_proposal(&[fork], "rotation notes", as_owner(owner))
        .map_err(|error| format!("the fork merges after the ruling: {error:?}"))?;
    assert_eq!(bundle.landed.len(), 1, "the fork merges after the ruling");
    for markdown in markdown_reads(&vault, note)? {
        assert!(
            markdown.contains(TOKEN) && !markdown.contains(&handle),
            "the merged NOTE reads the ruled value: {markdown}"
        );
        assert!(
            markdown.contains(HANDLE_OPEN) && !markdown.contains(SECOND_TOKEN),
            "the fork's own key keeps its handle: {markdown}"
        );
    }
    Ok(())
}

#[test]
fn a_ruling_on_the_notes_own_key_reaches_a_rewrite_that_keeps_its_handle() -> TestResult {
    let (_dir, vault, owner) = open_vault()?;
    let proof = proof_of(&vault, owner)?;
    let (note, live) = note_with_token(&vault, owner)?;
    let handle = found_handle(&vault, &proof, &note)?;
    let edit = NoteProgramEdit::Rewrite {
        text: format!("{live} Ship it."),
    };
    let fork = vault
        .fork_note(note, &edit, as_owner(owner))
        .map_err(|error| format!("FIXTURE: the rewrite is opened: {error:?}"))?;
    vault.rule_found_key_not_a_secret(&proof, ActSurface::ThisInstall, &handle)?;
    let pending = fork_markdown(&vault, owner, note, fork)?;
    assert!(
        valued(&pending),
        "the pending rewrite reads the value: {pending}"
    );
    land(&vault, owner, fork, true)?;
    for markdown in markdown_reads(&vault, note)? {
        assert!(
            valued(&markdown) && markdown.contains("Ship it."),
            "the switched NOTE reads the value: {markdown}"
        );
    }
    Ok(())
}

/// A Proposed CLAIM about `subject` for a citation to name: a pin's target
/// is a CLAIM, and a Proposed one passes the gate on a raw put.
fn citable_claim(vault: &Vault, subject: EntityId) -> Result<EntityId, Box<dyn std::error::Error>> {
    let claim = EntityId::now();
    let mut body = ClaimBody::new(
        "profile.note",
        ClaimSubject::Entity(subject),
        rmpv::Value::from("the release notes name the deploy step"),
        1.0,
        ClaimApprovalStatus::Proposed,
        ClaimLifecycleStatus::Active,
    )?;
    body.source = Some(ClaimSource::UserStated);
    vault.put_claim(&claim, &body, TimeRange { start: 1, end: 1 }, 1)?;
    Ok(claim)
}

/// A NOTE of `owner`'s that cites the span `quote` is in `note`'s markdown.
fn cite_in_another_note(vault: &Vault, owner: EntityId, note: EntityId, quote: &str) -> TestResult {
    let markdown = vault.note_document(note)?.markdown;
    let at = markdown
        .find(quote)
        .ok_or("FIXTURE: the quote stands in the NOTE")?;
    let start = markdown[..at].chars().count();
    let claim = citable_claim(vault, owner)?;
    let pin = vault.pin_note_span(note, claim, start, start + quote.chars().count())?;
    let citing = vault
        .create_note(
            "research",
            "Deploy steps, cited from the release notes.",
            as_owner(owner),
        )
        .map_err(|error| format!("FIXTURE: the citing NOTE is written: {error:?}"))?;
    vault
        .memory(owner, EdgeActorClass::Human)
        .cite_note_span(citing, &pin)?;
    assert!(
        matches!(
            vault.resolve_note_pin(&pin)?,
            NoteSpanResolution::Mapped { .. }
        ),
        "FIXTURE: the citation maps its span"
    );
    Ok(())
}

#[test]
fn a_merge_the_gate_holds_moves_none_of_the_forks_keys_to_the_note() -> TestResult {
    let (_dir, vault, owner) = open_vault()?;
    let proof = proof_of(&vault, owner)?;
    let note = vault
        .create_note("research", WRITTEN, as_owner(owner))
        .map_err(|error| format!("FIXTURE: the NOTE is written: {error:?}"))?;
    cite_in_another_note(&vault, owner, note, "Release notes")?;
    let base = vault
        .note_program_document(note)?
        .ok_or("FIXTURE: the NOTE has a document")?
        .version();
    let edit = NoteProgramEdit::WholeText {
        text: format!("Release memo. Deploy with token={TOKEN}."),
        timeout_ms: 1_000,
        base: Some(base),
    };
    let fork = vault
        .fork_note(note, &edit, as_owner(owner))
        .map_err(|error| format!("FIXTURE: the fork is opened: {error:?}"))?;
    let handle = found_handle(&vault, &proof, &fork)?;

    let bundle = vault
        .open_note_proposal(&[fork], "deploy notes", as_owner(owner))
        .map_err(|error| format!("FIXTURE: the proposal opens: {error:?}"))?;

    assert!(
        bundle.landed.is_empty() && bundle.waiting.len() == 1,
        "FIXTURE: the write gate holds a merge that edits a cited span"
    );
    for markdown in markdown_reads(&vault, note)? {
        assert_eq!(markdown, WRITTEN, "FIXTURE: the held merge lands no text");
    }
    assert!(
        vault
            .found_keys(&proof, false, 10)?
            .iter()
            .all(|notice| notice.record != note),
        "a held merge moves none of the fork's keys to the NOTE"
    );
    assert_eq!(
        found_handle(&vault, &proof, &fork)?,
        handle,
        "the fork's key stays with the pending fork"
    );
    Ok(())
}

#[test]
fn a_handle_a_merge_fork_wrote_on_its_own_lands_as_the_ruled_value() -> TestResult {
    let (_dir, vault, owner) = open_vault()?;
    let proof = proof_of(&vault, owner)?;
    let (note, live) = note_with_token(&vault, owner)?;
    let handle = found_handle(&vault, &proof, &note)?;
    let base = vault
        .note_program_document(note)?
        .ok_or("FIXTURE: the NOTE has a document")?
        .version();
    let edit = NoteProgramEdit::WholeText {
        text: format!("{live} Fallback: {HANDLE_OPEN}{handle}]."),
        timeout_ms: 1_000,
        base: Some(base),
    };
    let fork = vault
        .fork_note(note, &edit, as_owner(owner))
        .map_err(|error| format!("FIXTURE: the fork is opened: {error:?}"))?;
    vault.rule_found_key_not_a_secret(&proof, ActSurface::ThisInstall, &handle)?;

    land(&vault, owner, fork, false)?;

    for markdown in markdown_reads(&vault, note)? {
        assert!(
            valued(&markdown) && markdown.matches(TOKEN).count() == 2,
            "the handle the fork wrote lands as the ruled value: {markdown}"
        );
    }
    Ok(())
}
