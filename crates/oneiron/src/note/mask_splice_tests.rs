//! Mask-on-write budgets and stable NOTE pins through the public write doors.

use std::sync::Arc;
use std::time::{Duration, Instant};

use super::{NoteEdit, NoteEditOutcome, NoteForkReadRequest, NoteProgramEdit, NoteSpanResolution};
use crate::authority::{ActSurface, HostSlipIssuer, MachineRole};
use crate::consent::AuthenticatedOwner;
use crate::policy_model::SecretScanMode;
use crate::store::GateDecisionId;
use crate::{
    ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus, ClaimSource, ClaimSubject,
    EdgeActorClass, EntityId, TimeRange, Vault, VaultConfig, WriteActor,
};

type TestResult = Result<(), Box<dyn std::error::Error>>;

// Same provider-token fixture as tests/found_key_note_fork_restore.rs.
const TOKEN: &str = "ghp_0123456789abcdefghijklmnopqrstuvwxyz";
const COPIES: usize = 2_000;
const BUDGET: Duration = Duration::from_secs(60);
const SEED: &str = "Release notes.\n";

// Copy the found-key ruling fixture: revocation needs this install's profile.
fn fixture()
-> Result<(tempfile::TempDir, Vault, EntityId, AuthenticatedOwner), Box<dyn std::error::Error>> {
    let dir = tempfile::tempdir()?;
    let vault = Vault::open(dir.path(), VaultConfig::default())?;
    vault.install_device_keystore(Arc::new(oneiron_keystore::MemoryKeystore::default()));
    let owner = vault.ensure_embedded_owner_actor()?;
    let issuer = HostSlipIssuer::from_secret(b"found key note fork restore host")?;
    vault.ensure_host_root_slip(&issuer)?;
    vault.ensure_serving_install_profile(&issuer, MachineRole::Unanswered)?;
    let proof = vault.authenticate_owner(owner, &owner.to_hex(), true, GateDecisionId::now())?;
    vault.set_secret_scan_mode(&proof, SecretScanMode::On, 10)?;
    Ok((dir, vault, owner, proof))
}

fn repeated_body(value: &str) -> String {
    let mut body = String::new();
    for i in 0..COPIES {
        body.push_str(&format!(
            "gap {i:04}: {}\n{value}\n",
            "ordinary prose stays between the lifted spans. ".repeat(5)
        ));
    }
    assert!(
        body.len() < 1024 * 1024,
        "fixture body must stay under 1 MiB"
    );
    body
}

fn only_handle(
    vault: &Vault,
    proof: &AuthenticatedOwner,
    record: EntityId,
) -> Result<String, Box<dyn std::error::Error>> {
    let notices = vault.found_keys(proof, true, 10)?;
    assert_eq!(
        notices.len(),
        1,
        "one record's one distinct secret was lifted"
    );
    assert_eq!(notices[0].record, record);
    assert_eq!(
        notices[0].keys.len(),
        1,
        "all copies share one custody record"
    );
    Ok(notices[0].keys[0].handle.clone())
}

/// Before the splice this ran the unbounded diff for hours.
#[test]
fn a_large_note_with_many_copies_of_one_secret_is_masked_within_the_budget() -> TestResult {
    let (_dir, vault, owner, proof) = fixture()?;
    let note = vault.create_note(
        "research",
        SEED,
        WriteActor::new(owner, EdgeActorClass::Human),
    )?;
    let before = vault.note_document(note)?;
    let inserted = repeated_body(TOKEN);
    let written = format!("{SEED}{inserted}");
    assert_eq!(written.matches(TOKEN).count(), COPIES);
    assert!(written.len() < 1024 * 1024);

    // Birth admits before creating the document; edit its live body instead.
    // testkit-lint: allow(wall-clock) the elapsed time is the budget under test
    let started = Instant::now();
    let result = vault.memory(owner, EdgeActorClass::Human).apply_note_ops(
        note,
        &before.frontier,
        &[NoteEdit {
            start: SEED.chars().count(),
            delete: 0,
            insert: inserted,
        }],
    );
    let elapsed = started.elapsed();
    assert!(
        result.is_ok(),
        "masked write failed after {elapsed:?}: {result:?}"
    );
    assert!(
        elapsed <= BUDGET,
        "masked write took {elapsed:?}, budget {BUDGET:?}"
    );
    assert!(
        matches!(result?, NoteEditOutcome::Applied(_)),
        "free prose must apply"
    );

    let handle = only_handle(&vault, &proof, note)?;
    let text_form = format!("[secret {handle}]");
    let stored = vault.note_document(note)?.markdown;
    assert!(!stored.contains(TOKEN), "no secret copy may remain");
    assert_eq!(stored.matches(&text_form).count(), COPIES);
    // Whole-body equality also proves every distinct gap survives in order.
    assert_eq!(stored, written.replace(TOKEN, &text_form));
    Ok(())
}

#[test]
fn a_pin_between_two_secrets_keeps_its_quote_at_the_masked_offset() -> TestResult {
    let (_dir, vault, owner, proof) = fixture()?;
    vault.set_secret_scan_mode(&proof, SecretScanMode::Off, 11)?;
    let quote = "steady α🦀 gap quote";
    let written = format!("Release notes: {TOKEN}\n{quote}\nDeploy next: {TOKEN}\n");
    let note = vault.create_note(
        "research",
        &written,
        WriteActor::new(owner, EdgeActorClass::Human),
    )?;
    // Copy the Proposed-CLAIM citation fixture from found_key_note_restore.rs.
    let claim = EntityId::now();
    let mut body = ClaimBody::new(
        "profile.note",
        ClaimSubject::Entity(owner),
        rmpv::Value::from("the release notes name the deploy step"),
        1.0,
        ClaimApprovalStatus::Proposed,
        ClaimLifecycleStatus::Active,
    )?;
    body.source = Some(ClaimSource::UserStated);
    vault.put_claim(&claim, &body, TimeRange { start: 1, end: 1 }, 1)?;
    let start = written[..written.find(quote).unwrap()].chars().count();
    let pin = vault.pin_note_span(note, claim, start, start + quote.chars().count())?;
    let memory = vault.memory(owner, EdgeActorClass::Human);
    memory.cite_note_span(note, &pin)?;
    let before = vault.note_document(note)?;
    assert_eq!(before.pins, vec![pin.clone()]);
    assert_eq!(
        vault.resolve_note_pin(&pin)?,
        NoteSpanResolution::Mapped {
            start,
            end: start + quote.chars().count(),
            claim,
            quote: quote.into(),
        }
    );

    vault.set_secret_scan_mode(&proof, SecretScanMode::On, 12)?;
    let tail = "Tail remains.\n";
    let result = memory.apply_note_ops(
        note,
        &before.frontier,
        &[NoteEdit {
            start: written.chars().count(),
            delete: 0,
            insert: tail.into(),
        }],
    )?;
    assert!(
        matches!(result, NoteEditOutcome::Applied(_)),
        "the edit is outside the quote"
    );
    let handle = only_handle(&vault, &proof, note)?;
    let text_form = format!("[secret {handle}]");
    let after = vault.note_document(note)?;
    let expected = format!("{written}{tail}").replace(TOKEN, &text_form);
    assert_eq!(after.markdown, expected);
    assert_eq!(after.markdown.matches(&text_form).count(), 2);
    assert_eq!(
        after.pins, before.pins,
        "the stored pin itself must not be rebuilt"
    );
    let moved = expected[..expected.find(quote).unwrap()].chars().count();
    assert_ne!(moved, start, "masking must move the quoted gap");
    assert_eq!(
        vault.resolve_note_pin(&pin)?,
        NoteSpanResolution::Mapped {
            start: moved,
            end: moved + quote.chars().count(),
            claim,
            quote: quote.into(),
        }
    );
    Ok(())
}

/// Before the splice this ran the unbounded diff for hours.
#[test]
fn a_pending_rewrite_restores_many_copies_of_one_handle_within_the_budget() -> TestResult {
    let (_dir, vault, owner, proof) = fixture()?;
    let actor = WriteActor::new(owner, EdgeActorClass::Human);
    let original = format!("{SEED}Deploy with token={TOKEN}.");
    let note = vault.create_note("research", &original, actor)?;
    let handle = only_handle(&vault, &proof, note)?;
    let text_form = format!("[secret {handle}]");
    let masked = repeated_body(&text_form);
    assert_eq!(masked.matches(&text_form).count(), COPIES);
    let fork = vault.fork_note(
        note,
        &NoteProgramEdit::Rewrite {
            text: masked.clone(),
        },
        actor,
    )?;
    let request = NoteForkReadRequest {
        note_ref: note.to_hex(),
        fork_ref: fork.to_hex(),
        reason: None,
    };
    let memory = vault.memory(owner, EdgeActorClass::Human);
    let before = memory
        .read_note_fork(&request)?
        .value
        .unwrap()
        .markdown
        .unwrap();
    assert_eq!(before, masked);

    // testkit-lint: allow(wall-clock) the elapsed time is the budget under test
    let started = Instant::now();
    let result = vault.rule_found_key_not_a_secret(&proof, ActSurface::ThisInstall, &handle);
    let elapsed = started.elapsed();
    assert!(
        result.is_ok(),
        "ruling failed after {elapsed:?}: {result:?}"
    );
    assert!(
        elapsed <= BUDGET,
        "rewrite restore took {elapsed:?}, budget {BUDGET:?}"
    );
    result?;

    let restored = memory
        .read_note_fork(&request)?
        .value
        .unwrap()
        .markdown
        .unwrap();
    assert!(!restored.contains(&text_form), "no handle copy may remain");
    assert_eq!(restored.matches(TOKEN).count(), COPIES);
    assert_eq!(restored, masked.replace(&text_form, TOKEN));
    assert_eq!(vault.note_document(note)?.markdown, original);
    Ok(())
}
