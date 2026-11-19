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
//!
//! `reply_attachment_whose_words_come_from_an_unreadable_source_is_refused`
//! (FIX-LIST MAIL-ATTACHMENT-CLAMP-WORD-SOURCES, RULING CLAMP-7741 = B) is red
//! at 6f9c1251742c: a file that quotes a `conversation.summary` over a Tier-A
//! note is judged on the summary's own row, so the draft lands. On the head
//! the clamp follows the summary's words to the note and refuses the reply.

use std::sync::Arc;

use oneiron::authority::{HostSlipIssuer, MachineRole};
use oneiron::blob_artifact::{BlobArtifactBody, BlobVersionProvenance};
use oneiron::commitment_wake::COMMITMENT_REMINDER_WORDING_ATTEMPT_KIND;
use oneiron::core_write::{ConversationCreateInput, DagRecordAppendInput};
use oneiron::provenance::made_by::{
    MadeBy, MadeByClass, MadeByInput, MadeByInputRole, MadeByProcess,
};
use oneiron::test_doors::disclosure_word_sources::{
    install_shipped_policy_with_ordinary_predicate, mark_tier_a,
};
use oneiron::test_doors::reply_attachments as doors;
use oneiron::write_envelope::claim_body::encode_claim_body;
use oneiron::{
    ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus, ClaimSubject, EdgeActorClass, EntityId,
    TimeRange, Vault, VaultConfig, WriteActor,
};
use rmpv::Value;
use serde_json::json;

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

/// A note the owner wrote in a conversation of its own: the record a
/// summary's words come from.
fn side_note(vault: &Vault, owner: EntityId) -> Result<EntityId, Box<dyn std::error::Error>> {
    let host = vault.memory(owner, EdgeActorClass::Human);
    let receipt = host.conversations_create(&ConversationCreateInput {
        id: None,
        occurred_start: None,
        occurred_end: None,
        learned_at: None,
        body: json!({}),
        text: None,
    })?;
    let note = host.conversations_records_append(&DagRecordAppendInput {
        conversation: receipt.id,
        parent: None,
        reply_to: None,
        containing_turn: None,
        addr: None,
        to: None,
        advance: true,
        body: json!({"txt": "the side note", "speaker": "user"}),
        text: None,
        occurred_start: None,
        occurred_end: None,
        learned_at: None,
        session: None,
        quote: None,
        thread_audience: None,
    })?;
    Ok(EntityId::from_hex(&note.id)?)
}

/// An artifact whose version 1 quotes the claim `source` (stored as
/// `source_body`) as a reminder wording does (FIX 4997): the source as its
/// one input and the stored body's BLAKE3 as its params hash, under the
/// wording attempt's identity and run prefix. Version 2 is a plain upload.
fn quoting_artifact(
    vault: &Vault,
    owner: EntityId,
    source: EntityId,
    source_body: &ClaimBody,
) -> Result<EntityId, Box<dyn std::error::Error>> {
    let at = vault.now_recorded_at();
    let occurred = TimeRange { start: at, end: at };
    let actor = WriteActor::new(owner, EdgeActorClass::Human);
    let artifact = EntityId::now();
    vault.put_blob_artifact(
        &artifact,
        &BlobArtifactBody::new("report.txt", "text/plain"),
        occurred,
        at,
    )?;
    let made_by = MadeBy {
        inputs: vec![MadeByInput {
            row: source,
            role: MadeByInputRole::Input,
        }],
        process: MadeByProcess {
            actor: owner,
            class: MadeByClass::Concluded,
            identity: COMMITMENT_REMINDER_WORDING_ATTEMPT_KIND.to_owned(),
            version: "1".to_owned(),
            params_hash: blake3::hash(&encode_claim_body(source_body)?)
                .to_hex()
                .to_string(),
        },
        at,
        trigger: None,
    };
    vault.append_blob_artifact_version_made_by(
        &artifact,
        None,
        FIRST_VERSION,
        &BlobVersionProvenance::AgentRun {
            run_ref: format!("commitment-reminder-wording:{}", artifact.to_hex()),
        },
        &made_by,
        actor,
        occurred,
        at,
    )?;
    let at = vault.now_recorded_at();
    vault.append_blob_artifact_version(
        &artifact,
        SECOND_VERSION,
        &BlobVersionProvenance::UserUpload,
        actor,
        TimeRange { start: at, end: at },
        at,
    )?;
    Ok(artifact)
}

/// A file that quotes a summary is shown only with every record the
/// summary's words came from: once the note it covers is Tier A, a reply
/// naming that file is refused whole, though the summary's own row is
/// still readable.
#[test]
fn reply_attachment_whose_words_come_from_an_unreadable_source_is_refused() -> TestResult {
    let directory = tempfile::tempdir()?;
    let vault = open_vault(directory.path())?;
    let seeded = doors::seed_gmail_thread(&vault, now_sec()?)?;
    // The test writes the summary through the raw claim door, which the
    // shipped policy parks at the criticality floor for an undeclared
    // predicate.
    install_shipped_policy_with_ordinary_predicate(&vault, "conversation.summary")?;
    let note = side_note(&vault, seeded.owner)?;
    let summary = EntityId::now();
    let summary_body = ClaimBody::new(
        "conversation.summary",
        ClaimSubject::Entity(seeded.owner),
        Value::Map(vec![
            ("text".into(), "The side note, summarised.".into()),
            (
                "covers".into(),
                Value::Array(vec![Value::Binary(note.as_bytes().to_vec())]),
            ),
        ]),
        1.0,
        ClaimApprovalStatus::Approved,
        ClaimLifecycleStatus::Active,
    )?;
    let at = vault.now_recorded_at();
    vault.put_claim(
        &summary,
        &summary_body,
        TimeRange { start: at, end: at },
        at,
    )?;
    let artifact = quoting_artifact(&vault, seeded.owner, summary, &summary_body)?;
    mark_tier_a(&vault, &note)?;

    let drafted =
        doors::draft_reply_with_file(&vault, seeded.owner, &seeded.thread_ref, artifact, 1);

    let Err(refusal) = drafted else {
        panic!("a reply whose file quotes a summary of a Tier-A note is refused, not drafted");
    };
    assert!(
        refusal.contains("attachment 1 may not be shown to")
            && refusal.contains("the reply is refused whole"),
        "the refusal is the disclosure clamp's, for the quoting file: {refusal}"
    );
    Ok(())
}
