//! [HOSTED-IMPORT-JOB] (census item 14, L2-19; ARCH-0027 #hosted-import; the
//! Engine's ruling of 13 Nov 07:02): an export staged in the vault's own data
//! folder (`imports/<id>/`) is landed by serve's hosted-import worker as a
//! durable job. A process that stops part way leaves the job at its place;
//! the next process takes it up there and finishes it, each message landed
//! once and every row into the import's one review, and the staging is
//! removed. A duplicate import lands nothing new. The job's row counts the
//! export's conversations and messages, and what each landed conversation
//! counted.
//!
//! Stages exports and runs the worker's passes through
//! `oneiron_server::test_doors::hosted_import`:
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron-server
//! --all-features --features oneiron/test-support --test hosted_import_job`.
#![cfg(all(oneiron_test_support, unix))]

use std::path::{Path, PathBuf};

use oneiron::ingest::history::{HistorySource, HostedImportId, HostedImportJob, HostedImportState};
use oneiron::{Vault, VaultConfig};
use oneiron_server::test_doors::hosted_import::{pass, stage};
use serde_json::{Map, Value, json};

type TestError = Box<dyn std::error::Error>;
type TestResult = Result<(), TestError>;

/// A process-owned vault at `dir`, as `serve` opens it: this process holds
/// its writer lease, so its embedded owner may import.
fn open_vault(dir: &Path) -> Result<Vault, TestError> {
    let mut config = VaultConfig::device();
    config.map_size = 64 * 1024 * 1024;
    config.dimensions = 4;
    config.embedding_model = None;
    Ok(Vault::open_owned(dir, config)?)
}

/// One conversation of a synthetic export: the second it was created, how
/// many messages it holds, and the message whose text a later export edits.
struct Conversation {
    created: u32,
    messages: u32,
    edited: Option<u32>,
}

/// Writes a ChatGPT export (`conversations.json`) of one linear thread per
/// conversation, user and assistant in turn. Message ids are unique across
/// the export, as ChatGPT's are: the import ledger keys on them.
fn write_export(path: &Path, conversations: &[Conversation]) -> TestResult {
    let mut export = Vec::new();
    for (number, conversation) in conversations.iter().enumerate() {
        let id = format!("00000000-0000-4000-8000-{number:012}");
        let key = |index: u32| format!("c{number}-m{index}");
        let mut mapping = Map::new();
        mapping.insert(
            "root".to_owned(),
            json!({ "id": "root", "message": null, "parent": null, "children": [key(0)] }),
        );
        for index in 0..conversation.messages {
            let role = if index % 2 == 0 { "user" } else { "assistant" };
            let mut text = format!("Notes on the garden plan, part {number}.{index}.");
            if conversation.edited == Some(index) {
                text.push_str(" Moved the tomatoes to the south bed.");
            }
            let parent = if index == 0 {
                "root".to_owned()
            } else {
                key(index - 1)
            };
            let children: Vec<String> = (index + 1 < conversation.messages)
                .then(|| key(index + 1))
                .into_iter()
                .collect();
            mapping.insert(
                key(index),
                json!({
                    "id": key(index),
                    "parent": parent,
                    "children": children,
                    "message": {
                        "id": key(index),
                        "author": { "role": role, "name": null, "metadata": {} },
                        "create_time": f64::from(conversation.created) + f64::from(index),
                        "update_time": null,
                        "content": { "content_type": "text", "parts": [text] },
                        "status": "finished_successfully",
                        "end_turn": true,
                        "weight": 1.0,
                        "metadata": {},
                        "recipient": "all",
                        "channel": null
                    }
                }),
            );
        }
        export.push(json!({
            "title": format!("Garden plan {number}"),
            "create_time": f64::from(conversation.created),
            "update_time": f64::from(conversation.created + conversation.messages),
            "mapping": Value::Object(mapping),
            "current_node": key(conversation.messages - 1),
            "conversation_id": id,
            "id": id,
        }));
    }
    std::fs::write(path, serde_json::to_vec(&export)?)?;
    Ok(())
}

fn job(vault: &Vault, id: HostedImportId) -> Result<HostedImportJob, TestError> {
    vault
        .hosted_import(id)?
        .ok_or_else(|| format!("no row for hosted import {}", id.to_hex()).into())
}

fn staging(vault_dir: &Path, id: HostedImportId) -> PathBuf {
    vault_dir.join("imports").join(id.to_hex())
}

/// The job's counts: (cursor, new, skipped, changed, refused, pending).
fn counts(job: &HostedImportJob) -> (u64, u64, u64, u64, u64, u64) {
    (
        job.cursor,
        job.new,
        job.skipped,
        job.changed,
        job.refused,
        job.pending,
    )
}

#[test]
fn a_staged_export_resumes_after_a_restart_and_lands_each_message_once() -> TestResult {
    let vault_dir = tempfile::tempdir()?;
    let exports = tempfile::tempdir()?;
    let export = exports.path().join("conversations.json");
    // Three conversations, created 100 s apart, of 2, 3 and 4 messages.
    write_export(
        &export,
        &[
            Conversation {
                created: 1_757_840_000,
                messages: 2,
                edited: None,
            },
            Conversation {
                created: 1_757_840_100,
                messages: 3,
                edited: None,
            },
            Conversation {
                created: 1_757_840_200,
                messages: 4,
                edited: None,
            },
        ],
    )?;

    let vault = open_vault(vault_dir.path())?;
    let id = stage(vault_dir.path(), HistorySource::Chatgpt, &export)?;
    // The process stops after two conversations have landed.
    pass(&vault, vault_dir.path(), Some(2))?;
    let stopped = job(&vault, id)?;
    assert_eq!(stopped.state, HostedImportState::Landing);
    assert_eq!((stopped.conversations, stopped.messages), (3, 9));
    assert_eq!(stopped.cursor, 2, "two conversations landed");
    assert_eq!(vault.history_import_ledger_len(HistorySource::Chatgpt)?, 5);
    assert!(
        staging(vault_dir.path(), id).is_dir(),
        "the staging stays until the job ends"
    );
    drop(vault);

    // A new process takes the job up at its place and finishes it.
    let vault = open_vault(vault_dir.path())?;
    pass(&vault, vault_dir.path(), None)?;
    let landed = job(&vault, id)?;
    assert_eq!(
        landed.state,
        HostedImportState::Landed,
        "FAILBEFORE: the restart's pass takes the job up and lands the rest"
    );
    assert_eq!(counts(&landed), (3, 9, 0, 0, 0, 0));
    assert_eq!(vault.history_import_ledger_len(HistorySource::Chatgpt)?, 9);
    assert_eq!(
        landed.imported_at, stopped.imported_at,
        "every pass lands into the import's one review"
    );
    assert_eq!(landed.review_id(), stopped.review_id());
    assert!(
        !staging(vault_dir.path(), id).exists(),
        "the staging is removed once the job ends"
    );

    // The same export again: a job of its own that lands nothing new.
    let again = stage(vault_dir.path(), HistorySource::Chatgpt, &export)?;
    assert_ne!(again, id);
    pass(&vault, vault_dir.path(), None)?;
    let duplicate = job(&vault, again)?;
    assert_eq!(duplicate.state, HostedImportState::Landed);
    assert_eq!(counts(&duplicate), (3, 0, 9, 0, 0, 0));
    assert_eq!(vault.history_import_ledger_len(HistorySource::Chatgpt)?, 9);
    assert_ne!(
        duplicate.review_id(),
        landed.review_id(),
        "each import has a review of its own"
    );
    Ok(())
}

#[test]
fn the_job_row_counts_the_rows_of_each_landed_conversation() -> TestResult {
    let vault_dir = tempfile::tempdir()?;
    let exports = tempfile::tempdir()?;
    let first = exports.path().join("first.json");
    let conversations = |edited| {
        [
            Conversation {
                created: 1_757_840_000,
                messages: 2,
                edited,
            },
            Conversation {
                created: 1_757_840_100,
                messages: 3,
                edited: None,
            },
        ]
    };
    write_export(&first, &conversations(None))?;

    let vault = open_vault(vault_dir.path())?;
    let id = stage(vault_dir.path(), HistorySource::Chatgpt, &first)?;
    // A pass that lands nothing still makes the row and counts the export.
    pass(&vault, vault_dir.path(), Some(0))?;
    let decoded = job(&vault, id)?;
    assert_eq!(decoded.state, HostedImportState::Staged);
    assert_eq!((decoded.conversations, decoded.messages), (2, 5));
    assert_eq!(counts(&decoded), (0, 0, 0, 0, 0, 0));
    assert_eq!(
        decoded.staged_bytes,
        std::fs::metadata(&first)?.len(),
        "the row keeps what the stager counted"
    );

    pass(&vault, vault_dir.path(), Some(1))?;
    assert_eq!(
        counts(&job(&vault, id)?),
        (1, 2, 0, 0, 0, 0),
        "FAILBEFORE: the first conversation's two messages are counted new"
    );
    pass(&vault, vault_dir.path(), None)?;
    let landed = job(&vault, id)?;
    assert_eq!(landed.state, HostedImportState::Landed);
    assert_eq!(counts(&landed), (2, 5, 0, 0, 0, 0));

    // A later export with one message edited: one revision, four unchanged.
    let edited = exports.path().join("edited.json");
    write_export(&edited, &conversations(Some(1)))?;
    let later = stage(vault_dir.path(), HistorySource::Chatgpt, &edited)?;
    pass(&vault, vault_dir.path(), None)?;
    let revised = job(&vault, later)?;
    assert_eq!(revised.state, HostedImportState::Landed);
    assert_eq!(counts(&revised), (2, 0, 4, 1, 0, 0));
    assert_eq!(
        revised.new + revised.skipped + revised.changed + revised.refused + revised.pending,
        revised.messages,
        "every decoded message is counted once"
    );
    Ok(())
}
