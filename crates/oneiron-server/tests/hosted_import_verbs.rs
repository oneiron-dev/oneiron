//! [HOSTED-IMPORT-VERBS] (census item 14, L2-19; ARCH-0027 #hosted-import:
//! "Raw staging is deleted after ingest or cancel. Progress reports upload,
//! parse, searchable, embeddings and review apart, because uploaded is not
//! ready"; the Engine's rulings of 13 Nov 07:14). `vault.imports.get` reads
//! one hosted import's progress with its five phases apart, during the job
//! and after it. `vault.imports.cancel` stops a job: between two passes, or
//! during a pass at its next conversation. The job lands nothing more, its
//! staging is removed, and what landed stays in the import's review. A
//! caller that is neither the owner nor a holder of the matching Steward
//! grant is refused both verbs: `read` admits the read, `delete` the cancel.
//!
//! Every verb is reached by its name. Stages exports and runs the worker's
//! passes through `oneiron_server::test_doors::hosted_import`:
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron-server
//! --all-features --features oneiron/test-support --test hosted_import_verbs`.
#![cfg(all(oneiron_test_support, unix))]

use std::path::{Path, PathBuf};
use std::sync::Arc;

use oneiron::ingest::history::{
    HistorySource, HostedImportId, HostedImportJob, HostedImportStaged, history_import_review_id,
};
use oneiron::memory::{MEMORY_CODE_BAD_REQUEST, MEMORY_CODE_FORBIDDEN, MemoryResult};
use oneiron::store::GateDecisionId;
use oneiron::task_verb::sdk::invoke;
use oneiron::test_doors::coach::{coach, define_agent};
use oneiron::test_doors::steward::{
    STEWARD_DELETE_VERB, STEWARD_READ_VERB, open_owner_carrier_vault, stand_steward_grant,
};
use oneiron::{EdgeActorClass, EntityId, Vault, VaultConfig};
use oneiron_server::test_doors::hosted_import::{pass, pass_cancelled_after, stage};
use serde_json::{Map, Value, json};

type TestError = Box<dyn std::error::Error>;
type TestResult = Result<(), TestError>;

const GET: &str = "vault.imports.get";
const CANCEL: &str = "vault.imports.cancel";

/// A process-owned vault at `dir`, as `serve` opens it: this process holds
/// its writer lease, so its embedded owner may import and call the owner's
/// verbs. Answers the vault and its owner's PERSON.
fn open_vault(dir: &Path) -> Result<(Vault, EntityId), TestError> {
    let mut config = VaultConfig::device();
    config.map_size = 64 * 1024 * 1024;
    config.dimensions = 4;
    config.embedding_model = None;
    let vault = Vault::open_owned(dir, config)?;
    let owner = vault.ensure_embedded_owner_actor()?;
    Ok((vault, owner))
}

/// Writes a ChatGPT export (`conversations.json`) of one linear thread per
/// entry of `sizes`, each of that many messages, user and assistant in turn,
/// created 100 s apart. Message ids carry `tag`, so two exports never share
/// one: the import ledger keys on them.
fn write_export(path: &Path, tag: &str, sizes: &[u32]) -> TestResult {
    let mut export = Vec::new();
    for (number, &messages) in sizes.iter().enumerate() {
        let created = 1_757_840_000 + 100 * u32::try_from(number)?;
        let id = format!("{tag}-conversation-{number}");
        let key = |index: u32| format!("{tag}-c{number}-m{index}");
        let mut mapping = Map::new();
        mapping.insert(
            "root".to_owned(),
            json!({ "id": "root", "message": null, "parent": null, "children": [key(0)] }),
        );
        for index in 0..messages {
            let role = if index % 2 == 0 { "user" } else { "assistant" };
            let parent = if index == 0 {
                "root".to_owned()
            } else {
                key(index - 1)
            };
            let children: Vec<String> = (index + 1 < messages)
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
                        "create_time": f64::from(created) + f64::from(index),
                        "update_time": null,
                        "content": {
                            "content_type": "text",
                            "parts": [format!("Notes on the {tag} plan, part {number}.{index}.")]
                        },
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
            "title": format!("The {tag} plan {number}"),
            "create_time": f64::from(created),
            "update_time": f64::from(created + messages),
            "mapping": Value::Object(mapping),
            "current_node": key(messages - 1),
            "conversation_id": id,
            "id": id,
        }));
    }
    std::fs::write(path, serde_json::to_vec(&export)?)?;
    Ok(())
}

fn call(
    vault: &Vault,
    actor: EntityId,
    class: EdgeActorClass,
    verb: &str,
    input: Value,
) -> MemoryResult<Value> {
    invoke(&vault.memory(actor, class), verb, input)
}

fn lookup(id: HostedImportId) -> Value {
    json!({ "import": id.to_hex() })
}

fn job(vault: &Vault, id: HostedImportId) -> Result<HostedImportJob, TestError> {
    vault
        .hosted_import(id)?
        .ok_or_else(|| format!("no row for hosted import {}", id.to_hex()).into())
}

fn staging(vault_dir: &Path, id: HostedImportId) -> PathBuf {
    vault_dir.join("imports").join(id.to_hex())
}

/// The five phases of a progress answer, each as the verb answers it.
fn phases(view: &Value) -> [&Value; 5] {
    [
        &view["upload"],
        &view["parse"],
        &view["searchable"],
        &view["embeddings"],
        &view["review"],
    ]
}

/// A searchable phase: conversations landed and the messages counted new,
/// skipped, changed, refused and pending.
fn searchable(conversations: u64, new: u64) -> Value {
    json!({
        "conversations": conversations,
        "new": new,
        "skipped": 0,
        "changed": 0,
        "refused": 0,
        "pending": 0,
    })
}

/// A vault with no embedding model: `turns` TURNs, none waiting.
fn embeddings(turns: u64) -> Value {
    json!({ "embedder": false, "turns": turns, "pending": 0 })
}

#[test]
fn the_progress_reports_its_five_phases_apart_during_the_job_and_after_it() -> TestResult {
    let vault_dir = tempfile::tempdir()?;
    let exports = tempfile::tempdir()?;
    let export = exports.path().join("conversations.json");
    // Three conversations of 2, 3 and 4 messages: one TURN per message, as
    // each one-speaker run is a TURN of its own.
    write_export(&export, "garden", &[2, 3, 4])?;
    let (vault, owner) = open_vault(vault_dir.path())?;
    let human = EdgeActorClass::Human;
    let id = stage(vault_dir.path(), HistorySource::Chatgpt, &export)?;

    // A pass that lands nothing makes the row and decodes the export.
    pass(&vault, vault_dir.path(), Some(0))?;
    let row = job(&vault, id)?;
    let review = history_import_review_id(HistorySource::Chatgpt, row.imported_at);
    let staged = call(&vault, owner, human, GET, lookup(id))
        .expect("FAILBEFORE: the owner reads the import's progress");
    assert_eq!(staged["import"], json!(id.to_hex()));
    assert_eq!(staged["source"], json!("chatgpt"));
    assert_eq!(staged["state"], json!("staged"));
    let bytes = std::fs::read(&export)?;
    assert_eq!(
        phases(&staged),
        [
            &json!({
                "bytes": bytes.len(),
                "blake3": blake3::hash(&bytes).to_hex().to_string(),
            }),
            &json!({ "conversations": 3, "messages": 9 }),
            &searchable(0, 0),
            &embeddings(0),
            &json!({ "review_id": review, "waiting": 0, "dreamer_attempts_queued": 0 }),
        ],
        "uploaded and parsed is not searchable"
    );

    // Two conversations land: five messages searchable, in five TURNs.
    pass(&vault, vault_dir.path(), Some(2))?;
    let landing = call(&vault, owner, human, GET, lookup(id)).expect("the owner reads");
    assert_eq!(landing["state"], json!("landing"));
    assert_eq!(landing["searchable"], searchable(2, 5));
    assert_eq!(landing["embeddings"], embeddings(5));
    assert_eq!(
        landing["parse"],
        json!({ "conversations": 3, "messages": 9 })
    );

    // The rest lands: the job ends Landed and its staging is removed.
    pass(&vault, vault_dir.path(), None)?;
    let landed = call(&vault, owner, human, GET, lookup(id)).expect("the owner reads");
    assert_eq!(landed["state"], json!("landed"));
    assert_eq!(landed["failure"], Value::Null);
    assert_eq!(landed["searchable"], searchable(3, 9));
    assert_eq!(landed["embeddings"], embeddings(9));
    assert_eq!(landed["review"]["review_id"], json!(review));
    assert_eq!(
        landed["review"]["dreamer_attempts_queued"],
        json!(job(&vault, id)?.dreamer_attempts_queued),
        "the review phase names the Dreamer attempts the job's end queued"
    );
    assert_eq!(landed["cancelled_by"], Value::Null);
    assert!(!staging(vault_dir.path(), id).exists());

    // An import the vault does not know reads as none; a malformed id is
    // refused.
    let unknown = call(
        &vault,
        owner,
        human,
        GET,
        lookup(HostedImportId::generate()),
    )
    .expect("an unknown import");
    assert_eq!(unknown, Value::Null);
    let refused = call(&vault, owner, human, GET, json!({ "import": "not-an-id" }))
        .expect_err("a malformed id");
    assert_eq!(refused.code, MEMORY_CODE_BAD_REQUEST, "{refused:?}");
    Ok(())
}

#[test]
fn a_cancel_stops_the_job_removes_its_staging_and_keeps_what_landed() -> TestResult {
    let vault_dir = tempfile::tempdir()?;
    let exports = tempfile::tempdir()?;
    let (vault, owner) = open_vault(vault_dir.path())?;
    let vault = Arc::new(vault);
    let human = EdgeActorClass::Human;

    // Between two passes: one of three conversations has landed.
    let first = exports.path().join("first.json");
    write_export(&first, "garden", &[2, 3, 4])?;
    let id = stage(vault_dir.path(), HistorySource::Chatgpt, &first)?;
    pass(&vault, vault_dir.path(), Some(1))?;
    assert_eq!(job(&vault, id)?.cursor, 1);
    let asked = call(&vault, owner, human, CANCEL, lookup(id))
        .expect("FAILBEFORE: the owner cancels the import");
    assert_eq!(
        asked,
        json!({ "import": id.to_hex(), "state": "cancelling" }),
        "the job's worker stops it"
    );
    let cancelling = call(&vault, owner, human, GET, lookup(id)).expect("the owner reads");
    assert_eq!(cancelling["state"], json!("cancelling"));
    assert_eq!(cancelling["cancelled_by"], json!(owner.to_hex()));
    assert!(
        staging(vault_dir.path(), id).is_dir(),
        "the staging stays until the worker stops the job"
    );
    let again = call(&vault, owner, human, CANCEL, lookup(id)).expect("a second cancel");
    assert_eq!(again, asked, "a second cancel changes nothing");

    // The next pass lands nothing more, removes the staging and ends the
    // job Cancelled. The landed conversation stays in the import's review.
    pass(&vault, vault_dir.path(), None)?;
    let cancelled = call(&vault, owner, human, GET, lookup(id)).expect("the owner reads");
    assert_eq!(cancelled["state"], json!("cancelled"));
    assert_eq!(cancelled["searchable"], searchable(1, 2));
    assert_eq!(cancelled["embeddings"], embeddings(2));
    assert_eq!(
        cancelled["review"]["review_id"],
        json!(history_import_review_id(
            HistorySource::Chatgpt,
            job(&vault, id)?.imported_at
        ))
    );
    assert!(
        !staging(vault_dir.path(), id).exists(),
        "a cancelled job's staging is removed"
    );
    assert_eq!(
        vault.history_import_ledger_len(HistorySource::Chatgpt)?,
        2,
        "what landed before the cancel stays, and nothing more lands"
    );
    let ended = call(&vault, owner, human, CANCEL, lookup(id)).expect("a cancel after the end");
    assert_eq!(
        ended,
        json!({ "import": id.to_hex(), "state": "cancelled" })
    );
    let unknown = call(
        &vault,
        owner,
        human,
        CANCEL,
        lookup(HostedImportId::generate()),
    )
    .expect("unknown");
    assert_eq!(unknown, Value::Null);

    // During a pass: the cancel comes after the first conversation landed,
    // and the pass stops at the next one.
    let second = exports.path().join("second.json");
    write_export(&second, "orchard", &[2, 3, 4])?;
    let during = stage(vault_dir.path(), HistorySource::Chatgpt, &second)?;
    pass_cancelled_after(&vault, vault_dir.path(), during, 1)?;
    let stopped = call(&vault, owner, human, GET, lookup(during)).expect("the owner reads");
    assert_eq!(stopped["state"], json!("cancelled"));
    assert_eq!(
        stopped["parse"],
        json!({ "conversations": 3, "messages": 9 })
    );
    assert_eq!(stopped["searchable"], searchable(1, 2));
    assert!(!staging(vault_dir.path(), during).exists());
    assert_eq!(vault.history_import_ledger_len(HistorySource::Chatgpt)?, 4);
    Ok(())
}

/// A caller with no grant is refused both verbs. A Steward grant naming
/// `read` admits the read and not the cancel; one naming `delete` admits the
/// cancel and not the read. Each grant is checked at each call.
#[test]
fn only_the_matching_steward_grant_admits_a_holder_to_each_verb() -> TestResult {
    let vault_dir = tempfile::tempdir()?;
    let vault = open_owner_carrier_vault(vault_dir.path())?;
    coach(&vault)?;
    vault.provision_system_agent_grants()?;
    let owner = vault.ensure_embedded_owner_actor()?;
    let proof = vault.authenticate_owner(owner, &owner.to_hex(), true, GateDecisionId::now())?;
    let id = HostedImportId::generate();
    vault.hosted_import_create(
        &proof,
        id,
        HistorySource::Chatgpt,
        HostedImportStaged {
            bytes: 2,
            blake3: *blake3::hash(b"[]").as_bytes(),
        },
        1_780_000_000,
    )?;
    let agent = EdgeActorClass::Agent;
    let holder = define_agent(&vault)?;
    let stranger = define_agent(&vault)?;

    // A holder of `read` reads the progress, and is refused the cancel.
    stand_steward_grant(&vault, holder, &[STEWARD_READ_VERB])?;
    let read = call(&vault, holder, agent, GET, lookup(id))
        .expect("FAILBEFORE: a holder of read reads the progress");
    assert_eq!(read["state"], json!("staged"));
    let refused = call(&vault, holder, agent, CANCEL, lookup(id)).expect_err("read is no cancel");
    assert_eq!(refused.code, MEMORY_CODE_FORBIDDEN, "{refused:?}");

    // A caller with no grant is refused both verbs.
    let refused = call(&vault, stranger, agent, GET, lookup(id)).expect_err("no grant reads");
    assert_eq!(refused.code, MEMORY_CODE_FORBIDDEN, "{refused:?}");
    let refused = call(&vault, stranger, agent, CANCEL, lookup(id)).expect_err("no grant cancels");
    assert_eq!(refused.code, MEMORY_CODE_FORBIDDEN, "{refused:?}");
    assert_eq!(
        job(&vault, id)?.cancelled_by,
        None,
        "a refused cancel writes nothing"
    );

    // The grant that replaces it names `delete` alone: the holder cancels,
    // and is refused the read from this call on.
    stand_steward_grant(&vault, holder, &[STEWARD_DELETE_VERB])?;
    let asked = call(&vault, holder, agent, CANCEL, lookup(id)).expect("a holder of delete");
    assert_eq!(
        asked,
        json!({ "import": id.to_hex(), "state": "cancelling" })
    );
    assert_eq!(job(&vault, id)?.cancelled_by, Some(holder));
    let refused = call(&vault, holder, agent, GET, lookup(id)).expect_err("delete is no read");
    assert_eq!(refused.code, MEMORY_CODE_FORBIDDEN, "{refused:?}");
    Ok(())
}
