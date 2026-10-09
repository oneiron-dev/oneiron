//! Substrate invariants of an imported transcript (ARCH-0027, ARCH-0040):
//! whose words they are, when the vault learned them, what trust the Dreamer
//! gives them, and that an import cannot be made to read as live speech.

use super::ledger;
use super::{HistoryConversation, HistoryMessage, HistoryRole, HistorySource, HistoryThreadKind};
use crate::claim::ClaimSource;
use crate::consent::AuthenticatedOwner;
use crate::edge::{EdgeActorClass, EdgeKind};
use crate::entity_id::{EntityId, derived_domains};
use crate::memory::{WitnessAuthor, WitnessMessage, WitnessTurn};
use crate::store::GateDecisionId;
use crate::{Vault, VaultConfig};

const SOURCE: HistorySource = HistorySource::ClaudeCode;
const IMPORTED_AT: u64 = 1_800_000_000;

fn vault_and_owner() -> (tempfile::TempDir, Vault, AuthenticatedOwner) {
    let dir = tempfile::tempdir().expect("tempdir");
    let mut config = VaultConfig::device();
    config.map_size = 64 * 1024 * 1024;
    let vault = Vault::open(dir.path(), config).expect("open vault");
    let actor = vault.ensure_embedded_owner_actor().expect("owner actor");
    let owner = vault
        .authenticate_owner(actor, &actor.to_hex(), true, GateDecisionId::now())
        .expect("owner");
    (dir, vault, owner)
}

fn message(id: &str, role: HistoryRole, text: &str, at_ms: u64) -> HistoryMessage {
    HistoryMessage {
        native_id: id.to_owned(),
        parent_id: None,
        role,
        text: text.to_owned(),
        at_ms: Some(at_ms),
        said_by: None,
        tools: Vec::new(),
        alias: None,
    }
}

/// The ledger row of one imported message. Its read transaction closes before
/// the caller opens another: one thread holds one LMDB read at a time.
fn ledger_row(vault: &Vault, native: &str) -> ledger::LedgerRow {
    source_ledger_row(vault, SOURCE, native)
}

fn source_ledger_row(vault: &Vault, source: HistorySource, native: &str) -> ledger::LedgerRow {
    let txn = vault.store.env.read_txn().expect("txn");
    ledger::get(&vault.store, &txn, source, native)
        .expect("ledger read")
        .expect("ledger row")
}

/// Decodes one session log, its lines given one per item.
fn decode_log(source: HistorySource, stem: &str, lines: &[&str]) -> Vec<HistoryConversation> {
    let file = super::HistoryFile {
        stem: stem.to_owned(),
        parent: None,
    };
    source.decode(&lines.join("\n"), &file).expect("decode")
}

/// Imports every conversation and sums the reports: new, skipped, changed.
fn import_all(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    source: HistorySource,
    conversations: &[HistoryConversation],
) -> (u32, u32, u32) {
    conversations
        .iter()
        .fold((0, 0, 0), |(new, skipped, changed), conversation| {
            let report = vault
                .import_history(owner, source, conversation, IMPORTED_AT)
                .expect("import");
            (
                new + report.new,
                skipped + report.skipped,
                changed + report.changed,
            )
        })
}

fn user_words(conversations: &[HistoryConversation]) -> Vec<&str> {
    conversations
        .iter()
        .flat_map(|conversation| &conversation.messages)
        .filter(|message| message.role == HistoryRole::User)
        .map(|message| message.text.as_str())
        .collect()
}

fn session(id: &str, messages: Vec<HistoryMessage>) -> HistoryConversation {
    let mut conversation = HistoryConversation::new(id.to_owned(), HistoryThreadKind::Main, None);
    conversation.messages = messages;
    conversation
}

#[test]
fn an_imported_turn_is_the_sources_words_learned_at_import_and_imported_evidence() {
    let (_dir, vault, owner) = vault_and_owner();
    let said_at = 1_700_000_000_000;
    // A source clock an hour ahead of the import: still learned at the import.
    let ahead = (IMPORTED_AT + 3_600) * 1000;
    let conversation = session(
        "session-ana",
        vec![
            message("u1", HistoryRole::User, "I moved to Porto in May.", said_at),
            message(
                "a1",
                HistoryRole::Assistant,
                "Porto is lovely in spring.",
                said_at + 4_000,
            ),
            message(
                "a2",
                HistoryRole::Assistant,
                "The tiles on the Capela das Almas are worth a detour.",
                said_at + 65_000,
            ),
            message("u2", HistoryRole::User, "Noted for Saturday.", ahead),
        ],
    );
    let report = vault
        .import_history(&owner, SOURCE, &conversation, IMPORTED_AT)
        .expect("import");
    assert_eq!((report.new, report.refused), (4, 0));

    // Each message keeps its own source time, two in one assistant turn too.
    for (native, occurred) in [
        ("u1", said_at / 1000),
        ("a1", (said_at + 4_000) / 1000),
        ("a2", (said_at + 65_000) / 1000),
        ("u2", ahead / 1000),
    ] {
        let row = ledger_row(&vault, native);
        let header = vault
            .read_entity_header(&row.message)
            .expect("header read")
            .expect("message");
        assert_eq!(
            header.occurred_start, occurred,
            "occurred at the source's time"
        );
        assert_eq!(header.learned_at, IMPORTED_AT, "learned when imported");
        let edges = vault.edges_out(&row.message).expect("edges");
        assert!(
            edges.iter().all(|edge| edge.kind != EdgeKind::AuthoredBy),
            "the importer is not the author of the source's words"
        );
        let turn = vault.get_raw(&row.turn).expect("turn read").expect("turn");
        let body = &turn[crate::batch::ENTITY_METADATA_HEADER_LEN..];
        assert_eq!(
            crate::dreamer_consolidation::resources::native_turn_source(&vault, body)
                .expect("turn trust class"),
            ClaimSource::Imported,
            "imported evidence whatever the speaker"
        );
    }

    let again = vault
        .import_history(&owner, SOURCE, &conversation, IMPORTED_AT + 60)
        .expect("re-import");
    assert_eq!((again.new, again.skipped, again.changed), (0, 4, 0));
    assert_eq!(vault.history_import_ledger_len(SOURCE).expect("ledger"), 4);
}

fn plain_turn(conversation_ref: String, turn_ref: Option<String>) -> WitnessTurn {
    WitnessTurn {
        conversation_ref,
        turn_ref,
        messages: vec![WitnessMessage {
            id: None,
            author: WitnessAuthor::User,
            message_type: "dialogue".to_owned(),
            content: "a live word".to_owned(),
            metadata: None,
            is_visible: true,
            order: 40,
        }],
        occurred_at: IMPORTED_AT + 100,
    }
}

#[test]
fn witnessed_speech_never_joins_an_imported_conversation_or_turn() {
    let (_dir, vault, owner) = vault_and_owner();
    let conversation = session(
        "session-eve",
        vec![message(
            "u1",
            HistoryRole::User,
            "imported words",
            1_700_000_000_000,
        )],
    );
    vault
        .import_history(&owner, SOURCE, &conversation, IMPORTED_AT)
        .expect("import");
    let row = ledger_row(&vault, "u1");
    let conversation_ref = EntityId::derive(
        derived_domains::HISTORY_CONVERSATION,
        &[SOURCE.source_id().as_bytes(), b"session-eve"],
    )
    .expect("derived id")
    .to_hex();
    let memory = vault.memory(owner.actor(), EdgeActorClass::Human);
    // The Dreamer reads a turn's trust from the turn: live words appended to
    // an imported turn would count as imported, and the reverse.
    for turn in [
        plain_turn(conversation_ref.clone(), Some(row.turn.to_hex())),
        plain_turn(conversation_ref, None),
    ] {
        let refused = memory
            .witness(&turn)
            .expect_err("a live witness is refused");
        assert_eq!(refused.code, crate::memory::MEMORY_CODE_BAD_REQUEST);
    }
}

#[test]
fn an_imported_turns_source_survives_any_later_put() {
    let (_dir, vault, owner) = vault_and_owner();
    let conversation = session(
        "session-fay",
        vec![message(
            "u1",
            HistoryRole::User,
            "imported words",
            1_700_000_000_000,
        )],
    );
    vault
        .import_history(&owner, SOURCE, &conversation, IMPORTED_AT)
        .expect("import");
    let turn = ledger_row(&vault, "u1").turn;
    let conversation_id = EntityId::derive(
        derived_domains::HISTORY_CONVERSATION,
        &[SOURCE.source_id().as_bytes(), b"session-fay"],
    )
    .expect("derived id");
    let put = |id: &EntityId, entity_type: u8, fields: Vec<(rmpv::Value, rmpv::Value)>| {
        let header = vault
            .read_entity_header(id)
            .expect("header read")
            .expect("row");
        let mut body = Vec::new();
        rmpv::encode::write_value(&mut body, &rmpv::Value::Map(fields)).expect("encode");
        vault.put_entity(
            id,
            entity_type,
            crate::TimeRange {
                start: header.occurred_start,
                end: header.occurred_end,
            },
            header.learned_at + 1,
            &body,
        )
    };
    // Puts that would relabel the source's words as the owner's live speech:
    // the stamp dropped, the stamp made unreadable (the Dreamer would still
    // read it as imported while the doors read it as live), and the
    // conversation's stamp dropped (live speech could then join it).
    let speaker = || ("speaker".into(), "user".into());
    let refusals = [
        put(&turn, crate::registry::ENTITY_TYPE_TURN, vec![speaker()]),
        put(
            &turn,
            crate::registry::ENTITY_TYPE_TURN,
            vec![speaker(), ("import_source".into(), rmpv::Value::Nil)],
        ),
        put(
            &conversation_id,
            crate::registry::ENTITY_TYPE_CONVERSATION,
            vec![
                ("import_conversation".into(), "session-fay".into()),
                ("import_kind".into(), "main".into()),
            ],
        ),
    ];
    for refused in refusals {
        assert!(refused.is_err(), "an import source is a birth fact");
    }
    let body = vault.get_raw(&turn).expect("read").expect("turn");
    assert_eq!(
        crate::dreamer_consolidation::resources::native_turn_source(
            &vault,
            &body[crate::batch::ENTITY_METADATA_HEADER_LEN..]
        )
        .expect("trust class"),
        ClaimSource::Imported
    );
}

#[test]
fn a_codex_item_without_an_event_keeps_its_own_words() {
    // An older response-only request, then a newer turn whose item and event
    // both say "continue". The newer event belongs to the newer item; the
    // older request must not be rewritten with it, nor "continue" kept twice.
    let rollout = [
        r#"{"timestamp":"2026-09-20T10:00:00.000Z","type":"session_meta","payload":{"id":"s-1","timestamp":"2026-09-20T10:00:00.000Z"}}"#,
        r#"{"timestamp":"2026-09-20T10:00:01.000Z","type":"response_item","payload":{"type":"message","role":"user","content":[{"type":"input_text","text":"Please continue after checking the CSV parser"}]}}"#,
        r#"{"timestamp":"2026-09-20T10:00:05.000Z","type":"response_item","payload":{"type":"message","role":"assistant","content":[{"type":"output_text","text":"The parser is fine."}]}}"#,
        r#"{"timestamp":"2026-09-20T10:01:00.000Z","type":"response_item","payload":{"type":"message","role":"user","content":[{"type":"input_text","text":"continue"}]}}"#,
        r#"{"timestamp":"2026-09-20T10:01:00.001Z","type":"event_msg","payload":{"type":"user_message","message":"continue","images":[]}}"#,
    ]
    .join("\n");
    let file = super::HistoryFile {
        stem: "rollout-s-1".to_owned(),
        parent: None,
    };
    let conversations = HistorySource::Codex
        .decode(&rollout, &file)
        .expect("decode");
    let users: Vec<&str> = conversations[0]
        .messages
        .iter()
        .filter(|message| message.role == HistoryRole::User)
        .map(|message| message.text.as_str())
        .collect();
    assert_eq!(
        users,
        ["Please continue after checking the CSV parser", "continue"]
    );
    assert_eq!(conversations[0].skipped.duplicates, 1);
}

#[test]
fn a_regrouped_run_lands_its_new_message_beside_what_landed() {
    let (_dir, vault, owner) = vault_and_owner();
    let at = 1_700_000_000_000;
    // A later read of a source that regroups a run: the run that held
    // [a0, a1] now holds [a0, a2] under the same turn.
    let first = session(
        "session-gus",
        vec![
            message("u1", HistoryRole::User, "Which train to Sintra?", at),
            message(
                "a0",
                HistoryRole::Assistant,
                "From Rossio station.",
                at + 1_000,
            ),
            message(
                "a1",
                HistoryRole::Assistant,
                "Every twenty minutes.",
                at + 2_000,
            ),
        ],
    );
    let later = session(
        "session-gus",
        vec![
            message("u1", HistoryRole::User, "Which train to Sintra?", at),
            message(
                "a0",
                HistoryRole::Assistant,
                "From Rossio station.",
                at + 1_000,
            ),
            message(
                "a2",
                HistoryRole::Assistant,
                "Every half hour at weekends.",
                at + 3_000,
            ),
        ],
    );
    vault
        .import_history(&owner, SOURCE, &first, IMPORTED_AT)
        .expect("import");
    let report = vault
        .import_history(&owner, SOURCE, &later, IMPORTED_AT + 60)
        .expect("re-import");
    assert_eq!((report.new, report.skipped, report.refused), (1, 2, 0));
    assert_eq!(ledger_row(&vault, "a2").turn, ledger_row(&vault, "a1").turn);
}

#[test]
fn a_dry_run_reads_the_ledger_read_only_and_predicts_secret_refusals() {
    let (dir, vault, owner) = vault_and_owner();
    let at = 1_700_000_000_000;
    let first = session(
        "session-hal",
        vec![message(
            "u1",
            HistoryRole::User,
            "the deploy is at noon",
            at,
        )],
    );
    vault
        .import_history(&owner, SOURCE, &first, IMPORTED_AT)
        .expect("import");
    drop(vault);

    let snapshot = super::HistoryLedgerSnapshot::open(dir.path()).expect("read-only ledger");
    let later = session(
        "session-hal",
        vec![
            message("u1", HistoryRole::User, "the deploy is at noon", at),
            message("a1", HistoryRole::Assistant, "Noted.", at + 1_000),
            message(
                "u2",
                HistoryRole::User,
                "token=ghp_0123456789abcdefghijklmnopqrstuvwxyz",
                at + 2_000,
            ),
        ],
    );
    let mut dry_run = super::HistoryDryRun::default();
    let plan = snapshot.plan(SOURCE, &later, &mut dry_run).expect("plan");
    assert_eq!((plan.new, plan.skipped, plan.refused), (1, 1, 1));
    assert!(plan.refusal_reasons.contains("gate.secret_scan.detected"));
    assert_eq!(snapshot.ledger_len(SOURCE).expect("ledger"), 1);
}

#[test]
fn an_import_never_lands_in_a_plain_conversation_at_its_derived_id() {
    let (_dir, vault, owner) = vault_and_owner();
    // The ids derive from public source ids, so a plain writer can claim one
    // first. Imported rows landing there would read as live speech.
    let conversation_id = EntityId::derive(
        derived_domains::HISTORY_CONVERSATION,
        &[SOURCE.source_id().as_bytes(), b"session-ben"],
    )
    .expect("derived id");
    vault
        .memory(owner.actor(), EdgeActorClass::Human)
        .witness(&WitnessTurn {
            conversation_ref: conversation_id.to_hex(),
            turn_ref: None,
            messages: vec![WitnessMessage {
                id: None,
                author: WitnessAuthor::User,
                message_type: "dialogue".to_owned(),
                content: "a plain turn".to_owned(),
                metadata: None,
                is_visible: true,
                order: 0,
            }],
            occurred_at: IMPORTED_AT,
        })
        .expect("plain witness");

    let conversation = session(
        "session-ben",
        vec![message(
            "u1",
            HistoryRole::User,
            "imported words",
            1_700_000_000_000,
        )],
    );
    let report = vault
        .import_history(&owner, SOURCE, &conversation, IMPORTED_AT)
        .expect("import");
    assert_eq!((report.new, report.refused), (0, 1));
    assert_eq!(vault.history_import_ledger_len(SOURCE).expect("ledger"), 0);
}

#[test]
fn a_changed_message_lands_as_a_revision_beside_the_original() {
    let (_dir, vault, owner) = vault_and_owner();
    let first = session(
        "session-cy",
        vec![message(
            "u1",
            HistoryRole::User,
            "the launch is on Friday",
            1_700_000_000_000,
        )],
    );
    vault
        .import_history(&owner, SOURCE, &first, IMPORTED_AT)
        .expect("import");
    let original = ledger_row(&vault, "u1");

    let edited = session(
        "session-cy",
        vec![message(
            "u1",
            HistoryRole::User,
            "the launch is on Monday",
            1_700_000_000_000,
        )],
    );
    let report = vault
        .import_history(&owner, SOURCE, &edited, IMPORTED_AT + 60)
        .expect("re-import");
    assert_eq!((report.new, report.changed, report.refused), (0, 1, 0));
    let revised = ledger_row(&vault, "u1");
    assert_eq!(
        revised.hashes.len(),
        2,
        "the original's text and the revision's"
    );
    assert_ne!(
        revised.message, original.message,
        "a new MESSAGE, not an overwrite"
    );
    assert_eq!(revised.turn, original.turn);
    assert!(vault.get_raw(&original.message).expect("read").is_some());
    assert_eq!(vault.history_import_ledger_len(SOURCE).expect("ledger"), 1);
}

#[test]
fn a_secret_shaped_message_refuses_its_turn_and_the_rest_of_the_import_lands() {
    let (_dir, vault, owner) = vault_and_owner();
    let conversation = session(
        "session-dee",
        vec![
            message(
                "u1",
                HistoryRole::User,
                "here it is: token=ghp_0123456789abcdefghijklmnopqrstuvwxyz",
                1_700_000_000_000,
            ),
            message(
                "a1",
                HistoryRole::Assistant,
                "Revoke that token now.",
                1_700_000_005_000,
            ),
            message("u2", HistoryRole::User, "Revoked it.", 1_700_000_060_000),
        ],
    );
    let report = vault
        .import_history(&owner, SOURCE, &conversation, IMPORTED_AT)
        .expect("import");
    assert_eq!((report.new, report.refused), (2, 1));
    assert!(report.refusal_reasons.contains("gate.secret_scan.detected"));
    assert_eq!(vault.history_import_ledger_len(SOURCE).expect("ledger"), 2);

    // Not in the ledger, so the next import tries it again.
    let again = vault
        .import_history(&owner, SOURCE, &conversation, IMPORTED_AT + 60)
        .expect("re-import");
    assert_eq!((again.new, again.skipped, again.refused), (0, 2, 1));
}

/// Astra 1310 #1: a classic rollout's messages carry no ids. Correcting the
/// request's words keeps both messages where they were: the request lands
/// as a revision, and the unchanged reply after it is the same message.
#[test]
fn a_corrected_codex_request_without_an_id_lands_as_a_revision_and_its_reply_stays() {
    let (_dir, vault, owner) = vault_and_owner();
    let rollout = |request: &str| {
        let item = format!(
            r#"{{"timestamp":"2026-09-21T09:00:01.000Z","type":"response_item","payload":{{"type":"message","role":"user","content":[{{"type":"input_text","text":"{request}"}}]}}}}"#
        );
        let event = format!(
            r#"{{"timestamp":"2026-09-21T09:00:01.001Z","type":"event_msg","payload":{{"type":"user_message","message":"{request}","kind":"plain"}}}}"#
        );
        decode_log(
            HistorySource::Codex,
            "rollout-2026-09-21T09-00-00-s-edit",
            &[
                r#"{"timestamp":"2026-09-21T09:00:00.000Z","type":"session_meta","payload":{"id":"s-edit","timestamp":"2026-09-21T09:00:00.000Z","cli_version":"0.50.0"}}"#,
                &item,
                &event,
                r#"{"timestamp":"2026-09-21T09:00:06.000Z","type":"response_item","payload":{"type":"message","role":"assistant","content":[{"type":"output_text","text":"The total matches the bank statement."}]}}"#,
                r#"{"timestamp":"2026-09-21T09:00:06.001Z","type":"event_msg","payload":{"type":"agent_message","message":"The total matches the bank statement."}}"#,
            ],
        )
    };
    let first = rollout("Chek the ledger total against the bank");
    assert_eq!(
        import_all(&vault, &owner, HistorySource::Codex, &first),
        (2, 0, 0)
    );
    let corrected = rollout("Check the ledger total against the bank");
    assert_eq!(
        import_all(&vault, &owner, HistorySource::Codex, &corrected),
        (0, 1, 1),
        "the request is revised, the reply skipped"
    );
    assert_eq!(
        vault
            .history_import_ledger_len(HistorySource::Codex)
            .expect("ledger"),
        2
    );
}

/// Greptile 1310 (codex.rs:491): a current reply is logged as its event, then
/// as its item with the item's id. An import that read the log between the
/// two saw the event alone; once the item is logged the reply is the same
/// message, not a second one.
#[test]
fn a_codex_reply_read_before_its_item_was_logged_lands_once() {
    let (_dir, vault, owner) = vault_and_owner();
    let lines = [
        r#"{"timestamp":"2026-09-22T08:00:00.000Z","type":"session_meta","payload":{"id":"s-live","timestamp":"2026-09-22T08:00:00.000Z","cli_version":"0.100.0"}}"#,
        r#"{"timestamp":"2026-09-22T08:00:01.000Z","type":"response_item","payload":{"type":"message","role":"user","content":[{"type":"input_text","text":"Which columns does the CSV import read?"}],"id":"msg_live_u1"}}"#,
        r#"{"timestamp":"2026-09-22T08:00:01.001Z","type":"event_msg","payload":{"type":"item_completed","thread_id":"s-live","turn_id":"turn-1","item":{"type":"UserMessage","id":"item-1","content":[{"type":"text","text":"Which columns does the CSV import read?"}]}}}"#,
        r#"{"timestamp":"2026-09-22T08:00:07.000Z","type":"event_msg","payload":{"type":"item_completed","thread_id":"s-live","turn_id":"turn-1","item":{"type":"AgentMessage","id":"item-2","content":[{"type":"Text","text":"Date, payee and amount."}]}}}"#,
        r#"{"timestamp":"2026-09-22T08:00:07.001Z","type":"response_item","payload":{"type":"message","role":"assistant","content":[{"type":"output_text","text":"Date, payee and amount."}],"id":"msg_live_a1"}}"#,
    ];
    let stem = "rollout-2026-09-22T08-00-00-s-live";
    let partway = decode_log(HistorySource::Codex, stem, &lines[..4]);
    assert_eq!(
        import_all(&vault, &owner, HistorySource::Codex, &partway),
        (2, 0, 0)
    );
    let whole = decode_log(HistorySource::Codex, stem, &lines);
    assert_eq!(
        import_all(&vault, &owner, HistorySource::Codex, &whole),
        (0, 2, 0),
        "the reply's item is the event already imported"
    );
    assert_eq!(
        vault
            .history_import_ledger_len(HistorySource::Codex)
            .expect("ledger"),
        2
    );
}

/// Greptile 1310 (codex.rs:361): the same words asked in two turns are two
/// requests, even when the first is logged only as its item and the second
/// only as its event.
#[test]
fn the_same_codex_request_in_two_turns_stays_two_messages() {
    let conversations = decode_log(
        HistorySource::Codex,
        "rollout-2026-09-23T10-00-00-s-again",
        &[
            r#"{"timestamp":"2026-09-23T10:00:00.000Z","type":"session_meta","payload":{"id":"s-again","timestamp":"2026-09-23T10:00:00.000Z","cli_version":"0.100.0"}}"#,
            r#"{"timestamp":"2026-09-23T10:00:01.000Z","type":"response_item","payload":{"type":"message","role":"user","content":[{"type":"input_text","text":"continue"}],"id":"msg_again_u1"}}"#,
            r#"{"timestamp":"2026-09-23T10:00:09.000Z","type":"event_msg","payload":{"type":"item_completed","thread_id":"s-again","turn_id":"turn-1","item":{"type":"AgentMessage","id":"item-1","content":[{"type":"Text","text":"Step one is done."}]}}}"#,
            r#"{"timestamp":"2026-09-23T10:00:09.001Z","type":"response_item","payload":{"type":"message","role":"assistant","content":[{"type":"output_text","text":"Step one is done."}],"id":"msg_again_a1"}}"#,
            r#"{"timestamp":"2026-09-23T10:05:00.000Z","type":"event_msg","payload":{"type":"item_completed","thread_id":"s-again","turn_id":"turn-2","item":{"type":"UserMessage","id":"item-2","content":[{"type":"text","text":"continue"}]}}}"#,
            r#"{"timestamp":"2026-09-23T10:05:08.000Z","type":"event_msg","payload":{"type":"item_completed","thread_id":"s-again","turn_id":"turn-2","item":{"type":"AgentMessage","id":"item-3","content":[{"type":"Text","text":"Step two is done."}]}}}"#,
            r#"{"timestamp":"2026-09-23T10:05:08.001Z","type":"response_item","payload":{"type":"message","role":"assistant","content":[{"type":"output_text","text":"Step two is done."}],"id":"msg_again_a2"}}"#,
        ],
    );
    assert_eq!(user_words(&conversations), ["continue", "continue"]);
}

/// Astra 1310 #3, Greptile 1310 (claude_code.rs:283): a prompt typed early
/// in a session, and the same words queued later while the assistant was
/// busy, are two requests. The later one is kept only by the queue and a meta
/// wrapper, so the queue lands it.
#[test]
fn a_claude_code_prompt_queued_again_later_lands_again() {
    let conversations = decode_log(
        HistorySource::ClaudeCode,
        "7e1f0a2b-3333-4444-8555-966677778888",
        &[
            r#"{"parentUuid":null,"isSidechain":false,"userType":"external","sessionId":"7e1f0a2b-3333-4444-8555-966677778888","type":"user","message":{"role":"user","content":"continue"},"uuid":"d1000000-0000-4000-8000-000000000001","timestamp":"2026-09-24T07:00:00.000Z"}"#,
            r#"{"parentUuid":"d1000000-0000-4000-8000-000000000001","isSidechain":false,"userType":"external","sessionId":"7e1f0a2b-3333-4444-8555-966677778888","type":"assistant","message":{"role":"assistant","model":"claude-sonnet-4-5","content":[{"type":"text","text":"Seedlings are potted."}]},"uuid":"d1000000-0000-4000-8000-000000000002","timestamp":"2026-09-24T07:00:20.000Z"}"#,
            r#"{"type":"queue-operation","operation":"enqueue","timestamp":"2026-09-24T07:30:05.000Z","sessionId":"7e1f0a2b-3333-4444-8555-966677778888","content":"continue"}"#,
            r#"{"type":"queue-operation","operation":"dequeue","timestamp":"2026-09-24T07:30:40.000Z","sessionId":"7e1f0a2b-3333-4444-8555-966677778888"}"#,
            r#"{"parentUuid":"d1000000-0000-4000-8000-000000000002","isSidechain":false,"userType":"external","sessionId":"7e1f0a2b-3333-4444-8555-966677778888","type":"user","isMeta":true,"message":{"role":"user","content":"<system-reminder>The user sent: continue</system-reminder>"},"uuid":"d1000000-0000-4000-8000-000000000003","timestamp":"2026-09-24T07:30:40.000Z"}"#,
            r#"{"parentUuid":"d1000000-0000-4000-8000-000000000003","isSidechain":false,"userType":"external","sessionId":"7e1f0a2b-3333-4444-8555-966677778888","type":"assistant","message":{"role":"assistant","model":"claude-sonnet-4-5","content":[{"type":"text","text":"Labels are printed."}]},"uuid":"d1000000-0000-4000-8000-000000000004","timestamp":"2026-09-24T07:31:00.000Z"}"#,
        ],
    );
    assert_eq!(user_words(&conversations), ["continue", "continue"]);
}

/// Astra 1310 re-check R2: an inline sidechain's reply logged between a
/// queued prompt's hand-over and the session's own copy of it does not
/// answer the prompt, so the copy is still found and the prompt lands once.
#[test]
fn a_sidechain_reply_between_a_queued_prompt_and_its_copy_lands_the_prompt_once() {
    let conversations = decode_log(
        HistorySource::ClaudeCode,
        "7e1f0a2b-3333-4444-8555-966677778888",
        &[
            r#"{"type":"queue-operation","operation":"enqueue","timestamp":"2026-09-24T07:30:05.000Z","sessionId":"7e1f0a2b-3333-4444-8555-966677778888","content":"Also check the frost warning."}"#,
            r#"{"type":"queue-operation","operation":"dequeue","timestamp":"2026-09-24T07:30:40.000Z","sessionId":"7e1f0a2b-3333-4444-8555-966677778888"}"#,
            r#"{"parentUuid":null,"isSidechain":true,"agentId":"ag1","userType":"external","sessionId":"7e1f0a2b-3333-4444-8555-966677778888","type":"assistant","message":{"role":"assistant","model":"claude-sonnet-4-5","content":[{"type":"text","text":"Three beds need mulch."}]},"uuid":"d2000000-0000-4000-8000-000000000001","timestamp":"2026-09-24T07:30:41.000Z"}"#,
            r#"{"parentUuid":null,"isSidechain":false,"userType":"external","sessionId":"7e1f0a2b-3333-4444-8555-966677778888","type":"attachment","uuid":"d2000000-0000-4000-8000-000000000002","timestamp":"2026-09-24T07:30:42.000Z","attachment":{"type":"queued_command","prompt":"Also check the frost warning.","commandMode":"prompt","origin":{"kind":"human"}}}"#,
            r#"{"parentUuid":"d2000000-0000-4000-8000-000000000002","isSidechain":false,"userType":"external","sessionId":"7e1f0a2b-3333-4444-8555-966677778888","type":"assistant","message":{"role":"assistant","model":"claude-sonnet-4-5","content":[{"type":"text","text":"No frost this week."}]},"uuid":"d2000000-0000-4000-8000-000000000003","timestamp":"2026-09-24T07:31:00.000Z"}"#,
        ],
    );
    assert_eq!(
        user_words(&conversations),
        ["Also check the frost warning."]
    );
}

/// Greptile 1310 (claude_code.rs:328): an import that read a live log after a
/// queued prompt's hand-over, but before its queued-command attachment was
/// logged, landed the prompt from the queue. Once the attachment is logged
/// the prompt is the same message, not a second one.
#[test]
fn a_claude_code_prompt_read_before_its_queued_copy_was_logged_lands_once() {
    let (_dir, vault, owner) = vault_and_owner();
    let lines = [
        r#"{"parentUuid":null,"isSidechain":false,"userType":"external","sessionId":"5c2d8e41-1111-4222-8333-944455556666","type":"user","message":{"role":"user","content":"Repot the basil."},"uuid":"e3000000-0000-4000-8000-000000000001","timestamp":"2026-09-25T06:00:00.000Z"}"#,
        r#"{"type":"queue-operation","operation":"enqueue","timestamp":"2026-09-25T06:00:05.000Z","sessionId":"5c2d8e41-1111-4222-8333-944455556666","content":"Move the pots to the sill too."}"#,
        r#"{"parentUuid":"e3000000-0000-4000-8000-000000000001","isSidechain":false,"userType":"external","sessionId":"5c2d8e41-1111-4222-8333-944455556666","type":"assistant","message":{"role":"assistant","model":"claude-sonnet-4-5","content":[{"type":"text","text":"The basil is repotted."}]},"uuid":"e3000000-0000-4000-8000-000000000002","timestamp":"2026-09-25T06:00:20.000Z"}"#,
        r#"{"type":"queue-operation","operation":"dequeue","timestamp":"2026-09-25T06:00:21.000Z","sessionId":"5c2d8e41-1111-4222-8333-944455556666"}"#,
        r#"{"parentUuid":"e3000000-0000-4000-8000-000000000002","isSidechain":false,"userType":"external","sessionId":"5c2d8e41-1111-4222-8333-944455556666","type":"attachment","uuid":"e3000000-0000-4000-8000-000000000003","timestamp":"2026-09-25T06:00:21.000Z","attachment":{"type":"queued_command","prompt":"Move the pots to the sill too.","commandMode":"prompt","origin":{"kind":"human"}}}"#,
        r#"{"parentUuid":"e3000000-0000-4000-8000-000000000003","isSidechain":false,"userType":"external","sessionId":"5c2d8e41-1111-4222-8333-944455556666","type":"assistant","message":{"role":"assistant","model":"claude-sonnet-4-5","content":[{"type":"text","text":"The pots are on the sill."}]},"uuid":"e3000000-0000-4000-8000-000000000004","timestamp":"2026-09-25T06:00:40.000Z"}"#,
    ];
    let stem = "5c2d8e41-1111-4222-8333-944455556666";
    let partway = decode_log(SOURCE, stem, &lines[..4]);
    assert_eq!(import_all(&vault, &owner, SOURCE, &partway), (3, 0, 0));
    let whole = decode_log(SOURCE, stem, &lines);
    assert_eq!(
        import_all(&vault, &owner, SOURCE, &whole),
        (1, 3, 0),
        "the attachment is the queued prompt already imported"
    );
    assert_eq!(vault.history_import_ledger_len(SOURCE).expect("ledger"), 4);
}

/// One ChatGPT conversation with the given mapping nodes `(id, parent, role,
/// time, text)`, showing `current`.
fn chatgpt_export(current: &str, nodes: &[(&str, Option<&str>, &str, f64, &str)]) -> String {
    let mapping: serde_json::Map<String, serde_json::Value> = nodes
        .iter()
        .map(|(id, parent, role, time, text)| {
            let children: Vec<&str> = nodes
                .iter()
                .filter(|node| node.1 == Some(*id))
                .map(|node| node.0)
                .collect();
            let message = (!role.is_empty()).then(|| {
                serde_json::json!({
                    "id": id,
                    "author": {"role": role},
                    "create_time": time,
                    "content": {"content_type": "text", "parts": [text]},
                    "recipient": "all",
                })
            });
            (
                (*id).to_owned(),
                serde_json::json!({"id": id, "parent": parent, "children": children, "message": message}),
            )
        })
        .collect();
    serde_json::json!([{
        "conversation_id": "c-kyoto",
        "title": "Kyoto in April",
        "create_time": 1_757_840_000.0,
        "current_node": current,
        "mapping": mapping,
    }])
    .to_string()
}

/// Astra 1310 #4, Greptile 1310 (chatgpt.rs:94): a regenerated answer, then
/// a later export where the person went back to the first answer and asked
/// on. Each new message lands beside the answer it follows, whichever branch
/// the app showed at each export.
#[test]
fn a_chatgpt_reply_lands_beside_the_answer_it_follows_after_a_branch_switch() {
    let (_dir, vault, owner) = vault_and_owner();
    let source = HistorySource::Chatgpt;
    let file = super::HistoryFile {
        stem: "conversations.json".to_owned(),
        parent: None,
    };
    let asked: [(&str, Option<&str>, &str, f64, &str); 4] = [
        ("root", None, "", 0.0, ""),
        (
            "u1",
            Some("root"),
            "user",
            1_757_840_010.0,
            "Is Osaka a good day trip from Kyoto?",
        ),
        (
            "a1",
            Some("u1"),
            "assistant",
            1_757_840_015.0,
            "Yes, fifteen minutes by Shinkansen.",
        ),
        (
            "a1b",
            Some("u1"),
            "assistant",
            1_757_840_090.0,
            "Yes; the JR Special Rapid is cheaper.",
        ),
    ];
    let first = source
        .decode(&chatgpt_export("a1b", &asked), &file)
        .expect("decode");
    assert_eq!(import_all(&vault, &owner, source, &first), (3, 0, 0));

    let mut later = asked.to_vec();
    later.extend([
        (
            "u2",
            Some("a1"),
            "user",
            1_757_926_400.0,
            "Which car has the window seats?",
        ),
        (
            "a2",
            Some("u2"),
            "assistant",
            1_757_926_410.0,
            "Seats A and E.",
        ),
        (
            "u3",
            Some("a1b"),
            "user",
            1_757_926_500.0,
            "Does the Rapid need a reservation?",
        ),
        (
            "a3",
            Some("u3"),
            "assistant",
            1_757_926_510.0,
            "No, every seat is unreserved.",
        ),
    ]);
    let grown = source
        .decode(&chatgpt_export("a2", &later), &file)
        .expect("decode");
    assert_eq!(import_all(&vault, &owner, source, &grown), (4, 3, 0));
    let landed_in = |native: &str| source_ledger_row(&vault, source, native).conversation;
    for (asked, answered) in [("u2", "a1"), ("a2", "a1"), ("u3", "a1b"), ("a3", "a1b")] {
        assert_eq!(
            landed_in(asked),
            landed_in(answered),
            "{asked} follows {answered}"
        );
    }
    assert_ne!(landed_in("a1"), landed_in("a1b"));
}

/// Astra 1310 re-check R3: a later export adds a regenerated answer with no
/// time beside the answer an earlier export landed. The first answer stays
/// the conversation's, the regeneration takes its own branch, and a follow-up
/// to the first answer lands beside it.
#[test]
fn a_chatgpt_regeneration_without_a_time_does_not_take_the_first_answers_place() {
    let (_dir, vault, owner) = vault_and_owner();
    let source = HistorySource::Chatgpt;
    let file = super::HistoryFile {
        stem: "conversations.json".to_owned(),
        parent: None,
    };
    let asked: [(&str, Option<&str>, &str, f64, &str); 3] = [
        ("root", None, "", 0.0, ""),
        (
            "u1",
            Some("root"),
            "user",
            1_757_840_010.0,
            "Is Osaka a good day trip from Kyoto?",
        ),
        (
            "a1",
            Some("u1"),
            "assistant",
            1_757_840_015.0,
            "Yes, fifteen minutes by Shinkansen.",
        ),
    ];
    let first = source
        .decode(&chatgpt_export("a1", &asked), &file)
        .expect("decode");
    assert_eq!(import_all(&vault, &owner, source, &first), (2, 0, 0));

    let mut later = asked.to_vec();
    later.extend([
        (
            "a1b",
            Some("u1"),
            "assistant",
            f64::NAN,
            "Yes; the JR Special Rapid is cheaper.",
        ),
        (
            "u2",
            Some("a1"),
            "user",
            1_757_926_400.0,
            "Which car has the window seats?",
        ),
    ]);
    let grown = source
        .decode(&chatgpt_export("u2", &later), &file)
        .expect("decode");
    assert_eq!(import_all(&vault, &owner, source, &grown), (2, 2, 0));
    let landed_in = |native: &str| source_ledger_row(&vault, source, native).conversation;
    assert_eq!(landed_in("u2"), landed_in("a1"), "u2 follows a1");
    assert_eq!(landed_in("a1"), landed_in("u1"));
    assert_ne!(landed_in("a1b"), landed_in("a1"));
}

/// Greptile 1310 (land.rs:391): a resumed session's copy and the original
/// carry one message id. Another import lands its revision between this
/// import's ledger read and its write; neither text may drop out of the
/// ledger.
#[test]
fn an_import_landing_between_another_imports_read_and_write_keeps_both_texts() {
    let (_dir, vault, owner) = vault_and_owner();
    let vault = std::rc::Rc::new(vault);
    let at = 1_700_000_000_000;
    let said = |conversation: &str, text: &str| {
        session(
            conversation,
            vec![message("m1", HistoryRole::User, text, at)],
        )
    };
    vault
        .import_history(
            &owner,
            SOURCE,
            &said("session-orig", "pack the tent"),
            IMPORTED_AT,
        )
        .expect("import");

    let concurrent = said("session-resumed-b", "pack the tent and the stove");
    let (other_vault, other_owner) = (std::rc::Rc::clone(&vault), owner.clone());
    super::land::BETWEEN_READ_AND_WRITE.with_borrow_mut(|between| {
        *between = Some(Box::new(move || {
            let report = other_vault
                .import_history(&other_owner, SOURCE, &concurrent, IMPORTED_AT)
                .expect("concurrent import");
            assert_eq!(report.changed, 1);
        }));
    });
    let report = vault
        .import_history(
            &owner,
            SOURCE,
            &said("session-resumed-a", "pack the tent and the maps"),
            IMPORTED_AT,
        )
        .expect("import");
    assert_eq!((report.changed, report.refused), (1, 0));
    assert_eq!(
        ledger_row(&vault, "m1").hashes.len(),
        3,
        "the original, the concurrent revision and this one"
    );
}

/// Greptile 1310 (plan.rs:32): one dry run over two sources whose message
/// ids happen to match counts each as its own, as the import keeps them.
#[test]
fn a_dry_run_over_two_sources_keeps_their_messages_apart() {
    let (dir, vault, _owner) = vault_and_owner();
    drop(vault);
    let snapshot = super::HistoryLedgerSnapshot::open(dir.path()).expect("read-only ledger");
    let said = session(
        "conversation-1",
        vec![message(
            "m1",
            HistoryRole::User,
            "Hello there",
            1_700_000_000_000,
        )],
    );
    let mut dry_run = super::HistoryDryRun::default();
    let chatgpt = snapshot
        .plan(HistorySource::Chatgpt, &said, &mut dry_run)
        .expect("plan");
    let claude = snapshot
        .plan(HistorySource::Claude, &said, &mut dry_run)
        .expect("plan");
    assert_eq!((chatgpt.new, chatgpt.skipped), (1, 0));
    assert_eq!((claude.new, claude.skipped), (1, 0));
}
