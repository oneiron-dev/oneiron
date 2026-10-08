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
    }
}

/// The ledger row of one imported message. Its read transaction closes before
/// the caller opens another: one thread holds one LMDB read at a time.
fn ledger_row(vault: &Vault, native: &str) -> ledger::LedgerRow {
    let txn = vault.store.env.read_txn().expect("txn");
    ledger::get(&vault.store, &txn, SOURCE, native)
        .expect("ledger read")
        .expect("ledger row")
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
    // A ChatGPT export whose selected answer later changes: the run that held
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
