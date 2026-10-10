//! ARCH-0027: an imported coding session keeps the folder it ran in and when
//! it started, and importing its log again adds nothing it already holds.

use super::*;
use crate::VaultConfig;
use crate::memory::{WitnessAuthor, WitnessMessage, WitnessTurn};
use crate::registry::{ENTITY_TYPE_MESSAGE, ENTITY_TYPE_TURN};
use crate::store::GateDecisionId;

const IMPORTED_AT: u64 = 1_800_000_000;
const FOLDER: &str = "/home/dev/projects/garden";

/// A Claude Code session that started at 2026-09-25T06:00:00Z.
const CLAUDE_STARTED: u64 = 1_790_316_000;
const CLAUDE_LOG: [&str; 2] = [
    r#"{"parentUuid":null,"isSidechain":false,"userType":"external","cwd":"/home/dev/projects/garden","sessionId":"5c2d8e41-1111-4222-8333-944455556666","type":"user","message":{"role":"user","content":"Repot the basil."},"uuid":"e3000000-0000-4000-8000-000000000001","timestamp":"2026-09-25T06:00:00.000Z"}"#,
    r#"{"parentUuid":"e3000000-0000-4000-8000-000000000001","isSidechain":false,"userType":"external","cwd":"/home/dev/projects/garden","sessionId":"5c2d8e41-1111-4222-8333-944455556666","type":"assistant","message":{"role":"assistant","model":"claude-sonnet-4-5","content":[{"type":"text","text":"The basil is repotted."}]},"uuid":"e3000000-0000-4000-8000-000000000002","timestamp":"2026-09-25T06:00:20.000Z"}"#,
];

/// A Codex session that started at 2026-09-20T10:00:00Z; its first message
/// came seven seconds later.
const CODEX_STARTED: u64 = 1_789_898_400;
const CODEX_FIRST_MESSAGE: u64 = 1_789_898_407;
const CODEX_ROLLOUT: [&str; 3] = [
    r#"{"timestamp":"2026-09-20T10:00:00.000Z","type":"session_meta","payload":{"id":"s-garden","timestamp":"2026-09-20T10:00:00.000Z","cwd":"/home/dev/projects/garden","cli_version":"0.100.0"}}"#,
    r#"{"timestamp":"2026-09-20T10:00:07.000Z","type":"response_item","payload":{"type":"message","role":"user","content":[{"type":"input_text","text":"Water the tomatoes"}]}}"#,
    r#"{"timestamp":"2026-09-20T10:00:09.000Z","type":"response_item","payload":{"type":"message","role":"assistant","content":[{"type":"output_text","text":"The tomatoes are watered."}]}}"#,
];

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

fn decode(source: HistorySource, stem: &str, lines: &[&str]) -> HistoryConversation {
    let file = super::super::HistoryFile {
        stem: stem.to_owned(),
        parent: None,
    };
    let mut conversations = source.decode(&lines.join("\n"), &file).expect("decode");
    assert_eq!(conversations.len(), 1);
    conversations.remove(0)
}

fn import(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    source: HistorySource,
    conversation: &HistoryConversation,
    at: u64,
) -> HistoryImportReport {
    let report = vault
        .import_history(owner, source, conversation, at)
        .expect("import");
    assert_eq!(report.refused, 0, "{report:?}");
    report
}

/// Conversation, turn and message rows in the vault.
fn rows(vault: &Vault) -> [usize; 3] {
    [
        ENTITY_TYPE_CONVERSATION,
        ENTITY_TYPE_TURN,
        ENTITY_TYPE_MESSAGE,
    ]
    .map(|kind| vault.entities_by_type(kind).expect("list rows").len())
}

fn conversation_id(source: HistorySource, conversation: &HistoryConversation) -> EntityId {
    derive(
        derived_domains::HISTORY_CONVERSATION,
        &[source.source_id(), &conversation.native_id],
    )
    .expect("conversation id")
}

fn folder(vault: &Vault, id: EntityId) -> Option<String> {
    vault
        .conversation_body(id)
        .expect("conversation body")
        .extra
        .get(IMPORT_CWD_KEY)
        .and_then(|value| value.as_str().map(str::to_owned))
}

fn at(second: u64) -> TimeRange {
    TimeRange {
        start: second,
        end: second,
    }
}

/// The folder and start time come from the log: each line of a Claude Code
/// session, a Codex rollout's own meta. A second import of the same log adds
/// no row and does not write the conversation again.
#[test]
fn an_imported_session_keeps_its_folder_and_start_and_a_second_import_adds_no_row() {
    for (source, stem, log, started) in [
        (
            HistorySource::ClaudeCode,
            "5c2d8e41-1111-4222-8333-944455556666",
            &CLAUDE_LOG[..],
            CLAUDE_STARTED,
        ),
        (
            HistorySource::Codex,
            "rollout-2026-09-20T10-00-00-s-garden",
            &CODEX_ROLLOUT[..],
            CODEX_STARTED,
        ),
    ] {
        let (_dir, vault, owner) = vault_and_owner();
        let conversation = decode(source, stem, log);
        assert_eq!(conversation.cwd.as_deref(), Some(FOLDER), "{source:?}");
        let first = import(&vault, &owner, source, &conversation, IMPORTED_AT);
        assert_eq!(first.new, 2, "{source:?}");
        let id = conversation_id(source, &conversation);
        assert_eq!(folder(&vault, id).as_deref(), Some(FOLDER), "{source:?}");
        assert_eq!(vault.get_occurred(&id).expect("occurred"), at(started));

        let before = rows(&vault);
        let learned = vault.get_learned_at(&id).expect("learned at");
        let again = import(&vault, &owner, source, &conversation, IMPORTED_AT + 60);
        assert_eq!((again.new, again.changed, again.skipped), (0, 0, 2));
        assert_eq!(
            rows(&vault),
            before,
            "{source:?}: a second import added rows"
        );
        assert_eq!(
            vault.get_learned_at(&id).expect("learned at"),
            learned,
            "{source:?}: a second import wrote the conversation again"
        );
    }
}

/// A vault imported before the import kept the folder: importing the same
/// log again fills in the folder and the start time on the conversation, and
/// adds no row. The import after that writes nothing.
#[test]
fn importing_a_log_again_fills_in_what_an_earlier_import_left_out() {
    let (_dir, vault, owner) = vault_and_owner();
    let source = HistorySource::Codex;
    let conversation = decode(
        source,
        "rollout-2026-09-20T10-00-00-s-garden",
        &CODEX_ROLLOUT,
    );
    // What the earlier import landed: the conversation occurred with its
    // first message, and named no folder.
    let mut earlier = conversation.clone();
    earlier.cwd = None;
    earlier.own_started_at_ms = None;
    import(&vault, &owner, source, &earlier, IMPORTED_AT);
    let id = conversation_id(source, &conversation);
    assert_eq!(folder(&vault, id), None);
    assert_eq!(
        vault.get_occurred(&id).expect("occurred"),
        at(CODEX_FIRST_MESSAGE)
    );
    let before = rows(&vault);

    let again = import(&vault, &owner, source, &conversation, IMPORTED_AT + 60);
    assert_eq!((again.new, again.changed, again.skipped), (0, 0, 2));
    assert_eq!(folder(&vault, id).as_deref(), Some(FOLDER));
    assert_eq!(
        vault.get_occurred(&id).expect("occurred"),
        at(CODEX_STARTED)
    );
    assert_eq!(rows(&vault), before, "the fill-in added rows");

    let learned = vault.get_learned_at(&id).expect("learned at");
    import(&vault, &owner, source, &conversation, IMPORTED_AT + 120);
    assert_eq!(vault.get_learned_at(&id).expect("learned at"), learned);
}

/// A resumed Claude Code session's log starts with copies of the original's
/// lines, times and all. Each conversation occurs when its own words began:
/// the resumed one with its first message of its own, not the copies'.
#[test]
fn a_resumed_session_occurs_when_its_own_words_began() {
    const RESUMED: &str = "7f3e9d10-3333-4444-8555-966677778888";
    /// 2026-09-26T09:00:00Z, the resumed session's first own message.
    const RESUMED_STARTED: u64 = 1_790_413_200;
    let (_dir, vault, owner) = vault_and_owner();
    let source = HistorySource::ClaudeCode;
    let original = decode(source, "5c2d8e41-1111-4222-8333-944455556666", &CLAUDE_LOG);
    let copies =
        CLAUDE_LOG.map(|line| line.replace("5c2d8e41-1111-4222-8333-944455556666", RESUMED));
    let own = [
        r#"{"parentUuid":"e3000000-0000-4000-8000-000000000002","isSidechain":false,"userType":"external","cwd":"/home/dev/projects/garden","sessionId":"7f3e9d10-3333-4444-8555-966677778888","type":"user","message":{"role":"user","content":"Now the mint."},"uuid":"e4000000-0000-4000-8000-000000000001","timestamp":"2026-09-26T09:00:00.000Z"}"#,
        r#"{"parentUuid":"e4000000-0000-4000-8000-000000000001","isSidechain":false,"userType":"external","cwd":"/home/dev/projects/garden","sessionId":"7f3e9d10-3333-4444-8555-966677778888","type":"assistant","message":{"role":"assistant","model":"claude-sonnet-4-5","content":[{"type":"text","text":"The mint is repotted."}]},"uuid":"e4000000-0000-4000-8000-000000000002","timestamp":"2026-09-26T09:00:30.000Z"}"#,
    ];
    let lines: Vec<&str> = copies.iter().map(String::as_str).chain(own).collect();
    let resumed = decode(source, RESUMED, &lines);
    import(&vault, &owner, source, &original, IMPORTED_AT);
    let report = import(&vault, &owner, source, &resumed, IMPORTED_AT);
    assert_eq!((report.new, report.skipped), (2, 2), "the copies land once");

    let occurred = |conversation| {
        vault
            .get_occurred(&conversation_id(source, conversation))
            .expect("occurred")
    };
    assert_eq!(occurred(&original), at(CLAUDE_STARTED));
    assert_eq!(occurred(&resumed), at(RESUMED_STARTED));
    assert_eq!(
        folder(&vault, conversation_id(source, &resumed)).as_deref(),
        Some(FOLDER)
    );
}

/// The ids derive from public source ids, so a plain writer can claim one
/// first; the import refuses to land there (ARCH-0027). It must not write the
/// session's folder or start time on that plain conversation either.
#[test]
fn an_import_leaves_a_plain_conversation_at_its_derived_id_alone() {
    let (_dir, vault, owner) = vault_and_owner();
    let source = HistorySource::Codex;
    let conversation = decode(
        source,
        "rollout-2026-09-20T10-00-00-s-garden",
        &CODEX_ROLLOUT,
    );
    let id = conversation_id(source, &conversation);
    vault
        .memory(owner.actor(), EdgeActorClass::Human)
        .witness(&WitnessTurn {
            conversation_ref: id.to_hex(),
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
    let body = vault.get(&id).expect("read the plain conversation");
    let learned = vault.get_learned_at(&id).expect("learned at");

    let report = vault
        .import_history(&owner, source, &conversation, IMPORTED_AT + 60)
        .expect("import");
    assert_eq!((report.new, report.refused), (0, 2));
    assert_eq!(vault.get(&id).expect("read it again"), body);
    assert_eq!(vault.get_occurred(&id).expect("occurred"), at(IMPORTED_AT));
    assert_eq!(vault.get_learned_at(&id).expect("learned at"), learned);
}

/// In a shared vault the fill-in is a content write like each turn the import
/// lands: an owner whose grant there no longer lets them write content gets a
/// refusal, and the conversation keeps its body, time and learned time.
#[test]
fn a_fill_in_needs_the_shared_vault_content_write_a_turn_needs() {
    use crate::batch::ENTITY_METADATA_HEADER_LEN;
    use crate::federation::{
        FederationGrantRole, InitialSharedMember, SharedVaultPreset, decode_federation_grant_body,
        encode_federation_grant_body, scope_codec,
    };

    let (_dir, vault, owner) = vault_and_owner();
    let source = HistorySource::Codex;
    let conversation = decode(
        source,
        "rollout-2026-09-20T10-00-00-s-garden",
        &CODEX_ROLLOUT,
    );
    let mut earlier = conversation.clone();
    earlier.cwd = None;
    earlier.own_started_at_ms = None;
    import(&vault, &owner, source, &earlier, IMPORTED_AT);
    let id = conversation_id(source, &conversation);

    // The vault is shared, and the owner's grant there is cut to reading.
    let other = EntityId::now();
    vault
        .put_entity(
            &other,
            crate::registry::ENTITY_TYPE_PERSON,
            at(1),
            1,
            b"another owner",
        )
        .expect("put another owner");
    vault
        .initialize_shared_vault(
            &owner,
            42,
            Some(SharedVaultPreset::Team),
            &[InitialSharedMember {
                member_ref: other,
                role: Some(FederationGrantRole::Owner),
            }],
            10,
        )
        .expect("share the vault");
    let creation = vault
        .shared_vault_creation()
        .expect("read the shared vault")
        .expect("a shared vault");
    for grant_ref in creation.grant_refs {
        let grant_id = EntityId::from_hex(&grant_ref).expect("grant id");
        let raw = vault.get_raw(&grant_id).expect("read a grant").expect("grant");
        let mut grant = decode_federation_grant_body(&raw[ENTITY_METADATA_HEADER_LEN..])
            .expect("decode a grant");
        if grant.member_ref != owner.actor() {
            continue;
        }
        grant.authority_scope = scope_codec::read_preset();
        vault
            .batch()
            .put_replicated(
                &grant_id,
                crate::registry::ENTITY_TYPE_FEDERATION_GRANT,
                at(11),
                11,
                &encode_federation_grant_body(&grant).expect("encode the grant"),
            )
            .commit()
            .expect("cut the owner's grant to reading");
    }
    let body = vault.get(&id).expect("read the conversation");
    let learned = vault.get_learned_at(&id).expect("learned at");

    let report = vault
        .import_history(&owner, source, &conversation, IMPORTED_AT + 60)
        .expect("import");
    assert!(!report.refusal_reasons.is_empty(), "{report:?}");
    assert_eq!(vault.get(&id).expect("read it again"), body);
    assert_eq!(folder(&vault, id), None);
    assert_eq!(
        vault.get_occurred(&id).expect("occurred"),
        at(CODEX_FIRST_MESSAGE)
    );
    assert_eq!(vault.get_learned_at(&id).expect("learned at"), learned);
}
