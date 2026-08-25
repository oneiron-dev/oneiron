//! BRIDGE-01 acceptance tests, engine side. TS-layer ACs (bun build/test,
//! index.d.ts shape) are owner-deferred with the eiri repo this wave.
//!
//! The harness deliberately KEEPS the default policy manifest seeded by
//! `Vault::open` (unlike the legacy `test_util` opener) so the write gate is
//! live — production reality for the bridge.

use super::reads::*;
use super::structural::*;
use super::support::*;
use super::witness::*;
use super::*;
use crate::batch::{ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader};
use crate::claim::{ClaimApprovalStatus, ClaimLifecycleStatus};
use crate::config::VaultConfig;
use crate::dreamer_runner::DreamerConsolidationScope;
use crate::edge::{EdgeActorClass, EdgeKind};
use crate::entity_id::EntityId;
use crate::error::{Error, ErrorKind};
use crate::note::{NoteKind, TakeTarget};
use crate::registry::{
    ENTITY_TYPE_ASSET, ENTITY_TYPE_CLAIM, ENTITY_TYPE_CONVERSATION, ENTITY_TYPE_MESSAGE,
    ENTITY_TYPE_NOTE, ENTITY_TYPE_PERSON, ENTITY_TYPE_TASK, ENTITY_TYPE_TURN,
};
use crate::temporal::TimeRange;
use rmpv::Value;

pub(super) fn open_vault() -> (tempfile::TempDir, crate::Vault) {
    let dir = tempfile::tempdir().expect("tempdir");
    let vault = crate::Vault::open(dir.path(), VaultConfig::default()).expect("open vault");
    (dir, vault)
}

pub(super) fn test_time(at: u64) -> TimeRange {
    TimeRange { start: at, end: at }
}

/// Puts a PERSON entity usable as a facade actor (the gated candidate path
/// validates actor existence + class).
pub(super) fn put_person(vault: &crate::Vault, seed: u8) -> EntityId {
    let id = EntityId::from_bytes([seed; 16]).expect("person id");
    vault
        .put_entity(&id, ENTITY_TYPE_PERSON, test_time(1), 1, b"facade person")
        .expect("put person");
    id
}

pub(super) fn facade_for(vault: &crate::Vault, actor: EntityId) -> Memory<'_> {
    vault.memory(actor, EdgeActorClass::Human)
}

pub(super) fn claim_input(
    predicate: &str,
    subject: &EntityId,
    source: &str,
    value: serde_json::Value,
) -> ClaimInput {
    ClaimInput {
        id: None,
        predicate: predicate.to_owned(),
        subject_ref: subject.to_hex(),
        value,
        confidence: 1.0,
        source: source.to_owned(),
        world_ref: None,
        scope: None,
        valid_from: None,
        valid_to: None,
        occurred_at: Some(100),
        learned_at: Some(100),
        salience: None,
    }
}

/// Short refs are `"<short_id>:<body-hash>"`; the hash suffix advances when
/// a claim body is rewritten (supersede/retract), so entity identity is
/// compared on the stable short-id part.
pub(super) fn short_id_part(reference: &str) -> &str {
    reference.split(':').next().unwrap_or(reference)
}

pub(super) fn witness_message(order: u32, author: WitnessAuthor, content: &str) -> WitnessMessage {
    WitnessMessage {
        id: None,
        author,
        message_type: "dialogue".to_owned(),
        content: content.to_owned(),
        metadata: None,
        is_visible: true,
        order,
    }
}

// ── actor key grammar (design §4.3) ─────────────────────────────────────

#[test]
fn actor_key_grammar_parses_and_fails_closed() {
    let (_dir, vault) = open_vault();
    let person = put_person(&vault, 0x11);

    let (actor, class) =
        parse_actor_key(&vault, &format!("human:{}", person.to_hex())).expect("parse actor key");
    assert_eq!(actor, person);
    assert_eq!(class, EdgeActorClass::Human);

    let (_, agent_class) =
        parse_actor_key(&vault, &format!("agent:{}", person.to_hex())).expect("agent key");
    assert_eq!(agent_class, EdgeActorClass::Agent);

    for malformed in [
        "human",
        "wizard:0011001100110011001100110011aabb",
        "human:not-a-ref",
        "",
    ] {
        let err = parse_actor_key(&vault, malformed).expect_err("malformed key must fail");
        assert_eq!(err.code, FACADE_CODE_BAD_REQUEST, "key {malformed:?}");
        assert!(!err.suggestions.is_empty());
    }
}

// ── witness (AC-3, B2 create-or-get) ────────────────────────────────────

#[test]
fn witness_writes_turn_messages_edges_and_text() {
    let (_dir, vault) = open_vault();
    let actor = put_person(&vault, 0x21);
    let facade = facade_for(&vault, actor);

    let conversation_hex = EntityId::from_bytes([0x22; 16]).expect("conv id").to_hex();
    let receipt = facade
        .witness(&WitnessTurn {
            conversation_ref: conversation_hex.clone(),
            turn_ref: None,
            // ONE-1767: one call = ONE non-system speaker. Mixed-author turns
            // are witnessed as consecutive single-speaker turns, so this row
            // set is all `User` (a `Companion` row here is a bad request).
            messages: vec![
                witness_message(0, WitnessAuthor::User, "quantum banana ledger"),
                witness_message(1, WitnessAuthor::User, "second owner row"),
                witness_message(2, WitnessAuthor::User, "closing note"),
            ],
            occurred_at: 500,
        })
        .expect("witness turn");

    assert_eq!(receipt.message_short_ids.len(), 3);
    assert!(receipt.receipt_ref.starts_with("witness:"));

    // One TURN + three MESSAGE entities + the CONVERSATION exist with the
    // right kinds.
    let turn = facade
        .get_entity(&receipt.turn_short_id)
        .expect("get turn")
        .expect("turn exists");
    assert_eq!(turn.kind, "TURN");
    let conversation = facade
        .get_entity(&conversation_hex)
        .expect("get conversation")
        .expect("conversation exists");
    assert_eq!(conversation.kind, "CONVERSATION");

    // ONE-1767: the minted TURN body is EXACTLY the additive `speaker` entry
    // (turn-level grouping fact; content stays on the MESSAGE children), and
    // the structural TURN -> CONVERSATION `ChildOf` edge is minted with the
    // row — without it `plan_partitions` can never group the turn.
    let turn_body = turn.body.clone().expect("turn body decodes");
    assert_eq!(
        turn_body,
        serde_json::json!({"speaker": "user"}),
        "TURN body carries exactly the additive speaker entry"
    );
    let conversation_body = conversation.body.expect("conversation body");
    assert_eq!(
        conversation_body,
        serde_json::json!({}),
        "CONVERSATION body stays an empty container map"
    );
    let turn_id = EntityId::from_hex(&turn.id_hex).expect("turn hex id");
    let conversation_id = EntityId::from_hex(&conversation_hex).expect("conversation hex id");
    let has_child_of_conversation = vault
        .edges_out(&turn_id)
        .expect("turn edges out")
        .into_iter()
        .any(|edge| edge.kind == EdgeKind::ChildOf && edge.target == conversation_id);
    assert!(
        has_child_of_conversation,
        "TURN is minted with its ChildOf(conversation) edge"
    );

    // Edges + typed read-back envelope per message.
    for (index, short_id) in receipt.message_short_ids.iter().enumerate() {
        let view = facade
            .get_entity(short_id)
            .expect("get message")
            .expect("message exists");
        assert_eq!(view.kind, "MESSAGE");
        assert_eq!(view.occurred_start, 500);
        assert_eq!(view.learned_at, 500);
        let body = view.body.expect("message body decodes");
        assert_eq!(body["order"], serde_json::json!(index as u64));
        assert_eq!(body["is_visible"], serde_json::json!(true));
        assert_eq!(body["type"], serde_json::json!("dialogue"));
        // ONE-1767: the MESSAGE body's `author` string encoding is untouched
        // (facade vocabulary `user`, NOT the canonical Dreamer role — that
        // lives only on the TURN's `speaker`).
        assert_eq!(body["author"], serde_json::json!("user"));

        let id = EntityId::from_hex(&view.id_hex).expect("hex id");
        let edges = vault.edges_out(&id).expect("edges out");
        let kinds: Vec<EdgeKind> = edges.iter().map(|edge| edge.kind).collect();
        assert!(
            kinds.contains(&EdgeKind::PartOf),
            "PartOf edge on {short_id}"
        );
        assert!(
            kinds.contains(&EdgeKind::BelongsTo),
            "BelongsTo edge on {short_id}"
        );
        assert!(
            kinds.contains(&EdgeKind::AuthoredBy),
            "AuthoredBy edge on {short_id}"
        );
    }

    // BM25 finds the content.
    let hits = vault.search_text("banana", 10).expect("search");
    let first_message = facade
        .get_entity(&receipt.message_short_ids[0])
        .unwrap()
        .unwrap();
    assert!(
        hits.iter()
            .any(|hit| hit.id.to_hex() == first_message.id_hex),
        "witnessed content must be BM25-findable"
    );
}

#[test]
fn witness_create_or_get_reuses_containers_and_skips_system_author_edge() {
    let (_dir, vault) = open_vault();
    let actor = put_person(&vault, 0x31);
    let facade = facade_for(&vault, actor);

    let conversation_hex = EntityId::from_bytes([0x32; 16]).expect("conv").to_hex();
    let turn_hex = EntityId::from_bytes([0x33; 16]).expect("turn").to_hex();

    let first = facade
        .witness(&WitnessTurn {
            conversation_ref: conversation_hex.clone(),
            turn_ref: Some(turn_hex.clone()),
            messages: vec![witness_message(0, WitnessAuthor::User, "first half")],
            occurred_at: 600,
        })
        .expect("first witness");
    let turn_id = EntityId::from_hex(&turn_hex).unwrap();
    let conversation_id = EntityId::from_hex(&conversation_hex).unwrap();
    let turn_raw_before = vault.get_raw(&turn_id).unwrap().expect("turn raw");
    let conversation_raw_before = vault
        .get_raw(&conversation_id)
        .unwrap()
        .expect("conversation raw");
    // Second call APPENDS permitted System interleave to the same TURN (a
    // System-only call carries no grouping speaker, so it must match the
    // stored speaker vacuously and succeed).
    let second = facade
        .witness(&WitnessTurn {
            conversation_ref: conversation_hex,
            turn_ref: Some(turn_hex.clone()),
            messages: vec![witness_message(1, WitnessAuthor::System, "system row")],
            occurred_at: 601,
        })
        .expect("second witness");
    assert_eq!(first.turn_short_id, second.turn_short_id);

    let turns = vault.entities_by_type(ENTITY_TYPE_TURN).expect("turns");
    assert_eq!(turns.len(), 1, "turn must not be duplicated");
    let conversations = vault
        .entities_by_type(ENTITY_TYPE_CONVERSATION)
        .expect("conversations");
    assert_eq!(
        conversations.len(),
        1,
        "conversation must not be duplicated"
    );

    // ONE-1767: the TURN row no longer survives an append byte-identically —
    // it is RE-PUT with the same body and occurred interval but a strictly
    // newer `learned_at` so a post-watermark append re-dirties the turn for
    // consolidation. The CONVERSATION row stays byte-identical
    // (idempotency-critical for the §3.5 hash checks).
    let turn_raw_after = vault.get_raw(&turn_id).unwrap().expect("turn raw after");
    let header_before = EntityMetadataHeader::parse(&turn_raw_before).expect("turn header before");
    let header_after = EntityMetadataHeader::parse(&turn_raw_after).expect("turn header after");
    assert_eq!(
        &turn_raw_after[ENTITY_METADATA_HEADER_LEN..],
        &turn_raw_before[ENTITY_METADATA_HEADER_LEN..],
        "reused TURN body must stay byte-identical"
    );
    assert_eq!(
        (header_after.occurred_start, header_after.occurred_end),
        (header_before.occurred_start, header_before.occurred_end),
        "reused TURN keeps its original occurred interval"
    );
    assert!(
        header_after.learned_at > header_before.learned_at,
        "append re-dirties the TURN: learned_at must strictly advance"
    );
    assert_eq!(
        vault
            .get_raw(&conversation_id)
            .unwrap()
            .expect("conversation raw after"),
        conversation_raw_before,
        "reused CONVERSATION must be byte-identical"
    );

    // System-authored rows get no AuthoredBy edge (design §2.1).
    let system_view = facade
        .get_entity(&second.message_short_ids[0])
        .unwrap()
        .expect("system message");
    let system_id = EntityId::from_hex(&system_view.id_hex).unwrap();
    let kinds: Vec<EdgeKind> = vault
        .edges_out(&system_id)
        .expect("edges")
        .iter()
        .map(|edge| edge.kind)
        .collect();
    assert!(!kinds.contains(&EdgeKind::AuthoredBy));
    assert!(kinds.contains(&EdgeKind::PartOf));

    // Type mismatch on a container ref fails closed.
    let err = facade
        .witness(&WitnessTurn {
            conversation_ref: turn_hex,
            turn_ref: None,
            messages: vec![witness_message(0, WitnessAuthor::User, "x")],
            occurred_at: 602,
        })
        .expect_err("turn id passed as conversation must fail");
    assert_eq!(err.code, FACADE_CODE_BAD_REQUEST);
}

// ── ONE-1767 · TURN speaker: single-speaker invariant + append re-dirty ──

/// COUNT of meso PARTITION attempts on the queue (any state). The close also
/// registers its distill job and the substitution-mine pass on this queue,
/// so the attempt KIND alone does not name a consolidation round; the
/// payload's `attempt_type` does.
fn meso_partition_attempt_count(vault: &crate::Vault) -> usize {
    crate::attempt_queue::AttemptQueue::new(vault)
        .list()
        .expect("attempt list")
        .into_iter()
        .filter(|attempt| attempt.kind == crate::DREAMER_CONSOLIDATION_MESO_ATTEMPT_KIND)
        .map(|attempt| {
            crate::dreamer_runner::decode_dreamer_attempt_payload(&attempt.payload)
                .expect("attempt payload decodes")
        })
        .filter(|payload| payload.attempt_type == DreamerConsolidationScope::Meso.as_str())
        .count()
}

/// The production close's planning trio, run exactly as the driver runs it:
/// `read_watermark` -> `scan_dirty_turns` -> `plan_partitions`, folded into
/// the `end_session_with_wake` payload.
fn production_close_wake(vault: &crate::Vault) -> crate::SessionEndWake {
    let scope = DreamerConsolidationScope::Meso;
    let watermark = crate::read_watermark(vault, scope).expect("watermark");
    let dirty = crate::scan_dirty_turns(vault, scope, &watermark, usize::MAX).expect("scan");
    let advance_watermark_to = dirty.iter().map(|turn| turn.learned_at).max();
    let planned_turn_ids = dirty.iter().map(|turn| turn.turn_id).collect();
    let plans = crate::plan_partitions(vault, scope, &dirty, &watermark).expect("plan");
    crate::SessionEndWake {
        plans,
        planned_watermark: watermark.last_learned_at,
        planned_turn_ids,
        advance_watermark_to,
    }
}

fn mint_open_session(vault: &crate::Vault, at: u64) -> EntityId {
    match vault.mint_session(at).expect("mint session") {
        crate::session_lifecycle::SessionMintOutcome::Minted(id) => id,
        other => panic!("expected a fresh mint, got {other:?}"),
    }
}

/// The mandatory facade-shaped acceptance: a CONVERSATION and a
/// Companion-authored TURN minted ONLY through `Memory::witness` (body
/// and `ChildOf` edge included) feed the production SessionEnd close shape —
/// without the stamped `speaker` the scanner's role gate drops the turn, and
/// without the edge `plan_partitions` cannot group it.
#[test]
fn witness_facade_turn_enqueues_meso_on_session_close() {
    let (_dir, vault) = open_vault();
    let actor = put_person(&vault, 0x61);
    let facade = facade_for(&vault, actor);
    let session = mint_open_session(&vault, 400);

    let conversation_hex = EntityId::from_bytes([0x62; 16]).expect("conv id").to_hex();
    let receipt = facade
        .witness(&WitnessTurn {
            conversation_ref: conversation_hex.clone(),
            turn_ref: None,
            messages: vec![witness_message(
                0,
                WitnessAuthor::Companion,
                "companion turn headed for the close",
            )],
            occurred_at: 500,
        })
        .expect("witness turn");

    // The grouping fact is the canonical Dreamer ROLE string, not the facade
    // vocabulary: Companion stamps `assistant` (what `dreamer_turn_role`
    // admits), never `companion`.
    let turn = facade
        .get_entity(&receipt.turn_short_id)
        .expect("get turn")
        .expect("turn exists");
    assert_eq!(
        turn.body.expect("turn body"),
        serde_json::json!({"speaker": "assistant"}),
        "TURN body carries exactly the additive speaker entry"
    );
    let turn_id = EntityId::from_hex(&turn.id_hex).expect("turn id");
    let conversation_id = EntityId::from_hex(&conversation_hex).expect("conversation id");
    assert!(
        vault
            .edges_out(&turn_id)
            .expect("turn edges")
            .iter()
            .any(|edge| edge.kind == EdgeKind::ChildOf && edge.target == conversation_id),
        "the witness mint carries the TURN -> CONVERSATION ChildOf edge"
    );

    assert_eq!(
        meso_partition_attempt_count(&vault),
        0,
        "no consolidation attempt exists before the close"
    );

    // The PRODUCTION close shape: read watermark -> scan dirty turns ->
    // plan partitions -> end the session with that wake.
    let wake = production_close_wake(&vault);
    assert_eq!(
        wake.plans.len(),
        1,
        "one facade-minted dirty conversation, one partition plan"
    );
    assert_eq!(wake.planned_turn_ids, vec![turn_id]);
    assert_eq!(wake.plans[0].key.conversation_ref, conversation_id);
    let ended = vault
        .end_session_with_wake(&session, crate::SessionClosePredicate::Explicit, 900, &wake)
        .expect("end session")
        .expect("session ended");
    assert_eq!(ended.session, session);
    assert_eq!(
        meso_partition_attempt_count(&vault),
        1,
        "the facade-minted turn enqueued the Meso ATTEMPT at session close"
    );
}

/// One call carries ONE non-system speaker. Both bad shapes — the User +
/// Companion mint and the cross-speaker append — fail with the facade
/// bad-request code, and the refusal is ATOMIC: no rows, no edges, no text
/// postings, no turn rewrite, no session-activity bump survive either arm.
#[test]
fn witness_rejects_mixed_non_system_speakers_atomically() {
    let (_dir, vault) = open_vault();
    let actor = put_person(&vault, 0x63);
    let facade = facade_for(&vault, actor);
    mint_open_session(&vault, 400);

    // Arm one: the User + Companion MINT.
    let conversation_hex = EntityId::from_bytes([0x64; 16]).expect("conv id").to_hex();
    let err = facade
        .witness(&WitnessTurn {
            conversation_ref: conversation_hex.clone(),
            turn_ref: None,
            messages: vec![
                witness_message(0, WitnessAuthor::User, "owner row in the ledger"),
                witness_message(
                    1,
                    WitnessAuthor::Companion,
                    "companion row in the same call",
                ),
            ],
            occurred_at: 500,
        })
        .expect_err("a mixed non-system mint is a bad request");
    assert_eq!(err.code, FACADE_CODE_BAD_REQUEST);
    assert!(
        vault
            .entities_by_type(ENTITY_TYPE_TURN)
            .expect("turns")
            .is_empty(),
        "the refused mint left no TURN"
    );
    assert!(
        vault
            .entities_by_type(ENTITY_TYPE_MESSAGE)
            .expect("messages")
            .is_empty(),
        "the refused mint left no MESSAGE rows"
    );
    assert!(
        vault
            .entities_by_type(ENTITY_TYPE_CONVERSATION)
            .expect("conversations")
            .is_empty(),
        "the refused mint left no CONVERSATION"
    );
    assert!(
        vault.search_text("ledger", 10).expect("search").is_empty(),
        "the refused mint left no text postings"
    );
    let open = vault
        .open_session()
        .expect("open session read")
        .expect("session open");
    assert_eq!(
        open.last_activity, 400,
        "the refused mint never bumped session activity"
    );

    // Arm two: a Companion APPEND to a User turn.
    let conversation_id = EntityId::from_hex(&conversation_hex).expect("conversation id");
    let receipt = facade
        .witness(&WitnessTurn {
            conversation_ref: conversation_hex.clone(),
            turn_ref: None,
            messages: vec![witness_message(
                0,
                WitnessAuthor::User,
                "owner holds the turn alone",
            )],
            occurred_at: 500,
        })
        .expect("mint a user turn");
    let turn = facade
        .get_entity(&receipt.turn_short_id)
        .expect("get turn")
        .expect("turn exists");
    let turn_id = EntityId::from_hex(&turn.id_hex).expect("turn id");
    let turn_raw_before = vault.get_raw(&turn_id).expect("turn raw").expect("turn");
    let conversation_raw_before = vault
        .get_raw(&conversation_id)
        .expect("conversation raw")
        .expect("conversation");
    let turn_edges_before = vault.edges_out(&turn_id).expect("turn edges").len();

    let err = facade
        .witness(&WitnessTurn {
            conversation_ref: conversation_hex,
            turn_ref: Some(turn.id_hex),
            messages: vec![witness_message(
                1,
                WitnessAuthor::Companion,
                "companion usurps the owner turn",
            )],
            occurred_at: 600,
        })
        .expect_err("a cross-speaker append is a bad request");
    assert_eq!(err.code, FACADE_CODE_BAD_REQUEST);
    assert_eq!(
        vault
            .get_raw(&turn_id)
            .expect("turn raw after")
            .expect("turn"),
        turn_raw_before,
        "the refused append never re-put the TURN (not even a learned_at move)"
    );
    assert_eq!(
        vault
            .get_raw(&conversation_id)
            .expect("conversation raw after")
            .expect("conversation"),
        conversation_raw_before,
        "the refused append left the CONVERSATION untouched"
    );
    assert_eq!(
        vault
            .entities_by_type(ENTITY_TYPE_MESSAGE)
            .expect("messages")
            .len(),
        1,
        "the refused append added no MESSAGE"
    );
    assert_eq!(
        vault.edges_out(&turn_id).expect("turn edges after").len(),
        turn_edges_before,
        "the refused append changed no edges"
    );
    assert!(
        vault.search_text("usurps", 10).expect("search").is_empty(),
        "the refused append left no text postings"
    );
    let open = vault
        .open_session()
        .expect("open session read")
        .expect("session open");
    assert_eq!(
        open.last_activity, 500,
        "the refused append never bumped session activity past the mint"
    );
}

/// The pre-transaction "no such turn" answer is ADVISORY: when the same-id
/// TURN commits in the window before the write transaction opens, the
/// transaction-authoritative re-read takes the APPEND path — stored-speaker
/// validation included — instead of overwriting the committed row as a mint.
#[test]
fn witness_concurrent_same_type_turn_creation_routes_through_validation() {
    let (_dir, vault) = open_vault();
    let actor = put_person(&vault, 0x65);
    let facade = facade_for(&vault, actor);

    // Arm one: the raced TURN belongs to the speaker the call carries. The
    // concurrent body is not the witness mint shape — it carries a byte
    // marker any overwrite-as-new would erase — but it DOES carry the mint's
    // full binding facts (ONE-1767 second cycle): the speaker stamp and the
    // `ChildOf` conversation edge, both of which the append door validates.
    let conversation_hex = EntityId::from_bytes([0x66; 16]).expect("conv id").to_hex();
    let conversation_id = EntityId::from_hex(&conversation_hex).expect("conversation id");
    let turn_id = EntityId::from_bytes([0x67; 16]).expect("turn id");
    let concurrent_body = encode_rmpv(&Value::Map(vec![
        (Value::from("concurrent"), Value::from("marker")),
        (Value::from("speaker"), Value::from("assistant")),
    ]))
    .expect("concurrent body");
    let receipt = facade
        .witness_with_pre_txn_hook(
            &WitnessTurn {
                conversation_ref: conversation_hex,
                turn_ref: Some(turn_id.to_hex()),
                messages: vec![witness_message(0, WitnessAuthor::Companion, "late joiner")],
                occurred_at: 750,
            },
            || {
                let empty_body = encode_rmpv(&Value::Map(Vec::new())).expect("container body");
                vault
                    .batch()
                    .put(
                        &conversation_id,
                        ENTITY_TYPE_CONVERSATION,
                        test_time(700),
                        700,
                        &empty_body,
                    )
                    .put(
                        &turn_id,
                        ENTITY_TYPE_TURN,
                        test_time(700),
                        700,
                        &concurrent_body,
                    )
                    .edge(&turn_id, EdgeKind::ChildOf, &conversation_id, 1.0)
                    .commit()
                    .expect("the concurrent TURN commits in the advisory window");
            },
        )
        .expect("the race takes the append path, speaker validation included");
    assert_eq!(
        receipt.message_short_ids.len(),
        1,
        "the call's message landed on the raced turn"
    );

    // The committed row was re-put for the re-dirty, never overwritten as a
    // fresh mint: the marker body and the occurred interval survive intact;
    // only learned_at moved (700 -> 750).
    let raw = vault.get_raw(&turn_id).expect("turn raw").expect("turn");
    let header = EntityMetadataHeader::parse(&raw).expect("turn header");
    assert_eq!(
        &raw[ENTITY_METADATA_HEADER_LEN..],
        concurrent_body.as_slice(),
        "the raced row was never overwritten as a fresh mint"
    );
    assert_eq!(
        (header.occurred_start, header.occurred_end),
        (700, 700),
        "the append path preserved the raced row's occurred interval"
    );
    assert_eq!(
        header.learned_at, 750,
        "the append path re-dirtied the raced row"
    );
    let message = facade
        .get_entity(&receipt.message_short_ids[0])
        .expect("get message")
        .expect("message exists");
    let message_id = EntityId::from_hex(&message.id_hex).expect("message id");
    assert!(
        vault
            .edges_out(&message_id)
            .expect("message edges")
            .iter()
            .any(|edge| edge.kind == EdgeKind::PartOf && edge.target == turn_id),
        "the appended message is PartOf the raced turn"
    );

    // Arm two: the raced TURN belongs to SOMEONE ELSE. The seed is the same
    // full mint shape (speaker stamp + `ChildOf`), so it is the SPEAKER check
    // — not the conversation-binding check — that rejects the whole call; the
    // concurrent row survives byte-identically (body AND learned_at) and
    // nothing of the refused call persists.
    let conversation2_hex = EntityId::from_bytes([0x68; 16]).expect("conv 2").to_hex();
    let conversation2_id = EntityId::from_hex(&conversation2_hex).expect("conversation 2 id");
    let turn2_id = EntityId::from_bytes([0x69; 16]).expect("turn 2");
    let user_body = encode_rmpv(&Value::Map(vec![
        (Value::from("concurrent"), Value::from("marker")),
        (Value::from("speaker"), Value::from("user")),
    ]))
    .expect("user body");
    let container2_body = encode_rmpv(&Value::Map(Vec::new())).expect("container body");
    let err = facade
        .witness_with_pre_txn_hook(
            &WitnessTurn {
                conversation_ref: conversation2_hex,
                turn_ref: Some(turn2_id.to_hex()),
                messages: vec![witness_message(0, WitnessAuthor::Companion, "speaker grab")],
                occurred_at: 850,
            },
            || {
                vault
                    .batch()
                    .put(
                        &conversation2_id,
                        ENTITY_TYPE_CONVERSATION,
                        test_time(800),
                        800,
                        &container2_body,
                    )
                    .put(&turn2_id, ENTITY_TYPE_TURN, test_time(800), 800, &user_body)
                    .edge(&turn2_id, EdgeKind::ChildOf, &conversation2_id, 1.0)
                    .commit()
                    .expect("the concurrent TURN commits in the advisory window");
            },
        )
        .expect_err("the raced row's stored speaker is enforced");
    assert_eq!(err.code, FACADE_CODE_BAD_REQUEST);
    let raw2 = vault
        .get_raw(&turn2_id)
        .expect("turn 2 raw")
        .expect("turn 2");
    let header2 = EntityMetadataHeader::parse(&raw2).expect("turn 2 header");
    assert_eq!(
        &raw2[ENTITY_METADATA_HEADER_LEN..],
        user_body.as_slice(),
        "the refused call never overwrote the raced row"
    );
    assert_eq!(
        header2.learned_at, 800,
        "the refused call never even re-put the raced row"
    );
    let conversation2_raw = vault
        .get_raw(&conversation2_id)
        .expect("conversation 2 raw")
        .expect("the hook-seeded conversation persists");
    let conversation2_header =
        EntityMetadataHeader::parse(&conversation2_raw).expect("conversation 2 header");
    assert_eq!(
        conversation2_header.learned_at, 800,
        "the refused call never re-put the seeded CONVERSATION"
    );
    assert_eq!(
        &conversation2_raw[ENTITY_METADATA_HEADER_LEN..],
        container2_body.as_slice(),
        "the seeded CONVERSATION body is byte-identical"
    );
}

/// An append landing AFTER the watermark passed the turn RE-DIRTIES it: the
/// next dirty scan returns the SAME turn id with a strictly greater
/// `learned_at`, and the re-put leaves no stale temporal-learned key behind.
#[test]
fn witness_append_redirties_the_same_turn() {
    let (_dir, vault) = open_vault();
    let actor = put_person(&vault, 0x6A);
    let facade = facade_for(&vault, actor);
    let conversation_hex = EntityId::from_bytes([0x6B; 16]).expect("conv id").to_hex();
    let turn_id = EntityId::from_bytes([0x6C; 16]).expect("turn id");
    let scope = DreamerConsolidationScope::Meso;

    facade
        .witness(&WitnessTurn {
            conversation_ref: conversation_hex.clone(),
            turn_ref: Some(turn_id.to_hex()),
            messages: vec![witness_message(0, WitnessAuthor::User, "the original turn")],
            occurred_at: 1_000,
        })
        .expect("mint the turn");
    let minted_raw = vault.get_raw(&turn_id).expect("turn raw").expect("turn");

    // The watermark moves PAST the minted turn; a scan now finds nothing.
    crate::advance_watermark(&vault, scope, 1_000).expect("advance watermark");
    let watermark = crate::read_watermark(&vault, scope).expect("watermark");
    assert!(
        crate::scan_dirty_turns(&vault, scope, &watermark, 10)
            .expect("scan")
            .is_empty(),
        "the minted turn is already consolidated"
    );

    // The same-speaker append (with permitted System interleave) is BACKDATED
    // before the minted stamp — exactly the case where rewriting an
    // equal/older learned_at would stay invisible to consolidation.
    facade
        .witness(&WitnessTurn {
            conversation_ref: conversation_hex,
            turn_ref: Some(turn_id.to_hex()),
            messages: vec![
                witness_message(1, WitnessAuthor::User, "the turn continues"),
                witness_message(2, WitnessAuthor::System, "tool row in between"),
            ],
            occurred_at: 900,
        })
        .expect("backdated same-speaker append");

    // learned_at moved STRICTLY beyond the watermark (max(900, 1000 + 1))…
    let raw = vault
        .get_raw(&turn_id)
        .expect("turn raw after")
        .expect("turn");
    let header = EntityMetadataHeader::parse(&raw).expect("header after");
    let minted_header = EntityMetadataHeader::parse(&minted_raw).expect("header before");
    assert_eq!(
        header.learned_at, 1_001,
        "a backdated append still re-dirties: strictly newer learned_at"
    );
    assert_eq!(
        (header.occurred_start, header.occurred_end),
        (minted_header.occurred_start, minted_header.occurred_end),
        "the re-put preserved the original occurred interval"
    );
    assert_eq!(
        &raw[ENTITY_METADATA_HEADER_LEN..],
        &minted_raw[ENTITY_METADATA_HEADER_LEN..],
        "the re-put preserved the body bytes"
    );

    // …and the next dirty scan returns THE SAME turn id above the watermark.
    let watermark = crate::read_watermark(&vault, scope).expect("watermark after");
    let dirty = crate::scan_dirty_turns(&vault, scope, &watermark, 10).expect("scan after");
    assert_eq!(dirty.len(), 1, "the append re-dirtied exactly one turn");
    assert_eq!(dirty[0].turn_id, turn_id, "it is the SAME turn");
    assert!(
        dirty[0].learned_at > watermark.last_learned_at,
        "strictly above the watermark: {} > {}",
        dirty[0].learned_at,
        watermark.last_learned_at
    );

    // The re-put removed the stale temporal-learned key: only the new stamp
    // indexes the turn (apply_put deletes the old key and inserts the new).
    let rtxn = vault.store.env.read_txn().expect("read txn");
    let mut old_key = [0_u8; 24];
    old_key[..8].copy_from_slice(&1_000_u64.to_be_bytes());
    old_key[8..24].copy_from_slice(turn_id.as_bytes());
    assert!(
        vault
            .store
            .temporal_learned
            .get(&rtxn, &old_key[..])
            .expect("old key read")
            .is_none(),
        "no stale old learned key survives the re-put"
    );
    let mut new_key = [0_u8; 24];
    new_key[..8].copy_from_slice(&1_001_u64.to_be_bytes());
    new_key[8..24].copy_from_slice(turn_id.as_bytes());
    assert!(
        vault
            .store
            .temporal_learned
            .get(&rtxn, &new_key[..])
            .expect("new key read")
            .is_some(),
        "the new learned key indexes the re-dirtied turn"
    );
}

/// System/tooling rows are permitted INTERLEAVE on an established turn: the
/// stored speaker is untouched and the append re-dirties it. But a call with
/// no non-system speaker can never MINT a turn — there is no grouping fact
/// to stamp, and inventing one is refused.
#[test]
fn witness_system_interleave_appends_but_never_mints_a_turn() {
    let (_dir, vault) = open_vault();
    let actor = put_person(&vault, 0x6D);
    let facade = facade_for(&vault, actor);
    let conversation_hex = EntityId::from_bytes([0x6E; 16]).expect("conv id").to_hex();
    let turn_id = EntityId::from_bytes([0x6F; 16]).expect("turn id");

    facade
        .witness(&WitnessTurn {
            conversation_ref: conversation_hex.clone(),
            turn_ref: Some(turn_id.to_hex()),
            messages: vec![witness_message(
                0,
                WitnessAuthor::Companion,
                "the assistant turn",
            )],
            occurred_at: 600,
        })
        .expect("mint an assistant turn");

    // The System-only APPEND succeeds and re-dirties the turn.
    facade
        .witness(&WitnessTurn {
            conversation_ref: conversation_hex,
            turn_ref: Some(turn_id.to_hex()),
            messages: vec![witness_message(1, WitnessAuthor::System, "tool result row")],
            occurred_at: 601,
        })
        .expect("system interleave on an established turn is permitted");
    let raw = vault.get_raw(&turn_id).expect("turn raw").expect("turn");
    let header = EntityMetadataHeader::parse(&raw).expect("turn header");
    assert_eq!(
        header.learned_at, 601,
        "the system-only append re-dirtied the turn"
    );
    let body = facade
        .get_entity(&turn_id.to_hex())
        .expect("get turn")
        .expect("turn")
        .body
        .expect("turn body");
    assert_eq!(
        body,
        serde_json::json!({"speaker": "assistant"}),
        "the stored grouping speaker is untouched by interleave"
    );

    // The System-only MINT fails closed, whether the caller names a fresh
    // turn id or lets the door mint one.
    for turn_ref in [
        None,
        Some(
            EntityId::from_bytes([0x70; 16])
                .expect("fresh turn")
                .to_hex(),
        ),
    ] {
        let err = facade
            .witness(&WitnessTurn {
                conversation_ref: EntityId::from_bytes([0x71; 16])
                    .expect("fresh conv")
                    .to_hex(),
                turn_ref,
                messages: vec![witness_message(
                    0,
                    WitnessAuthor::System,
                    "orphan system rows",
                )],
                occurred_at: 700,
            })
            .expect_err("a system-only mint has no grouping speaker");
        assert_eq!(err.code, FACADE_CODE_BAD_REQUEST);
    }
    assert_eq!(
        vault
            .entities_by_type(ENTITY_TYPE_TURN)
            .expect("turns")
            .len(),
        1,
        "no system-only TURN was ever minted"
    );
}

/// Appending to a TURN minted before the speaker stamp fails CLOSED. The
/// writer decodes exactly one stored `speaker` string: it never scans the
/// MESSAGE children, never follows `AuthoredBy`, and never synthesizes a
/// speaker for a turn that does not carry one.
#[test]
fn witness_append_rejects_unstamped_turn_without_legacy_fallback() {
    let (_dir, vault) = open_vault();
    let actor = put_person(&vault, 0x72);
    let facade = facade_for(&vault, actor);
    let conversation_id = EntityId::from_bytes([0x73; 16]).expect("conv id");
    let turn_id = EntityId::from_bytes([0x74; 16]).expect("turn id");
    let bait_message_id = EntityId::from_bytes([0x75; 16]).expect("bait message id");

    // The pre-stamp write shape: an EMPTY container map (the pre-ONE-1767
    // mint) plus — the fallback bait — a fully-attributed MESSAGE child a
    // child-scanning reader would recover `user` from.
    let empty_body = encode_rmpv(&Value::Map(Vec::new())).expect("empty container body");
    let bait_body =
        encode_witness_message_body(&witness_message(0, WitnessAuthor::User, "the bait child"))
            .expect("bait message body");
    vault
        .batch()
        .put(
            &conversation_id,
            ENTITY_TYPE_CONVERSATION,
            test_time(500),
            500,
            &empty_body,
        )
        .put(&turn_id, ENTITY_TYPE_TURN, test_time(500), 500, &empty_body)
        .put(
            &bait_message_id,
            ENTITY_TYPE_MESSAGE,
            test_time(500),
            500,
            &bait_body,
        )
        .edge(&bait_message_id, EdgeKind::PartOf, &turn_id, 1.0)
        .edge(&bait_message_id, EdgeKind::BelongsTo, &conversation_id, 1.0)
        .commit()
        .expect("seed the unstamped turn and its bait child");
    let turn_raw_before = vault.get_raw(&turn_id).expect("turn raw").expect("turn");

    let err = facade
        .witness(&WitnessTurn {
            conversation_ref: conversation_id.to_hex(),
            turn_ref: Some(turn_id.to_hex()),
            messages: vec![witness_message(
                1,
                WitnessAuthor::User,
                "append to the old turn",
            )],
            occurred_at: 550,
        })
        .expect_err("an unstamped turn has no grouping speaker to match against");
    assert_eq!(err.code, FACADE_CODE_BAD_REQUEST);

    // The refusal left everything alone: the bait child is still the ONLY
    // message and the unstamped turn was never re-put.
    assert_eq!(
        vault
            .get_raw(&turn_id)
            .expect("turn raw after")
            .expect("turn"),
        turn_raw_before,
        "the unstamped turn is untouched"
    );
    assert_eq!(
        vault
            .entities_by_type(ENTITY_TYPE_MESSAGE)
            .expect("messages")
            .len(),
        1,
        "the refused append landed no MESSAGE beside the bait child"
    );
}

/// ONE-1767 second cycle · append conversation binding: the TURN's stored
/// `ChildOf` IS its conversation. An append naming a DIFFERENT (fresh-hex,
/// create-or-get valid) conversation_ref is a bad request refused ATOMICALLY:
/// no minted CONVERSATION, no MESSAGE row, no edge, no text posting, no TURN
/// re-put, and no session-activity bump survives.
#[test]
fn witness_append_rejects_a_different_conversation_atomically() {
    let (_dir, vault) = open_vault();
    let actor = put_person(&vault, 0x76);
    let facade = facade_for(&vault, actor);
    mint_open_session(&vault, 400);

    let conversation_a_id = EntityId::from_bytes([0x77; 16]).expect("conv A");
    let conversation_b_id = EntityId::from_bytes([0x78; 16]).expect("conv B");
    let turn_id = EntityId::from_bytes([0x79; 16]).expect("turn id");
    facade
        .witness(&WitnessTurn {
            conversation_ref: conversation_a_id.to_hex(),
            turn_ref: Some(turn_id.to_hex()),
            messages: vec![witness_message(0, WitnessAuthor::User, "the home turn")],
            occurred_at: 500,
        })
        .expect("mint the turn in conversation A");
    let turn_raw_before = vault.get_raw(&turn_id).expect("turn raw").expect("turn");

    // SAME speaker, different conversation: only the binding check can refuse
    // this call. A fresh 32-hex conversation ref resolves create-or-get, so
    // without the binding check this call would also mint an empty conv B.
    let err = facade
        .witness(&WitnessTurn {
            conversation_ref: conversation_b_id.to_hex(),
            turn_ref: Some(turn_id.to_hex()),
            messages: vec![witness_message(
                1,
                WitnessAuthor::User,
                "cross-conversation hijack",
            )],
            occurred_at: 600,
        })
        .expect_err("an append under a foreign conversation is a bad request");
    assert_eq!(err.code, FACADE_CODE_BAD_REQUEST);
    assert!(
        err.message.contains("conversation"),
        "the refusal is the conversation-binding arm, got {:?}",
        err.message
    );

    assert!(
        vault
            .get_raw(&conversation_b_id)
            .expect("conv B read")
            .is_none(),
        "the refused call minted no fresh CONVERSATION"
    );
    assert_eq!(
        vault
            .entities_by_type(ENTITY_TYPE_CONVERSATION)
            .expect("conversations")
            .len(),
        1,
        "conversation A remains the only conversation"
    );
    assert_eq!(
        vault
            .entities_by_type(ENTITY_TYPE_MESSAGE)
            .expect("messages")
            .len(),
        1,
        "the refused append landed no MESSAGE row"
    );
    assert_eq!(
        vault
            .get_raw(&turn_id)
            .expect("turn raw after")
            .expect("turn"),
        turn_raw_before,
        "the refused append never re-put the TURN (not even a learned_at move)"
    );
    let turn_edges = vault.edges_out(&turn_id).expect("turn edges after");
    assert_eq!(
        turn_edges.len(),
        1,
        "the turn still carries exactly its minted ChildOf edge"
    );
    assert_eq!(
        turn_edges[0].target, conversation_a_id,
        "the stored ChildOf still names conversation A"
    );
    assert!(
        vault.search_text("hijack", 10).expect("search").is_empty(),
        "the refused append left no text postings"
    );
    let open = vault
        .open_session()
        .expect("open session read")
        .expect("session open");
    assert_eq!(
        open.last_activity, 500,
        "the refused append never bumped session activity past the mint"
    );
}

// ── commit / approval policy (AC-4) ─────────────────────────────────────

#[test]
fn commit_user_stated_band0_lands_auto_with_resolvable_receipt() {
    let (_dir, vault) = open_vault();
    let actor = put_person(&vault, 0x41);
    let subject = put_person(&vault, 0x42);
    let facade = facade_for(&vault, actor);

    let receipt = facade
        .claim_upsert(&claim_input(
            "profile.name",
            &subject,
            "user_stated",
            serde_json::json!("Ada"),
        ))
        .expect("auto claim");
    assert_eq!(receipt.approval, "auto");
    assert!(receipt.receipt_ref.starts_with("gate:"));

    // receipt_ref resolves via receipts().
    let receipts = facade.receipts(50).expect("receipts");
    let decision = receipts
        .iter()
        .find(|r| r.receipt_ref == receipt.receipt_ref)
        .expect("decision resolvable via receipts()");
    assert_eq!(decision.outcome, "allow");
    assert_eq!(decision.actor_class, "human");

    // Nothing parked for consent.
    let pending = facade.pending_writes(50).expect("pending");
    assert!(pending.is_empty());
}

#[test]
fn commit_imported_lands_proposed_and_appears_in_pending_writes() {
    let (_dir, vault) = open_vault();
    let actor = put_person(&vault, 0x51);
    let subject = put_person(&vault, 0x52);
    let facade = facade_for(&vault, actor);

    let receipt = facade
        .claim_upsert(&claim_input(
            "eiri.onboarding.answer",
            &subject,
            "imported",
            serde_json::json!({"question_id": "q-1", "selected_option_id": "a"}),
        ))
        .expect("imported claim");
    assert_eq!(receipt.approval, "proposed");
    assert!(receipt.receipt_ref.starts_with("gate:"));

    let pending = facade.pending_writes(50).expect("pending");
    assert_eq!(pending.len(), 1);
    let receipts = facade.receipts(50).expect("receipts");
    assert!(
        receipts
            .iter()
            .any(|r| r.receipt_ref == receipt.receipt_ref),
        "receipt_ref must resolve via receipts()"
    );
    assert!(
        receipts.iter().any(|r| r.outcome == "pending"),
        "gate outcome for the parked write is pending"
    );
}

#[test]
fn commit_auto_request_downgrades_to_proposed_when_gate_pends() {
    let (_dir, vault) = open_vault();
    let actor = put_person(&vault, 0x61);
    let subject = put_person(&vault, 0x62);

    // A Person-backed agent has a valid actor binding, but this explicit
    // ceiling still prevents the Auto request from attaching.
    let mut manifest = crate::gate::default_policy_manifest();
    let mut cursor = std::io::Cursor::new(manifest.as_slice());
    let rmpv::Value::Map(mut entries) = rmpv::decode::read_value(&mut cursor).expect("decode")
    else {
        panic!("default policy manifest is a map");
    };
    for (key, value) in &mut entries {
        if key.as_str() == Some("actor_ceilings") {
            let rmpv::Value::Array(rows) = value else {
                panic!("actor ceilings are an array");
            };
            rows.push(rmpv::Value::Map(vec![
                (rmpv::Value::from("actor_class"), rmpv::Value::from("agent")),
                (
                    rmpv::Value::from("actor_ref"),
                    rmpv::Value::from(actor.to_hex()),
                ),
                (rmpv::Value::from("ceiling"), rmpv::Value::from("proposed")),
            ]));
        }
    }
    manifest.clear();
    rmpv::encode::write_value(&mut manifest, &rmpv::Value::Map(entries)).expect("encode");
    crate::test_util::put_policy_manifest_bytes(
        &vault,
        crate::gate::default_policy_manifest_id().expect("default manifest id"),
        &manifest,
    )
    .expect("install agent ceiling");
    let facade = vault.memory(actor, EdgeActorClass::Agent);

    // Unknown predicates default to CRITICAL criticality under the default
    // policy manifest, so the gate pends the auto request; the facade
    // resubmits proposed instead of dropping the write.
    let receipt = facade
        .claim_upsert(&claim_input(
            "eiri.preference.color",
            &subject,
            "user_stated",
            serde_json::json!("teal"),
        ))
        .expect("downgraded claim");
    assert_eq!(receipt.approval, "proposed");
    let pending = facade.pending_writes(50).expect("pending");
    assert_eq!(pending.len(), 1, "downgraded write parks for consent");
    assert!(
        pending[0]
            .reason_codes
            .contains(&"gate.pending.actor_ceiling".to_owned()),
        "the non-attachable Agent Auto request must pend for its actor ceiling"
    );
}

#[test]
fn commit_sensitivity_scope_key_forces_proposed() {
    let (_dir, vault) = open_vault();
    let actor = put_person(&vault, 0x63);
    let subject = put_person(&vault, 0x64);
    let facade = facade_for(&vault, actor);

    let mut input = claim_input(
        "profile.name",
        &subject,
        "user_stated",
        serde_json::json!("Mira"),
    );
    input.scope = Some(serde_json::json!({"sensitivity": 0}));
    let receipt = facade.claim_upsert(&input).expect("scoped claim");
    assert_eq!(
        receipt.approval, "proposed",
        "explicit sensitivity key ⇒ proposed request"
    );
}

// ── supersession (AC-2 engine side, B1c) ────────────────────────────────

#[test]
fn claim_upsert_supersedes_prior_single_cardinality() {
    let (_dir, vault) = open_vault();
    let actor = put_person(&vault, 0x71);
    let subject = put_person(&vault, 0x72);
    let facade = facade_for(&vault, actor);

    let first = facade
        .claim_upsert(&claim_input(
            "profile.name",
            &subject,
            "user_stated",
            serde_json::json!("Ada"),
        ))
        .expect("first revision");
    let mut second_input = claim_input(
        "profile.name",
        &subject,
        "user_stated",
        serde_json::json!("Ada Lovelace"),
    );
    second_input.learned_at = Some(200);
    second_input.occurred_at = Some(200);
    let second = facade.claim_upsert(&second_input).expect("second revision");

    assert_eq!(
        second.superseded_short_id.as_deref().map(short_id_part),
        Some(short_id_part(&first.claim_short_id)),
        "second revision supersedes the first"
    );

    // Prior claim stays readable with lifecycle superseded.
    let history = facade
        .claim_history(&second.claim_short_id)
        .expect("history");
    assert_eq!(history.len(), 2);
    assert_eq!(history[0].lifecycle, "superseded");
    assert_eq!(history[0].value, serde_json::json!("Ada"));
    assert_eq!(history[1].lifecycle, "active");

    // Supersedes edge new → old.
    let new_id = EntityId::from_hex(&history[1].claim_ref).unwrap();
    let old_id = EntityId::from_hex(&history[0].claim_ref).unwrap();
    let edges = vault.edges_out(&new_id).expect("edges");
    assert!(
        edges
            .iter()
            .any(|edge| edge.kind == EdgeKind::Supersedes && edge.target == old_id),
        "Supersedes edge must link new → old"
    );
}

#[test]
fn multi_cardinality_supersede_matches_on_question_id() {
    let (_dir, vault) = open_vault();
    let actor = put_person(&vault, 0x81);
    let subject = put_person(&vault, 0x82);
    let facade = facade_for(&vault, actor);

    let answer = |question: &str, option: &str, at: u64| {
        let mut input = claim_input(
            "eiri.onboarding.answer",
            &subject,
            "imported",
            serde_json::json!({"question_id": question, "selected_option_id": option}),
        );
        input.occurred_at = Some(at);
        input.learned_at = Some(at);
        input
    };

    let answer_a = facade
        .claim_upsert(&answer("q-a", "1", 100))
        .expect("answer a");
    let answer_b = facade
        .claim_upsert(&answer("q-b", "2", 101))
        .expect("answer b");
    assert!(answer_a.superseded_short_id.is_none());
    assert!(
        answer_b.superseded_short_id.is_none(),
        "answering question B must never supersede the answer to question A (B1c)"
    );

    let re_answer_a = facade
        .claim_upsert(&answer("q-a", "3", 102))
        .expect("re-answer a");
    assert_eq!(
        re_answer_a
            .superseded_short_id
            .as_deref()
            .map(short_id_part),
        Some(short_id_part(&answer_a.claim_short_id)),
        "re-answer supersedes the same question's prior claim"
    );

    // B's claim is untouched.
    let claims = facade
        .claim_list(&ClaimListFilter {
            subject_ref: Some(subject.to_hex()),
            predicate: Some("eiri.onboarding.answer".to_owned()),
            lifecycle: Some("active".to_owned()),
            limit: 10,
        })
        .expect("list");
    assert_eq!(claims.len(), 2, "one active claim per question id");
}

// ── per-element gating (AC-5) ───────────────────────────────────────────

#[test]
fn commit_batch_gating_is_per_element() {
    let (_dir, vault) = open_vault();
    let actor = put_person(&vault, 0x91);
    let subject = put_person(&vault, 0x92);
    let facade = facade_for(&vault, actor);

    let receipts = facade
        .commit(&[
            claim_input(
                "profile.name",
                &subject,
                "user_stated",
                serde_json::json!("Ada"),
            ),
            // Violates the predicate ceiling (uppercase, no dot segments).
            claim_input(
                "BadPredicate",
                &subject,
                "user_stated",
                serde_json::json!("x"),
            ),
            claim_input(
                "profile.age",
                &subject,
                "user_stated",
                serde_json::json!(37),
            ),
        ])
        .expect("commit batch");

    assert_eq!(receipts.len(), 3);
    assert_eq!(receipts[0].approval, "auto");
    assert_eq!(receipts[1].approval, "rejected");
    assert!(receipts[1].receipt_ref.starts_with("rejected:"));
    assert_eq!(
        receipts[2].approval, "auto",
        "elements after a rejection still land"
    );

    // Per-element gate decisions exist for both written claims.
    let receipts_list = facade.receipts(50).expect("receipts");
    assert!(
        receipts_list
            .iter()
            .any(|r| r.receipt_ref == receipts[0].receipt_ref)
    );
    assert!(
        receipts_list
            .iter()
            .any(|r| r.receipt_ref == receipts[2].receipt_ref)
    );
    assert_ne!(receipts[0].receipt_ref, receipts[2].receipt_ref);

    // The rejected element persisted nothing.
    let claims = facade
        .claim_list(&ClaimListFilter {
            subject_ref: Some(subject.to_hex()),
            predicate: None,
            lifecycle: None,
            limit: 10,
        })
        .expect("list");
    assert_eq!(claims.len(), 2);
}

// ── safe delete (AC-6) ──────────────────────────────────────────────────

#[test]
fn safe_delete_requires_named_reason_and_returns_receipt() {
    let (_dir, vault) = open_vault();
    let actor = put_person(&vault, 0xB5);
    let facade = facade_for(&vault, actor);

    let soft_target = put_person(&vault, 0xB6);
    let receipt = facade
        .safe_delete(&soft_target.to_hex(), SafeDeleteReason::UserDelete)
        .expect("user delete");
    assert!(receipt.existed);
    assert_eq!(receipt.reason, "user_delete");
    assert!(
        receipt.receipt_ref.is_none(),
        "tombstone path writes no receipt entity"
    );

    let hard_target = put_person(&vault, 0xB7);
    let receipt = facade
        .safe_delete(&hard_target.to_hex(), SafeDeleteReason::UserHardDelete)
        .expect("hard delete");
    assert!(receipt.existed);
    let receipt_ref = receipt
        .receipt_ref
        .expect("hard delete writes a redaction receipt");
    assert!(receipt_ref.starts_with("redaction:"));
    let receipt_id = EntityId::from_hex(
        receipt_ref
            .strip_prefix("redaction:")
            .expect("redaction receipt prefix"),
    )
    .expect("receipt id");
    let raw = vault
        .get_raw(&receipt_id)
        .expect("read receipt")
        .expect("receipt exists");
    let audit = crate::deletion::decode_redaction_audit_receipt(
        &raw[crate::batch::ENTITY_METADATA_HEADER_LEN..],
    )
    .expect("decode redaction audit receipt");
    let request_id = audit.request_id.replace('-', "");
    let actor_hex = actor.to_hex();
    let decision = vault
        .gate_decisions(50)
        .expect("gate decisions")
        .into_iter()
        .find(|decision| decision.decision_id.to_hex() == request_id)
        .expect("deletion decision keyed by redaction request id");
    assert_eq!(decision.outcome, "allow");
    assert_eq!(decision.content_kind, "deletion");
    assert_eq!(decision.actor_class, "human");
    assert_eq!(decision.actor_ref.as_deref(), Some(actor_hex.as_str()));
    assert_eq!(decision.reason_codes, ["gate.allow.owner_delete"]);
    assert!(
        decision.claim_id.is_none(),
        "deletion authority must remain distinct from claim receipts"
    );
    assert!(
        facade
            .get_entity(&hard_target.to_hex())
            .expect("read back")
            .is_none(),
        "hard-deleted entity is purged"
    );

    let gdpr_target = put_person(&vault, 0xB8);
    let receipt = facade
        .safe_delete(&gdpr_target.to_hex(), SafeDeleteReason::GdprDelete)
        .expect("gdpr delete");
    assert!(receipt.receipt_ref.is_some());
}

/// DA-C/DA-E/DA-F: a crash after tombstone-first TXN1 leaves the subject
/// untouched until startup recovery executes the purge; TXN1's request-keyed
/// recovery sidecar lets that TXN3 append the authority record exactly once.
#[cfg(feature = "sync")]
#[test]
fn safe_delete_txn1_crash_recovers_purge_with_one_authority_record() {
    use std::sync::Arc;

    use crate::registry::ENTITY_TYPE_REDACTION_AUDIT;
    use crate::sync::{WindowKey, WindowManager, bridge::Materializer};

    let dir = tempfile::tempdir().expect("tempdir");
    let (victim, gate_decision_id) = {
        let vault = Arc::new(
            crate::Vault::open(dir.path(), VaultConfig::default()).expect("open first vault"),
        );
        let actor = put_person(&vault, 0xBC);
        let victim = put_person(&vault, 0xBD);
        // Keep the deletion window live so TXN1 covers the observer-A
        // suppression path as well as the transient document path.
        let manager = Arc::new(WindowManager::new(
            Arc::clone(&vault),
            Arc::new(Materializer::new()),
            "facade-crash-live-window",
        ));
        manager
            .open_window(&WindowKey::from_timestamp(1))
            .expect("open live deletion window");
        let facade = facade_for(&vault, actor);

        crate::deletion::arm_fail_after_tombstone_before_purge();
        facade
            .safe_delete(&victim.to_hex(), SafeDeleteReason::UserHardDelete)
            .expect_err("test crash after durable TXN1");

        assert!(
            vault.get_raw(&victim).expect("read victim").is_some(),
            "TXN1 tombstone must precede, not perform, the active-store purge"
        );
        let deletion = vault
            .entity_deletion_metadata(&victim, 1)
            .expect("read tombstone metadata")
            .expect("TXN1 persisted tombstone metadata");
        let request_id = uuid::Uuid::parse_str(
            deletion
                .request_id
                .as_deref()
                .expect("tombstone request id"),
        )
        .expect("request id UUID")
        .into_bytes();
        let gate_decision_id = crate::store::GateDecisionId::from_bytes(request_id);
        let rtxn = vault.store.env.read_txn().expect("read transaction");
        let staged = vault
            .store
            .pending_deletion_gate_decision_in_txn(&rtxn, gate_decision_id)
            .expect("read TXN1 authority sidecar")
            .expect("TXN1 staged request-keyed authority data");
        assert_eq!(staged.content_kind, "deletion");
        drop(rtxn);
        let unrelated_target = EntityId::from_bytes([0xBE; 16]).expect("unrelated target id");
        let consumed = vault
            .with_write_txn(|wtxn| {
                vault.store.append_pending_deletion_gate_decision_in_txn(
                    wtxn,
                    gate_decision_id,
                    unrelated_target.as_bytes(),
                    crate::deletion::TombstoneReason::UserHardDelete.wire_byte(),
                )
            })
            .expect("mismatched tombstone must not consume sidecar");
        assert!(
            consumed.is_none(),
            "a different target may not consume this request-keyed sidecar"
        );
        assert!(
            vault
                .gate_decisions(50)
                .expect("gate decisions")
                .iter()
                .all(|decision| decision.decision_id != gate_decision_id),
            "TXN1 must not append the final GateDecisionRecord before TXN3"
        );
        assert_eq!(
            vault
                .count_entities_by_type(ENTITY_TYPE_REDACTION_AUDIT)
                .expect("receipt count"),
            0,
            "the execution receipt belongs to the later purge transaction"
        );
        drop(manager);
        (victim, gate_decision_id)
    };

    let recovered = Arc::new(
        crate::Vault::open(dir.path(), VaultConfig::default()).expect("reopen after crash"),
    );
    let manager = Arc::new(WindowManager::new(
        Arc::clone(&recovered),
        Arc::new(Materializer::new()),
        "facade-crash-recovery",
    ));
    manager
        .open_window(&WindowKey::from_timestamp(1))
        .expect("startup recovery drives the pending purge");
    assert!(
        recovered
            .get_raw(&victim)
            .expect("read recovered victim")
            .is_none(),
        "the TXN1 tombstone must drive TXN3 purge completion on recovery"
    );
    assert_eq!(
        recovered
            .gate_decisions(50)
            .expect("gate decisions after recovery")
            .iter()
            .filter(|decision| decision.decision_id == gate_decision_id)
            .count(),
        1,
        "recovery must not multiply the request-keyed authority record"
    );
    assert_eq!(
        recovered
            .count_entities_by_type(ENTITY_TYPE_REDACTION_AUDIT)
            .expect("receipt count after recovery"),
        1,
        "recovery performs the one delayed execution attestation"
    );

    drop(manager);
    drop(recovered);
    let recovered_again = Arc::new(
        crate::Vault::open(dir.path(), VaultConfig::default()).expect("reopen idempotently"),
    );
    let manager_again = Arc::new(WindowManager::new(
        Arc::clone(&recovered_again),
        Arc::new(Materializer::new()),
        "facade-crash-recovery",
    ));
    manager_again
        .open_window(&WindowKey::from_timestamp(1))
        .expect("second recovery is idempotent");
    assert_eq!(
        recovered_again
            .gate_decisions(50)
            .expect("gate decisions after second recovery")
            .iter()
            .filter(|decision| decision.decision_id == gate_decision_id)
            .count(),
        1,
        "double recovery must preserve exactly once authority evidence"
    );
    assert_eq!(
        recovered_again
            .count_entities_by_type(ENTITY_TYPE_REDACTION_AUDIT)
            .expect("receipt count after second recovery"),
        1,
        "double recovery must not mint a second execution attestation"
    );
}

/// F1: suppressing Observer A for the authority-atomic tombstone commit must
/// not suppress the steady-state route to an already-connected peer.
#[cfg(feature = "sync")]
#[test]
fn safe_delete_live_tombstone_reaches_attached_outbound_channel() {
    use std::sync::Arc;

    use crate::sync::{WindowKey, WindowManager, bridge::Materializer};

    let dir = tempfile::tempdir().expect("tempdir");
    let vault =
        Arc::new(crate::Vault::open(dir.path(), VaultConfig::default()).expect("open vault"));
    let actor = put_person(&vault, 0xC1);
    let victim = put_person(&vault, 0xC2);
    let manager = Arc::new(WindowManager::new(
        Arc::clone(&vault),
        Arc::new(Materializer::new()),
        "facade-live-route",
    ));
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
    manager.outbound().attach(tx);
    let window = manager
        .open_window(&WindowKey::from_timestamp(1))
        .expect("open deletion window");
    let receiver_base = crate::sync::loro_support::export_snapshot(&window.doc)
        .expect("receiver starts from the sender's pre-delete state");

    facade_for(&vault, actor)
        .safe_delete(&victim.to_hex(), SafeDeleteReason::UserHardDelete)
        .expect("safe delete");

    let update = rx
        .try_recv()
        .expect("connected peer receives tombstone without reconnect");
    assert_eq!(update.window_key, WindowKey::from_timestamp(1).as_str());
    let remote = crate::sync::schema::create_window_doc("remote", &WindowKey::from_timestamp(1));
    remote
        .import(&receiver_base)
        .expect("import receiver base state");
    remote
        .import(&update.update_bytes)
        .expect("live-routed update imports");
    assert!(
        remote.get_map("tombstones").get(&victim.to_hex()).is_some(),
        "the live route carries the deletion tombstone"
    );
}

/// F3: a live-doc commit that outlives a failed persistence transaction is
/// already protected by a durable authority-required marker + complete
/// sidecar. If the sidecar is missing, recovery refuses the purge and leaves
/// its durable retry marker;
/// ordinary remote tombstones remain a legitimate sidecar-free control.
#[cfg(feature = "sync")]
#[test]
fn live_tombstone_persist_failure_requires_complete_authority_sidecar() {
    use std::sync::Arc;

    use loro::{LoroValue, ValueOrContainer};

    use crate::sync::{WindowKey, WindowManager, bridge::Materializer};

    let dir = tempfile::tempdir().expect("tempdir");
    let (victim, decision_id) = {
        let vault = Arc::new(
            crate::Vault::open(dir.path(), VaultConfig::default()).expect("open first vault"),
        );
        let actor = put_person(&vault, 0xC3);
        let victim = put_person(&vault, 0xC4);
        let manager = Arc::new(WindowManager::new(
            Arc::clone(&vault),
            Arc::new(Materializer::new()),
            "facade-live-txn1-failure",
        ));
        let window = manager
            .open_window(&WindowKey::from_timestamp(1))
            .expect("open live deletion window");

        crate::deletion::arm_fail_live_tombstone_persist();
        facade_for(&vault, actor)
            .safe_delete(&victim.to_hex(), SafeDeleteReason::UserHardDelete)
            .expect_err("live commit survives a failed persistence transaction");
        assert!(
            vault.get_raw(&victim).expect("read victim").is_some(),
            "failed TXN1 must not reach the purge"
        );
        let raw = match window.doc.get_map("tombstones").get(&victim.to_hex()) {
            Some(ValueOrContainer::Value(LoroValue::Binary(bytes))) => bytes.to_vec(),
            other => panic!("committed live tombstone missing: {other:?}"),
        };
        let request_id: [u8; 16] = raw[9..25].try_into().expect("request id bytes");
        let decision_id = crate::store::GateDecisionId::from_bytes(request_id);
        let rtxn = vault.store.env.read_txn().expect("read transaction");
        assert!(
            vault
                .store
                .pending_deletion_gate_decision_in_txn(&rtxn, decision_id)
                .expect("read staged sidecar")
                .is_some(),
            "authority sidecar is durable before the live tombstone commit"
        );
        drop(rtxn);

        // Model the orphan live commit being persisted later by an ordinary
        // full-state flush, then remove only the sidecar while retaining the
        // separate authority-required marker.
        window
            .persist_state(&vault)
            .expect("persist orphan live commit");
        vault
            .with_write_txn(|wtxn| {
                vault
                    .store
                    .remove_pending_deletion_gate_sidecar_for_test(wtxn, decision_id)
            })
            .expect("simulate lost authority sidecar");
        drop(window);
        drop(manager);
        (victim, decision_id)
    };

    let recovered = Arc::new(
        crate::Vault::open(dir.path(), VaultConfig::default()).expect("reopen after failed TXN1"),
    );
    let manager = Arc::new(WindowManager::new(
        Arc::clone(&recovered),
        Arc::new(Materializer::new()),
        "facade-live-txn1-recovery",
    ));
    manager
        .open_window(&WindowKey::from_timestamp(1))
        .expect("recovery keeps the window available while marking the failed purge for retry");
    assert!(
        recovered.get_raw(&victim).expect("read victim").is_some(),
        "failed authority recovery rolls the purge back"
    );
    assert!(
        crate::sync::pending_remat_windows(&recovered)
            .expect("pending recovery markers")
            .contains(&WindowKey::from_timestamp(1).as_str().to_owned()),
        "refused purge remains durably queued for fail-closed retry"
    );
    assert!(
        recovered
            .gate_decisions(50)
            .expect("gate decisions")
            .iter()
            .all(|decision| decision.decision_id != decision_id),
        "no authority record is fabricated from an incomplete sidecar"
    );

    // Legitimate remote control: no local required marker exists, so the
    // same replay boundary accepts and purges a peer-authored hard tombstone.
    let remote_victim = put_person(&recovered, 0xC5);
    let remote = crate::deletion::TombstoneValueV2 {
        reason: crate::deletion::TombstoneReason::UserHardDelete,
        deleted_at: 42,
        request_id: [0xD5; 16],
    };
    recovered
        .apply_replayed_tombstone_for_sync(&remote_victim, &remote.encode())
        .expect("sidecar-free remote tombstone remains valid");
    assert!(
        recovered
            .get_raw(&remote_victim)
            .expect("read remote victim")
            .is_none(),
        "legitimate remote hard tombstone purges normally"
    );
}

// ── error surface (AC-7) ────────────────────────────────────────────────

#[test]
fn facade_errors_carry_stable_codes_and_suggestions() {
    let (_dir, vault) = open_vault();
    let actor = put_person(&vault, 0xB1);
    let subject = put_person(&vault, 0xB2);
    let facade = facade_for(&vault, actor);

    // Wrong-predicate case.
    let err = facade
        .claim_upsert(&claim_input(
            "Bad Predicate!",
            &subject,
            "user_stated",
            serde_json::json!("x"),
        ))
        .expect_err("bad predicate must fail");
    assert_eq!(err.code, FACADE_CODE_BAD_REQUEST);
    assert!(!err.suggestions.is_empty());

    // Above-ceiling case: confidence outside [0, 1].
    let mut over = claim_input(
        "profile.name",
        &subject,
        "user_stated",
        serde_json::json!("x"),
    );
    over.confidence = 2.0;
    let err = facade.claim_upsert(&over).expect_err("confidence ceiling");
    assert_eq!(err.code, FACADE_CODE_BAD_REQUEST);
    assert!(!err.suggestions.is_empty());

    // Maintenance-band kinds are not writable through the facade.
    let err = facade
        .put_structural(&StructuralPutInput {
            id: None,
            kind: "REDACTION_AUDIT".to_owned(),
            body: serde_json::json!({}),
            text_fields: None,
            edges: None,
            occurred_at: 100,
            learned_at: None,
        })
        .expect_err("maintenance kind must be rejected");
    assert_eq!(err.code, FACADE_CODE_FORBIDDEN);
    assert!(!err.suggestions.is_empty());

    // Unknown claim source.
    let mut bad_source = claim_input(
        "profile.name",
        &subject,
        "user_stated",
        serde_json::json!(1),
    );
    bad_source.source = "vibes".to_owned();
    let err = facade
        .claim_upsert(&bad_source)
        .expect_err("unknown source");
    assert_eq!(err.code, FACADE_CODE_BAD_REQUEST);
    assert!(err.suggestions.iter().any(|s| s.contains("user_stated")));
}

// ── B2 migrator write-verb group ────────────────────────────────────────

#[test]
fn put_structural_carries_text_index_fields_and_edges() {
    let (_dir, vault) = open_vault();
    let actor = put_person(&vault, 0xC1);
    let facade = facade_for(&vault, actor);

    let asset = facade
        .put_structural(&StructuralPutInput {
            id: None,
            kind: "ASSET".to_owned(),
            body: serde_json::json!({"hash": "abc123", "media_type": "audio/mp4"}),
            text_fields: None,
            edges: None,
            occurred_at: 700,
            learned_at: None,
        })
        .expect("asset put");

    let person = facade
        .put_structural(&StructuralPutInput {
            id: None,
            kind: "PERSON".to_owned(),
            body: serde_json::json!({"name": "Chihiro", "bio": "loves moss gardens"}),
            text_fields: Some(vec![
                TextIndexField {
                    field: "name".to_owned(),
                    value: "Chihiro".to_owned(),
                },
                TextIndexField {
                    field: "bio".to_owned(),
                    value: "loves moss gardens".to_owned(),
                },
            ]),
            edges: Some(vec![StructuralEdgeSpec {
                edge_kind: "attached".to_owned(),
                target_ref: asset.id_hex.clone(),
                weight: None,
            }]),
            occurred_at: 701,
            learned_at: None,
        })
        .expect("person put");

    // Kind + body round-trip.
    let view = facade
        .get_entity(&person.entity_ref)
        .expect("get")
        .expect("exists");
    assert_eq!(view.kind, "PERSON");
    assert_eq!(view.body.unwrap()["name"], serde_json::json!("Chihiro"));

    // Edge landed.
    let person_id = EntityId::from_hex(&person.id_hex).unwrap();
    let asset_id = EntityId::from_hex(&asset.id_hex).unwrap();
    let edges = vault.edges_out(&person_id).expect("edges");
    assert!(
        edges
            .iter()
            .any(|e| e.kind == EdgeKind::Attached && e.target == asset_id)
    );

    // Text fields are BM25-findable.
    let hits = vault.search_text("moss", 10).expect("search");
    assert!(hits.iter().any(|hit| hit.id == person_id));

    // CLAIM kind is rejected on this verb.
    let err = facade
        .put_structural(&StructuralPutInput {
            id: None,
            kind: "CLAIM".to_owned(),
            body: serde_json::json!({}),
            text_fields: None,
            edges: None,
            occurred_at: 702,
            learned_at: None,
        })
        .expect_err("CLAIM kind must go through commit");
    assert_eq!(err.code, FACADE_CODE_BAD_REQUEST);
    assert!(err.suggestions.iter().any(|s| s.contains("commit")));

    // Entities land with correct type bytes.
    assert_eq!(vault.entities_by_type(ENTITY_TYPE_ASSET).unwrap().len(), 1);
}

#[test]
fn put_habit_checkin_appends_child_with_pinned_role() {
    let (_dir, vault) = open_vault();
    let actor = put_person(&vault, 0xD1);
    let facade = facade_for(&vault, actor);

    let habit = facade
        .put_structural(&StructuralPutInput {
            id: None,
            kind: "TASK".to_owned(),
            body: serde_json::json!({"role": 4, "content": "meditate"}),
            text_fields: None,
            edges: None,
            occurred_at: 800,
            learned_at: None,
        })
        .expect("habit put");

    let checkin = facade
        .put_habit_checkin(&HabitCheckinInput {
            habit_ref: habit.id_hex.clone(),
            id: None,
            data: Some(serde_json::json!({"note": "10 minutes"})),
            occurred_at: 801,
            learned_at: None,
        })
        .expect("checkin");

    let checkin_id = EntityId::from_hex(&checkin.id_hex).unwrap();
    let habit_id = EntityId::from_hex(&habit.id_hex).unwrap();
    let edges = vault.edges_out(&checkin_id).expect("edges");
    assert!(
        edges
            .iter()
            .any(|e| e.kind == EdgeKind::ChildOf && e.target == habit_id),
        "checkin carries the pack-contract ChildOf edge"
    );
    let view = facade
        .get_entity(&checkin.entity_ref)
        .unwrap()
        .expect("checkin view");
    let body = view.body.unwrap();
    assert_eq!(
        body["role"],
        serde_json::json!(5),
        "facade stamps HabitCheckin role"
    );
    assert_eq!(body["note"], serde_json::json!("10 minutes"));
    assert_eq!(vault.entities_by_type(ENTITY_TYPE_TASK).unwrap().len(), 2);

    // Caller-supplied role keys are rejected.
    let err = facade
        .put_habit_checkin(&HabitCheckinInput {
            habit_ref: habit.id_hex,
            id: None,
            data: Some(serde_json::json!({"role": 1})),
            occurred_at: 802,
            learned_at: None,
        })
        .expect_err("role key must be facade-stamped");
    assert_eq!(err.code, FACADE_CODE_BAD_REQUEST);
}

/// ONE-1889: the structural door is create-only for EVERY stored kind, not
/// just TASK. Fixture kinds: TASK (the kind the old special case covered)
/// plus EVENT and ASSET — two non-actor-capable kinds this door can actually
/// create under the existing gates (CLAIM/MACHINE/NOTE are refused at the
/// kind gate and PERSON is owner-gated, so none of them can reach the
/// stored-row check as a fixture).
#[test]
fn put_structural_mints_but_never_overwrites_typed_entities() {
    let (_dir, vault) = open_vault();
    let actor = put_person(&vault, 0xD2);
    let facade = facade_for(&vault, actor);

    for (index, (kind, fresh_body)) in [
        (
            "TASK",
            serde_json::json!({"role": 4, "content": "original"}),
        ),
        ("EVENT", serde_json::json!({"name": "hanami"})),
        ("ASSET", serde_json::json!({"hash": "abc123"})),
    ]
    .into_iter()
    .enumerate()
    {
        let at = 810 + (index as u64) * 10;
        let minted = facade
            .put_structural(&StructuralPutInput {
                id: None,
                kind: kind.to_owned(),
                body: fresh_body,
                text_fields: None,
                edges: None,
                occurred_at: at,
                learned_at: None,
            })
            .unwrap_or_else(|err| panic!("fresh {kind} mint: {err}"));
        let id = EntityId::from_hex(&minted.id_hex).expect("minted id");
        let before = vault
            .get_raw(&id)
            .expect("read before")
            .expect("entity exists");

        // Same-kind retry and cross-kind retry at the same id are BOTH
        // refused, and both produce the identical error: the guard reads the
        // stored row, so the incoming kind never changes the outcome.
        let same_kind = facade
            .put_structural(&StructuralPutInput {
                id: Some(minted.id_hex.clone()),
                kind: kind.to_owned(),
                body: serde_json::json!({"name": "same-kind overwrite"}),
                text_fields: None,
                edges: None,
                occurred_at: at + 1,
                learned_at: None,
            })
            .unwrap_err();
        let cross_kind = facade
            .put_structural(&StructuralPutInput {
                id: Some(minted.id_hex.clone()),
                kind: if kind == "EVENT" { "ASSET" } else { "EVENT" }.to_owned(),
                body: serde_json::json!({"name": "cross-kind overwrite"}),
                text_fields: None,
                edges: None,
                occurred_at: at + 2,
                learned_at: None,
            })
            .unwrap_err();

        assert_eq!(same_kind.code, FACADE_CODE_FORBIDDEN, "kind {kind}");
        assert!(
            same_kind.message.contains(kind),
            "refusal must name the STORED kind {kind}: {}",
            same_kind.message
        );
        assert_eq!(
            same_kind, cross_kind,
            "{kind}: same-kind and cross-kind retries must be indistinguishable"
        );
        assert_eq!(
            vault.get_raw(&id).expect("read after").expect("survives"),
            before,
            "{kind} body must be untouched by the refused overwrites"
        );
    }

    // Exactly one entity of each fixture kind exists: three mints, zero
    // overwrites, and no refusal minted a second row.
    assert_eq!(
        vault
            .entities_by_type(ENTITY_TYPE_TASK)
            .expect("task entities")
            .len(),
        1
    );
    assert_eq!(
        vault
            .entities_by_type(ENTITY_TYPE_ASSET)
            .expect("asset entities")
            .len(),
        1
    );
}

/// ONE-1889: reusing a live id with a DIFFERENT kind plus a richer payload
/// (body + text fields + edges) must leave the first entity's every trace
/// byte-for-byte intact — no body, no edge, no text posting, no short id, no
/// temporal row from the refused call.
#[test]
fn put_structural_rejects_cross_kind_id_reuse_without_side_effects() {
    let (_dir, vault) = open_vault();
    let actor = put_person(&vault, 0xD3);
    let facade = facade_for(&vault, actor);

    let neighbor = facade
        .put_structural(&StructuralPutInput {
            id: None,
            kind: "ASSET".to_owned(),
            body: serde_json::json!({"hash": "neighbor"}),
            text_fields: None,
            edges: None,
            occurred_at: 900,
            learned_at: None,
        })
        .expect("neighbor mint");
    let victim = facade
        .put_structural(&StructuralPutInput {
            id: None,
            kind: "EVENT".to_owned(),
            body: serde_json::json!({"name": "tsukimi"}),
            text_fields: Some(vec![TextIndexField {
                field: "name".to_owned(),
                value: "tsukimi moonviewing".to_owned(),
            }]),
            edges: None,
            occurred_at: 901,
            learned_at: None,
        })
        .expect("victim mint");
    let victim_id = EntityId::from_hex(&victim.id_hex).expect("victim id");
    let neighbor_id = EntityId::from_hex(&neighbor.id_hex).expect("neighbor id");

    let body_before = vault.get_raw(&victim_id).expect("raw").expect("exists");
    let edges_before = vault.edges_out(&victim_id).expect("edges before");
    let view_before = facade
        .get_entity(&victim.entity_ref)
        .expect("get before")
        .expect("view before");
    let text_before = vault.search_text("tsukimi", 10).expect("search before");
    assert!(edges_before.is_empty(), "victim starts with no edges");
    assert!(
        text_before.iter().any(|hit| hit.id == victim_id),
        "victim's own text field must be indexed before the refusal"
    );

    let error = facade
        .put_structural(&StructuralPutInput {
            id: Some(victim.id_hex.clone()),
            kind: "TASK".to_owned(),
            body: serde_json::json!({"role": 4, "content": "clobbered"}),
            text_fields: Some(vec![TextIndexField {
                field: "content".to_owned(),
                value: "clobbered kabuki".to_owned(),
            }]),
            edges: Some(vec![StructuralEdgeSpec {
                edge_kind: "attached".to_owned(),
                target_ref: neighbor.id_hex,
                weight: None,
            }]),
            occurred_at: 902,
            learned_at: None,
        })
        .expect_err("cross-kind id reuse must be refused");
    assert_eq!(error.code, FACADE_CODE_FORBIDDEN);
    assert!(
        error.message.contains("EVENT"),
        "refusal names the STORED kind, not the incoming TASK: {}",
        error.message
    );

    // Every trace of the refused call is absent, and the first state survives.
    assert_eq!(
        vault
            .get_raw(&victim_id)
            .expect("raw after")
            .expect("after"),
        body_before,
        "stored EVENT body must be byte-identical"
    );
    assert_eq!(
        vault.edges_out(&victim_id).expect("edges after").len(),
        0,
        "the refused call's edge must not have landed"
    );
    assert!(
        vault
            .edges_out(&neighbor_id)
            .expect("neighbor edges")
            .is_empty(),
        "no edge may reach the neighbor either"
    );
    let view_after = facade
        .get_entity(&victim.entity_ref)
        .expect("get after")
        .expect("view after");
    assert_eq!(view_after.kind, "EVENT", "stored kind is unchanged");
    assert_eq!(view_before, view_after, "the whole view is unchanged");
    assert!(
        vault
            .search_text("clobbered", 10)
            .expect("search clobbered")
            .is_empty(),
        "the refused call's text field must not be indexed"
    );
    assert!(
        vault
            .search_text("tsukimi", 10)
            .expect("search after")
            .iter()
            .any(|hit| hit.id == victim_id),
        "the original text posting survives"
    );
    assert!(
        vault
            .entities_by_type(ENTITY_TYPE_TASK)
            .expect("task entities")
            .is_empty(),
        "the refused TASK put must not have created anything"
    );
}

#[test]
fn put_companion_record_creates_and_optionally_retires() {
    let (_dir, vault) = open_vault();
    let actor = put_person(&vault, 0xE1);
    let owner = put_person(&vault, 0xE2);
    let persona = put_person(&vault, 0xE3);
    let facade = facade_for(&vault, actor);

    let active = facade
        .put_companion_record(&CompanionRecordInput {
            id: None,
            owner_ref: owner.to_hex(),
            persona_ref: persona.to_hex(),
            value: serde_json::json!({"name": "Yuki", "vibes": ["calm"]}),
            source: None,
            retired_at: None,
            learned_at: 900,
        })
        .expect("companion record");
    let record = vault
        .get_companion_record(&EntityId::from_hex(&active.id_hex).unwrap())
        .expect("read record")
        .expect("record exists");
    assert_eq!(record.lifecycle, ClaimLifecycleStatus::Active);
    assert!(!record.lifecycle_events.is_empty(), "created event stamped");

    // A second persona registered retired (migration of isActive == false).
    let persona_two = put_person(&vault, 0xE4);
    let retired = facade
        .put_companion_record(&CompanionRecordInput {
            id: None,
            owner_ref: owner.to_hex(),
            persona_ref: persona_two.to_hex(),
            value: serde_json::json!({"name": "Rei"}),
            source: Some("imported".to_owned()),
            retired_at: Some(950),
            learned_at: 900,
        })
        .expect("retired record");
    let record = vault
        .get_companion_record(&EntityId::from_hex(&retired.id_hex).unwrap())
        .expect("read record")
        .expect("record exists");
    assert_eq!(record.lifecycle, ClaimLifecycleStatus::Retracted);

    // The hard-delete resurrection guard is rechecked in the same write
    // transaction as companion creation, rather than trusting a stale
    // preflight probe for caller-supplied ids.
    let tombstoned_id = put_person(&vault, 0xE5);
    assert!(vault.delete_entity(&tombstoned_id).expect("hard delete"));
    let err = facade
        .put_companion_record(&CompanionRecordInput {
            id: Some(tombstoned_id.to_hex()),
            owner_ref: owner.to_hex(),
            persona_ref: persona.to_hex(),
            value: serde_json::json!({"name": "Never resurrect"}),
            source: None,
            retired_at: None,
            learned_at: 960,
        })
        .expect_err("hard-deleted ids must not become companion records");
    assert_eq!(err.code, FACADE_CODE_FORBIDDEN);
    assert!(
        vault
            .get_companion_record(&tombstoned_id)
            .expect("read rejected record")
            .is_none()
    );
}

#[test]
fn admit_imported_claim_rides_the_ingest_trust_ceiling() {
    let (_dir, vault) = open_vault();
    let actor = put_person(&vault, 0xF1);
    let subject = put_person(&vault, 0xF2);
    let facade = facade_for(&vault, actor);

    // The only registered source at base has permits_auto == false, so the
    // admission parks proposed — the gate still decides (B1a).
    let receipt = facade
        .admit_imported_claim(&AdmitImportedClaimInput {
            source_id: "jsonl-transcript".to_owned(),
            source_record_id: "row-42".to_owned(),
            id: None,
            subject_ref: subject.to_hex(),
            predicate: "eiri.onboarding.answer".to_owned(),
            value: serde_json::json!({"question_id": "q-9", "selected_option_id": "b"}),
            occurred_at: 1000,
            learned_at: None,
        })
        .expect("admission");
    assert_eq!(receipt.approval, "proposed");
    assert!(receipt.receipt_ref.starts_with("gate:"));
    let pending = facade.pending_writes(10).expect("pending");
    assert_eq!(pending.len(), 1);

    // Unregistered sources fail closed (convex_migration lands in ONE-258).
    let err = facade
        .admit_imported_claim(&AdmitImportedClaimInput {
            source_id: "convex_migration".to_owned(),
            source_record_id: "row-1".to_owned(),
            id: None,
            subject_ref: subject.to_hex(),
            predicate: "eiri.onboarding.answer".to_owned(),
            value: serde_json::json!({"question_id": "q-1"}),
            occurred_at: 1001,
            learned_at: None,
        })
        .expect_err("unknown ingest source must fail closed");
    assert_eq!(err.code, FACADE_CODE_BAD_REQUEST);
    assert!(err.suggestions.iter().any(|s| s.contains("registry")));
}

#[test]
fn blob_door_round_trips_bytes_and_dedupes_head() {
    // FINDING (flagged in the ONE-1454 report): under the DEFAULT policy
    // manifest, `blob.version` is an unknown predicate ⇒ CRITICAL
    // criticality ⇒ the engine's UserUpload auto-approval is gate-refused
    // (gate.pending.criticality_floor). The engine's own blob tests clear
    // the manifest; this test mirrors that until ONE-258's runbook installs
    // a manifest rule for blob.version.
    let (_dir, vault) = crate::test_util::open_test_vault_with(VaultConfig::default());
    let actor = put_person(&vault, 0x12);
    let facade = facade_for(&vault, actor);

    let artifact = facade
        .put_blob_artifact(&BlobArtifactInput {
            id: None,
            name: "voice-note.m4a".to_owned(),
            media_type: "audio/mp4".to_owned(),
            occurred_at: 1100,
            learned_at: None,
        })
        .expect("artifact");

    let mut bytes = vec![0_u8; 2048];
    let mut state: u64 = 0x1234_5678_9ABC_DEF0;
    for chunk in bytes.chunks_mut(8) {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        let raw = state.to_le_bytes();
        chunk.copy_from_slice(&raw[..chunk.len()]);
    }

    let version = facade
        .append_blob_version(&artifact.id_hex, &bytes, None, 1101, None)
        .expect("append");
    assert_eq!(version.version, 1);
    assert_eq!(version.content_hash_hex.len(), 64);

    let read = facade
        .read_blob_version(&artifact.id_hex, version.version)
        .expect("read")
        .expect("version exists");
    assert_eq!(read, bytes, "byte identity through the blob door");

    // Re-appending identical head bytes is a dedupe no-op.
    let again = facade
        .append_blob_version(&artifact.id_hex, &bytes, None, 1102, None)
        .expect("re-append");
    assert_eq!(again.version, 1);
}

// ── reads: list/history/retract/hydrate ─────────────────────────────────

#[test]
fn claim_retract_preserves_readable_history() {
    let (_dir, vault) = open_vault();
    let actor = put_person(&vault, 0x13);
    let subject = put_person(&vault, 0x14);
    let facade = facade_for(&vault, actor);

    let receipt = facade
        .claim_upsert(&claim_input(
            "profile.name",
            &subject,
            "user_stated",
            serde_json::json!("Ada"),
        ))
        .expect("claim");
    let retracted = facade
        .claim_retract(&receipt.claim_short_id)
        .expect("retract");
    assert_eq!(
        short_id_part(&retracted.claim_short_id),
        short_id_part(&receipt.claim_short_id)
    );
    assert!(retracted.receipt_ref.starts_with("gate:"));
    assert_ne!(
        retracted.receipt_ref, receipt.receipt_ref,
        "retraction must return its own gate decision, not the earlier write receipt"
    );
    assert!(
        facade
            .receipts(50)
            .expect("receipts")
            .iter()
            .any(|entry| entry.receipt_ref == retracted.receipt_ref),
        "ordinary retraction receipt_ref must remain resolvable"
    );

    let claims = facade
        .claim_list(&ClaimListFilter {
            subject_ref: Some(subject.to_hex()),
            predicate: Some("profile.name".to_owned()),
            lifecycle: Some("retracted".to_owned()),
            limit: 10,
        })
        .expect("list retracted");
    assert_eq!(claims.len(), 1);
    assert_eq!(claims[0].lifecycle, "retracted");
}

#[test]
fn agent_retracts_parked_proposal_without_dismissing_unrelated_stale_consent() {
    let (_dir, vault) = open_vault();
    let agent = put_person(&vault, 0x17);
    let subject = put_person(&vault, 0x18);
    let facade = vault.memory(agent, EdgeActorClass::Agent);

    let parked = facade
        .claim_upsert(&claim_input(
            "profile.mood",
            &subject,
            "observed",
            serde_json::json!("curious"),
        ))
        .expect("agent proposal parks for consent");
    assert_eq!(parked.approval, "proposed");
    let parked_id = EntityId::from_hex(
        &facade
            .get_entity(&parked.claim_short_id)
            .expect("read parked claim")
            .expect("parked claim exists")
            .id_hex,
    )
    .expect("parked claim id");

    let unrelated = facade
        .claim_upsert(&claim_input(
            "profile.color",
            &subject,
            "observed",
            serde_json::json!("teal"),
        ))
        .expect("unrelated agent proposal parks for consent");
    assert_eq!(unrelated.approval, "proposed");
    let unrelated_id = EntityId::from_hex(
        &facade
            .get_entity(&unrelated.claim_short_id)
            .expect("read unrelated claim")
            .expect("unrelated claim exists")
            .id_hex,
    )
    .expect("unrelated claim id");

    let pending_before = vault.pending_gate_consents(10).expect("pending consent");
    let parked_pending = pending_before
        .iter()
        .find(|record| record.claim_id == *parked_id.as_bytes())
        .expect("parked proposal consent")
        .clone();
    assert!(
        pending_before
            .iter()
            .any(|record| record.claim_id == *parked_id.as_bytes()),
        "the self-authored proposal must be parked before retraction"
    );
    assert!(
        pending_before
            .iter()
            .any(|record| record.claim_id == *unrelated_id.as_bytes()),
        "the unrelated proposal must be parked before retraction"
    );

    let retract_receipt = facade
        .claim_retract(&parked.claim_short_id)
        .expect("agent retracts its own parked proposal");
    let retract_decision = vault
        .gate_decisions(10)
        .expect("gate decisions")
        .into_iter()
        .find(|record| {
            retract_receipt.receipt_ref == format!("gate:{}", record.decision_id.to_hex())
        })
        .expect("retraction consent receipt");
    assert_eq!(retract_decision.outcome, "retracted");
    assert_eq!(
        retract_decision.reason_codes,
        vec!["gate.pending.claim_retracted"]
    );
    assert_eq!(retract_decision.diff_handle, parked_pending.diff_handle);
    assert_eq!(
        retract_decision.read_frontier_hash, parked_pending.read_frontier_hash,
        "withdrawal receipt preserves the consent's original policy binding"
    );

    // Retraction is a state transition, not a tray-only dismissal: the
    // claim remains stored as bitemporal history with its lifecycle closed.
    let retracted = vault
        .get_claim(&parked_id)
        .expect("read retracted claim")
        .expect("retracted claim remains stored");
    assert_eq!(retracted.lifecycle, ClaimLifecycleStatus::Retracted);
    assert!(
        retracted.valid_to.is_some(),
        "retraction stamps a valid end"
    );

    let pending_after_retract = vault.pending_gate_consents(10).expect("pending consent");
    assert!(
        !pending_after_retract
            .iter()
            .any(|record| record.claim_id == *parked_id.as_bytes()),
        "retracted proposal must no longer occupy the consent tray"
    );
    assert!(
        pending_after_retract
            .iter()
            .any(|record| record.claim_id == *unrelated_id.as_bytes()),
        "retract must not resolve unrelated parked consent"
    );

    // Ordinary content drift remains fail-closed. The retract-only rebinding
    // must not make a different parked proposal redeemable by changing it.
    let mut drifted = vault
        .get_claim(&unrelated_id)
        .expect("read unrelated claim")
        .expect("unrelated claim remains stored");
    drifted.value = rmpv::Value::from("blue");
    drifted.approval = ClaimApprovalStatus::Approved;
    let err = vault
        .put_claim(&unrelated_id, &drifted, test_time(101), 101)
        .expect_err("unrelated drifted consent remains stale");
    assert!(matches!(err, Error::GateConsentStale { claim_id } if claim_id == unrelated_id));
    assert!(
        vault
            .pending_gate_consents(10)
            .expect("pending consent")
            .iter()
            .any(|record| record.claim_id == *unrelated_id.as_bytes()),
        "stale unrelated proposal must stay parked"
    );
}

#[test]
fn same_id_replacement_cannot_be_retracted_by_the_prior_agent() {
    let (_dir, vault) = open_vault();
    let first_agent = put_person(&vault, 0x19);
    let replacement_agent = put_person(&vault, 0x1A);
    let subject = put_person(&vault, 0x1B);
    let first_facade = vault.memory(first_agent, EdgeActorClass::Agent);
    let replacement_facade = vault.memory(replacement_agent, EdgeActorClass::Agent);
    let claim_id = EntityId::from_bytes([0x1C; 16]).expect("claim id");

    let mut first = claim_input(
        "profile.mood",
        &subject,
        "observed",
        serde_json::json!("curious"),
    );
    first.id = Some(claim_id.to_hex());
    first_facade
        .claim_upsert(&first)
        .expect("first agent parks proposal");

    let mut replacement = claim_input(
        "profile.color",
        &subject,
        "observed",
        serde_json::json!("teal"),
    );
    replacement.id = Some(claim_id.to_hex());
    // Reproduce the former split-transaction race deterministically: the
    // replacement lands after call setup but immediately before the retraction
    // write transaction begins. The fixed path authorizes only after acquiring
    // that transaction, so it observes and rejects the replacement author.
    let err = first_facade
        .claim_retract_with_pre_txn_hook(&claim_id.to_hex(), || {
            replacement_facade
                .claim_upsert(&replacement)
                .expect("second agent replaces same id in former race window");
        })
        .expect_err("prior author has no authority over same-id replacement");
    assert_eq!(err.code, FACADE_CODE_FORBIDDEN);
    let current = vault
        .get_claim(&claim_id)
        .expect("read replacement")
        .expect("replacement remains");
    assert_eq!(current.predicate, "profile.color");
    assert_eq!(current.lifecycle, ClaimLifecycleStatus::Active);
    assert!(
        vault
            .pending_gate_consents(10)
            .expect("pending consent")
            .iter()
            .any(|record| record.claim_id == *claim_id.as_bytes()),
        "replacement agent's consent row remains actionable"
    );
}

#[test]
fn hydrate_round_trips_witness_short_ids() {
    let (_dir, vault) = open_vault();
    let actor = put_person(&vault, 0x15);
    let facade = facade_for(&vault, actor);

    let receipt = facade
        .witness(&WitnessTurn {
            conversation_ref: EntityId::from_bytes([0x16; 16]).unwrap().to_hex(),
            turn_ref: None,
            messages: vec![witness_message(0, WitnessAuthor::User, "hydrate me")],
            occurred_at: 1200,
        })
        .expect("witness");

    let mut refs = vec![receipt.turn_short_id.clone()];
    refs.extend(receipt.message_short_ids.iter().cloned());
    let views = facade.hydrate(&refs).expect("hydrate");
    assert_eq!(views.len(), 2);
    assert_eq!(views[0].kind, "TURN");
    assert_eq!(views[1].kind, "MESSAGE");
    assert_eq!(
        views[1].body.as_ref().unwrap()["content"],
        serde_json::json!("hydrate me")
    );

    let err = facade
        .hydrate(&["zz999:ff".to_owned()])
        .expect_err("dangling short ref must be a typed error");
    assert_eq!(err.code, FACADE_CODE_NOT_FOUND);
}

// ── RT-03 (ONE-1685): turn-witness bumps the open session ───────────────

#[test]
fn witness_bumps_open_session_activity_atomically() {
    let (_dir, vault) = open_vault();
    let actor = put_person(&vault, 0x71);
    let facade = facade_for(&vault, actor);

    let session = match vault.mint_session(400).expect("mint session") {
        crate::session_lifecycle::SessionMintOutcome::Minted(id) => id,
        other => panic!("expected fresh mint, got {other:?}"),
    };

    let conversation_hex = EntityId::from_bytes([0x72; 16]).expect("conv id").to_hex();
    facade
        .witness(&WitnessTurn {
            conversation_ref: conversation_hex.clone(),
            turn_ref: None,
            messages: vec![witness_message(0, WitnessAuthor::User, "hello again")],
            occurred_at: 500,
        })
        .expect("witness turn");

    let open = vault
        .open_session()
        .expect("open session read")
        .expect("session still open");
    assert_eq!(open.session, session);
    assert_eq!(
        open.last_activity, 500,
        "turn-witness bumps last_activity to the turn's occurred_at"
    );

    // An OLDER turn (backfill) never rewinds the activity clock.
    facade
        .witness(&WitnessTurn {
            conversation_ref: conversation_hex,
            turn_ref: None,
            messages: vec![witness_message(0, WitnessAuthor::User, "backfilled note")],
            occurred_at: 450,
        })
        .expect("witness backfill turn");
    let open = vault
        .open_session()
        .expect("open session read")
        .expect("session still open");
    assert_eq!(open.last_activity, 500, "activity clock is monotonic");
}

#[test]
fn witness_without_an_open_session_stays_valid() {
    let (_dir, vault) = open_vault();
    let actor = put_person(&vault, 0x73);
    let facade = facade_for(&vault, actor);

    // ARCH-0002 open-endedness: turns outside any session are valid; the
    // bump is a no-op, not an error, and no session is minted.
    let conversation_hex = EntityId::from_bytes([0x74; 16]).expect("conv id").to_hex();
    facade
        .witness(&WitnessTurn {
            conversation_ref: conversation_hex,
            turn_ref: None,
            messages: vec![witness_message(0, WitnessAuthor::User, "sessionless turn")],
            occurred_at: 600,
        })
        .expect("witness sessionless turn");
    assert_eq!(vault.open_session().expect("open session read"), None);
}

// ── S-AUTH3: owner-verb authority-log teeth (ONE-1633 / ESB-C) ───────────

/// A single-key authority root. One roster key means no peer cosign is
/// required, so a rooted facade fixture is two entries total.
fn authority_root(
    seed: u8,
) -> (
    crate::authority::AuthorityLogEntry,
    ed25519_dalek::SigningKey,
) {
    use crate::authority::{
        AuthorityAttestation, AuthorityKey, AuthorityLogEntry, AuthorityOp, AuthoritySignature,
        AuthorityTier, DeviceAuthority, ROLE_ADMIN, ROLE_OWNER,
    };
    let signing = ed25519_dalek::SigningKey::from_bytes(&[seed; 32]);
    let key = AuthorityKey::Ed25519(signing.verifying_key().to_bytes());
    let entry = AuthorityLogEntry {
        schema_version: crate::authority::AUTHORITY_LOG_SCHEMA_VERSION,
        vault_id: None,
        seq: 0,
        parent_hashes: Vec::new(),
        op: AuthorityOp::Genesis {
            device: DeviceAuthority {
                key: key.clone(),
                transport_key_binding: [7; 32],
                attestation: AuthorityAttestation {
                    kind: "SoftwareArgon2id".to_owned(),
                    evidence: vec![1, 2, 3],
                },
                tier: AuthorityTier::Software,
                roles: ROLE_OWNER | ROLE_ADMIN,
            },
            genesis_nonce: [seed.wrapping_add(10); 32],
            tier_floor: AuthorityTier::Software,
            pending_widen_delay_secs: crate::authority::DEFAULT_PENDING_WIDEN_DELAY_SECS,
        },
        signer: AuthoritySignature {
            suite: key.suite(),
            public_key: key,
            signature: vec![0; 64],
        },
        cosigns: Vec::new(),
        ts: 100,
    };
    (sign_authority(entry, &signing), signing)
}

fn sign_authority(
    mut entry: crate::authority::AuthorityLogEntry,
    key: &ed25519_dalek::SigningKey,
) -> crate::authority::AuthorityLogEntry {
    use ed25519_dalek::Signer;
    let transcript = crate::authority::authority_transcript(&entry).expect("transcript");
    entry.signer.signature = key.sign(&transcript).to_bytes().to_vec();
    entry
}

/// Roots `vault` and binds `actor` at `class` in ONE atomic ceremony.
fn root_vault_binding(vault: &crate::Vault, seed: u8, actor: EntityId, class: &str) {
    use crate::authority::{AuthorityKey, AuthorityLogEntry, AuthorityOp, AuthoritySignature};
    let (genesis, signing) = authority_root(seed);
    let vault_id = crate::authority::genesis_vault_id(&genesis).expect("vault id");
    let key = AuthorityKey::Ed25519(signing.verifying_key().to_bytes());
    let bind = sign_authority(
        AuthorityLogEntry {
            schema_version: crate::authority::AUTHORITY_LOG_SCHEMA_VERSION,
            vault_id: Some(vault_id),
            seq: 1,
            parent_hashes: vec![
                crate::authority::authority_entry_hash(&genesis).expect("genesis hash"),
            ],
            op: AuthorityOp::BindActor {
                authority_key: key.clone(),
                actor_ref: actor,
                actor_class: class.to_owned(),
                epoch: 1,
            },
            signer: AuthoritySignature {
                suite: key.suite(),
                public_key: key,
                signature: vec![0; 64],
            },
            cosigns: Vec::new(),
            ts: 101,
        },
        &signing,
    );
    vault
        .put_authority_log_entries(&[(genesis, test_time(1), 1), (bind, test_time(2), 2)])
        .expect("atomic genesis owner-binding");
}

/// T9: on a ROOTED vault the three owner verbs demand a folded ACTIVE
/// human-class binding. This is the ESB-C fix: asserting `human` at the
/// facade is no longer enough — the authority log has to agree.
#[test]
fn owner_verbs_require_active_owner_binding_when_rooted() {
    let (_dir, vault) = open_vault();
    let owner = put_person(&vault, 0x5E);
    let agent = put_person(&vault, 0x5F);
    let subject = put_person(&vault, 0x60);
    let owner_facade = facade_for(&vault, owner);
    let agent_facade = vault.memory(agent, EdgeActorClass::Agent);
    let agent_claim = agent_facade
        .claim_upsert(&claim_input(
            "profile.mood",
            &subject,
            "observed",
            serde_json::json!("calm"),
        ))
        .expect("agent claim");

    root_vault_binding(&vault, 0x71, owner, "human");

    // Bound owner: every owner verb still works. No capability is removed by
    // this lane — the binding just has to exist.
    owner_facade
        .put_structural(&StructuralPutInput {
            id: None,
            kind: "PERSON".to_owned(),
            body: serde_json::json!({"name": "minted"}),
            text_fields: None,
            edges: None,
            occurred_at: 700,
            learned_at: None,
        })
        .expect("bound owner mints PERSON");
    owner_facade
        .claim_retract(&agent_claim.claim_short_id)
        .expect("bound owner retracts another actor's claim");
    owner_facade
        .safe_delete(&subject.to_hex(), SafeDeleteReason::UserDelete)
        .expect("bound owner deletes");

    // An UNBOUND human actor on the same rooted vault is refused on all three.
    let stranger = put_person(&vault, 0x61);
    let stranger_facade = facade_for(&vault, stranger);
    let victim = put_person(&vault, 0x62);
    let other_claim = agent_facade
        .claim_upsert(&claim_input(
            "profile.color",
            &victim,
            "observed",
            serde_json::json!("teal"),
        ))
        .expect("second agent claim");
    for err in [
        stranger_facade
            .put_structural(&StructuralPutInput {
                id: None,
                kind: "PERSON".to_owned(),
                body: serde_json::json!({"name": "forged"}),
                text_fields: None,
                edges: None,
                occurred_at: 701,
                learned_at: None,
            })
            .expect_err("unbound PERSON mint"),
        stranger_facade
            .claim_retract(&other_claim.claim_short_id)
            .expect_err("unbound cross-actor retract"),
        stranger_facade
            .safe_delete(&victim.to_hex(), SafeDeleteReason::UserDelete)
            .expect_err("unbound delete"),
    ] {
        assert_eq!(err.code, FACADE_CODE_FORBIDDEN);
        assert!(
            err.message.contains("no active owner binding"),
            "{}",
            err.message
        );
    }

    // Retracting your OWN claim is not an owner power and needs no binding.
    let self_claim = stranger_facade
        .claim_upsert(&claim_input(
            "profile.note",
            &victim,
            "user_stated",
            serde_json::json!("mine"),
        ))
        .expect("stranger writes own claim");
    stranger_facade
        .claim_retract(&self_claim.claim_short_id)
        .expect("self-retraction never needs an owner binding");
}

/// T10: an UNROOTED vault keeps today's store-truth behavior exactly.
///
/// This pins the ratified enforcement mode (S-AUTH3 D6 fork (a),
/// "enforce-when-root-exists"): teeth arrive when a host DECLARES authority,
/// not before. Every shipped vault has no authority log at all, so nothing
/// breaks on upgrade. [owner] fork note: under the alternate "hard flip"
/// ruling these three expectations invert to FORBIDDEN.
#[test]
fn unrooted_vault_keeps_store_truth_owner_verbs() {
    let (_dir, vault) = open_vault();
    let owner = put_person(&vault, 0x63);
    let agent = put_person(&vault, 0x64);
    let subject = put_person(&vault, 0x65);
    let owner_facade = facade_for(&vault, owner);
    let agent_claim = vault
        .memory(agent, EdgeActorClass::Agent)
        .claim_upsert(&claim_input(
            "profile.mood",
            &subject,
            "observed",
            serde_json::json!("calm"),
        ))
        .expect("agent claim");

    assert!(
        vault.authority_fold().expect("fold").vault_id.is_none(),
        "fixture must have no declared authority root"
    );
    owner_facade
        .put_structural(&StructuralPutInput {
            id: None,
            kind: "PERSON".to_owned(),
            body: serde_json::json!({"name": "minted"}),
            text_fields: None,
            edges: None,
            occurred_at: 702,
            learned_at: None,
        })
        .expect("unrooted PERSON mint unchanged");
    owner_facade
        .claim_retract(&agent_claim.claim_short_id)
        .expect("unrooted cross-actor retract unchanged");
    owner_facade
        .safe_delete(&subject.to_hex(), SafeDeleteReason::UserDelete)
        .expect("unrooted delete unchanged");
}

/// T11: the binding class is EXACT and revocation is real.
#[test]
fn exact_class_binding_no_cross_class_satisfaction() {
    let (_dir, vault) = open_vault();
    let owner = put_person(&vault, 0x66);
    let subject = put_person(&vault, 0x67);
    // Bound at "agent" only. A human-class owner verb must NOT be satisfied
    // by an agent-class binding — near-miss classes are the ESB-C defect.
    root_vault_binding(&vault, 0x72, owner, "agent");

    let err = facade_for(&vault, owner)
        .safe_delete(&subject.to_hex(), SafeDeleteReason::UserDelete)
        .expect_err("agent-class binding must not satisfy a human-class verb");
    assert_eq!(err.code, FACADE_CODE_FORBIDDEN);
    assert!(
        err.message.contains("no active owner binding"),
        "{}",
        err.message
    );
}

/// T11b: a RevokeActor watermark takes the owner's teeth away again.
#[test]
fn revoked_binding_forbids_owner_verbs() {
    use crate::authority::{AuthorityKey, AuthorityLogEntry, AuthorityOp, AuthoritySignature};
    let (_dir, vault) = open_vault();
    let owner = put_person(&vault, 0x68);
    let subject = put_person(&vault, 0x69);
    let facade = facade_for(&vault, owner);

    let (genesis, signing) = authority_root(0x73);
    let vault_id = crate::authority::genesis_vault_id(&genesis).expect("vault id");
    let key = AuthorityKey::Ed25519(signing.verifying_key().to_bytes());
    let genesis_hash = crate::authority::authority_entry_hash(&genesis).expect("genesis hash");
    let owner_entry = |seq: u64, op: AuthorityOp, parents: Vec<[u8; 32]>| {
        sign_authority(
            AuthorityLogEntry {
                schema_version: crate::authority::AUTHORITY_LOG_SCHEMA_VERSION,
                vault_id: Some(vault_id),
                seq,
                parent_hashes: parents,
                op,
                signer: AuthoritySignature {
                    suite: key.suite(),
                    public_key: key.clone(),
                    signature: vec![0; 64],
                },
                cosigns: Vec::new(),
                ts: 100 + seq,
            },
            &signing,
        )
    };
    let bind = owner_entry(
        1,
        AuthorityOp::BindActor {
            authority_key: key.clone(),
            actor_ref: owner,
            actor_class: "human".to_owned(),
            epoch: 1,
        },
        vec![genesis_hash],
    );
    let bind_hash = crate::authority::authority_entry_hash(&bind).expect("bind hash");
    vault
        .put_authority_log_entries(&[(genesis, test_time(1), 1), (bind, test_time(2), 2)])
        .expect("root + bind");
    facade
        .safe_delete(&subject.to_hex(), SafeDeleteReason::UserDelete)
        .expect("bound owner deletes");

    let revoke = owner_entry(
        2,
        AuthorityOp::RevokeActor {
            authority_key: key.clone(),
            epoch: 1,
        },
        vec![bind_hash],
    );
    vault
        .put_authority_log_entries(&[(revoke, test_time(3), 3)])
        .expect("revoke binding");

    let victim = put_person(&vault, 0x6A);
    let err = facade
        .safe_delete(&victim.to_hex(), SafeDeleteReason::UserDelete)
        .expect_err("a revoked binding must lose its owner teeth");
    assert_eq!(err.code, FACADE_CODE_FORBIDDEN);
    assert!(
        err.message.contains("no active owner binding"),
        "{}",
        err.message
    );
}

/// Roots `vault`, binds `actor` as `human`, and returns the SIGNED
/// `RevokeActor` that takes the binding away again — unpersisted, so a caller
/// chooses the exact instant it lands.
fn root_binding_with_pending_revocation(
    vault: &crate::Vault,
    seed: u8,
    actor: EntityId,
) -> crate::authority::AuthorityLogEntry {
    use crate::authority::{AuthorityKey, AuthorityLogEntry, AuthorityOp, AuthoritySignature};
    let (genesis, signing) = authority_root(seed);
    let vault_id = crate::authority::genesis_vault_id(&genesis).expect("vault id");
    let key = AuthorityKey::Ed25519(signing.verifying_key().to_bytes());
    let genesis_hash = crate::authority::authority_entry_hash(&genesis).expect("genesis hash");
    let owner_entry = |seq: u64, op: AuthorityOp, parents: Vec<[u8; 32]>| {
        sign_authority(
            AuthorityLogEntry {
                schema_version: crate::authority::AUTHORITY_LOG_SCHEMA_VERSION,
                vault_id: Some(vault_id),
                seq,
                parent_hashes: parents,
                op,
                signer: AuthoritySignature {
                    suite: key.suite(),
                    public_key: key.clone(),
                    signature: vec![0; 64],
                },
                cosigns: Vec::new(),
                ts: 100 + seq,
            },
            &signing,
        )
    };
    let bind = owner_entry(
        1,
        AuthorityOp::BindActor {
            authority_key: key.clone(),
            actor_ref: actor,
            actor_class: "human".to_owned(),
            epoch: 1,
        },
        vec![genesis_hash],
    );
    let bind_hash = crate::authority::authority_entry_hash(&bind).expect("bind hash");
    vault
        .put_authority_log_entries(&[(genesis, test_time(1), 1), (bind, test_time(2), 2)])
        .expect("root + bind");
    owner_entry(
        2,
        AuthorityOp::RevokeActor {
            authority_key: key.clone(),
            epoch: 1,
        },
        vec![bind_hash],
    )
}

/// fix-leg 5 item 1: the delete owner-gate is TOCTOU-closed.
///
/// `evaluate_deletion_gate` folds the owner binding in a read txn it then
/// DROPS. Everything the destructive transactions do afterwards runs on that
/// dropped snapshot's authority — so a `RevokeActor` committed in the window
/// between the two was, before this fix, never observed and the delete tore
/// anyway. The sibling owner verbs (`claim_retract`, the structural arm) never
/// had the hole because they fold INSIDE their write txns; this drives the race
/// deterministically through the ONE-1149 rendezvous seam and pins the same
/// behavior for deletion.
#[test]
fn revocation_racing_a_gated_delete_refuses_and_tears_nothing() {
    for reason in [
        SafeDeleteReason::UserDelete,
        SafeDeleteReason::UserHardDelete,
    ] {
        let (_dir, vault) = open_vault();
        let owner = put_person(&vault, 0x90);
        let subject = put_person(&vault, 0x91);
        let revoke = root_binding_with_pending_revocation(&vault, 0x92, owner);

        // Control: the binding is live, so the gate passes end to end.
        let warmup = put_person(&vault, 0x93);
        facade_for(&vault, owner)
            .safe_delete(&warmup.to_hex(), reason)
            .expect("control: a bound owner deletes");

        let gate = std::sync::Arc::new(std::sync::Barrier::new(2));
        // The rendezvous fires from inside the delete AFTER its header read
        // proves the target exists and BEFORE it takes any write lock — i.e.
        // squarely inside the gate-to-purge window this test is about.
        let (tx, rx) = std::sync::mpsc::sync_channel::<()>(0);
        crate::deletion::install_after_header_read_signal(tx);

        let err = std::thread::scope(|scope| {
            let deleter_gate = std::sync::Arc::clone(&gate);
            let vault_ref = &vault;
            let deleter = scope.spawn(move || {
                deleter_gate.wait();
                facade_for(vault_ref, owner).safe_delete(&subject.to_hex(), reason)
            });
            // Stage the revocation in a HELD write txn: LMDB MVCC keeps it
            // invisible to the deleter's gate fold, so the gate is guaranteed
            // to evaluate against the still-live binding.
            let mut wtxn = vault.store.env.write_txn().expect("write txn");
            vault
                .put_authority_log_entries_in_txn(&mut wtxn, &[(revoke, test_time(3), 3)])
                .expect("stage revocation");
            gate.wait();
            // The deleter has read its header and signalled; commit the
            // revocation now and release the write lock it is about to want.
            rx.recv()
                .expect("deleter must signal after the header read");
            wtxn.commit().expect("commit revocation");
            deleter
                .join()
                .expect("deleter thread must not panic")
                .expect_err("a revocation landing before the destructive commit must refuse")
        });

        assert_eq!(err.code, FACADE_CODE_FORBIDDEN, "reason {reason:?}");
        assert!(
            err.message.contains("no active owner binding"),
            "reason {reason:?}: the refusal must name the real cause, not a \
             generic concurrency error: {}",
            err.message
        );
        // Nothing torn: the subject survives intact.
        assert_eq!(
            vault.get_entity_type(&subject).expect("get subject"),
            Some(ENTITY_TYPE_PERSON),
            "reason {reason:?}: a refused delete must leave the entity whole"
        );
    }
}

/// fix-leg 6: a refusal must not publish.
///
/// fix-5 re-folded the owner at five destructive sites, but the sync leg's
/// authority lived in `stage_deletion_gate_recovery`'s transaction, which
/// COMMITS and drops its snapshot; `finish_crdt_tombstone_persist` then wrote
/// the CRDT snapshot, the `u:w:` carrier and the delete-bearing `q:` row in a
/// LATER transaction carrying no authority at all. A `RevokeActor` landing
/// between the two therefore let the tombstone reach peers and only the purge
/// re-check refused — `safe_delete` returned FORBIDDEN *after* an unauthorized
/// deletion had already been published, which is unrecoverable: a peer that
/// applied it has hard-deleted the entity.
///
/// The rendezvous fires exactly in that interval. The assertions are the
/// no-publish invariant, carrier by carrier: no live-doc tombstone, no `d:w:`
/// snapshot, no `u:w:` row, no `q:` queue row, and no pending gate sidecar
/// that a later replay could redeem.
#[cfg(feature = "sync")]
#[test]
fn revocation_racing_the_tombstone_publish_refuses_and_publishes_nothing() {
    use std::sync::Arc;

    use crate::sync::{WindowKey, WindowManager, bridge::Materializer};

    let _serial = lock_delete_rendezvous();
    let dir = tempfile::tempdir().expect("tempdir");
    let vault =
        Arc::new(crate::Vault::open(dir.path(), VaultConfig::default()).expect("open vault"));
    let owner = put_person(&vault, 0x94);
    let subject = put_person(&vault, 0x95);
    let revoke = root_binding_with_pending_revocation(&vault, 0x96, owner);

    let manager = Arc::new(WindowManager::new(
        Arc::clone(&vault),
        Arc::new(Materializer::new()),
        "facade-publish-boundary",
    ));
    // A connected peer: `route_live` would hand it the tombstone the instant
    // the publish leaked one.
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
    manager.outbound().attach(tx);
    let window_key = WindowKey::from_timestamp(1);
    let window = manager
        .open_window(&window_key)
        .expect("open live deletion window");

    // Control: with the binding live, the same path publishes end to end — so
    // the assertions below pin the refusal, not a broken fixture.
    let warmup = put_person(&vault, 0x97);
    facade_for(&vault, owner)
        .safe_delete(&warmup.to_hex(), SafeDeleteReason::UserHardDelete)
        .expect("control: a bound owner publishes a tombstone");
    rx.try_recv().expect("control: the peer receives it");

    // Two-phase rendezvous: `arrived` fires once the deleter's gate sidecar is
    // durably staged (its txn committed, no lock held); `resume` releases it
    // into the publish txn after the revocation has landed. The deleter's own
    // staging txn takes the write lock, so the fix-5 held-txn trick would
    // deadlock here — the revocation has to commit while the deleter parks.
    let (arrived_tx, arrived_rx) = std::sync::mpsc::sync_channel(0);
    let (resume_tx, resume_rx) = std::sync::mpsc::sync_channel::<()>(0);
    crate::deletion::install_delete_rendezvous(
        crate::deletion::DeleteRendezvous::BeforeTombstonePublish,
        subject,
        arrived_tx,
        resume_rx,
    );

    let (err, staged_decision_id) = std::thread::scope(|scope| {
        let vault_ref = &vault;
        let deleter = scope.spawn(move || {
            facade_for(vault_ref, owner)
                .safe_delete(&subject.to_hex(), SafeDeleteReason::UserHardDelete)
        });
        // The staged decision id: a refused delete returns no request id, so
        // this is the only handle on the sidecar the refusal must withdraw.
        let staged_decision_id = arrived_rx
            .recv()
            .expect("deleter must signal once its gate sidecar is staged")
            .expect("a hard arm stages a gate sidecar and names it here");
        // The pre-txn gate and the staging re-fold have BOTH already passed on
        // the live binding; the delete is parked believing it is authorized.
        vault
            .put_authority_log_entries(&[(revoke, test_time(3), 3)])
            .expect("commit revocation inside the publish window");
        resume_tx.send(()).expect("release the deleter");
        let err = deleter
            .join()
            .expect("deleter thread must not panic")
            .expect_err("a revocation landing before the publish commit must refuse");
        (err, staged_decision_id)
    });

    assert_eq!(err.code, FACADE_CODE_FORBIDDEN);
    assert!(
        err.message.contains("no active owner binding"),
        "the parked pre-gate error must survive the publish boundary, not \
         degrade to a generic concurrency code: {}",
        err.message
    );

    // Victim intact.
    assert_eq!(
        vault.get_entity_type(&subject).expect("get subject"),
        Some(ENTITY_TYPE_PERSON),
        "a refused delete must leave the entity whole"
    );

    // No carrier published — live doc, snapshot, update row, queue row.
    assert!(
        window
            .doc
            .get_map("tombstones")
            .get(&subject.to_hex())
            .is_none(),
        "a refused delete must not leave a tombstone in the shared live doc"
    );
    assert!(
        rx.try_recv().is_err(),
        "a refused delete must not route an outbound update to the peer"
    );
    let snapshot = vault
        .sync_state_get(&format!("d:w:{window_key}"))
        .expect("read persisted window snapshot");
    if let Some(snapshot) = snapshot {
        let persisted = crate::sync::loro_support::doc_from_snapshot(&snapshot)
            .expect("persisted snapshot decodes");
        assert!(
            persisted
                .get_map("tombstones")
                .get(&subject.to_hex())
                .is_none(),
            "the refused tombstone must not reach the d:w: snapshot"
        );
    }
    for update_key in vault
        .sync_state_keys_with_prefix(&format!("u:w:{window_key}:"))
        .expect("read pending update rows")
    {
        let bytes = vault
            .sync_state_get(&update_key)
            .expect("read update row")
            .expect("update row exists");
        let replayed = crate::sync::schema::create_window_doc("probe", &window_key);
        crate::sync::loro_support::import_doc(&replayed, &bytes).expect("update row imports");
        assert!(
            replayed
                .get_map("tombstones")
                .get(&subject.to_hex())
                .is_none(),
            "the refused tombstone must not reach a u:w: carrier ({update_key})"
        );
    }
    let queue = crate::sync::SyncQueue::new(Arc::clone(&vault)).expect("open sync queue");
    for queued in queue.drain_updates().expect("drain queued updates") {
        let replayed = crate::sync::schema::create_window_doc("probe", &window_key);
        crate::sync::loro_support::import_doc(&replayed, &queued.encoded)
            .expect("queued update imports");
        assert!(
            replayed
                .get_map("tombstones")
                .get(&subject.to_hex())
                .is_none(),
            "the refused tombstone must not reach a delete-bearing q: row"
        );
    }

    // No pending gate sidecar: the staging from the earlier txn must be
    // withdrawn by the refusal itself, or a later replay would redeem it as a
    // pending AUTHORIZED deletion.
    let rtxn = vault.store.env.read_txn().expect("read txn");
    assert!(
        vault
            .store
            .pending_deletion_gate_decision_in_txn(&rtxn, staged_decision_id)
            .expect("read sidecar")
            .is_none(),
        "a refused publish must leave no redeemable authority sidecar"
    );
    drop(rtxn);
    // ...and no authority record was minted for a deletion that never happened.
    assert!(
        vault
            .gate_decisions(50)
            .expect("gate decisions")
            .iter()
            .all(|decision| decision.decision_id != staged_decision_id),
        "a refused publish must mint no gate decision"
    );
}

/// A vault wired for the fix-leg 7 publish-boundary regressions: an attached
/// peer channel plus, on the LIVE leg, an open registry window — so both halves
/// of "did this delete publish?" are observable, the shared live doc and the
/// outbound route.
///
/// `window: None` is the TRANSIENT leg (window never opened), where the publish
/// takes the import-merge path instead of the shared doc. It is a genuinely
/// different code path through `write_crdt_tombstone`, so every regression here
/// runs both.
/// Vector width for the orphan-residue fixture. Small and arbitrary — the
/// headerless delete door only cares that a `vectors` row exists.
#[cfg(feature = "sync")]
const RESIDUE_VECTOR_DIMS: usize = 4;

#[cfg(feature = "sync")]
struct PublishBoundaryHarness {
    _dir: tempfile::TempDir,
    vault: std::sync::Arc<crate::Vault>,
    window: Option<std::sync::Arc<crate::sync::window::LoadedWindow>>,
    window_key: crate::sync::WindowKey,
    outbound: tokio::sync::mpsc::UnboundedReceiver<crate::sync::types::LocalUpdate>,
    _manager: std::sync::Arc<crate::sync::WindowManager>,
}

#[cfg(feature = "sync")]
impl PublishBoundaryHarness {
    fn open(label: &str, live_window: bool) -> Self {
        Self::open_with_config(label, live_window, VaultConfig::default())
    }

    /// [`Self::open`] with an embedding model declared, which
    /// `ensure_model_id_for_vector_write` requires before any vector write —
    /// the only way to build the orphan-vector residue the headerless delete
    /// door needs.
    fn open_for_vector_residue(label: &str, live_window: bool) -> Self {
        Self::open_with_config(
            label,
            live_window,
            VaultConfig {
                embedding_model: Some("test/model@v1".to_owned()),
                dimensions: RESIDUE_VECTOR_DIMS,
                ..VaultConfig::default()
            },
        )
    }

    fn open_with_config(label: &str, live_window: bool, config: VaultConfig) -> Self {
        use std::sync::Arc;

        use crate::sync::{WindowKey, WindowManager, bridge::Materializer};

        let dir = tempfile::tempdir().expect("tempdir");
        let vault = Arc::new(crate::Vault::open(dir.path(), config).expect("open vault"));
        let manager = Arc::new(WindowManager::new(
            Arc::clone(&vault),
            Arc::new(Materializer::new()),
            label,
        ));
        let (tx, outbound) = tokio::sync::mpsc::unbounded_channel();
        manager.outbound().attach(tx);
        // Every fixture entity is put at `learned_at = 1`, so this is the window
        // the headerful deletes address.
        let window_key = WindowKey::from_timestamp(1);
        // `open_window` also attaches the manager to the vault, which is what
        // routes deletes at all — the transient leg does that explicitly so its
        // outbound assertions mean something.
        let window = if live_window {
            Some(
                manager
                    .open_window(&window_key)
                    .expect("open live deletion window"),
            )
        } else {
            manager.attach_to_vault();
            None
        };
        Self {
            _dir: dir,
            vault,
            window,
            window_key,
            outbound,
            _manager: manager,
        }
    }

    /// Whether the shared live doc carries a tombstone for `id`. Vacuously
    /// false on the transient leg, which has no live doc to carry one.
    fn live_doc_tombstoned(&self, id: &EntityId) -> bool {
        self.window
            .as_ref()
            .is_some_and(|window| window.doc.get_map("tombstones").get(&id.to_hex()).is_some())
    }

    /// Whether the persisted `d:w:` snapshot carries a tombstone for `id`.
    /// A window with no snapshot row yet trivially carries none.
    fn snapshot_tombstoned(&self, id: &EntityId) -> bool {
        let Some(snapshot) = self
            .vault
            .sync_state_get(&format!("d:w:{}", self.window_key))
            .expect("read persisted window snapshot")
        else {
            return false;
        };
        crate::sync::loro_support::doc_from_snapshot(&snapshot)
            .expect("persisted snapshot decodes")
            .get_map("tombstones")
            .get(&id.to_hex())
            .is_some()
    }

    /// Whether any pending `u:w:` update row replays a tombstone for `id`.
    fn update_rows_tombstoned(&self, id: &EntityId) -> bool {
        self.vault
            .sync_state_keys_with_prefix(&format!("u:w:{}:", self.window_key))
            .expect("read pending update rows")
            .into_iter()
            .any(|update_key| {
                let bytes = self
                    .vault
                    .sync_state_get(&update_key)
                    .expect("read update row")
                    .expect("update row exists");
                let replayed = crate::sync::schema::create_window_doc("probe", &self.window_key);
                crate::sync::loro_support::import_doc(&replayed, &bytes)
                    .expect("update row imports");
                replayed.get_map("tombstones").get(&id.to_hex()).is_some()
            })
    }

    /// Whether any queued `q:` row replays a tombstone for `id`. DRAINS the
    /// queue, so call it once per subject.
    fn queue_rows_tombstoned(&self, id: &EntityId) -> bool {
        let queue = crate::sync::SyncQueue::new(std::sync::Arc::clone(&self.vault))
            .expect("open sync queue");
        queue
            .drain_updates()
            .expect("drain queued updates")
            .into_iter()
            .any(|queued| {
                let replayed = crate::sync::schema::create_window_doc("probe", &self.window_key);
                crate::sync::loro_support::import_doc(&replayed, &queued.encoded)
                    .expect("queued update imports");
                replayed.get_map("tombstones").get(&id.to_hex()).is_some()
            })
    }

    /// Whether a `pt:` pending-tombstone marker for `id` survives — the
    /// replayable carrier a refusal must withdraw. Checks BOTH candidate window
    /// labels: the soft arm addresses `learned_at`'s window and the headerless
    /// leg addresses NOW's, and at a month boundary those differ.
    fn replayable_pending_marker(&self, id: &EntityId) -> bool {
        [
            self.window_key.as_str().to_owned(),
            crate::deletion::window_label_from_timestamp(crate::unix_seconds_now()),
        ]
        .iter()
        .any(|window_label| {
            self.vault
                .sync_state_get(&crate::deletion::pending_tombstone_key(window_label, id))
                .expect("read pt: marker")
                .is_some()
        })
    }

    /// Every no-publish assertion in one call, for a delete that must have been
    /// refused BEFORE its linearization point.
    fn assert_nothing_published(&mut self, id: &EntityId, context: &str) {
        assert!(
            !self.live_doc_tombstoned(id),
            "{context}: a refused delete must not leave a tombstone in the shared live doc"
        );
        assert!(
            self.outbound.try_recv().is_err(),
            "{context}: a refused delete must not route an outbound update to the peer"
        );
        assert!(
            !self.snapshot_tombstoned(id),
            "{context}: the refused tombstone must not reach the d:w: snapshot"
        );
        assert!(
            !self.update_rows_tombstoned(id),
            "{context}: the refused tombstone must not reach a u:w: carrier"
        );
        assert!(
            !self.queue_rows_tombstoned(id),
            "{context}: the refused tombstone must not reach a delete-bearing q: row"
        );
        assert!(
            !self.replayable_pending_marker(id),
            "{context}: the refused tombstone must not survive as a replayable pt: marker"
        );
    }
}

/// The delete rendezvous is ONE process-global slot, and `cargo test` runs these
/// in parallel threads of a single process. Two tests installing concurrently
/// would clobber each other's channels — one delete parks on a receiver the
/// other test owns, the other gets a `RecvError` from a dropped sender. Every
/// test that installs a rendezvous holds this lock for the whole install→join
/// window. Poison is ignored deliberately: a panicking test has already failed
/// and must not cascade into unrelated ones.
static DELETE_RENDEZVOUS_TESTS: std::sync::Mutex<()> = std::sync::Mutex::new(());

fn lock_delete_rendezvous() -> std::sync::MutexGuard<'static, ()> {
    DELETE_RENDEZVOUS_TESTS
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// Parks a gated delete at `step`, commits `revoke` while it waits, and returns
/// the delete's result. The two-phase shape is forced: the steps around these
/// seams take the LMDB write lock themselves, so the revocation cannot be
/// pre-staged in a held txn — the deleter must announce while holding nothing.
///
/// Caller must hold [`lock_delete_rendezvous`].
fn safe_delete_with_revocation_at(
    vault: &std::sync::Arc<crate::Vault>,
    owner: EntityId,
    target: EntityId,
    reason: SafeDeleteReason,
    step: crate::deletion::DeleteRendezvous,
    revoke: crate::authority::AuthorityLogEntry,
) -> FacadeResult<DeleteReceipt> {
    let (arrived_tx, arrived_rx) = std::sync::mpsc::sync_channel(0);
    let (resume_tx, resume_rx) = std::sync::mpsc::sync_channel::<()>(0);
    crate::deletion::install_delete_rendezvous(step, target, arrived_tx, resume_rx);

    std::thread::scope(|scope| {
        let vault_ref = vault.as_ref();
        let deleter =
            scope.spawn(move || facade_for(vault_ref, owner).safe_delete(&target.to_hex(), reason));
        arrived_rx
            .recv()
            .expect("the deleter must reach the installed rendezvous");
        vault
            .put_authority_log_entries(&[(revoke, test_time(3), 3)])
            .expect("commit the revocation while the deleter is parked");
        resume_tx.send(()).expect("release the deleter");
        deleter.join().expect("deleter thread must not panic")
    })
}

/// fix-leg 7 P1-1: the SOFT arm's publish must pass the gate too.
///
/// `user_delete` scrubs the body to a 25 B shell in one txn, then publishes the
/// tombstone. fix-5 re-folded the owner in the scrub txn and fix-6 gated the
/// hard arms' publish — but the soft arm called `write_crdt_tombstone(..., None,
/// None)`, so its publication passed NO gate at all. A `RevokeActor` landing
/// between the scrub commit and the publish was never observed: the tombstone
/// reached the live doc and the peer, the `d:w:`/`u:w:`/`q:` carriers persisted,
/// and the `pt:` marker the scrub txn had already committed stayed on disk as a
/// replayable propagation intent — an unauthorized soft delete, published.
///
/// Both legs, because they are different code paths through the publish: LIVE
/// (window open, registry-owned shared doc, `route_live` on the wire) and
/// TRANSIENT (window closed, doc import-merged from persisted state). fix-6's
/// concern list flagged the transient-leg symmetry as an open follow-up; it is
/// folded in here.
#[cfg(feature = "sync")]
#[test]
fn revocation_racing_the_soft_delete_publish_refuses_and_publishes_nothing() {
    let _serial = lock_delete_rendezvous();
    for live_window in [true, false] {
        let leg = if live_window { "live" } else { "transient" };
        let mut harness = PublishBoundaryHarness::open("facade-soft-publish-boundary", live_window);
        let owner = put_person(&harness.vault, 0x20);
        let subject = put_person(&harness.vault, 0x2A);
        let revoke = root_binding_with_pending_revocation(&harness.vault, 0x2B, owner);

        // Control: with the binding live, the soft arm publishes end to end —
        // so the assertions below pin the refusal, not a broken fixture.
        let warmup = put_person(&harness.vault, 0x2C);
        facade_for(&harness.vault, owner)
            .safe_delete(&warmup.to_hex(), SafeDeleteReason::UserDelete)
            .expect("control: a bound owner soft-deletes");
        assert!(
            harness.snapshot_tombstoned(&warmup),
            "{leg} control: the d:w: snapshot must carry the warmup tombstone — \
             on both legs the publish txn persists it"
        );
        if live_window {
            assert!(
                harness.live_doc_tombstoned(&warmup),
                "{leg} control: the live doc must carry the warmup tombstone"
            );
            // `route_live` is the LIVE leg's last act. The transient leg has no
            // open window to route through — its delivery is the queued `q:`
            // row, which the control below leaves in place deliberately.
            assert!(
                harness.outbound.try_recv().is_ok(),
                "{leg} control: the peer receives the warmup tombstone"
            );
        }
        // Drain the control's outbound traffic so the refusal assertion below
        // reads an empty channel only if the REFUSED delete routed nothing.
        while harness.outbound.try_recv().is_ok() {}

        let err = safe_delete_with_revocation_at(
            &harness.vault,
            owner,
            subject,
            SafeDeleteReason::UserDelete,
            crate::deletion::DeleteRendezvous::BeforeTombstonePublish,
            revoke,
        )
        .expect_err("a revocation landing before the publish commit must refuse");

        assert_eq!(err.code, FACADE_CODE_FORBIDDEN, "{leg}");
        assert!(
            err.message.contains("no active owner binding"),
            "{leg}: the parked pre-gate error must survive the publish boundary, \
             not degrade to a generic concurrency code: {}",
            err.message
        );
        // The shell scrub already committed — that is the pre-publication act
        // this arm is allowed to have done, and fix-5's re-fold gated it. What
        // must NOT exist is any published or replayable carrier.
        harness.assert_nothing_published(&subject, leg);
    }
}

/// fix-leg 7 P1-2 (a): a revocation committed AFTER the publish commit does NOT
/// refuse — the delete COMPLETES.
///
/// The publish commit is the delete's linearization point. fix-5 re-folded the
/// owner at the destructive steps that follow it (soft-erase, purge, headerless
/// purge), which meant a `RevokeActor` landing in the interval publish→purge
/// produced the rejected-call-publishes shape: the caller got FORBIDDEN while
/// the tombstone was already on the wire and peers were already tearing the
/// entity. That refusal is both unactionable and false — sync replay of the
/// published tombstone purges this replica regardless, so the local state the
/// refusal claims to have preserved does not survive anyway.
///
/// Under the ruling the answer is settled at publish: a revocation LMDB-ordered
/// after that commit simply follows an operation that was authorized when it
/// committed, which is ordinary linearizable ordering, not a race. Both
/// post-publication rendezvous points are driven, across every hard reason and
/// the headerless door.
///
/// MUTATION PROBE: re-adding an authority re-fold at any post-publish site
/// fails this test (the delete returns FORBIDDEN and the victim survives) while
/// the pre-publish regressions above still pass — the two directions are pinned
/// independently.
#[cfg(feature = "sync")]
#[test]
fn revocation_after_the_publish_commit_lets_the_delete_complete() {
    let _serial = lock_delete_rendezvous();
    let steps = [
        // Entry to the first post-publication destructive step: the soft-erase
        // for gdpr/policy, the purge for user_hard_delete.
        crate::deletion::DeleteRendezvous::AfterTombstonePublish,
        // Entry to the purge on the arms that ran a soft-erase first.
        crate::deletion::DeleteRendezvous::BeforeHardPurge,
    ];
    let reasons = [
        SafeDeleteReason::UserHardDelete,
        SafeDeleteReason::GdprDelete,
        SafeDeleteReason::PolicyDelete,
    ];
    for live_window in [true, false] {
        for step in steps {
            for reason in reasons {
                let leg = if live_window { "live" } else { "transient" };
                let case = format!("{leg}/{step:?}/{reason:?}");
                let harness =
                    PublishBoundaryHarness::open("facade-post-publish-boundary", live_window);
                let owner = put_person(&harness.vault, 0x2D);
                let subject = put_person(&harness.vault, 0x2E);
                let revoke = root_binding_with_pending_revocation(&harness.vault, 0x2F, owner);

                let receipt = safe_delete_with_revocation_at(
                    &harness.vault,
                    owner,
                    subject,
                    reason,
                    step,
                    revoke,
                )
                .unwrap_or_else(|err| {
                    panic!(
                        "{case}: a revocation ordered AFTER the publish commit must not \
                         refuse a committed deletion, but got {}: {}",
                        err.code, err.message
                    )
                });

                assert!(receipt.existed, "{case}: the delete must claim the erasure");
                assert!(
                    receipt.receipt_ref.is_some(),
                    "{case}: every hard reason writes a REDACTION_AUDIT receipt"
                );
                // Torn for real: the entity row is gone, not merely shelled.
                assert_eq!(
                    harness
                        .vault
                        .get_entity_type(&subject)
                        .expect("get subject"),
                    None,
                    "{case}: the victim must be purged"
                );
                // ...and the `dt:` local hard-delete truth is durable.
                let rtxn = harness.vault.store.env.read_txn().expect("read txn");
                assert!(
                    harness
                        .vault
                        .local_hard_delete_marker_exists_in_txn(&rtxn, &subject)
                        .expect("read dt: marker"),
                    "{case}: the purge txn must write the dt: marker"
                );
            }
        }
    }
}

/// fix-leg 7 P1-2 (a), headerless door: same law where there is no header.
///
/// `delete_entity_without_header` erases orphan residue (a vector with no
/// entities row). It publishes a tombstone first and purges after, so it has the
/// same post-publication interval — and fix-5 put a re-fold in its purge txn
/// too. Driven separately because the residue fixture cannot be built through
/// `put_person`.
#[cfg(feature = "sync")]
#[test]
fn revocation_after_the_publish_commit_lets_a_headerless_delete_complete() {
    let _serial = lock_delete_rendezvous();
    for live_window in [true, false] {
        let leg = if live_window { "live" } else { "transient" };
        let harness = PublishBoundaryHarness::open_for_vector_residue(
            "facade-headerless-boundary",
            live_window,
        );
        let owner = put_person(&harness.vault, 0x34);
        let revoke = root_binding_with_pending_revocation(&harness.vault, 0x35, owner);

        // Headerless residue: a vector with no entities row, so the delete takes
        // `delete_entity_without_header`.
        let subject = EntityId::from_bytes([0x3B; 16]).expect("residue id");
        harness
            .vault
            .put_vector(&subject, &[0.1, 0.2, 0.3, 0.4])
            .expect("put orphan vector");
        assert!(
            harness.vault.get_raw(&subject).expect("get raw").is_none(),
            "{leg}: headerless precondition — no entities row"
        );

        let receipt = safe_delete_with_revocation_at(
            &harness.vault,
            owner,
            subject,
            SafeDeleteReason::GdprDelete,
            crate::deletion::DeleteRendezvous::AfterTombstonePublish,
            revoke,
        )
        .unwrap_or_else(|err| {
            panic!(
                "{leg}: the headerless purge must not re-decide authority after \
                 publication, but got {}: {}",
                err.code, err.message
            )
        });

        // `existed` tracks the ENTITIES row, which a headerless residue has none
        // of by construction — so the erasure evidence here is the audit receipt
        // and the purged vector, exactly as the pre-existing headerless fixtures
        // assert.
        assert!(
            receipt.receipt_ref.is_some(),
            "{leg}: the headerless purge must write its REDACTION_AUDIT receipt"
        );
        assert_eq!(
            harness.vault.get_vector(&subject).expect("get vector"),
            None,
            "{leg}: the orphan vector must be purged"
        );
        let rtxn = harness.vault.store.env.read_txn().expect("read txn");
        assert!(
            harness
                .vault
                .local_hard_delete_marker_exists_in_txn(&rtxn, &subject)
                .expect("read dt: marker"),
            "{leg}: the headerless purge txn must write the dt: marker"
        );
    }
}

/// fix-leg 8 P1: WITHOUT a publish commit there is no linearization point, so
/// the first destructive transaction must still re-prove authority.
///
/// `write_crdt_tombstone` is a NO-OP in a build without `sync` — it publishes
/// nothing and returns `crdt_persisted: false`. fix-7 read "after the publish
/// commit, do not re-check" as unconditional and removed the soft-erase and
/// purge re-folds, which on this build removed the ONLY in-transaction authority
/// checks the hard arms had: nothing had published, so the check fix-7 relied on
/// never ran. A `RevokeActor` landing after `safe_delete`'s entry fold then let
/// `user_hard_delete` / `gdpr_delete` / `policy_delete` tear the entity locally,
/// append an `allow` gate record, and commit the `pt:` marker whose verbatim
/// tombstone bytes a later sync-enabled boot replays through
/// `replay_pending_tombstones` — an unauthorized deletion, published on a delay.
///
/// The refined rule keys on `crdt_persisted`, not on the cargo feature: a
/// `sync` build path that declines to publish must obey the same law, and a
/// `#[cfg]` here would silently exempt it. The rendezvous parks the deleter in
/// the window after the entry fold and before the first destructive commit —
/// which on this build is where `AfterTombstonePublish` fires, since the
/// "publish" it names did nothing.
///
/// MUTATION PROBE: drop the conditional reverify from the hard arms' first
/// destructive txn and this test fails — the delete succeeds, the victim is
/// purged, and the replayable `pt:` marker survives.
#[cfg(not(feature = "sync"))]
#[test]
fn revocation_after_a_nonpublishing_delete_refuses_and_tears_nothing() {
    let _serial = lock_delete_rendezvous();
    for reason in [
        SafeDeleteReason::UserHardDelete,
        SafeDeleteReason::GdprDelete,
        SafeDeleteReason::PolicyDelete,
    ] {
        let case = format!("{reason:?}");
        let dir = tempfile::tempdir().expect("tempdir");
        let vault = std::sync::Arc::new(
            crate::Vault::open(dir.path(), VaultConfig::default()).expect("open vault"),
        );
        let owner = put_person(&vault, 0x40);
        let subject = put_person(&vault, 0x41);
        let revoke = root_binding_with_pending_revocation(&vault, 0x42, owner);

        let err = safe_delete_with_revocation_at(
            &vault,
            owner,
            subject,
            reason,
            crate::deletion::DeleteRendezvous::AfterTombstonePublish,
            revoke,
        )
        .expect_err(&format!(
            "{case}: nothing published, so the first destructive txn is this \
             delete's linearization point and MUST refuse"
        ));

        assert_eq!(err.code, FACADE_CODE_FORBIDDEN, "{case}");
        assert!(
            err.message.contains("no active owner binding"),
            "{case}: the parked pre-gate error must survive, not degrade to a \
             generic concurrency code: {}",
            err.message
        );
        // Intact, not merely un-purged: the shell scrub must not have run either.
        assert_eq!(
            vault.get_entity_type(&subject).expect("get subject"),
            Some(ENTITY_TYPE_PERSON),
            "{case}: a refused delete must leave the entity whole"
        );
        assert_eq!(
            vault
                .get_raw(&subject)
                .expect("get raw")
                .expect("subject row survives")
                .len(),
            crate::batch::ENTITY_METADATA_HEADER_LEN + b"facade person".len(),
            "{case}: the body must be un-scrubbed — a 25 B shell would mean the \
             soft-erase committed before the refusal"
        );
        assert_no_local_delete_artifacts(&vault, &subject, &case);
    }
}

/// Every durable artifact a REFUSED sync-disabled delete must not leave behind,
/// in one call. Distinct from `PublishBoundaryHarness::assert_nothing_published`,
/// which pins the CRDT carriers a `sync` build could leak; without the feature
/// there are no such carriers, and the whole surface is local:
///
/// - `pt:{window}:{id}` — the pending-tombstone marker. THE one that matters:
///   it holds the verbatim 25 B tombstone wire value, and
///   `sync::window::replay_pending_tombstones` turns it into a published
///   tombstone on the next sync-enabled boot. A revoked owner leaving one behind
///   has published an unauthorized deletion, just deferred.
/// - `dt:{id}` — the permanent local hard-delete marker. It is
///   presence-consulted by the materialization gates, so a stray one bricks the
///   id against every future write.
/// - `h:` sweep rows + REDACTION_AUDIT receipts — a refused delete audits no
///   erasure, because none happened.
/// - gate decisions — the authority ledger must not record an `allow` for a
///   deletion the authority refused.
///
/// Both window labels are probed for `pt:`: the headerful arms address
/// `learned_at`'s window and the headerless leg addresses NOW's, and at a month
/// boundary those differ.
#[cfg(not(feature = "sync"))]
fn assert_no_local_delete_artifacts(vault: &crate::Vault, id: &EntityId, context: &str) {
    use crate::registry::ENTITY_TYPE_REDACTION_AUDIT;

    let rtxn = vault.store.env.read_txn().expect("read txn");
    for window_label in [
        crate::deletion::window_label_from_timestamp(1),
        crate::deletion::window_label_from_timestamp(crate::unix_seconds_now()),
    ] {
        assert!(
            vault
                .store
                .sync_state
                .get(
                    &rtxn,
                    &crate::deletion::pending_tombstone_key(&window_label, id)
                )
                .expect("read pt: marker")
                .is_none(),
            "{context}: a refused delete must leave no replayable pt: marker \
             (a sync-enabled boot would replay it into the very publication the \
             refusal denied)"
        );
    }
    assert!(
        !vault
            .local_hard_delete_marker_exists_in_txn(&rtxn, id)
            .expect("read dt: marker"),
        "{context}: a refused delete must write no dt: local hard-delete marker"
    );
    assert!(
        vault
            .store
            .sync_queue
            .prefix_iter(&rtxn, crate::deletion::HARD_ERASE_SWEEP_PREFIX)
            .expect("iter sweep rows")
            .next()
            .is_none(),
        "{context}: a refused delete must queue no h: hard-erase sweep row"
    );
    drop(rtxn);
    assert!(
        vault
            .entities_by_type(ENTITY_TYPE_REDACTION_AUDIT)
            .expect("list receipts")
            .is_empty(),
        "{context}: a refused delete must mint no REDACTION_AUDIT receipt"
    );
    assert!(
        vault
            .gate_decisions(50)
            .expect("gate decisions")
            .iter()
            .all(|decision| decision.content_kind != "deletion"),
        "{context}: a refused delete must append no allow-gate deletion decision"
    );
}

/// fix-leg 8 P1, headerless leg: same law where there is no header.
///
/// `delete_entity_without_header` erases orphan residue (a vector with no
/// entities row). Its pre-publication guards were the scope probe's read txn and
/// the publish txn's re-fold — and on a build with no `sync` the second does not
/// exist, so fix-7's removal of the purge re-fold left this door with NO
/// in-transaction authority check at all. The residue is the part that makes it
/// bite differently from the headerful arms: it is the actual user data (a
/// vector, a BM25 posting), and a refused delete must leave it whole.
///
/// MUTATION PROBE: drop the conditional reverify from the headerless purge txn
/// and this test fails — the residue is erased and the receipt is minted.
#[cfg(not(feature = "sync"))]
#[test]
fn revocation_after_a_nonpublishing_headerless_delete_refuses_and_tears_nothing() {
    let _serial = lock_delete_rendezvous();
    let dir = tempfile::tempdir().expect("tempdir");
    let vault = std::sync::Arc::new(
        crate::Vault::open(
            dir.path(),
            VaultConfig {
                embedding_model: Some("test/model@v1".to_owned()),
                dimensions: 4,
                ..VaultConfig::default()
            },
        )
        .expect("open vault"),
    );
    let owner = put_person(&vault, 0x43);
    let revoke = root_binding_with_pending_revocation(&vault, 0x44, owner);

    // Headerless residue: a vector with no entities row, so the delete takes
    // `delete_entity_without_header`.
    let subject = EntityId::from_bytes([0x45; 16]).expect("residue id");
    vault
        .put_vector(&subject, &[0.1, 0.2, 0.3, 0.4])
        .expect("put orphan vector");
    assert!(
        vault.get_raw(&subject).expect("get raw").is_none(),
        "headerless precondition — no entities row"
    );

    let err = safe_delete_with_revocation_at(
        &vault,
        owner,
        subject,
        SafeDeleteReason::GdprDelete,
        crate::deletion::DeleteRendezvous::AfterTombstonePublish,
        revoke,
    )
    .expect_err(
        "the headerless purge is this delete's ONLY durable act when nothing \
         published, so it MUST re-decide authority",
    );

    assert_eq!(err.code, FACADE_CODE_FORBIDDEN);
    assert!(
        err.message.contains("no active owner binding"),
        "{}",
        err.message
    );
    // The residue itself survives — the point of the headerless door.
    assert_eq!(
        vault.get_vector(&subject).expect("get vector"),
        Some(vec![0.1, 0.2, 0.3, 0.4]),
        "a refused headerless delete must leave the orphan vector intact"
    );
    assert_no_local_delete_artifacts(&vault, &subject, "headerless");
}

/// fix-leg 9 P1: on the NON-PUBLISHING path the soft erase and the `pt:`
/// propagation intent are ONE transaction.
///
/// fix-8 put the conditional re-fold in the gdpr/policy soft-erase txn, and that
/// txn commits — but the replayable `pt:` marker was only written later, in the
/// purge txn. Between those two commits the erasure had a shape no compliance
/// path may have: the body was scrubbed locally and irreversibly, every peer
/// still held the full data, and NO durable record of the intent to propagate
/// the delete existed. A crash there — or any error on the purge path, which is
/// the ordinary failure this reaches through — silently downgraded a GDPR /
/// policy erasure to a local-only scrub. Nothing would ever heal it: a retry
/// captures the bodiless 25 B shell, and the sync-enabled boot that would have
/// replayed the deletion finds no marker to replay.
///
/// Driven by failing the marker write itself, which is the strongest available
/// statement of atomicity: whatever the transaction had done up to that point
/// must vanish with it. Both reasons that take the soft-erase phase, because
/// they are one arm and a future edit could split them.
///
/// MUTATION PROBE: move the `pt:` write back to the purge txn (drop it from the
/// scrub txn) and this test fails — the injection never fires, the delete
/// SUCCEEDS, and `expect_err` panics.
#[cfg(not(feature = "sync"))]
#[test]
fn a_failed_first_txn_pending_tombstone_rolls_back_the_soft_erase() {
    for reason in [SafeDeleteReason::GdprDelete, SafeDeleteReason::PolicyDelete] {
        let case = format!("{reason:?}");

        // Control, on its OWN vault: unarmed, the same delete completes and
        // leaves the marker. It runs separately so the armed leg's
        // "no artifacts at all" assertion stays absolute — a control delete in
        // the same vault would leave a legitimate receipt and pt: row.
        let (control_dir, control_vault) = open_nonpublishing_delete_vault();
        let control_owner = put_person(&control_vault, 0x50);
        let control_subject = put_person(&control_vault, 0x51);
        root_vault_binding(&control_vault, 0x52, control_owner, "human");
        facade_for(&control_vault, control_owner)
            .safe_delete(&control_subject.to_hex(), reason)
            .unwrap_or_else(|err| panic!("{case} control: {}: {}", err.code, err.message));
        assert!(
            first_txn_pending_tombstone_exists(&control_vault, &control_subject),
            "{case} control: a completed sync-OFF erasure keeps its replayable \
             pt: propagation intent, written in the scrub txn"
        );
        drop(control_dir);

        let (_dir, vault) = open_nonpublishing_delete_vault();
        let owner = put_person(&vault, 0x53);
        let subject = put_person(&vault, 0x54);
        // The soft erase deletes the vector row too, so a surviving vector is
        // independent evidence that the scrub itself rolled back — not merely
        // that the entity body was left alone.
        vault
            .put_vector(&subject, &[0.5, 0.6, 0.7, 0.8])
            .expect("put subject vector");
        root_vault_binding(&vault, 0x55, owner, "human");

        crate::deletion::arm_fail_first_txn_pending_tombstone();
        let err = facade_for(&vault, owner)
            .safe_delete(&subject.to_hex(), reason)
            .expect_err(
                "the pt: marker is written INSIDE the re-verified soft-erase \
                 txn, so failing it must fail the whole delete",
            );
        assert_eq!(err.code, FACADE_CODE_INTERNAL, "{case}");

        // The scrub rolled back with the marker: body whole, vector whole.
        assert_eq!(
            vault
                .get_raw(&subject)
                .expect("get raw")
                .expect("subject row survives")
                .len(),
            crate::batch::ENTITY_METADATA_HEADER_LEN + b"facade person".len(),
            "{case}: a 25 B shell would mean the scrub committed without the \
             marker — the exact split fix-leg 9 closes"
        );
        assert_eq!(
            vault.get_vector(&subject).expect("get vector"),
            Some(vec![0.5, 0.6, 0.7, 0.8]),
            "{case}: the soft erase deletes the vector row, so it must return"
        );
        assert_no_local_delete_artifacts(&vault, &subject, &case);
    }
}

/// fix-leg 9, the `existed` half of the guard: a soft erase that found NOTHING
/// still writes no `pt:`.
///
/// Moving the marker into the scrub txn put a `pt:` write on a path that had
/// none, so it inherits ONE-1149's rule and must be pinned there: a delete whose
/// scope raced away between the header read and the scrub txn erased nothing,
/// and a `pt:` marker is a claim that this delete has data to propagate away.
/// Emitting one would replay a deletion for an id this call never touched.
/// `assert_no_erasure_audit_artifacts` pins the same law for the purge txn's
/// marker; nothing covered the new site, because the pre-existing headerful
/// raced test uses `user_hard_delete`, which has no soft-erase phase at all.
///
/// MUTATION PROBE: drop `existed &&` from the scrub txn's marker guard and this
/// test fails — the raced delete reports `missing()` while leaving a replayable
/// `pt:` behind.
#[cfg(not(feature = "sync"))]
#[test]
fn a_soft_erase_that_erased_nothing_writes_no_pending_tombstone() {
    for reason in [DeleteReason::GdprDelete, DeleteReason::PolicyDelete] {
        let case = format!("{reason:?}");
        let learned_at = 1_772_000_000;

        for attempt in 0..3 {
            let (_dir, vault) = open_nonpublishing_delete_vault();
            let id = EntityId::from_bytes([0x56; 16]).expect("victim id");
            vault
                .batch()
                .put(
                    &id,
                    ENTITY_TYPE_PERSON,
                    TimeRange {
                        start: learned_at,
                        end: learned_at,
                    },
                    learned_at,
                    b"raced-away-before-the-scrub",
                )
                .commit()
                .expect("put victim");

            // The eraser stages the full-scope erase in a HELD write txn, so the
            // deleter's lock-free header read still sees the entity; the commit
            // lands while the deleter blocks on the write lock, and its scrub txn
            // then finds nothing. Identical construction to the ONE-1149
            // raced-to-nothing legs.
            let (tx, rx) = std::sync::mpsc::sync_channel::<()>(0);
            crate::deletion::install_after_header_read_signal(tx);
            let barrier = std::sync::Arc::new(std::sync::Barrier::new(2));
            let outcome = std::thread::scope(|scope| {
                let mut wtxn = vault.store.env.write_txn().expect("write txn");
                crate::batch::deindex_entity(&vault.store, &mut wtxn, &id).expect("stage erase");
                let deleter_barrier = std::sync::Arc::clone(&barrier);
                let vault_ref = &vault;
                let deleter = scope.spawn(move || {
                    deleter_barrier.wait();
                    vault_ref.delete_entity_with_reason(&id, reason)
                });
                barrier.wait();
                rx.recv()
                    .expect("deleter must signal after the header read");
                wtxn.commit().expect("commit the racing erase");
                deleter.join().expect("deleter thread must not panic")
            })
            .expect("a raced delete is not an error");

            if vault.get_raw(&id).expect("get raw").is_some() {
                // Scheduling miss: the deleter never reached the raced branch.
                assert!(attempt < 2, "{case}: raced branch never constructed");
                continue;
            }
            assert!(
                !outcome.existed,
                "{case}: a delete that erased nothing must not claim it did"
            );
            assert!(
                !first_txn_pending_tombstone_exists(&vault, &id),
                "{case}: the scrub txn erased nothing, so it must stage no \
                 replayable pt: propagation intent for it"
            );
            break;
        }
    }
}

/// fix-leg 10 P1: an EMPTY commit settles nothing, so it must not latch
/// `authority_settled`.
///
/// fix-8 latched the flag unconditionally the moment the soft-erase txn ran, on
/// the theory that a committed destructive transaction is this delete's
/// linearization point. It is — when it actually erased something. When the
/// delete's scope raced away between the header read and the scrub txn
/// (`existed == false`, ONE-1149's shape), that transaction commits nothing at
/// all: no body scrubbed, no vector dropped, no `pt:` staged. Latching on it
/// declared a linearization point that does not exist, and the purge txn then
/// asked NO authority question.
///
/// What that bought an attacker: a `RevokeActor` AND a same-id re-put both
/// landing in the window before the purge were ignored wholesale. The purge tore
/// the REPLACEMENT state — data the revoked actor was never authorized to touch
/// and that this delete never even read — wrote the `dt:` marker that bricks the
/// id forever, committed the replayable `pt:` propagation intent, and appended
/// the stale `allow` gate decision minted from a snapshot two commits stale.
///
/// Fully deterministic, using the rendezvous slot TWICE: the deleter parks
/// before its scrub txn while the harness races the scope away, then parks again
/// at `BeforeHardPurge` while the harness commits the revocation and the re-put.
/// No `AFTER_HEADER_READ` contention with the other raced tests, and no retry
/// loop — LMDB's single writer does the ordering.
///
/// MUTATION PROBE: latch unconditionally again (`authority_settled = true;`) and
/// this test fails — the purge re-folds nothing, the delete SUCCEEDS, and
/// `expect_err` panics with the replacement torn and `dt:`/`pt:`/receipt/gate
/// artifacts on disk.
#[cfg(not(feature = "sync"))]
#[test]
fn a_raced_to_nothing_scrub_leaves_authority_unsettled_for_the_purge() {
    const REPLACEMENT: &[u8] = b"state re-put after the empty scrub";
    let _serial = lock_delete_rendezvous();

    for reason in [SafeDeleteReason::GdprDelete, SafeDeleteReason::PolicyDelete] {
        let case = format!("{reason:?}");
        let (_dir, vault) = open_nonpublishing_delete_vault();
        let owner = put_person(&vault, 0x57);
        let revoke = root_binding_with_pending_revocation(&vault, 0x58, owner);
        let subject = EntityId::from_bytes([0x59; 16]).expect("subject id");
        vault
            .put_entity(&subject, ENTITY_TYPE_PERSON, test_time(1), 1, b"original")
            .expect("put the original scope");

        // Park #1: after the entry gate and the no-op publish, BEFORE the scrub
        // txn opens — the deleter holds no write lock here.
        let (arrived_tx, arrived_rx) = std::sync::mpsc::sync_channel(0);
        let (resume_tx, resume_rx) = std::sync::mpsc::sync_channel::<()>(0);
        crate::deletion::install_delete_rendezvous(
            crate::deletion::DeleteRendezvous::AfterTombstonePublish,
            subject,
            arrived_tx,
            resume_rx,
        );

        let result = std::thread::scope(|scope| {
            let vault_ref = &vault;
            let deleter = scope
                .spawn(move || facade_for(vault_ref, owner).safe_delete(&subject.to_hex(), reason));
            arrived_rx
                .recv()
                .expect("the deleter must park before its scrub txn");

            // Race the ORIGINAL scope to nothing. The scrub txn below will find
            // `existed == false` and commit empty.
            let mut wtxn = vault.store.env.write_txn().expect("write txn");
            crate::batch::deindex_entity(&vault.store, &mut wtxn, &subject)
                .expect("race the scope away");
            wtxn.commit().expect("commit the racing erase");
            assert!(
                vault.get_raw(&subject).expect("get raw").is_none(),
                "{case}: precondition — the scrub must find nothing"
            );

            // Park #2, installed while the deleter is still held at park #1: the
            // slot was `take`n when it fired, so this is the next one it hits.
            let (arrived_tx, arrived_rx) = std::sync::mpsc::sync_channel(0);
            let (resume_purge_tx, resume_purge_rx) = std::sync::mpsc::sync_channel::<()>(0);
            crate::deletion::install_delete_rendezvous(
                crate::deletion::DeleteRendezvous::BeforeHardPurge,
                subject,
                arrived_tx,
                resume_purge_rx,
            );
            resume_tx.send(()).expect("release into the empty scrub");
            arrived_rx
                .recv()
                .expect("the deleter must park after the empty scrub commits");

            // The two commits the empty scrub falsely claimed to have ordered
            // behind it: authority is gone, and the id carries NEW state.
            vault
                .put_authority_log_entries(&[(revoke, test_time(3), 3)])
                .expect("commit the revocation");
            vault
                .put_entity(&subject, ENTITY_TYPE_PERSON, test_time(4), 4, REPLACEMENT)
                .expect("re-put the same id");
            vault
                .put_vector(&subject, &[0.9, 0.8, 0.7, 0.6])
                .expect("re-put a vector");
            resume_purge_tx.send(()).expect("release into the purge");
            deleter.join().expect("deleter thread must not panic")
        });

        let err = result.expect_err(&format!(
            "{case}: the empty scrub linearized nothing, so the purge is this \
             delete's first irreversible act and MUST re-prove authority"
        ));
        assert_eq!(err.code, FACADE_CODE_FORBIDDEN, "{case}");
        assert!(
            err.message.contains("no active owner binding"),
            "{case}: the parked pre-gate error must survive, not degrade to a \
             generic concurrency code: {}",
            err.message
        );
        // The replacement is whole — the purge must not tear state this delete
        // never read, on an authority that no longer exists.
        assert_eq!(
            vault
                .get_raw(&subject)
                .expect("get raw")
                .expect("the replacement row survives")
                .len(),
            crate::batch::ENTITY_METADATA_HEADER_LEN + REPLACEMENT.len(),
            "{case}: the re-put body must be untouched"
        );
        assert_eq!(
            vault.get_vector(&subject).expect("get vector"),
            Some(vec![0.9, 0.8, 0.7, 0.6]),
            "{case}: the re-put vector must be untouched"
        );
        assert_no_local_delete_artifacts(&vault, &subject, &case);
    }
}

/// A vault with vectors enabled, for the non-publishing delete regressions that
/// need vector residue as rollback evidence.
#[cfg(not(feature = "sync"))]
fn open_nonpublishing_delete_vault() -> (tempfile::TempDir, crate::Vault) {
    let dir = tempfile::tempdir().expect("tempdir");
    let vault = crate::Vault::open(
        dir.path(),
        VaultConfig {
            embedding_model: Some("test/model@v1".to_owned()),
            dimensions: 4,
            ..VaultConfig::default()
        },
    )
    .expect("open vault");
    (dir, vault)
}

/// Whether ANY `pt:` marker exists for `id`, in any window.
///
/// Prefix-scanned rather than keyed: the headerful arms address the entity's own
/// `learned_at` window, and a helper that guessed one label would silently pass
/// its "no marker" assertion for a marker written under a different one — the
/// failure mode that hides exactly the leak these regressions hunt.
#[cfg(not(feature = "sync"))]
fn first_txn_pending_tombstone_exists(vault: &crate::Vault, id: &EntityId) -> bool {
    let rtxn = vault.store.env.read_txn().expect("read txn");
    let suffix = format!(":{}", id.to_hex());
    vault
        .store
        .sync_state
        .prefix_iter(&rtxn, crate::deletion::PENDING_TOMBSTONE_PREFIX)
        .expect("iter pt: markers")
        .any(|row| row.expect("pt: row").0.ends_with(&suffix))
}

/// P2-b: `fold.vault_id == None` is TWO states, and only one of them may pass.
///
/// A log carrying two independent genesis roots folds to `vault_id: None` with
/// `ConflictingVaultRoot` issues and an EMPTY `actor_bindings` map — the same
/// shape as a vault that never declared authority. Reading that as "unrooted,
/// keep store truth" hands every owner verb to any caller precisely when the
/// authority root is contested, which is the fail-open this pins shut.
#[test]
fn conflicting_vault_roots_fail_owner_verbs_closed() {
    let (_dir, vault) = open_vault();
    let owner = put_person(&vault, 0x6B);
    let subject = put_person(&vault, 0x6C);
    let facade = facade_for(&vault, owner);

    // Two independently rooted genesis entries in one log. Each is internally
    // valid; together they are a collapse.
    let (genesis_a, _) = authority_root(0x74);
    let (genesis_b, _) = authority_root(0x75);
    vault
        .put_authority_log_entries(&[(genesis_a, test_time(1), 1), (genesis_b, test_time(2), 2)])
        .expect("two independent roots are individually valid rows");

    let fold = vault.authority_fold().expect("fold");
    assert!(
        fold.vault_root_is_conflicted(),
        "fixture must produce the conflicting-roots collapse"
    );
    assert!(
        fold.vault_id.is_none() && fold.actor_bindings.is_empty(),
        "the collapse must be indistinguishable from unrooted on shape alone \
         — that indistinguishability IS the bug being pinned"
    );

    // INVALID_STATE, not FORBIDDEN: nothing is wrong with the caller, the
    // vault's authority is. The taxonomy is what tells a host to repair the
    // log rather than to go mint a binding.
    let err = facade
        .safe_delete(&subject.to_hex(), SafeDeleteReason::UserDelete)
        .expect_err("owner verbs must fail closed under conflicting roots");
    assert_eq!(err.code, FACADE_CODE_INVALID_STATE);
    assert!(
        err.message.contains("conflicting vault roots"),
        "{}",
        err.message
    );

    // The other two owner verbs take the same door.
    for err in [
        facade
            .put_structural(&StructuralPutInput {
                id: None,
                kind: "PERSON".to_owned(),
                body: serde_json::json!({"name": "forged"}),
                text_fields: None,
                edges: None,
                occurred_at: 703,
                learned_at: None,
            })
            .expect_err("conflicted-root PERSON mint"),
        {
            let agent = put_person(&vault, 0x6D);
            let claim = vault
                .memory(agent, EdgeActorClass::Agent)
                .claim_upsert(&claim_input(
                    "profile.mood",
                    &subject,
                    "observed",
                    serde_json::json!("calm"),
                ))
                .expect("agent claim");
            facade
                .claim_retract(&claim.claim_short_id)
                .expect_err("conflicted-root cross-actor retract")
        },
    ] {
        assert_eq!(err.code, FACADE_CODE_INVALID_STATE);
    }
}

/// A sidecar-less rotation must never hand the RETIRED key owner verbs through
/// the facade gate.
///
/// The owner gate reads `authority_fold_readonly_in_txn`, which used to omit
/// entries with no first-seen sidecar — leaving a delayable widen pending
/// forever. For `RotateKey` that is fail-OPEN: pending means the RETIRED key is
/// still a live owner-capable roster key. On a legacy rooted vault whose
/// rotation lost its sidecar, an attacker holding the retired key files a DAG
/// SIBLING `BindActor(retired_key, attacker, "human")` parented at genesis, and
/// the gate hands them every owner verb.
///
/// fix-3 closed that by synthesizing the migration's `learned_at.min(now)`.
/// fix-leg 4 removes `learned_at` from the answer entirely — it is peer-written,
/// so the long-past values in this fixture are the attacker's own claim — and
/// the gate suspends instead: INVALID_STATE while the fold cannot date the
/// rotation, cleared by one write-path fold, after which the rotation serves its
/// delay from local observation. Either way the retired key never authorizes.
#[test]
fn sidecarless_rotation_denies_owner_verbs_through_the_facade() {
    use crate::authority::{AuthorityKey, AuthorityLogEntry, AuthorityOp, AuthoritySignature};
    let (_dir, vault) = open_vault();
    let attacker = put_person(&vault, 0x76);
    let subject = put_person(&vault, 0x77);
    let facade = facade_for(&vault, attacker);

    let (genesis, signing) = authority_root(0x78);
    let vault_id = crate::authority::genesis_vault_id(&genesis).expect("vault id");
    let genesis_hash = crate::authority::authority_entry_hash(&genesis).expect("genesis hash");
    let retired = AuthorityKey::Ed25519(signing.verifying_key().to_bytes());
    let successor = ed25519_dalek::SigningKey::from_bytes(&[0x79; 32]);
    let owner_entry = |seq: u64, op: AuthorityOp, ts: u64| {
        sign_authority(
            AuthorityLogEntry {
                schema_version: crate::authority::AUTHORITY_LOG_SCHEMA_VERSION,
                vault_id: Some(vault_id),
                seq,
                // Every child parents at GENESIS: the squatting bind is a
                // sibling of the rotation, so no topological rule kills it and
                // only the rotation's MATURITY can.
                parent_hashes: vec![genesis_hash],
                op,
                signer: AuthoritySignature {
                    suite: retired.suite(),
                    public_key: retired.clone(),
                    signature: vec![0; 64],
                },
                cosigns: Vec::new(),
                ts,
            },
            &signing,
        )
    };
    let rotate = owner_entry(
        1,
        AuthorityOp::RotateKey {
            old_key: retired.clone(),
            new_device: crate::authority::DeviceAuthority {
                key: AuthorityKey::Ed25519(successor.verifying_key().to_bytes()),
                transport_key_binding: [7; 32],
                attestation: crate::authority::AuthorityAttestation {
                    kind: "SoftwareArgon2id".to_owned(),
                    evidence: vec![1, 2, 3],
                },
                tier: crate::authority::AuthorityTier::Software,
                roles: crate::authority::ROLE_OWNER | crate::authority::ROLE_ADMIN,
            },
        },
        101,
    );
    let squat = owner_entry(
        2,
        AuthorityOp::BindActor {
            authority_key: retired.clone(),
            actor_ref: attacker,
            actor_class: "human".to_owned(),
            epoch: 1,
        },
        102,
    );
    vault
        .put_authority_log_entries(&[
            (genesis, test_time(1), 1),
            (rotate, test_time(2), 2),
            (squat, test_time(3), 3),
        ])
        .expect("legacy log rows are individually valid");

    // Rewind to the legacy shape: no sidecars, migration marker unset. The
    // long-past `learned_at` values are the attacker's claim that the rotation
    // elapsed ages ago — which fix-leg 4 refuses to act on.
    strip_authority_first_seen_state(&vault);

    // Pre-migration the fold cannot date the rotation, so every owner verb is
    // SUSPENDED — the gate refuses rather than reading maturity out of the
    // attacker's own `learned_at`.
    let agent = put_person(&vault, 0x7A);
    let claim = vault
        .memory(agent, EdgeActorClass::Agent)
        .claim_upsert(&claim_input(
            "profile.mood",
            &subject,
            "observed",
            serde_json::json!("calm"),
        ))
        .expect("agent claim");
    for err in [
        facade
            .safe_delete(&subject.to_hex(), SafeDeleteReason::UserDelete)
            .expect_err("retired key must not delete"),
        facade
            .put_structural(&StructuralPutInput {
                id: None,
                kind: "PERSON".to_owned(),
                body: serde_json::json!({"name": "forged"}),
                text_fields: None,
                edges: None,
                occurred_at: 704,
                learned_at: None,
            })
            .expect_err("retired key must not mint a PERSON"),
        facade
            .claim_retract(&claim.claim_short_id)
            .expect_err("retired key must not retract another actor's claim"),
    ] {
        assert_eq!(err.code, FACADE_CODE_INVALID_STATE, "{}", err.message);
        assert!(
            err.message.contains("owner verbs are suspended"),
            "{}",
            err.message
        );
    }

    // The suspension is self-clearing, not a brick: one write-path fold records
    // the local observation and the rotation becomes datable. It is freshly
    // observed, so it now sits INSIDE its delay — the veto window a legacy
    // import is supposed to serve — rather than being declared elapsed by the
    // peer that shipped it.
    let full = vault.authority_fold().expect("fold");
    assert!(
        !full.pending_widens.is_empty(),
        "the rotation is dated at migration time, so its delay has not elapsed"
    );
    let rtxn = vault.store.env.read_txn().expect("read txn");
    assert_eq!(
        vault
            .authority_fold_readonly_in_txn(&rtxn)
            .expect("a locally dated log folds"),
        full,
        "once observed locally the gate's fold agrees with the write-path fold"
    );
    drop(rtxn);
}

/// fix-3: a sidecar lost AFTER the one-shot migration is unrecoverable, so the
/// owner gate suspends rather than authorizing on a fold it cannot compute.
///
/// Distinct from the legacy case above: there the migration had not run and the
/// value is reproducible. Once the marker is set the migration will never revisit
/// that row, and both remaining guesses are unsafe — so this is INVALID_STATE
/// (the vault's authority is broken), never a silent pass.
#[test]
fn owner_verbs_suspend_when_a_first_seen_sidecar_is_lost_after_migration() {
    let (_dir, vault) = open_vault();
    let owner = put_person(&vault, 0x7B);
    let subject = put_person(&vault, 0x7C);
    let facade = facade_for(&vault, owner);
    root_vault_binding(&vault, 0x7D, owner, "human");

    // Settle: the full fold is what sets the one-shot marker.
    vault.authority_fold().expect("fold");
    facade
        .safe_delete(&subject.to_hex(), SafeDeleteReason::UserDelete)
        .expect("the bound owner works before the sidecar is lost");

    let sidecars = authority_first_seen_sidecar_keys(&vault);
    assert!(!sidecars.is_empty(), "the migration must have written rows");
    vault
        .with_write_txn(|wtxn| {
            for key in &sidecars {
                assert!(vault.store.sync_state.delete(wtxn, key.as_str())?);
            }
            Ok(())
        })
        .expect("drop the sidecars");

    let victim = put_person(&vault, 0x7E);
    let err = facade
        .safe_delete(&victim.to_hex(), SafeDeleteReason::UserDelete)
        .expect_err("an uncomputable fold must suspend owner verbs");
    assert_eq!(err.code, FACADE_CODE_INVALID_STATE);
    assert!(
        err.message.contains("owner verbs are suspended"),
        "{}",
        err.message
    );
}

/// Every per-entry first-seen sidecar key currently stored.
fn authority_first_seen_sidecar_keys(vault: &crate::Vault) -> Vec<String> {
    let rtxn = vault.store.env.read_txn().expect("read txn");
    let keys = vault
        .store
        .sync_state
        .iter(&rtxn)
        .expect("iter sync_state")
        .map(|row| row.expect("sync_state row").0.into_owned())
        .filter(|key| {
            key.starts_with("authlog:first_seen:")
                && key != crate::authority::authority_first_seen_clock_sync_key()
                && key != crate::authority::authority_first_seen_backfill_sync_key()
        })
        .collect();
    drop(rtxn);
    keys
}

/// Rewinds a vault to the pre-migration shape: sidecars gone, marker unset.
fn strip_authority_first_seen_state(vault: &crate::Vault) {
    let mut keys = authority_first_seen_sidecar_keys(vault);
    assert!(!keys.is_empty(), "fixture must have written sidecars");
    keys.push(crate::authority::authority_first_seen_backfill_sync_key().to_owned());
    vault
        .with_write_txn(|wtxn| {
            for key in &keys {
                vault.store.sync_state.delete(wtxn, key.as_str())?;
            }
            Ok(())
        })
        .expect("strip first-seen state");
}

/// ONE-1924 — the facade edge-name seam speaks canonical snake_case in BOTH
/// directions for every minted kind. `blocked_by` parses to the u8-23 kind and
/// renders back as `blocked_by`; the camelCase `blockedBy` spelling is NOT
/// exposed at this engine seam.
#[test]
fn edge_kind_names_round_trip_including_blocked_by() {
    assert_eq!(edge_kind_from_str("blocked_by"), Some(EdgeKind::BlockedBy));
    assert_eq!(edge_kind_name(EdgeKind::BlockedBy), "blocked_by");
    assert_eq!(edge_kind_from_str("blockedBy"), None);

    for kind in [
        EdgeKind::AuthoredBy,
        EdgeKind::ScopedTo,
        EdgeKind::PartOf,
        EdgeKind::Supersedes,
        EdgeKind::BelongsTo,
        EdgeKind::ClaimOf,
        EdgeKind::ChildOf,
        EdgeKind::AssignedTo,
        EdgeKind::DerivedFrom,
        EdgeKind::Mentions,
        EdgeKind::About,
        EdgeKind::Supports,
        EdgeKind::Opposes,
        EdgeKind::ParticipatesIn,
        EdgeKind::Attached,
        EdgeKind::EmployedBy,
        EdgeKind::HasFacet,
        EdgeKind::FacetOf,
        EdgeKind::InWorld,
        EdgeKind::SetIn,
        EdgeKind::MergedInto,
        EdgeKind::SplitInto,
        EdgeKind::BlockedBy,
    ] {
        let name = edge_kind_name(kind);
        assert_eq!(
            edge_kind_from_str(name),
            Some(kind),
            "{kind:?} name {name} must parse back to itself"
        );
    }
}

// ── ONE-1728 K7 · witness-door ownership backstop (ARCH-0052 D2(a)) ──────

/// The canonical witness door refuses a conversation owned by a live session
/// overlay, before any write, with the typed refusal and its own facade code.
/// This is the backstop the K4 taint guard cannot express: the ops of THIS
/// witness name only fresh ids, so nothing in the batch is tainted — what is
/// wrong is the door, not the payload.
#[test]
fn witness_door_rejects_a_conversation_owned_by_a_live_session() {
    let (_dir, vault) = open_vault();
    let actor = put_person(&vault, 0x41);
    let facade = facade_for(&vault, actor);
    let conversation = EntityId::from_bytes([0x42; 16]).expect("conv id");

    let session = vault
        .off_record_session_vault()
        .enter(
            "sess-witness-door",
            crate::off_record::OffRecordBackendClass::Local,
        )
        .expect("enter session");
    let overlay = session.overlay();
    let segment = overlay.install_txn_segment().expect("segment");
    overlay
        .put(
            crate::session_overlay::OverlayKeyspace::Entities,
            conversation.as_bytes(),
            b"session-owned conversation shell",
        )
        .expect("stage overlay shell");
    segment.commit().expect("commit segment");

    let refused = facade
        .witness(&WitnessTurn {
            conversation_ref: conversation.to_hex(),
            turn_ref: None,
            messages: vec![witness_message(0, WitnessAuthor::User, "door probe")],
            occurred_at: 700,
        })
        .expect_err("the base door must refuse a session-owned conversation");
    assert_eq!(refused.code, FACADE_CODE_OFF_RECORD_SESSION_DOOR);
    assert!(
        refused.message.contains("sess-witness-door"),
        "the refusal names the owning session: {}",
        refused.message
    );

    // The refusal happens before any write: no TURN, no MESSAGE, no shell.
    let entity_rows = {
        let rtxn = vault.store.env.read_txn().expect("read txn");
        vault.store.entities.len(&rtxn).expect("entity count")
    };
    session.close().expect("close session");
    assert_eq!(
        {
            let rtxn = vault.store.env.read_txn().expect("read txn");
            vault.store.entities.len(&rtxn).expect("entity count")
        },
        entity_rows,
        "a refused witness writes nothing"
    );
    assert_eq!(vault.get_raw(&conversation).expect("get raw"), None);
}

/// Ownership is what the door checks — not the mere existence of a live
/// session. An unrelated conversation stays witnessable while a session is
/// open, so the backstop cannot become a global write freeze.
#[test]
fn witness_door_admits_a_conversation_no_session_owns() {
    let (_dir, vault) = open_vault();
    let actor = put_person(&vault, 0x43);
    let facade = facade_for(&vault, actor);
    let owned = EntityId::from_bytes([0x44; 16]).expect("owned conv id");
    let free = EntityId::from_bytes([0x45; 16]).expect("free conv id");

    let session = vault
        .off_record_session_vault()
        .enter(
            "sess-witness-door-scope",
            crate::off_record::OffRecordBackendClass::Local,
        )
        .expect("enter session");
    let overlay = session.overlay();
    let segment = overlay.install_txn_segment().expect("segment");
    overlay
        .put(
            crate::session_overlay::OverlayKeyspace::Entities,
            owned.as_bytes(),
            b"session-owned conversation shell",
        )
        .expect("stage overlay shell");
    segment.commit().expect("commit segment");

    facade
        .witness(&WitnessTurn {
            conversation_ref: free.to_hex(),
            turn_ref: None,
            messages: vec![witness_message(0, WitnessAuthor::User, "ordinary turn")],
            occurred_at: 800,
        })
        .expect("an unowned conversation stays witnessable");
    assert!(vault.get_raw(&free).expect("get raw").is_some());
    session.close().expect("close session");
}

// ── ONE-1728 · witness through the session vault (ARCH-0052 §7) ──────────

/// Enters a room and returns the handle plus a facade bound to a fresh actor.
fn session_witness_fixture<'v>(
    vault: &'v crate::Vault,
    session_ref: &str,
    actor_seed: u8,
) -> (crate::off_record::OffRecordSession<'v>, EntityId) {
    let actor = put_person(vault, actor_seed);
    let session = vault
        .off_record_session_vault()
        .enter(session_ref, crate::off_record::OffRecordBackendClass::Local)
        .expect("enter session");
    (session, actor)
}

/// The load-bearing property of the whole ticket: a session-witnessed turn is
/// READABLE IN THE ROOM and INVISIBLE FROM BASE.
///
/// Both halves matter. Invisible-only would be indistinguishable from having
/// dropped the write; readable-only would be an ordinary base write wearing a
/// session's name.
#[test]
fn session_witness_lands_in_the_overlay_and_never_in_base() {
    let (_dir, vault) = open_vault();
    let (session, actor) = session_witness_fixture(&vault, "sess-witness-overlay", 0x51);
    let facade = facade_for(&vault, actor);

    let base_entity_rows = {
        let rtxn = vault.store.env.read_txn().expect("read txn");
        vault.store.entities.len(&rtxn).expect("entity count")
    };

    let receipt = facade
        .witness_into_session(
            &session,
            &WitnessTurn {
                conversation_ref: String::new(),
                turn_ref: None,
                messages: vec![witness_message(0, WitnessAuthor::User, "in-room utterance")],
                occurred_at: 900,
            },
            Some("the room's summary"),
        )
        .expect("session witness");

    // The room sees its own turn through the composed view.
    let view = session.read_view().expect("read view");
    let rtxn = vault.store.env.read_txn().expect("read txn");
    let turn_id = EntityId::from_hex(
        receipt
            .receipt_ref
            .strip_prefix("witness:")
            .expect("receipt ref names the turn"),
    )
    .expect("turn id");
    assert!(
        view.entities
            .get(&rtxn, turn_id.as_bytes())
            .expect("session get")
            .is_some(),
        "the session handle reads the turn it just witnessed"
    );
    drop(rtxn);
    drop(view);

    // Base sees nothing: not the turn, not the messages, not the summary, not
    // the shell. The row COUNT is the honest assertion — a per-id probe could
    // miss a row written under an id the test does not know.
    assert_eq!(vault.get_raw(&turn_id).expect("base get"), None);
    assert_eq!(
        {
            let rtxn = vault.store.env.read_txn().expect("read txn");
            vault.store.entities.len(&rtxn).expect("entity count")
        },
        base_entity_rows,
        "a session witness adds ZERO base entity rows"
    );

    session.close().expect("close session");
}

/// The receipt's short ids are SESSION-LOCAL: they carry the `s` sigil, so an
/// in-room alias can neither collide with nor shadow a durable short id, and a
/// leaked alias fails to parse at a base door rather than silently resolving
/// to the wrong entity.
#[test]
fn session_witness_receipt_carries_session_local_short_ids() {
    let (_dir, vault) = open_vault();
    let (session, actor) = session_witness_fixture(&vault, "sess-witness-alias", 0x52);
    let facade = facade_for(&vault, actor);

    let receipt = facade
        .witness_into_session(
            &session,
            &WitnessTurn {
                conversation_ref: String::new(),
                turn_ref: None,
                messages: vec![witness_message(0, WitnessAuthor::User, "alias probe")],
                occurred_at: 910,
            },
            None,
        )
        .expect("session witness");

    for alias in std::iter::once(&receipt.turn_short_id).chain(&receipt.message_short_ids) {
        let (short_id, _hash) = alias.split_once(':').expect("alias is short_id:hash");
        assert!(
            short_id.starts_with('s') && short_id[1..].chars().all(|c| c.is_ascii_digit()),
            "session aliases use the `s<n>` namespace, got {alias:?}"
        );
        // A base alias is <two letters><digits>, so `s<n>` cannot be minted by
        // the base counter and cannot shadow a durable alias. The base door
        // therefore resolves it to NOTHING — never to some other entity, which
        // is the failure mode a shared namespace would have produced.
        let (_, hash) = alias.split_once(':').expect("alias is short_id:hash");
        let hash = u8::from_str_radix(hash, 16).expect("hash is hex");
        assert!(
            vault
                .hydrate_short_id(short_id, hash)
                .expect("base hydrate")
                .is_none(),
            "session alias {alias:?} must not resolve through the base door"
        );
    }

    session.close().expect("close session");
}

/// One room is ONE conversation. A second witness reuses the shell allocated
/// by the first instead of minting a fresh one, so an in-session reader sees a
/// conversation rather than a turn-per-conversation shred.
#[test]
fn repeat_session_witness_reuses_the_room_shell() {
    let (_dir, vault) = open_vault();
    let (session, actor) = session_witness_fixture(&vault, "sess-witness-shell", 0x53);
    let facade = facade_for(&vault, actor);

    let turn = |content: &str, at: u64| WitnessTurn {
        conversation_ref: String::new(),
        turn_ref: None,
        messages: vec![witness_message(0, WitnessAuthor::User, content)],
        occurred_at: at,
    };
    facade
        .witness_into_session(&session, &turn("first", 920), None)
        .expect("first witness");
    let shell = session
        .overlay_conversation_shell()
        .expect("room shell after the first turn");
    facade
        .witness_into_session(&session, &turn("second", 921), None)
        .expect("second witness");
    assert_eq!(
        session.overlay_conversation_shell().expect("room shell"),
        shell,
        "both turns belong to the same room shell"
    );

    // Exactly ONE conversation shell row exists in the room.
    let view = session.read_view().expect("read view");
    let rtxn = vault.store.env.read_txn().expect("read txn");
    let shells = view
        .type_index
        .prefix_iter(&rtxn, &[ENTITY_TYPE_CONVERSATION])
        .expect("type scan")
        .count();
    assert_eq!(shells, 1, "a room witnesses into one conversation shell");
    drop(rtxn);
    drop(view);

    session.close().expect("close session");
}

/// K10: after a flip to on-record, the SAME session witness lands in BASE —
/// under a fresh continuation shell, never the overlay conversation id.
///
/// Reusing the overlay shell would write a base row referencing an overlay
/// member (the taint K4 rejects) and would make the private room reachable
/// from base by following the edge. The two transcripts stay separate
/// conversations, which is what "pre-flip turns remain base-invisible" means
/// structurally rather than by convention.
#[test]
fn post_flip_session_witness_lands_in_base_under_a_fresh_shell() {
    let (_dir, vault) = open_vault();
    let (session, actor) = session_witness_fixture(&vault, "sess-witness-flip", 0x54);
    let facade = facade_for(&vault, actor);

    facade
        .witness_into_session(
            &session,
            &WitnessTurn {
                conversation_ref: String::new(),
                turn_ref: None,
                messages: vec![witness_message(0, WitnessAuthor::User, "off-record turn")],
                occurred_at: 930,
            },
            None,
        )
        .expect("pre-flip witness");
    let overlay_shell = session.overlay_conversation_shell().expect("room shell");

    session.flip_on_record().expect("flip on record");
    let receipt = facade
        .witness_into_session(
            &session,
            &WitnessTurn {
                conversation_ref: String::new(),
                turn_ref: None,
                messages: vec![witness_message(0, WitnessAuthor::User, "on-record turn")],
                occurred_at: 931,
            },
            None,
        )
        .expect("post-flip witness");

    let post_flip_turn = EntityId::from_hex(
        receipt
            .receipt_ref
            .strip_prefix("witness:")
            .expect("receipt ref names the turn"),
    )
    .expect("turn id");
    assert!(
        vault.get_raw(&post_flip_turn).expect("base get").is_some(),
        "an on-record turn is an ordinary base write"
    );
    let continuation = session
        .on_record_continuation_shell()
        .expect("continuation");
    assert_ne!(
        continuation, overlay_shell,
        "the continuation shell is never the overlay conversation id"
    );
    assert!(
        vault.get_raw(&overlay_shell).expect("base get").is_none(),
        "the room's own shell stays invisible to base across the flip"
    );

    session.close().expect("close session");
}

/// K10, the durable half: a BASE-routed session witness whose route went stale
/// commits ZERO base rows.
///
/// The base arm publishes the room's substance durably, so it is the arm where
/// a missed flip actually leaks: a witness admitted while the room was on
/// record must not land turn + messages + continuation shell in base once the
/// room has flipped back off record. The route minted before the flip stands
/// in for the in-flight route of a witness the flip overtakes mid-call.
#[test]
fn a_stale_base_route_session_witness_commits_no_base_rows() {
    let (_dir, vault) = open_vault();
    let (session, actor) = session_witness_fixture(&vault, "sess-witness-stale-base", 0x56);
    let facade = facade_for(&vault, actor);

    session.flip_on_record().expect("flip on record");
    let route = session.write_route().expect("mint base route");
    let continuation = session
        .on_record_continuation_shell()
        .expect("continuation shell");
    session.flip_off_record().expect("flip back off record");

    let base_entity_rows = {
        let rtxn = vault.store.env.read_txn().expect("read txn");
        vault.store.entities.len(&rtxn).expect("entity count")
    };
    let refused = facade
        .witness_with_route(
            &WitnessTurn {
                conversation_ref: continuation.to_hex(),
                turn_ref: None,
                messages: vec![witness_message(
                    0,
                    WitnessAuthor::User,
                    "overtaken by the flip",
                )],
                occurred_at: 950,
            },
            Some(&route),
        )
        .expect_err("a stale base route refuses the witness");
    assert!(
        refused.message.contains("off-record overlay generation"),
        "the refusal is the stale-route family, got {refused:?}"
    );
    assert_eq!(
        {
            let rtxn = vault.store.env.read_txn().expect("read txn");
            vault.store.entities.len(&rtxn).expect("entity count")
        },
        base_entity_rows,
        "a refused base-routed witness adds ZERO base entity rows"
    );

    session.close().expect("close session");
}

/// A route minted before a mode flip is refused by `revalidate` before ANY
/// staging — so a flip landing mid-call cannot leave half a turn in a room the
/// caller no longer believes it is in.
#[test]
fn a_route_minted_before_a_flip_is_refused() {
    let (_dir, vault) = open_vault();
    let (session, _actor) = session_witness_fixture(&vault, "sess-stale-route", 0x55);

    let route = session.write_route().expect("mint route");
    route.revalidate().expect("a fresh route is valid");
    session.flip_on_record().expect("flip on record");

    let refused = route
        .revalidate()
        .expect_err("a route minted before the flip is stale");
    assert_eq!(refused.kind(), ErrorKind::OffRecordOverlayLeaseClosed);

    session.close().expect("close session");
}

/// R3 lock order: the base writer is taken BEFORE the overlay segment permit,
/// on EVERY session write path.
///
/// The overlay states the invariant itself (`acquire_segment_lease`: "Base
/// writers are acquired before this permit; there is no reverse-order path"),
/// and the witness obeys it. The session retrieval-telemetry arm did not — it
/// installed the segment, then opened the base txn — so a witness holding the
/// base writer and waiting for the permit met a telemetry run holding the
/// permit and waiting for the writer: ABBA, on one room, no timeout anywhere in
/// the stack.
///
/// The whole race runs in a DETACHED driver thread and the test body waits on a
/// channel. That is deliberate: a deadlock inside `thread::scope` would hang
/// the suite (the implicit join blocks even while unwinding), so the watchdog
/// has to sit outside the scope. A timeout here IS the deadlock.
#[test]
fn concurrent_room_witness_and_telemetry_never_invert_the_lock_order() {
    use std::sync::atomic::{AtomicUsize, Ordering as AtomicOrdering};

    const ROUNDS: usize = 40;

    let (done_tx, done_rx) = std::sync::mpsc::channel::<(usize, usize, bool)>();
    std::thread::spawn(move || {
        let (_dir, vault) = open_vault();
        let (session, actor) = session_witness_fixture(&vault, "sess-lock-order", 0x57);
        let facade = facade_for(&vault, actor);
        let overlay_shell = session
            .overlay_conversation_shell()
            .expect("allocate the room shell up front");

        let witnessed = AtomicUsize::new(0);
        let searched = AtomicUsize::new(0);
        std::thread::scope(|scope| {
            scope.spawn(|| {
                for round in 0..ROUNDS {
                    // Refusals are legitimate: the flipper may have sealed the
                    // room under this route. Only a HANG is a failure.
                    if facade
                        .witness_into_session(
                            &session,
                            &WitnessTurn {
                                conversation_ref: String::new(),
                                turn_ref: None,
                                messages: vec![witness_message(
                                    0,
                                    WitnessAuthor::User,
                                    "lockorderneedle",
                                )],
                                occurred_at: 960 + round as u64,
                            },
                            None,
                        )
                        .is_ok()
                    {
                        witnessed.fetch_add(1, AtomicOrdering::Relaxed);
                    }
                }
            });
            scope.spawn(|| {
                for _ in 0..ROUNDS {
                    if session.search_text("lockorderneedle", 4).is_ok() {
                        searched.fetch_add(1, AtomicOrdering::Relaxed);
                    }
                }
            });
            scope.spawn(|| {
                for _ in 0..ROUNDS {
                    let _ = session.flip_on_record();
                    let _ = session.flip_off_record();
                }
            });
        });

        // Classification survived the race: the room's own conversation shell
        // never became a base row, whichever arm each call took.
        let shell_leaked = vault.get_raw(&overlay_shell).expect("base get").is_some();
        done_tx
            .send((
                witnessed.load(AtomicOrdering::Relaxed),
                searched.load(AtomicOrdering::Relaxed),
                shell_leaked,
            ))
            .ok();
    });

    let (witnessed, searched, shell_leaked) = match done_rx
        .recv_timeout(std::time::Duration::from_secs(90))
    {
        Ok(outcome) => outcome,
        Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {
            panic!(
                "concurrent room witness + telemetry deadlocked (segment permit taken before the base writer)"
            )
        }
        Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
            panic!("the concurrency driver thread panicked")
        }
    };
    assert!(
        witnessed > 0 && searched > 0,
        "both writers must make real progress, not merely fail fast \
         (witnessed {witnessed}, searched {searched})"
    );
    assert!(
        !shell_leaked,
        "the room's overlay conversation shell must never become a base row"
    );
}

/// R4: a FAILED session witness must not burn the room's one-shot shell claim.
///
/// The claim was consumed before the caller-controlled fallible work (message
/// id parsing, body encoding) and before the write transaction, with no
/// rollback. A first witness carrying a malformed message id therefore returned
/// `Err` having staged nothing — yet the room was marked shell-staged, so the
/// NEXT witness hung its `PartOf`/`BelongsTo` edges off a conversation id with
/// no entity row: a dangling journal that promote (ONE-1730) would replay.
#[test]
fn a_failed_session_witness_does_not_burn_the_room_shell_claim() {
    let (_dir, vault) = open_vault();
    let (session, actor) = session_witness_fixture(&vault, "sess-witness-shell-claim", 0x58);
    let facade = facade_for(&vault, actor);

    let mut malformed = witness_message(0, WitnessAuthor::User, "never lands");
    malformed.id = Some("zz".to_owned());
    let refused = facade
        .witness_into_session(
            &session,
            &WitnessTurn {
                conversation_ref: String::new(),
                turn_ref: None,
                messages: vec![malformed],
                occurred_at: 970,
            },
            None,
        )
        .expect_err("a malformed message id refuses the witness");
    assert_eq!(refused.code, FACADE_CODE_BAD_REQUEST);

    facade
        .witness_into_session(
            &session,
            &WitnessTurn {
                conversation_ref: String::new(),
                turn_ref: None,
                messages: vec![witness_message(0, WitnessAuthor::User, "lands for real")],
                occurred_at: 971,
            },
            None,
        )
        .expect("the next witness succeeds");

    let shell = session.overlay_conversation_shell().expect("room shell");
    let view = session.read_view().expect("read view");
    let rtxn = vault.store.env.read_txn().expect("read txn");
    assert!(
        view.entities
            .get(&rtxn, shell.as_bytes())
            .expect("shell lookup")
            .is_some(),
        "the room's conversation shell row exists, so no edge dangles"
    );
    assert_eq!(
        view.type_index
            .prefix_iter(&rtxn, &[ENTITY_TYPE_CONVERSATION])
            .expect("type scan")
            .count(),
        1,
        "the claim stays one-shot: exactly ONE shell row per room"
    );
    drop(rtxn);
    drop(view);

    session.close().expect("close session");
}

/// R4, the other half: a witness that fails INSIDE the write transaction
/// RELEASES the shell claim.
///
/// Deferring the claim past the caller-controlled parsing is not enough — the
/// transaction itself is fallible (actor binding, overlay budget). This room's
/// byte budget admits a small turn and refuses an oversized one, so the first
/// witness dies after the claim is taken and after the shell `Put` is staged,
/// with the segment discarded. Only a released claim lets the next witness
/// stage the shell row the room's edges point at.
#[test]
fn an_in_transaction_failure_releases_the_room_shell_claim() {
    let (_dir, vault) = open_vault();
    let actor = put_person(&vault, 0x59);
    let facade = facade_for(&vault, actor);
    let session = vault
        .off_record_session_vault()
        .enter_with_budget(
            "sess-witness-shell-rollback",
            crate::off_record::OffRecordBackendClass::Local,
            64 * 1024,
        )
        .expect("enter session");

    let turn = |content: String, at: u64| WitnessTurn {
        conversation_ref: String::new(),
        turn_ref: None,
        messages: vec![witness_message(0, WitnessAuthor::User, &content)],
        occurred_at: at,
    };
    let refused = facade
        .witness_into_session(&session, &turn("x".repeat(256 * 1024), 980), None)
        .expect_err("a turn larger than the whole room budget is refused");
    assert!(
        refused.message.contains("off-record overlay is full"),
        "the refusal is the overlay-budget family, got {refused:?}"
    );

    facade
        .witness_into_session(&session, &turn("small enough".to_owned(), 981), None)
        .expect("the next witness succeeds");

    let shell = session.overlay_conversation_shell().expect("room shell");
    let view = session.read_view().expect("read view");
    let rtxn = vault.store.env.read_txn().expect("read txn");
    assert!(
        view.entities
            .get(&rtxn, shell.as_bytes())
            .expect("shell lookup")
            .is_some(),
        "the released claim let the next witness stage the shell row"
    );
    assert_eq!(
        view.type_index
            .prefix_iter(&rtxn, &[ENTITY_TYPE_CONVERSATION])
            .expect("type scan")
            .count(),
        1,
        "still one-shot: exactly ONE shell row per room"
    );
    drop(rtxn);
    drop(view);

    session.close().expect("close session");
}

// ── ONE-1767 second cycle · the overlay witness runs the TURN mint contract ──

/// Every overlay witness mints a FRESH TURN, so the base door's mint contract
/// binds this door too: mixed non-system and all-system calls are the same
/// bad request, the staged TURN body carries the canonical speaker, and the
/// TURN -> room-shell `ChildOf` edge is journaled with it — the two facts a
/// promote must replay for consolidation to group and role the turn.
#[test]
fn session_witness_turn_carries_the_mint_contract() {
    let (_dir, vault) = open_vault();
    let (session, actor) = session_witness_fixture(&vault, "sess-witness-mint-contract", 0x5D);
    let facade = facade_for(&vault, actor);

    let mixed = facade
        .witness_into_session(
            &session,
            &WitnessTurn {
                conversation_ref: String::new(),
                turn_ref: None,
                messages: vec![
                    witness_message(0, WitnessAuthor::User, "owner row"),
                    witness_message(1, WitnessAuthor::Companion, "companion row"),
                ],
                occurred_at: 940,
            },
            None,
        )
        .expect_err("a mixed non-system overlay witness is a bad request");
    assert_eq!(mixed.code, FACADE_CODE_BAD_REQUEST);
    assert!(
        mixed.message.contains("one non-system speaker"),
        "the mixed speaker refusal is the base door's, got {:?}",
        mixed.message
    );

    let system_only = facade
        .witness_into_session(
            &session,
            &WitnessTurn {
                conversation_ref: String::new(),
                turn_ref: None,
                messages: vec![witness_message(0, WitnessAuthor::System, "tooling row")],
                occurred_at: 941,
            },
            None,
        )
        .expect_err("an all-system overlay witness is a bad request");
    assert_eq!(system_only.code, FACADE_CODE_BAD_REQUEST);
    assert!(
        system_only.message.contains("needs one non-system speaker"),
        "the all-system refusal is the base door's, got {:?}",
        system_only.message
    );

    // The refusals staged nothing and burned no claim: the real witness mints
    // the room's ONE shell and its ONE TURN.
    let receipt = facade
        .witness_into_session(
            &session,
            &WitnessTurn {
                conversation_ref: String::new(),
                turn_ref: None,
                messages: vec![
                    witness_message(0, WitnessAuthor::Companion, "the in-room answer"),
                    witness_message(1, WitnessAuthor::System, "permitted interleave"),
                ],
                occurred_at: 942,
            },
            None,
        )
        .expect("the room still witnesses after the refused calls");
    let turn_id = EntityId::from_hex(
        receipt
            .receipt_ref
            .strip_prefix("witness:")
            .expect("receipt ref names the turn"),
    )
    .expect("turn id");
    let shell = session.overlay_conversation_shell().expect("room shell");

    let view = session.read_view().expect("read view");
    let rtxn = vault.store.env.read_txn().expect("read txn");
    let raw = view
        .entities
        .get(&rtxn, turn_id.as_bytes())
        .expect("session get")
        .expect("the staged TURN reads back in the room")
        .into_owned();
    let speaker = decode_witness_turn_speaker(&raw[ENTITY_METADATA_HEADER_LEN..])
        .expect("the staged TURN body carries its speaker entry");
    assert_eq!(
        speaker, "assistant",
        "Companion stamps the canonical Dreamer role, never `companion`"
    );
    let prefix = crate::vault::edge_kind_prefix(&turn_id, EdgeKind::ChildOf);
    let mut bound = None;
    for row in view
        .edges_out
        .prefix_iter(&rtxn, &prefix)
        .expect("edge scan")
    {
        let (key, _) = row.expect("edge row");
        let (_, _, target) = crate::edge::parse_strict_edge_record_key(&key).expect("edge key");
        bound = Some(target);
    }
    assert_eq!(
        bound,
        Some(shell),
        "the staged TURN is `ChildOf` the room shell"
    );
    assert_eq!(
        view.type_index
            .prefix_iter(&rtxn, &[ENTITY_TYPE_TURN])
            .expect("turn scan")
            .count(),
        1,
        "only the admitted witness staged a TURN"
    );
    assert_eq!(
        view.type_index
            .prefix_iter(&rtxn, &[ENTITY_TYPE_CONVERSATION])
            .expect("conversation scan")
            .count(),
        1,
        "the refused calls staged no shell; the witness kept the claim one-shot"
    );
    drop(rtxn);
    drop(view);

    session.close().expect("close session");
}

/// The promote half of the same contract: a promoted overlay turn lands in
/// base WITH the stamped speaker and its `ChildOf` edge to the room shell, so
/// `conversation_of` answers the shell and `decode_turn_body` finds the role.
#[test]
fn promoted_session_turn_lands_with_speaker_and_conversation_binding() {
    let (_dir, vault) = open_vault();
    let (session, actor) = session_witness_fixture(&vault, "sess-witness-promote-stamp", 0x5E);
    let facade = facade_for(&vault, actor);

    let receipt = facade
        .witness_into_session(
            &session,
            &WitnessTurn {
                conversation_ref: String::new(),
                turn_ref: None,
                messages: vec![witness_message(0, WitnessAuthor::User, "publish this turn")],
                occurred_at: 950,
            },
            None,
        )
        .expect("overlay witness");
    let turn_id = EntityId::from_hex(
        receipt
            .receipt_ref
            .strip_prefix("witness:")
            .expect("receipt ref names the turn"),
    )
    .expect("turn id");
    let shell = session.overlay_conversation_shell().expect("room shell");

    let outcome = session.promote_turn(&turn_id).expect("promote the turn");
    assert_eq!(
        outcome.replayed.len(),
        3,
        "the closure replays shell + turn + message"
    );

    // Base now holds the turn with exactly the minted body —
    let turn = facade
        .get_entity(&turn_id.to_hex())
        .expect("get promoted turn")
        .expect("promoted turn is a base row");
    assert_eq!(
        turn.body.expect("turn body"),
        serde_json::json!({"speaker": "user"}),
        "the promoted TURN body carries the canonical speaker"
    );
    // — and the `ChildOf` binding `conversation_of` reads.
    let bound = vault
        .edges_out(&turn_id)
        .expect("promoted turn edges")
        .into_iter()
        .find(|edge| edge.kind == EdgeKind::ChildOf)
        .map(|edge| edge.target);
    assert_eq!(
        bound,
        Some(shell),
        "the promoted turn's ChildOf resolves the room shell"
    );
    assert!(
        vault.get_raw(&shell).expect("shell read").is_some(),
        "the room shell promoted with the turn's closure"
    );

    session.close().expect("close session");
}

// ── ONE-1377 · author_take (ARCH-0032 NOTE · OF-330) ────────────────────

fn opinion_claim(vault: &crate::Vault, actor: EntityId, subject: EntityId) -> EntityId {
    let reference = facade_for(vault, actor)
        .claim_upsert(&claim_input(
            "profile.name",
            &subject,
            "user_stated",
            serde_json::json!("Ada"),
        ))
        .expect("claim")
        .claim_short_id;
    let id = resolve_entity_ref(vault, &reference).expect("claim id");
    assert_eq!(
        vault.get_entity_type(&id).expect("type"),
        Some(ENTITY_TYPE_CLAIM),
        "fixture must be a type-0 CLAIM"
    );
    id
}

fn note_body_of(vault: &crate::Vault, note_id: &EntityId) -> crate::note::NoteBody {
    let raw = vault.get_raw(note_id).expect("raw").expect("note exists");
    crate::note::decode_note_body(&raw[crate::batch::ENTITY_METADATA_HEADER_LEN..])
        .expect("note body decodes under the pinned ABI")
}

/// Two actors, one claim, two takes. Divergence is append-only: two NOTE ids,
/// two independent `AuthoredBy` edges, no upsert keyed by `(actor, target)`
/// and no cross-attribution.
#[test]
fn two_actor_divergent_takes() {
    let (_dir, vault) = open_vault();
    let ada = put_person(&vault, 0x71);
    let bo = put_person(&vault, 0x72);
    let subject = put_person(&vault, 0x73);
    let claim = opinion_claim(&vault, ada, subject);

    let ada_markdown = "Right — the passport backs it.";
    let bo_markdown = "Wrong: that is a stage name.";
    let first = facade_for(&vault, ada)
        .author_take(TakeTarget::Claim(claim), ada_markdown)
        .expect("ada take");
    let second = facade_for(&vault, bo)
        .author_take(TakeTarget::Claim(claim), bo_markdown)
        .expect("bo take");

    assert_ne!(
        first.id_hex, second.id_hex,
        "a second actor's take must mint its own NOTE, never overwrite the first"
    );
    assert_eq!(
        vault
            .entities_by_type(ENTITY_TYPE_NOTE)
            .expect("notes")
            .len(),
        2
    );

    for (receipt, author, markdown) in [(&first, ada, ada_markdown), (&second, bo, bo_markdown)] {
        let note_id = EntityId::from_hex(&receipt.id_hex).expect("note id");
        let body = note_body_of(&vault, &note_id);
        assert_eq!(body.kind, NoteKind::OpinionTake);
        assert_eq!(body.markdown, markdown);
        assert_eq!(body.author_ref, author, "takes must not cross-attribute");

        let edges = vault.edges_out(&note_id).expect("edges");
        assert_eq!(edges.len(), 2, "a take writes exactly AuthoredBy + ClaimOf");
        let authored = edges
            .iter()
            .find(|edge| edge.kind == EdgeKind::AuthoredBy)
            .expect("AuthoredBy edge is mandatory");
        assert_eq!(
            authored.target, body.author_ref,
            "the stored author_ref must equal the AuthoredBy target"
        );
        assert!(
            edges
                .iter()
                .any(|edge| edge.kind == EdgeKind::ClaimOf && edge.target == claim)
        );
    }

    // Retrieval keeps both rows typed NOTE — neither is reprinted as a claim.
    for note in vault.entities_by_type(ENTITY_TYPE_NOTE).expect("notes") {
        let view = facade_for(&vault, ada)
            .get_entity(&note.to_hex())
            .expect("get")
            .expect("note view");
        assert_eq!(view.kind, "NOTE");
    }
}

/// The neutral-CLAIM invariant: a take is written BESIDE the claim. The
/// target's raw bytes (body, lifecycle, learned-at), its content hash, and its
/// outbound edges are all identical afterwards; the only difference anywhere
/// is one new inbound `ClaimOf` from the take.
#[test]
fn take_never_mutates_claim() {
    let (_dir, vault) = open_vault();
    let actor = put_person(&vault, 0x74);
    let subject = put_person(&vault, 0x75);
    let facade = facade_for(&vault, actor);
    let claim = opinion_claim(&vault, actor, subject);
    let claim_hex = claim.to_hex();

    let before_raw = vault.get_raw(&claim).expect("raw").expect("claim exists");
    let before_lifecycle = vault
        .get_claim(&claim)
        .expect("claim body")
        .expect("body")
        .lifecycle;
    // The short ref's suffix IS the body content hash: a rewritten claim
    // advances it, so equality here is the content-hash assertion.
    let before_ref = facade
        .get_entity(&claim_hex)
        .expect("get")
        .expect("claim view")
        .short_ref;
    let before_out: Vec<_> = vault
        .edges_out(&claim)
        .expect("edges out")
        .iter()
        .map(|edge| (edge.kind, edge.target))
        .collect();
    let before_in: Vec<_> = vault
        .edges_in(&claim)
        .expect("edges in")
        .iter()
        .map(|edge| (edge.kind, edge.target))
        .collect();

    let take = facade
        .author_take(TakeTarget::Claim(claim), "Contested; see the 1994 filing.")
        .expect("take");
    let note_id = EntityId::from_hex(&take.id_hex).expect("note id");

    assert_eq!(
        vault.get_raw(&claim).expect("raw").expect("claim exists"),
        before_raw,
        "author_take must leave the target claim byte-identical"
    );
    assert_eq!(
        vault
            .get_claim(&claim)
            .expect("claim body")
            .expect("body")
            .lifecycle,
        before_lifecycle
    );
    assert_eq!(
        facade
            .get_entity(&claim_hex)
            .expect("get")
            .expect("claim view")
            .short_ref,
        before_ref,
        "the claim's content hash must not advance"
    );
    assert_eq!(
        vault
            .edges_out(&claim)
            .expect("edges out")
            .iter()
            .map(|edge| (edge.kind, edge.target))
            .collect::<Vec<_>>(),
        before_out
    );

    let after_in: Vec<_> = vault
        .edges_in(&claim)
        .expect("edges in")
        .iter()
        .map(|edge| (edge.kind, edge.target))
        .collect();
    let added: Vec<_> = after_in
        .iter()
        .filter(|edge| !before_in.contains(edge))
        .collect();
    assert_eq!(
        added,
        vec![&(EdgeKind::ClaimOf, note_id)],
        "the only new edge may be the take's inbound ClaimOf"
    );
    assert_eq!(after_in.len(), before_in.len() + 1);
}

/// Every refusal path leaves nothing behind, and no door lets a caller choose
/// the author.
#[test]
fn author_take_fails_closed_and_never_lets_a_caller_pick_the_author() {
    let (_dir, vault) = open_vault();
    let actor = put_person(&vault, 0x76);
    let impostor = put_person(&vault, 0x77);
    let subject = put_person(&vault, 0x78);
    let facade = facade_for(&vault, actor);

    // A `Claim` target that is not type-0 — the ClaimOf edge would lie.
    let err = facade
        .author_take(TakeTarget::Claim(subject), "not a claim")
        .expect_err("non-CLAIM claim target must be refused");
    assert_eq!(err.code, FACADE_CODE_BAD_REQUEST);

    // Missing targets, on both arms.
    let absent = EntityId::from_bytes([0xEE; 16]).expect("absent id");
    for target in [TakeTarget::Subject(absent), TakeTarget::Claim(absent)] {
        let err = facade
            .author_take(target, "about a ghost")
            .expect_err("missing target must be refused");
        assert_eq!(err.code, FACADE_CODE_NOT_FOUND);
    }

    // Blank markdown never reaches the store.
    assert!(
        facade
            .author_take(TakeTarget::Subject(subject), "   ")
            .is_err(),
        "blank markdown must be refused"
    );

    // An unbound actor cannot author: the binding is store-truth, checked in
    // the same write transaction.
    let unbound = EntityId::from_bytes([0xDD; 16]).expect("unbound id");
    assert!(
        vault
            .memory(unbound, EdgeActorClass::Human)
            .author_take(TakeTarget::Subject(subject), "who am I")
            .is_err(),
        "an actor that does not exist must not author a take"
    );

    // Nothing above committed: no orphan NOTE, no orphan edge on the target.
    assert!(
        vault
            .entities_by_type(ENTITY_TYPE_NOTE)
            .expect("notes")
            .is_empty(),
        "refused takes must leave no orphan NOTE"
    );
    assert!(
        vault
            .edges_in(&subject)
            .expect("edges in")
            .iter()
            .all(|edge| edge.kind != EdgeKind::About && edge.kind != EdgeKind::ClaimOf),
        "refused takes must leave no orphan link edge"
    );

    // The broad structural door refuses NOTE outright: were it open, a caller
    // could hand-write author_ref and forge another actor's take.
    let err = facade
        .put_structural(&StructuralPutInput {
            id: None,
            kind: "NOTE".to_owned(),
            body: serde_json::json!({
                "kind": "opinion/take",
                "author_ref": impostor.to_hex(),
                "markdown": "words the impostor never wrote",
            }),
            text_fields: None,
            edges: None,
            occurred_at: 900,
            learned_at: None,
        })
        .expect_err("NOTE must not be writable through put_structural");
    assert_eq!(err.code, FACADE_CODE_FORBIDDEN);
    assert!(err.suggestions.iter().any(|s| s.contains("author_take")));
    assert!(
        vault
            .entities_by_type(ENTITY_TYPE_NOTE)
            .expect("notes")
            .is_empty()
    );

    // The honest door stamps the bound actor, not the impostor the caller
    // would have named.
    let receipt = facade
        .author_take(TakeTarget::Subject(subject), "an attributed aside")
        .expect("take");
    let note_id = EntityId::from_hex(&receipt.id_hex).expect("note id");
    let body = note_body_of(&vault, &note_id);
    assert_eq!(body.author_ref, actor);
    assert_ne!(body.author_ref, impostor);
    let edges = vault.edges_out(&note_id).expect("edges");
    assert_eq!(edges.len(), 2);
    assert!(
        edges
            .iter()
            .any(|edge| edge.kind == EdgeKind::About && edge.target == subject),
        "a subject take links with About, never ClaimOf"
    );
}

/// Closing `put_structural` was not enough: the raw batch door admits every
/// registered public type, so registering NOTE opened a second way in — one
/// that would have committed a caller-written `author_ref` with no
/// `AuthoredBy` and no link edge at all. Attribution is engine-stamped, so
/// the raw door refuses the type outright on both batch builders and
/// `author_take` remains the only NOTE writer.
#[test]
fn raw_note_put_is_refused_at_the_batch_door() {
    let (_dir, vault) = open_vault();
    let actor = put_person(&vault, 0x79);
    let impostor = put_person(&vault, 0x7A);
    let subject = put_person(&vault, 0x7B);

    let forged = crate::note::encode_note_body(&crate::note::NoteBody {
        kind: NoteKind::OpinionTake,
        author_ref: impostor,
        markdown: "words the impostor never wrote".to_owned(),
    })
    .expect("body encodes");

    let batch_note = EntityId::from_bytes([0x7C; 16]).expect("note id");
    let err = vault
        .batch()
        .put(&batch_note, ENTITY_TYPE_NOTE, test_time(900), 900, &forged)
        .commit()
        .expect_err("raw batch NOTE put must be refused");
    let crate::error::Error::InvalidNoteBody(message) = err else {
        panic!("raw NOTE put must fail as an invalid NOTE body");
    };
    assert!(
        message.contains("author_take"),
        "the refusal must name the only door that stamps an author"
    );

    let txn_note = EntityId::from_bytes([0x7D; 16]).expect("note id");
    let err = vault
        .with_write_txn(|wtxn| {
            vault
                .batch_in()
                .put(&txn_note, ENTITY_TYPE_NOTE, test_time(900), 900, &forged)
                .apply(wtxn)
        })
        .expect_err("raw transaction-batch NOTE put must be refused");
    assert!(matches!(err, crate::error::Error::InvalidNoteBody(_)));

    // The typed door does not inherit the bypass blindly. Handed the forged
    // body and the real actor, it refuses: the stored `author_ref` must be
    // the actor the door was given.
    let typed_note = EntityId::from_bytes([0x7E; 16]).expect("note id");
    let err = vault
        .with_write_txn(|wtxn| {
            vault
                .batch_in()
                .put_authored_note(&typed_note, &actor, test_time(900), 900, &forged)
                .apply(wtxn)
        })
        .expect_err("the typed door must refuse a body attributed to another actor");
    assert!(matches!(err, crate::error::Error::InvalidNoteBody(_)));

    assert!(
        vault
            .entities_by_type(ENTITY_TYPE_NOTE)
            .expect("notes")
            .is_empty(),
        "a refused raw put must leave no NOTE behind"
    );

    // The typed door is unaffected, and still stamps the bound actor.
    let receipt = facade_for(&vault, actor)
        .author_take(TakeTarget::Subject(subject), "the honest door")
        .expect("take");
    let note_id = EntityId::from_hex(&receipt.id_hex).expect("note id");
    assert_eq!(note_body_of(&vault, &note_id).author_ref, actor);
}

// ── ONE-1936: write-verb validity guard at the facade doors ──────────

#[test]
fn facade_stale_upsert_rolls_back_new_claim() {
    let (_dir, vault) = open_vault();
    let actor = put_person(&vault, 0x71);
    let subject = put_person(&vault, 0x72);
    let facade = facade_for(&vault, actor);

    let prior_id = EntityId::from_bytes([0x76; 16]).expect("prior id");
    let replacement_id = EntityId::from_bytes([0x73; 16]).expect("replacement id");
    let winner_id = EntityId::from_bytes([0x77; 16]).expect("winner id");

    let mut first = claim_input(
        "profile.lives_in",
        &subject,
        "user_stated",
        serde_json::json!("osaka"),
    );
    first.id = Some(prior_id.to_hex());
    facade.claim_upsert(&first).expect("first revision lands");

    let mut replacement = claim_input(
        "profile.lives_in",
        &subject,
        "user_stated",
        serde_json::json!("tokyo"),
    );
    replacement.id = Some(replacement_id.to_hex());

    // The advisory prior lookup has already named `prior_id`; a concurrent
    // writer closes it in the window before the write transaction opens. That
    // window is exactly what the in-txn guard exists for.
    let mut winner = claim_input(
        "profile.lives_in",
        &subject,
        "user_stated",
        serde_json::json!("kyoto"),
    );
    winner.id = Some(winner_id.to_hex());
    let winner_short_ref = std::cell::RefCell::new(String::new());
    let err = facade
        .claim_upsert_with_pre_txn_hook(&replacement, || {
            let receipt = facade_for(&vault, actor)
                .claim_upsert(&winner)
                .expect("the concurrent revision wins the race");
            *winner_short_ref.borrow_mut() = receipt.claim_short_id;
        })
        .expect_err("the advisory prior moved before the transaction");

    assert_eq!(err.code, FACADE_CODE_INVALID_STATE);
    assert_eq!(
        err.successor_short_id.as_deref(),
        Some(winner_short_ref.borrow().as_str()),
        "the successor travels as a typed field, not only in prose"
    );

    // The staged replacement rolled back with the refusal: it was never
    // written, and the prior kept the close the WINNER gave it.
    assert!(
        vault
            .get_claim(&replacement_id)
            .expect("read replacement")
            .is_none(),
        "a refused upsert must not leave its staged claim behind"
    );
    assert_eq!(
        vault
            .get_claim(&prior_id)
            .expect("read prior")
            .expect("prior")
            .lifecycle,
        ClaimLifecycleStatus::Superseded
    );
    assert_eq!(
        vault
            .get_claim(&winner_id)
            .expect("read winner")
            .expect("winner")
            .lifecycle,
        ClaimLifecycleStatus::Active,
        "the refusal never retargets the verb at the successor"
    );
}

#[test]
fn facade_stale_retract_exposes_invalid_state_and_successor() {
    let (_dir, vault) = open_vault();
    let actor = put_person(&vault, 0x74);
    let subject = put_person(&vault, 0x75);
    let facade = facade_for(&vault, actor);

    let prior_id = EntityId::from_bytes([0x78; 16]).expect("prior id");
    let replacement_id = EntityId::from_bytes([0x79; 16]).expect("replacement id");

    let mut first = claim_input(
        "profile.lives_in",
        &subject,
        "user_stated",
        serde_json::json!("osaka"),
    );
    first.id = Some(prior_id.to_hex());
    facade.claim_upsert(&first).expect("first revision lands");

    let mut replacement = claim_input(
        "profile.lives_in",
        &subject,
        "user_stated",
        serde_json::json!("tokyo"),
    );
    replacement.id = Some(replacement_id.to_hex());
    let replacement_receipt = facade
        .claim_upsert(&replacement)
        .expect("replacement supersedes the first");

    // By hex id: the prior's short ref rotated its content-hash suffix when
    // the supersession rewrote its body, and a client holding the pre-close
    // ref would get NOT_FOUND before ever reaching the guard.
    let err = facade
        .claim_retract(&prior_id.to_hex())
        .expect_err("retracting a replaced head is a stale-target refusal");
    assert_eq!(err.code, FACADE_CODE_INVALID_STATE);
    assert_eq!(
        err.successor_short_id.as_deref(),
        Some(replacement_receipt.claim_short_id.as_str())
    );

    // Never retargeted, never silently no-opped: the successor stays live and
    // the stale target keeps its own close.
    assert_eq!(
        vault
            .get_claim(&replacement_id)
            .expect("read successor")
            .expect("successor")
            .lifecycle,
        ClaimLifecycleStatus::Active
    );
    assert_eq!(
        vault
            .get_claim(&prior_id)
            .expect("read prior")
            .expect("prior")
            .lifecycle,
        ClaimLifecycleStatus::Superseded
    );
}

// ── ONE-1414 · `same_as` wire mapping + generic-write refusal ─────────────

/// The `same_as` wire name round-trips both directions and resolves to the
/// byte-20 kind. The camelCase spelling is not exposed at this engine seam,
/// exactly as for `blocked_by`.
#[test]
fn same_as_edge_kind_name_round_trips() {
    assert_eq!(edge_kind_from_str("same_as"), Some(EdgeKind::SameAs));
    assert_eq!(edge_kind_name(EdgeKind::SameAs), "same_as");
    assert_eq!(edge_kind_from_str("sameAs"), None);
    assert_eq!(EdgeKind::SameAs as u8, 20);
}

/// ONE-1414 done-means 5 (generic half) — the broad structural door REFUSES to
/// mint a `same_as` link.
///
/// A raw link here would assert cross-vault identity with no status claim, no
/// per-pact consent surface, and no actor — and the export filter reads that
/// consent to decide what crosses a grant, so a forgeable link is a disclosure
/// surface. `federation::put_coreference_link` is the owning write door.
#[test]
fn put_structural_refuses_to_mint_a_same_as_link() {
    let (_dir, vault) = open_vault();
    let actor = put_person(&vault, 0xC7);
    let facade = facade_for(&vault, actor);

    let other = facade
        .put_structural(&StructuralPutInput {
            id: None,
            kind: "PERSON".to_owned(),
            body: serde_json::json!({"name": "Nadeshiko"}),
            text_fields: None,
            edges: None,
            occurred_at: 800,
            learned_at: None,
        })
        .expect("plain person put");

    let err = facade
        .put_structural(&StructuralPutInput {
            id: None,
            kind: "PERSON".to_owned(),
            body: serde_json::json!({"name": "Nadeshiko elsewhere"}),
            text_fields: None,
            edges: Some(vec![StructuralEdgeSpec {
                edge_kind: "same_as".to_owned(),
                target_ref: other.id_hex.clone(),
                weight: None,
            }]),
            occurred_at: 801,
            learned_at: None,
        })
        .expect_err("the structural door must refuse a raw same_as link");
    assert_eq!(err.code, FACADE_CODE_FORBIDDEN);
    assert!(!err.suggestions.is_empty());

    // Refused before any write: no `same_as` row exists anywhere.
    let other_id = EntityId::from_hex(&other.id_hex).unwrap();
    assert!(
        vault
            .edges_in(&other_id)
            .expect("edges in")
            .iter()
            .all(|edge| edge.kind != EdgeKind::SameAs)
    );
}

#[test]
fn napi_schedule_outbound_forwards_timezone_context() {
    let (_dir, vault) = open_vault();
    let actor = put_person(&vault, 0x78);
    let facade = facade_for(&vault, actor);
    let draft = OutboundDraftInput {
        verb: "send".to_owned(),
        channel: "email".to_owned(),
        target: "test@example.com".to_owned(),
        on_behalf_of: None,
        content_ref: Some("content:napi-timezone".to_owned()),
        idempotency_key: Some("napi-timezone-forward".to_owned()),
        dedupe_key: None,
        trigger: "agent_immediate".to_owned(),
        trigger_ref: "session:napi".to_owned(),
        job_ref: None,
        occurred_at: Some(3_600),
    };
    let receipt = facade
        .schedule_outbound_with_context(
            &draft,
            &OutboundScheduleContext {
                utc_offset_minutes: Some(60),
                iana_timezone: Some("Europe/Paris".to_owned()),
                human_explicit_instant: false,
                apns_interruption_level: None,
                resolved_level: None,
            },
        )
        .expect("timezone context schedules");
    assert!(receipt.intent_ref.starts_with("intent:"));
    assert!(receipt.gate_decision_ref.is_some());
    // The schedule-only Hold window is what admits the durable TASK; assert the
    // precondition explicitly so the round-trip below can never pass vacuously.
    assert_eq!(receipt.outcome, "held");

    // The context does not merely validate: it reaches the shared TASK and is
    // readable back off the public row.
    let scheduled = vault
        .connector_send_tasks()
        .expect("connector tasks")
        .into_iter()
        .find(|task| task.intent.idempotency_key.as_deref() == Some("napi-timezone-forward"))
        .expect("context-aware schedule writes a TASK");
    assert_eq!(scheduled.utc_offset_minutes, Some(60));
    assert_eq!(scheduled.iana_timezone.as_deref(), Some("Europe/Paris"));
    assert!(!scheduled.human_explicit_instant);
    assert_eq!(scheduled.apns_interruption_level, None);
    assert_eq!(scheduled.resolved_level, None);

    // An omitted context preserves hostless behavior: no clock is invented.
    let hostless_draft = OutboundDraftInput {
        idempotency_key: Some("napi-timezone-hostless".to_owned()),
        ..draft.clone()
    };
    facade
        .schedule_outbound(&hostless_draft)
        .expect("hostless schedule still works");
    let hostless = vault
        .connector_send_tasks()
        .expect("connector tasks")
        .into_iter()
        .find(|task| task.intent.idempotency_key.as_deref() == Some("napi-timezone-hostless"))
        .expect("hostless task");
    assert_eq!(hostless.utc_offset_minutes, None);
    assert_eq!(hostless.iana_timezone, None);

    // Fail-closed: every invalid clock authority is rejected BEFORE any TASK or
    // attempt write, so the row count cannot move.
    let before = vault.connector_send_tasks().expect("connector tasks").len();
    for (context, expected) in [
        (
            OutboundScheduleContext {
                iana_timezone: Some("Europe/Paris".to_owned()),
                ..Default::default()
            },
            "iana_timezone requires utc_offset_minutes",
        ),
        (
            OutboundScheduleContext {
                utc_offset_minutes: Some(841),
                ..Default::default()
            },
            "utc_offset_minutes must be in -840..=840",
        ),
        (
            OutboundScheduleContext {
                utc_offset_minutes: Some(-841),
                ..Default::default()
            },
            "utc_offset_minutes must be in -840..=840",
        ),
        (
            OutboundScheduleContext {
                utc_offset_minutes: Some(60),
                iana_timezone: Some("   ".to_owned()),
                ..Default::default()
            },
            "iana_timezone must be non-blank and contain no controls",
        ),
        (
            OutboundScheduleContext {
                utc_offset_minutes: Some(60),
                iana_timezone: Some("Europe/\u{7}Paris".to_owned()),
                ..Default::default()
            },
            "iana_timezone must be non-blank and contain no controls",
        ),
        (
            // An APNs level on a non-APNs send is a category error.
            OutboundScheduleContext {
                utc_offset_minutes: Some(60),
                apns_interruption_level: Some(
                    crate::delivery_window::DeliveryWindowApnsInterruptionLevel::Critical,
                ),
                ..Default::default()
            },
            "APNs interruption level requires an APNs push",
        ),
    ] {
        let rejected_draft = OutboundDraftInput {
            idempotency_key: Some(format!("napi-timezone-reject:{expected}")),
            ..draft.clone()
        };
        let err = facade
            .schedule_outbound_with_context(&rejected_draft, &context)
            .expect_err("invalid clock authority must not schedule");
        assert!(
            err.to_string().contains(expected),
            "expected {expected:?}, got {err}"
        );
    }
    assert_eq!(
        vault.connector_send_tasks().expect("connector tasks").len(),
        before,
        "a rejected schedule writes no TASK"
    );

    // The offset range is inclusive at both civil edges.
    for (edge, key) in [(-840_i16, "napi-timezone-min"), (840, "napi-timezone-max")] {
        let edge_draft = OutboundDraftInput {
            idempotency_key: Some(key.to_owned()),
            ..draft.clone()
        };
        facade
            .schedule_outbound_with_context(
                &edge_draft,
                &OutboundScheduleContext {
                    utc_offset_minutes: Some(edge),
                    ..Default::default()
                },
            )
            .unwrap_or_else(|err| panic!("offset {edge} must be accepted: {err}"));
    }
}
