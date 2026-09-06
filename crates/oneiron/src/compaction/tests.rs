//! DREAM-008 (ONE-1250) compaction handoff admission fixtures.
//!
//! One fixture per validation axis, each asserting the DISTINCT typed
//! [`CompactionPacketError`] that axis raises. The point of the matrix is
//! that no two axes collapse into one refusal — a caller can always tell
//! "this turn is not in that sitting" from "this turn's sitting was never
//! recorded".

use super::*;

use crate::config::VaultConfig;
use crate::edge::{EdgeActorClass, EdgeKind};
use crate::error::ErrorKind;
use crate::memory::{WitnessAuthor, WitnessMessage, WitnessTurn};
use crate::registry::{ENTITY_TYPE_CONVERSATION, ENTITY_TYPE_PERSON};
use crate::session_lifecycle::SessionMintOutcome;
use crate::temporal::TimeRange;
use crate::test_util::{entity, open_test_vault_with};

// ── fixture plumbing ────────────────────────────────────────────────────

fn open_vault() -> (tempfile::TempDir, Vault) {
    open_test_vault_with(VaultConfig::device())
}

fn put_actor(vault: &Vault, seed: u8) -> EntityId {
    let actor = entity(seed);
    vault
        .put_entity(
            &actor,
            ENTITY_TYPE_PERSON,
            TimeRange { start: 1, end: 1 },
            1,
            b"compaction fixture actor",
        )
        .expect("put actor");
    actor
}

fn mint_session(vault: &Vault, now: u64) -> EntityId {
    match vault.mint_session(now).expect("mint session") {
        SessionMintOutcome::Minted(session) => session,
        other => panic!("expected a fresh mint, got {other:?}"),
    }
}

/// Witnesses one turn under whatever session is currently open, returning
/// the TURN id. Rides the PRODUCTION witness door, so the membership edge
/// under test is the one production writes.
fn witness_turn(
    vault: &Vault,
    actor: EntityId,
    conversation: u8,
    turn: u8,
    at: u64,
    order: u32,
) -> EntityId {
    let turn_id = entity(turn);
    vault
        .memory(actor, EdgeActorClass::Human)
        .witness(&WitnessTurn {
            conversation_ref: entity(conversation).to_hex(),
            turn_ref: Some(turn_id.to_hex()),
            messages: vec![WitnessMessage {
                id: None,
                author: WitnessAuthor::User,
                message_type: "dialogue".to_owned(),
                content: "compaction fixture content".to_owned(),
                metadata: None,
                is_visible: true,
                order,
            }],
            occurred_at: at,
        })
        .expect("witness turn");
    turn_id
}

fn snapshot(byte: u8, byte_len: u64) -> CompactionSnapshotRef {
    CompactionSnapshotRef {
        content_hash: [byte; 32],
        byte_len,
    }
}

/// A well-formed TurnDigest packet. Every negative fixture mutates exactly
/// ONE field of this baseline, so a refusal can only come from that axis.
fn digest_packet(session: EntityId, turn_ids: Vec<EntityId>) -> CompactionPacket {
    CompactionPacket {
        schema_version: COMPACTION_PACKET_SCHEMA_VERSION,
        session_ref: session,
        turn_ids,
        payload_kind: CompactionPayloadKind::TurnDigest.as_u8(),
        snapshot: snapshot(0xAB, 4_096),
        digest_text: Some("the sitting, compacted".to_owned()),
        working_set_refs: Vec::new(),
    }
}

fn working_set_packet(session: EntityId, turn_ids: Vec<EntityId>) -> CompactionPacket {
    CompactionPacket {
        schema_version: COMPACTION_PACKET_SCHEMA_VERSION,
        session_ref: session,
        turn_ids,
        payload_kind: CompactionPayloadKind::WorkingSetHandoff.as_u8(),
        snapshot: snapshot(0xCD, 2_048),
        digest_text: None,
        working_set_refs: vec![entity(0x60)],
    }
}

/// Unwraps the per-axis refusal, asserting the carrier variant and kind.
fn rejection(error: Error) -> CompactionPacketError {
    assert_eq!(error.kind(), ErrorKind::CompactionPacketRejected);
    match error {
        Error::CompactionPacketRejected(axis) => axis,
        other => panic!("expected a compaction packet rejection, got {other:?}"),
    }
}

fn membership_of(vault: &Vault, turn: &EntityId) -> Option<EntityId> {
    let rtxn = vault.store.env.read_txn().expect("read txn");
    let recorded =
        turn_session_membership_in_txn(&vault.store, &rtxn, turn).expect("membership read");
    drop(rtxn);
    recorded
}

/// The TURN's PUBLIC out-edge set. Membership rides `vault_meta`, not the
/// graph, so this must be byte-for-byte what the witness door already
/// minted — no compaction-only edge leaks into retrieval or traversal.
fn turn_out_edges(vault: &Vault, turn: &EntityId) -> Vec<(EdgeKind, EntityId)> {
    vault
        .edges_out(turn)
        .expect("turn edges out")
        .into_iter()
        .map(|edge| (edge.kind, edge.target))
        .collect()
}

fn stored_row_count(vault: &Vault) -> (u64, u64, u64) {
    let rtxn = vault.store.env.read_txn().expect("read txn");
    let entities = vault.store.entities.len(&rtxn).expect("entity count");
    let edges = vault.store.edges_out.len(&rtxn).expect("edge count");
    let meta = vault.store.vault_meta.len(&rtxn).expect("meta count");
    drop(rtxn);
    (entities, edges, meta)
}

/// One admitted vault: actor, open session, one witnessed turn.
fn admitted_fixture(
    actor_seed: u8,
    conversation_seed: u8,
    turn_seed: u8,
) -> (tempfile::TempDir, Vault, EntityId, EntityId) {
    let (dir, vault) = open_vault();
    let actor = put_actor(&vault, actor_seed);
    let session = mint_session(&vault, 400);
    let turn = witness_turn(&vault, actor, conversation_seed, turn_seed, 500, 0);
    (dir, vault, session, turn)
}

// ── the happy path + the witness's read accessors ───────────────────────

#[test]
fn admit_accepts_a_well_formed_turn_digest_packet() {
    let (_dir, vault, session, turn) = admitted_fixture(0x20, 0x21, 0x22);

    let packet = digest_packet(session, vec![turn]);
    let admitted =
        admit_compaction_packet(&vault, packet.clone(), None).expect("well-formed packet admits");

    assert_eq!(admitted.schema_version(), COMPACTION_PACKET_SCHEMA_VERSION);
    assert_eq!(admitted.session(), session);
    assert_eq!(admitted.turn_ids(), &[turn][..]);
    assert_eq!(admitted.payload_kind(), CompactionPayloadKind::TurnDigest);
    assert_eq!(admitted.snapshot(), &packet.snapshot);
    assert_eq!(admitted.digest_text(), Some("the sitting, compacted"));
    assert!(admitted.working_set_refs().is_empty());
}

#[test]
fn admit_accepts_a_well_formed_working_set_packet_against_a_matching_expected_ref() {
    let (_dir, vault, session, turn) = admitted_fixture(0x23, 0x24, 0x25);

    let packet = working_set_packet(session, vec![turn]);
    let expected = packet.snapshot;
    let admitted = admit_compaction_packet(&vault, packet, Some(&expected))
        .expect("matching expected snapshot admits");

    assert_eq!(
        admitted.payload_kind(),
        CompactionPayloadKind::WorkingSetHandoff
    );
    assert_eq!(admitted.working_set_refs(), &[entity(0x60)][..]);
    assert_eq!(admitted.digest_text(), None);
}

// ── schema pin ──────────────────────────────────────────────────────────

#[test]
fn admit_refuses_a_foreign_schema_version_without_migrating() {
    let (_dir, vault, session, turn) = admitted_fixture(0x26, 0x27, 0x28);

    let mut packet = digest_packet(session, vec![turn]);
    packet.schema_version = COMPACTION_PACKET_SCHEMA_VERSION + 1;

    let error = admit_compaction_packet(&vault, packet, None).expect_err("schema pin is closed");
    assert_eq!(
        rejection(error),
        CompactionPacketError::SchemaMismatch {
            expected: COMPACTION_PACKET_SCHEMA_VERSION,
            got: COMPACTION_PACKET_SCHEMA_VERSION + 1,
        }
    );
}

// ── turn set ────────────────────────────────────────────────────────────

#[test]
fn admit_refuses_a_packet_that_compacts_nothing() {
    let (_dir, vault, session, _turn) = admitted_fixture(0x29, 0x2A, 0x2B);

    let packet = digest_packet(session, Vec::new());

    let error = admit_compaction_packet(&vault, packet, None).expect_err("empty turn set refused");
    assert_eq!(rejection(error), CompactionPacketError::EmptyTurnIds);
}

#[test]
fn admit_refuses_a_turn_id_that_does_not_resolve() {
    let (_dir, vault, session, turn) = admitted_fixture(0x2C, 0x2D, 0x2E);
    let ghost = entity(0x2F);

    let packet = digest_packet(session, vec![turn, ghost]);

    let error = admit_compaction_packet(&vault, packet, None).expect_err("unknown turn refused");
    assert_eq!(
        rejection(error),
        CompactionPacketError::UnknownTurn { turn: ghost }
    );
}

#[test]
fn admit_refuses_a_turn_ref_that_resolves_to_another_entity_type() {
    let (_dir, vault, session, _turn) = admitted_fixture(0x30, 0x31, 0x32);

    // The CONVERSATION the witness above created is a live entity whose
    // type byte is NOT `ENTITY_TYPE_TURN`.
    let conversation = entity(0x31);
    let packet = digest_packet(session, vec![conversation]);

    let error = admit_compaction_packet(&vault, packet, None).expect_err("non-TURN entity refused");
    assert_eq!(
        rejection(error),
        CompactionPacketError::TurnNotTurnEntity {
            turn: conversation,
            entity_type: ENTITY_TYPE_CONVERSATION,
        }
    );
}

// ── membership: the unknown answer never becomes the wrong answer ───────

#[test]
fn admit_refuses_a_turn_recorded_against_another_session() {
    let (_dir, vault, session, turn) = admitted_fixture(0x33, 0x34, 0x35);

    // A second, live SESSION the turn was never witnessed into.
    let other_session = entity(0x36);
    vault
        .put_entity(
            &other_session,
            ENTITY_TYPE_SESSION,
            TimeRange { start: 1, end: 1 },
            1,
            b"other sitting",
        )
        .expect("put other session");

    let packet = digest_packet(other_session, vec![turn]);

    let error = admit_compaction_packet(&vault, packet, None).expect_err("foreign sitting refused");
    assert_eq!(
        rejection(error),
        CompactionPacketError::TurnFromOtherSession {
            turn,
            recorded: session,
        }
    );
}

#[test]
fn admit_refuses_a_legacy_turn_with_no_recorded_membership() {
    let (_dir, vault) = open_vault();
    let _actor = put_actor(&vault, 0x37);
    let session = mint_session(&vault, 400);

    // A TURN written the way turns existed BEFORE membership recording
    // landed: a live row with no TURN -> SESSION edge at all.
    let legacy_turn = entity(0x38);
    vault
        .put_entity(
            &legacy_turn,
            ENTITY_TYPE_TURN,
            TimeRange { start: 1, end: 1 },
            1,
            b"legacy turn",
        )
        .expect("put legacy turn");
    assert_eq!(membership_of(&vault, &legacy_turn), None);

    let packet = digest_packet(session, vec![legacy_turn]);

    let error = admit_compaction_packet(&vault, packet, None)
        .expect_err("an unrecorded sitting is not a pass");
    let axis = rejection(error);
    assert_eq!(
        axis,
        CompactionPacketError::SessionMembershipNotRecorded { turn: legacy_turn }
    );
    // The distinction that matters: legacy data is refused for being
    // UNPROVEN, never mislabelled as belonging elsewhere.
    assert_ne!(
        axis,
        CompactionPacketError::TurnFromOtherSession {
            turn: legacy_turn,
            recorded: session,
        }
    );
}

// ── session ref ─────────────────────────────────────────────────────────

#[test]
fn admit_refuses_a_session_ref_that_does_not_resolve() {
    let (_dir, vault, _session, turn) = admitted_fixture(0x39, 0x3A, 0x3B);
    let missing = entity(0x3C);

    let packet = digest_packet(missing, vec![turn]);

    let error = admit_compaction_packet(&vault, packet, None).expect_err("missing session refused");
    assert_eq!(
        rejection(error),
        CompactionPacketError::UnknownSession { session: missing }
    );
}

#[test]
fn admit_refuses_a_session_ref_that_resolves_to_a_non_session_entity() {
    let (_dir, vault, _session, turn) = admitted_fixture(0x3D, 0x3E, 0x3F);

    // The conversation is live, but it is not a sitting.
    let conversation = entity(0x3E);
    let packet = digest_packet(conversation, vec![turn]);

    let error = admit_compaction_packet(&vault, packet, None).expect_err("non-SESSION ref refused");
    assert_eq!(
        rejection(error),
        CompactionPacketError::UnknownSession {
            session: conversation
        }
    );
}

// ── snapshot ref ────────────────────────────────────────────────────────

#[test]
fn admit_refuses_a_zero_or_malformed_snapshot_ref() {
    let (_dir, vault, session, turn) = admitted_fixture(0x40, 0x41, 0x43);

    let mut zero_hash = digest_packet(session, vec![turn]);
    zero_hash.snapshot = snapshot(0x00, 4_096);
    let error =
        admit_compaction_packet(&vault, zero_hash, None).expect_err("zero content hash refused");
    assert_eq!(
        rejection(error),
        CompactionPacketError::SnapshotMalformed("zero content hash")
    );

    let mut zero_len = digest_packet(session, vec![turn]);
    zero_len.snapshot = snapshot(0xAB, 0);
    let error =
        admit_compaction_packet(&vault, zero_len, None).expect_err("zero byte length refused");
    assert_eq!(
        rejection(error),
        CompactionPacketError::SnapshotMalformed("zero byte length")
    );
}

#[test]
fn admit_refuses_a_snapshot_that_differs_from_the_caller_supplied_expected_ref() {
    let (_dir, vault, session, turn) = admitted_fixture(0x44, 0x45, 0x46);

    // Content-hash divergence.
    let packet = digest_packet(session, vec![turn]);
    let expected = snapshot(0xEE, 4_096);
    let error = admit_compaction_packet(&vault, packet, Some(&expected))
        .expect_err("hash mismatch refused");
    assert_eq!(
        rejection(error),
        CompactionPacketError::SnapshotMismatch {
            field: "content_hash"
        }
    );

    // Byte-length divergence under an identical hash.
    let packet = digest_packet(session, vec![turn]);
    let expected = snapshot(0xAB, 4_097);
    let error = admit_compaction_packet(&vault, packet, Some(&expected))
        .expect_err("length mismatch refused");
    assert_eq!(
        rejection(error),
        CompactionPacketError::SnapshotMismatch { field: "byte_len" }
    );
}

// ── payload kind and per-kind shape ─────────────────────────────────────

#[test]
fn admit_refuses_an_unknown_payload_kind_byte() {
    let (_dir, vault, session, turn) = admitted_fixture(0x48, 0x49, 0x4A);

    for byte in [2_u8, 7, 255] {
        assert_eq!(
            CompactionPayloadKind::from_u8(byte),
            None,
            "byte {byte} must stay outside the closed set"
        );
        let mut packet = digest_packet(session, vec![turn]);
        packet.payload_kind = byte;

        let error = admit_compaction_packet(&vault, packet, None)
            .expect_err("unknown payload kind refused");
        assert_eq!(
            rejection(error),
            CompactionPacketError::PayloadKindUnknown { byte }
        );
    }
}

#[test]
fn admit_refuses_a_turn_digest_payload_whose_shape_is_wrong() {
    let (_dir, vault, session, turn) = admitted_fixture(0x4B, 0x4C, 0x4D);

    let mut missing_digest = digest_packet(session, vec![turn]);
    missing_digest.digest_text = None;
    assert_eq!(
        rejection(
            admit_compaction_packet(&vault, missing_digest, None)
                .expect_err("absent digest refused")
        ),
        CompactionPacketError::PayloadShapeViolation("turn digest requires non-empty digest_text")
    );

    let mut empty_digest = digest_packet(session, vec![turn]);
    empty_digest.digest_text = Some(String::new());
    assert_eq!(
        rejection(
            admit_compaction_packet(&vault, empty_digest, None).expect_err("empty digest refused")
        ),
        CompactionPacketError::PayloadShapeViolation("turn digest requires non-empty digest_text")
    );

    let mut both_families = digest_packet(session, vec![turn]);
    both_families.working_set_refs = vec![entity(0x61)];
    assert_eq!(
        rejection(
            admit_compaction_packet(&vault, both_families, None)
                .expect_err("mixed payload families refused")
        ),
        CompactionPacketError::PayloadShapeViolation("turn digest carries no working_set_refs")
    );
}

#[test]
fn admit_refuses_a_working_set_payload_whose_shape_is_wrong() {
    let (_dir, vault, session, turn) = admitted_fixture(0x4E, 0x4F, 0x50);

    let mut empty_refs = working_set_packet(session, vec![turn]);
    empty_refs.working_set_refs = Vec::new();
    assert_eq!(
        rejection(
            admit_compaction_packet(&vault, empty_refs, None)
                .expect_err("empty working set refused")
        ),
        CompactionPacketError::PayloadShapeViolation(
            "working set handoff requires non-empty working_set_refs"
        )
    );

    let mut both_families = working_set_packet(session, vec![turn]);
    both_families.digest_text = Some("prose that does not belong here".to_owned());
    assert_eq!(
        rejection(
            admit_compaction_packet(&vault, both_families, None)
                .expect_err("mixed payload families refused")
        ),
        CompactionPacketError::PayloadShapeViolation("working set handoff carries no digest_text")
    );
}

// ── the membership carrier itself ───────────────────────────────────────

#[test]
fn the_witness_txn_records_a_readable_turn_to_session_membership() {
    let (_dir, vault, session, turn) = admitted_fixture(0x52, 0x53, 0x54);

    assert_eq!(
        membership_of(&vault, &turn),
        Some(session),
        "the production witness door recorded the sitting"
    );
}

#[test]
fn recording_membership_leaves_the_turns_public_edge_surface_untouched() {
    // The membership fact is `vault_meta` plumbing, so a turn witnessed
    // inside a sitting has EXACTLY the edges the witness door mints — the
    // `ChildOf` conversation binding and nothing else. Retrieval, PPR
    // traversal and `conversation_of` see no compaction-only edge.
    let (_dir, vault, session, turn) = admitted_fixture(0x63, 0x64, 0x65);
    assert_eq!(membership_of(&vault, &turn), Some(session));
    assert_eq!(
        turn_out_edges(&vault, &turn),
        vec![(EdgeKind::ChildOf, entity(0x64))]
    );
}

#[test]
fn a_turn_witnessed_outside_any_session_records_no_membership() {
    let (_dir, vault) = open_vault();
    let actor = put_actor(&vault, 0x55);

    // ARCH-0002 open-endedness: a sessionless turn stays valid, and the
    // membership write is a no-op rather than an invented sitting.
    let turn = witness_turn(&vault, actor, 0x56, 0x57, 600, 0);

    assert_eq!(membership_of(&vault, &turn), None);
}

#[test]
fn appending_to_a_turn_never_rewrites_its_membership() {
    let (_dir, vault) = open_vault();
    let actor = put_actor(&vault, 0x58);
    let session = mint_session(&vault, 400);
    let turn = witness_turn(&vault, actor, 0x59, 0x5A, 500, 0);
    assert_eq!(membership_of(&vault, &turn), Some(session));

    // Append a new message at a distinct position in the same TURN.
    // Membership is first-write-wins, so the turn keeps one sitting.
    let appended = witness_turn(&vault, actor, 0x59, 0x5A, 900, 1);
    assert_eq!(appended, turn);
    assert_eq!(
        membership_of(&vault, &turn),
        Some(session),
        "a turn never carries two sittings"
    );
}

// ── witness unforgeability (compile surface) ────────────────────────────

/// [`ValidatedCompactionPacket`] carries private fields and no public
/// constructor, so [`admit_compaction_packet`] is the only way to obtain
/// one. The COMPILE-surface half of that claim is the `compile_fail`
/// doctest on the type (a struct literal outside this module does not
/// build); this half pins its runtime consequence — the witness a caller
/// holds always mirrors a packet that actually passed the door, field for
/// field, with the payload kind DECODED rather than asserted.
#[test]
fn a_validated_packet_can_only_come_from_the_admission_door() {
    let (_dir, vault, session, turn) = admitted_fixture(0x5B, 0x5C, 0x5D);

    let packet = digest_packet(session, vec![turn]);
    let admitted = admit_compaction_packet(&vault, packet.clone(), None).expect("admit");

    assert_eq!(admitted.session(), packet.session_ref);
    assert_eq!(admitted.turn_ids(), packet.turn_ids.as_slice());
    assert_eq!(admitted.snapshot(), &packet.snapshot);
    assert_eq!(admitted.schema_version(), packet.schema_version);
    assert_eq!(admitted.payload_kind().as_u8(), packet.payload_kind);
}

// ── admission is read-only ──────────────────────────────────────────────

#[test]
fn admission_writes_nothing_on_either_outcome() {
    let (_dir, vault, session, turn) = admitted_fixture(0x5E, 0x5F, 0x62);

    let before = stored_row_count(&vault);

    let mut refused = digest_packet(session, vec![turn]);
    refused.schema_version = COMPACTION_PACKET_SCHEMA_VERSION + 7;
    admit_compaction_packet(&vault, refused, None).expect_err("refused");
    assert_eq!(stored_row_count(&vault), before, "a refusal writes nothing");

    admit_compaction_packet(&vault, digest_packet(session, vec![turn]), None).expect("admit");
    assert_eq!(
        stored_row_count(&vault),
        before,
        "an admission writes nothing either"
    );
}
