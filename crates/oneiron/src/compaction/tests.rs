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
fn witness_turn(vault: &Vault, actor: EntityId, conversation: u8, turn: u8, at: u64) -> EntityId {
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
                order: 0,
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

/// Unwraps a crate-internal invariant refusal, asserting carrier and kind.
fn invariant(error: Error) -> &'static str {
    assert_eq!(error.kind(), ErrorKind::InvariantViolation);
    match error {
        Error::InvariantViolation(detail) => detail,
        other => panic!("expected an invariant violation, got {other:?}"),
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
    let turn = witness_turn(&vault, actor, conversation_seed, turn_seed, 500);
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
    let turn = witness_turn(&vault, actor, 0x56, 0x57, 600);

    assert_eq!(membership_of(&vault, &turn), None);
}

#[test]
fn appending_to_a_turn_never_rewrites_its_membership() {
    let (_dir, vault) = open_vault();
    let actor = put_actor(&vault, 0x58);
    let session = mint_session(&vault, 400);
    let turn = witness_turn(&vault, actor, 0x59, 0x5A, 500);
    assert_eq!(membership_of(&vault, &turn), Some(session));

    // The same TURN is appended to. Membership is first-write-wins, so the
    // append rewrites nothing and the turn keeps one sitting.
    let appended = witness_turn(&vault, actor, 0x59, 0x5A, 900);
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

// ═══════════════════════════════════════════════════════════════════════
// RT-05 (ONE-1687) — the in-engine compaction driver
// ═══════════════════════════════════════════════════════════════════════

use std::sync::Arc;
use std::time::Duration;

use crate::agent_def::{ContextBudgetSplit, MemoryProfile};
use crate::context_pack::PackFormat;
use crate::llm::ModelTierRef;
use crate::off_record::OffRecordBackendClass;
use crate::registry::ENTITY_TYPE_TURN;
use crate::write_envelope::WriteActor;

const CHEAP_BACKEND: &str = "test.cheap.slm";
const FRONTIER_BACKEND: &str = "test.frontier";

/// A cheap backend that reports what it was asked to compact, so a test can
/// tell an engine-fabricated request from the host-assembled one.
struct CheapBackend;

impl CompactionBackend for CheapBackend {
    fn backend_key(&self) -> &str {
        CHEAP_BACKEND
    }

    fn tier_class(&self) -> CompactionTierClass {
        CompactionTierClass::Cheap
    }

    fn compact(&self, request: &CompactionRequest) -> Result<CompactionProduct> {
        Ok(CompactionProduct {
            summary_text: format!("epoch text over {} rows", request.window.len()),
            latency: Duration::from_millis(500),
        })
    }
}

/// A backend that DECLARES a frontier tier. The registry must never accept it,
/// so `compact` is unreachable by construction.
struct FrontierBackend;

impl CompactionBackend for FrontierBackend {
    fn backend_key(&self) -> &str {
        FRONTIER_BACKEND
    }

    fn tier_class(&self) -> CompactionTierClass {
        CompactionTierClass::Frontier
    }

    fn compact(&self, _request: &CompactionRequest) -> Result<CompactionProduct> {
        unreachable!("a frontier backend is refused at registration and never resolves")
    }
}

fn cheap_registry() -> CompactionBackendRegistry {
    let mut registry = CompactionBackendRegistry::new();
    registry
        .register(Arc::new(CheapBackend))
        .expect("a cheap backend registers");
    registry
}

fn profile(budget: u64, ownership: CompactionOwnership) -> MemoryProfile {
    MemoryProfile::new(
        budget,
        ModelTierRef(CHEAP_BACKEND.to_owned()),
        ownership,
    )
}

fn engine_driver(budget: u64) -> CompactionDriver {
    CompactionDriver::for_profile(&profile(budget, CompactionOwnership::Engine), &cheap_registry())
        .expect("engine profile resolves")
        .expect("an engine profile produces a driver")
}

fn put_turn(vault: &Vault, seed: u8, at: u64) -> EntityId {
    let id = entity(seed);
    vault
        .put_entity(
            &id,
            ENTITY_TYPE_TURN,
            TimeRange { start: at, end: at },
            at,
            b"rt-05 window turn",
        )
        .expect("put turn");
    id
}

fn window_row(turn_id: EntityId, turn: u64) -> CompactionWindowMessage {
    CompactionWindowMessage {
        message_id: EntityId::now(),
        turn_id,
        content: format!("turn {turn} content"),
        turn,
        tokens: 10,
    }
}

/// A window of `count` rows over freshly stored TURNs, numbered from `first`.
fn host_window(vault: &Vault, seed: u8, first: u64, count: u64) -> Vec<CompactionWindowMessage> {
    (0..count)
        .map(|offset| {
            let turn = first + offset;
            let turn_id = put_turn(
                vault,
                seed.wrapping_add(u8::try_from(offset % 200).expect("offset fits")),
                turn,
            );
            window_row(turn_id, turn)
        })
        .collect()
}

fn loom_actor(vault: &Vault, seed: u8) -> WriteActor {
    WriteActor::new(put_actor(vault, seed), EdgeActorClass::Agent)
}

/// Drives one full crossing → request → compact → integrate cycle.
fn compact_once(
    vault: &Vault,
    driver: &mut CompactionDriver,
    session: EntityId,
    actor: WriteActor,
    window: Vec<CompactionWindowMessage>,
) -> Result<SwapPlan> {
    let directive = driver.evaluate_now(vault, u64::MAX)?;
    assert!(matches!(directive, CompactionDirective::Begin { .. }));
    let request = driver.request_for(vault, &session, window)?;
    let product = driver.backend().compact(&request)?;
    driver.integrate(vault, &session, actor, &request, product, &[])
}

fn stored_summary_body(vault: &Vault, id: &EntityId) -> EpochSummaryBody {
    let raw = vault
        .get(id)
        .expect("read summary")
        .expect("summary exists");
    decode_epoch_summary_body(&raw).expect("stored body decodes as an epoch summary")
}

// ── backend registry and the frontier ban ───────────────────────────────

#[test]
fn registry_refuses_frontier_and_resolves_only_registered_cheap_backends() {
    let mut registry = CompactionBackendRegistry::new();

    let refused = registry
        .register(Arc::new(FrontierBackend))
        .expect_err("a frontier backend is refused at registration");
    assert_eq!(
        invariant(refused),
        "compaction backend declares a frontier tier and is refused"
    );
    assert_eq!(
        registry.tier_class_of(FRONTIER_BACKEND),
        None,
        "a refused backend never enters the map, so it cannot resolve later"
    );

    registry
        .register(Arc::new(CheapBackend))
        .expect("a cheap backend registers");
    assert_eq!(
        registry.tier_class_of(CHEAP_BACKEND),
        Some(CompactionTierClass::Cheap)
    );

    let unknown = profile(1_000, CompactionOwnership::Engine);
    let mut unknown = unknown;
    unknown.compaction_backend = ModelTierRef("never.registered".to_owned());
    assert_eq!(
        invariant(
            registry
                .resolve(&unknown)
                .err()
                .expect("unknown key fails typed")
        ),
        "compaction backend key is not registered"
    );
}

#[test]
fn for_profile_yields_no_driver_for_byoa_and_a_driver_for_engine() {
    let registry = cheap_registry();

    assert!(
        CompactionDriver::for_profile(&profile(1_000, CompactionOwnership::Byoa), &registry)
            .expect("byoa resolves without error")
            .is_none(),
        "byoa is exclusion by construction: no driver exists to compact that window"
    );
    assert!(
        CompactionDriver::for_profile(&profile(1_000, CompactionOwnership::Engine), &registry)
            .expect("engine resolves")
            .is_some()
    );
}

// ── the margin law ──────────────────────────────────────────────────────

#[test]
fn driver_observe_velocity_displaces_the_cold_start_seeds() {
    let mut driver = engine_driver(1_000);
    let seeded = driver.margin().margin_tokens();
    assert_eq!(
        seeded,
        (MarginLaw::SEED_LATENCY_MS / 1_000.0 * MarginLaw::SEED_VELOCITY_TPS) as u64,
        "before any sample the margin is the seed product, not a stored constant"
    );

    // The FIRST sample displaces the seed outright.
    driver.observe_velocity(500.0);
    let grown = driver.margin().margin_tokens();
    assert!(
        grown > seeded,
        "a larger measured velocity grows the margin: {grown} !> {seeded}"
    );
    assert_eq!(driver.margin().measured_velocity_tps(), 500);

    // Feeding a smaller sample moves it back down — nothing is pinned.
    driver.observe_velocity(1.0);
    assert!(driver.margin().margin_tokens() < grown);
}

// ── threshold, state machine, and the real serialized product ───────────

#[test]
fn a_real_serialized_pack_drives_one_begin_per_threshold_crossing() -> Result<()> {
    let (_dir, vault) = open_test_vault_with(crate::test_util::embedding_test_config());
    let first = entity(0x71);
    let second = entity(0x72);
    for (id, vector, text) in [
        (first, [1.0_f32, 0.0, 0.0, 0.0], "threshold first"),
        (second, [0.0, 1.0, 0.0, 0.0], "threshold second"),
    ] {
        let mut payload = Vec::new();
        rmpv::encode::write_value(
            &mut payload,
            &rmpv::Value::Map(vec![(
                rmpv::Value::from("content"),
                rmpv::Value::from(text),
            )]),
        )
        .expect("encode turn body");
        vault
            .batch()
            .put(
                &id,
                ENTITY_TYPE_TURN,
                TimeRange { start: 1, end: 1 },
                1,
                &payload,
            )
            .vector(&id, &vector)
            .commit()?;
    }

    let pack = vault
        .context_pack()
        .search_vector(&[1.0, 0.0, 0.0, 0.0], 10)
        .format(PackFormat::Plaintext)
        // The host's contract: apply the profile at builder construction, then
        // hand the REAL serialized product to the driver.
        .memory_profile(Some(&profile(512, CompactionOwnership::Engine)))
        .run_serialized_with_stats()?
        .value;
    assert!(
        pack.stats.tokens.total_tokens > 0,
        "the serialized product carries real token accounting"
    );

    let mut driver = engine_driver(4);
    let first_directive = driver.observe_serialized_pack(&vault, &pack)?;
    assert!(
        matches!(first_directive, CompactionDirective::Begin { .. }),
        "crossing the soft threshold begins a background compaction"
    );
    assert_eq!(
        driver.observe_serialized_pack(&vault, &pack)?,
        CompactionDirective::Quiet,
        "a second observation while compacting is Quiet, not a queue"
    );
    Ok(())
}

#[test]
fn a_thousand_token_profile_compacts_at_five_hundred_not_zero() -> Result<()> {
    let (_dir, vault) = open_vault();
    let mut driver = engine_driver(1_000);
    assert_eq!(
        driver.compact_at(),
        500,
        "the floor holds the threshold at half the budget when margin >= budget"
    );

    assert_eq!(
        driver.evaluate_now(&vault, 499)?,
        CompactionDirective::Quiet
    );
    assert!(matches!(
        driver.evaluate_now(&vault, 500)?,
        CompactionDirective::Begin { .. }
    ));
    Ok(())
}

#[test]
fn a_backend_error_abandons_to_idle_and_the_next_crossing_begins_again() -> Result<()> {
    let (_dir, vault) = open_vault();
    let mut driver = engine_driver(1_000);

    assert!(matches!(
        driver.evaluate_now(&vault, 900)?,
        CompactionDirective::Begin { .. }
    ));
    assert!(driver.is_compacting());

    driver.abandon();
    assert!(!driver.is_compacting(), "abandon returns to Idle");
    assert!(
        matches!(
            driver.evaluate_now(&vault, 900)?,
            CompactionDirective::Begin { .. }
        ),
        "the next crossing begins again — abandon minted nothing to block it"
    );
    Ok(())
}

// ── the request ─────────────────────────────────────────────────────────

#[test]
fn request_for_is_legal_only_while_compacting() -> Result<()> {
    let (_dir, vault) = open_vault();
    let session = mint_session(&vault, 10);
    let driver = engine_driver(1_000);
    let window = host_window(&vault, 0x80, 1, 2);

    let refused = driver
        .request_for(&vault, &session, window)
        .expect_err("Idle has no recorded watermark to build a request from");
    assert_eq!(
        invariant(refused),
        "request_for is legal only while compacting"
    );
    Ok(())
}

#[test]
fn request_for_carries_the_host_window_and_the_profile_summary_budget() -> Result<()> {
    let (_dir, vault) = open_vault();
    let session = mint_session(&vault, 10);
    let mut driver = engine_driver(1_000);
    driver.evaluate_now(&vault, u64::MAX)?;

    let window = host_window(&vault, 0x90, 1, 3);
    let turn_ids: Vec<EntityId> = window.iter().map(|row| row.turn_id).collect();
    let request = driver.request_for(&vault, &session, window)?;

    assert_eq!(request.session_ref, session);
    assert_eq!(
        request.window.iter().map(|row| row.turn_id).collect::<Vec<_>>(),
        turn_ids,
        "the host's rows ride through verbatim, TURN ids included"
    );
    assert!(request.window.iter().all(|row| !row.content.is_empty()));
    assert_eq!(
        request.summary_token_budget, 250,
        "no split: the named default summary fraction of the window budget"
    );
    assert_eq!(request.turn_start, 1, "the first epoch starts at the window");

    // The split, when present, is the authority instead.
    let split_profile = profile(1_000, CompactionOwnership::Engine)
        .with_budget_split(ContextBudgetSplit::new(0.25, 0.25, 0.4, 0.1));
    let mut split_driver = CompactionDriver::for_profile(&split_profile, &cheap_registry())?
        .expect("engine driver");
    split_driver.evaluate_now(&vault, u64::MAX)?;
    let split_request =
        split_driver.request_for(&vault, &session, host_window(&vault, 0xA0, 1, 1))?;
    assert_eq!(split_request.summary_token_budget, 400);
    Ok(())
}

#[test]
fn the_request_watermark_carries_no_epoch_number() {
    // The type itself is the proof: a watermark that cannot NAME an epoch
    // cannot leak one into the request, so numbering can only happen inside
    // `integrate`'s write transaction.
    let watermark = CompactionWatermark {
        learned_at: 7,
        turn_id: None,
    };
    let rendered = format!("{watermark:?}");
    assert!(
        !rendered.contains("epoch"),
        "CompactionWatermark carries no epoch field: {rendered}"
    );
}

// ── the margin law's starvation table ───────────────────────────────────

#[test]
fn starvation_check_covers_the_whole_predicate_table() -> Result<()> {
    let (_dir, vault) = open_vault();

    // Idle: no in-flight compaction, so `remaining_latency` has no referent.
    let idle = engine_driver(1_000);
    assert_eq!(idle.starvation_check(Duration::from_secs(5), 10), None);

    // Neither condition: a wide budget and a slow session.
    let mut calm = engine_driver(1_000_000);
    calm.observe_velocity(1.0);
    calm.evaluate_now(&vault, u64::MAX)?;
    assert_eq!(
        calm.starvation_check(Duration::from_secs(1), 10_000),
        None,
        "1 tps for 1s against 10000 tokens of headroom starves nothing"
    );

    // Degeneracy only: margin >= budget with a positive velocity, but the
    // headroom still absorbs the projected write.
    let mut degenerate = engine_driver(10);
    degenerate.observe_velocity(1.0);
    degenerate.evaluate_now(&vault, u64::MAX)?;
    let margin = degenerate.margin().margin_tokens();
    assert!(margin >= 10, "the seeded latency makes this degenerate");
    assert_eq!(
        degenerate.starvation_check(Duration::from_secs(1), 10_000),
        Some(CompactionSignal::Starvation {
            deficit_tokens: margin - 10,
            measured_latency_ms: degenerate.margin().measured_latency_ms(),
            measured_velocity_tps: 1,
        }),
        "degeneracy-only deficit is margin - budget"
    );

    // Overrun only: a wide budget, but the session out-writes the remaining
    // latency.
    let mut overrun = engine_driver(1_000_000);
    overrun.observe_velocity(100.0);
    overrun.evaluate_now(&vault, u64::MAX)?;
    assert!(overrun.margin().margin_tokens() < 1_000_000);
    assert_eq!(
        overrun.starvation_check(Duration::from_secs(10), 400),
        Some(CompactionSignal::Starvation {
            deficit_tokens: 600,
            measured_latency_ms: overrun.margin().measured_latency_ms(),
            measured_velocity_tps: 100,
        }),
        "overrun deficit is ceil(velocity * remaining - headroom)"
    );

    // Both: degenerate budget AND an overrun.
    let mut both = engine_driver(10);
    both.observe_velocity(100.0);
    both.evaluate_now(&vault, u64::MAX)?;
    assert!(matches!(
        both.starvation_check(Duration::from_secs(10), 400),
        Some(CompactionSignal::Starvation {
            deficit_tokens: 600,
            ..
        })
    ));

    // The session is still message-accepting throughout: emitting a signal is
    // the whole response, and the driver stays in flight.
    assert!(both.is_compacting());
    assert_eq!(both.evaluate_now(&vault, u64::MAX)?, CompactionDirective::Quiet);
    Ok(())
}

// ── the epoch summary mint ──────────────────────────────────────────────

#[test]
fn integrate_mints_one_epoch_summary_from_the_request() -> Result<()> {
    let (_dir, vault) = open_vault();
    let session = mint_session(&vault, 10);
    let actor = loom_actor(&vault, 0x64);
    let mut driver = engine_driver(1_000);
    let window = host_window(&vault, 0xB0, 1, 3);
    let turn_ids: Vec<EntityId> = window.iter().map(|row| row.turn_id).collect();

    let plan = compact_once(&vault, &mut driver, session, actor, window)?;
    assert_eq!(plan.epoch, 1, "a session's first compaction is epoch 1");

    let body = stored_summary_body(&vault, &plan.summary_id);
    assert_eq!(body.v, EPOCH_SUMMARY_BODY_VERSION);
    assert_eq!(body.session, session.to_hex());
    assert_eq!(body.epoch, 1);
    assert_eq!((body.turn_start, body.turn_end), (1, 3));
    assert_eq!(body.level, EPOCH_SUMMARY_LEVEL, "epoch summaries mint at 0");
    assert_eq!(
        body.actor,
        actor.entity_ref().to_hex(),
        "the byline is the 32-hex ref of the actor passed to integrate"
    );

    let edges = vault.edges_out(&plan.summary_id)?;
    let derived: Vec<EntityId> = edges
        .iter()
        .filter(|edge| edge.kind == EdgeKind::DerivedFrom)
        .map(|edge| edge.target)
        .collect();
    assert_eq!(derived.len(), 3, "one DerivedFrom edge per covered turn");
    for turn in &turn_ids {
        assert_eq!(
            derived.iter().filter(|target| *target == turn).count(),
            1,
            "each request turn is a DerivedFrom target exactly once"
        );
    }

    // The state machine returned to Idle and fed the measured latency in.
    assert!(!driver.is_compacting());
    assert_eq!(driver.margin().measured_latency_ms(), 500);
    Ok(())
}

#[test]
fn a_second_compaction_mints_epoch_two_and_starts_at_prior_turn_end_plus_one() -> Result<()> {
    let (_dir, vault) = open_vault();
    let session = mint_session(&vault, 10);
    let actor = loom_actor(&vault, 0x65);
    let mut driver = engine_driver(1_000);

    let first = compact_once(
        &vault,
        &mut driver,
        session,
        actor,
        host_window(&vault, 0xC0, 1, 3),
    )?;
    assert_eq!(first.epoch, 1);

    // The DURABLE prior summary is the counter — no mutable session row.
    driver.evaluate_now(&vault, u64::MAX)?;
    let second_window = host_window(&vault, 0xD0, 4, 2);
    let request = driver.request_for(&vault, &session, second_window)?;
    assert_eq!(
        request.turn_start, 4,
        "the next span begins at the durable prior turn_end + 1"
    );

    let product = driver.backend().compact(&request)?;
    let second = driver.integrate(&vault, &session, actor, &request, product, &[])?;
    assert_eq!(second.epoch, 2);

    let body = stored_summary_body(&vault, &second.summary_id);
    assert_eq!((body.turn_start, body.turn_end), (4, 5));

    // The first keyframe is untouched: byte-stable from its mint moment.
    let first_body = stored_summary_body(&vault, &first.summary_id);
    assert_eq!(first_body.epoch, 1);
    assert_eq!((first_body.turn_start, first_body.turn_end), (1, 3));
    Ok(())
}

#[test]
fn the_mint_is_byte_stable_and_leaves_the_scope_clause_untouched() -> Result<()> {
    let (_dir, vault) = open_vault();
    let session = mint_session(&vault, 10);
    let actor = loom_actor(&vault, 0x66);

    // The scope clause: compaction touches the MESSAGE LOG only. These rows
    // stand in for the system prompt / agent definition / TASK intent that a
    // swap must not be able to reach.
    let untouched = entity(0x6A);
    vault.put_entity(
        &untouched,
        ENTITY_TYPE_TURN,
        TimeRange { start: 1, end: 1 },
        1,
        b"not a message-log entry",
    )?;
    let before = vault.get(&untouched)?.expect("row exists");

    let mut driver = engine_driver(1_000);
    let plan = compact_once(
        &vault,
        &mut driver,
        session,
        actor,
        host_window(&vault, 0x50, 1, 2),
    )?;

    let minted = vault.get(&plan.summary_id)?.expect("summary exists");
    let re_encoded = encode_epoch_summary_body(&decode_epoch_summary_body(&minted)?)?;
    assert_eq!(
        minted, re_encoded,
        "the stored body re-encodes byte-identically: the keyframe is cacheable"
    );
    assert_eq!(
        vault.get(&untouched)?.expect("row still exists"),
        before,
        "the swap cannot reach a row that is not a message-log entry"
    );
    Ok(())
}

#[test]
fn the_swap_plan_replays_the_accumulated_tail_without_duplicating_a_message() -> Result<()> {
    let (_dir, vault) = open_vault();
    let session = mint_session(&vault, 10);
    let actor = loom_actor(&vault, 0x67);
    let mut driver = engine_driver(1_000);

    let window = host_window(&vault, 0xF0, 1, 3);
    let accumulated = host_window(&vault, 0x30, 4, 2);
    let prefix_ids: Vec<EntityId> = window.iter().map(|row| row.message_id).collect();

    driver.evaluate_now(&vault, u64::MAX)?;
    let request = driver.request_for(&vault, &session, window)?;
    let product = driver.backend().compact(&request)?;
    let plan = driver.integrate(&vault, &session, actor, &request, product, &accumulated)?;

    assert_eq!(
        plan.retained_tail, accumulated,
        "the retained tail is exactly what the host accumulated after the watermark"
    );
    for row in &plan.retained_tail {
        assert!(
            !prefix_ids.contains(&row.message_id),
            "nothing is counted twice across the swapped prefix and the replayed tail"
        );
    }
    Ok(())
}

// ── the epoch-summary codec ─────────────────────────────────────────────

fn sample_body() -> EpochSummaryBody {
    EpochSummaryBody {
        v: EPOCH_SUMMARY_BODY_VERSION,
        session: entity(0x13).to_hex(),
        epoch: 3,
        turn_start: 4,
        turn_end: 9,
        level: EPOCH_SUMMARY_LEVEL,
        text: "the epoch, compacted".to_owned(),
        actor: entity(0x12).to_hex(),
    }
}

#[test]
fn epoch_summary_body_keys_are_eight_with_actor_last() {
    assert_eq!(EPOCH_SUMMARY_BODY_KEYS.len(), 8);
    assert_eq!(
        EPOCH_SUMMARY_BODY_KEYS,
        [
            "v",
            "session",
            "epoch",
            "turn_start",
            "turn_end",
            "level",
            "text",
            "actor",
        ]
    );
    assert_eq!(*EPOCH_SUMMARY_BODY_KEYS.last().expect("non-empty"), "actor");
}

#[test]
fn epoch_summary_body_round_trips_byte_identically() -> Result<()> {
    let body = sample_body();
    let bytes = encode_epoch_summary_body(&body)?;
    assert_eq!(decode_epoch_summary_body(&bytes)?, body);
    assert_eq!(encode_epoch_summary_body(&decode_epoch_summary_body(&bytes)?)?, bytes);
    Ok(())
}

#[test]
fn epoch_summary_strict_decode_rejection_matrix() -> Result<()> {
    let base = encode_epoch_summary_body(&sample_body())?;

    let invalid = |bytes: &[u8]| {
        let error = decode_epoch_summary_body(bytes).expect_err("strict decode refuses");
        assert_eq!(error.kind(), ErrorKind::InvariantViolation);
    };

    // Trailing bytes after the map.
    let mut trailing = base.clone();
    trailing.push(0xC0);
    invalid(&trailing);

    // Not a map at all.
    let mut not_a_map = Vec::new();
    rmpv::encode::write_value(&mut not_a_map, &rmpv::Value::from("summary"))
        .expect("encode string");
    invalid(&not_a_map);

    let entries_of = |extra: Vec<(rmpv::Value, rmpv::Value)>| {
        let mut entries: Vec<(rmpv::Value, rmpv::Value)> = vec![
            (rmpv::Value::from("v"), rmpv::Value::from(1_u64)),
            (
                rmpv::Value::from("session"),
                rmpv::Value::from(entity(0x13).to_hex()),
            ),
            (rmpv::Value::from("epoch"), rmpv::Value::from(3_u64)),
            (rmpv::Value::from("turn_start"), rmpv::Value::from(4_u64)),
            (rmpv::Value::from("turn_end"), rmpv::Value::from(9_u64)),
            (rmpv::Value::from("level"), rmpv::Value::from(0_u64)),
            (rmpv::Value::from("text"), rmpv::Value::from("t")),
            (
                rmpv::Value::from("actor"),
                rmpv::Value::from(entity(0x12).to_hex()),
            ),
        ];
        entries.extend(extra);
        let mut out = Vec::new();
        rmpv::encode::write_value(&mut out, &rmpv::Value::Map(entries)).expect("encode map");
        out
    };

    // Unknown key.
    invalid(&entries_of(vec![(
        rmpv::Value::from("rendered"),
        rmpv::Value::from("smuggled"),
    )]));
    // Duplicate key.
    invalid(&entries_of(vec![(
        rmpv::Value::from("epoch"),
        rmpv::Value::from(4_u64),
    )]));
    // Non-string key.
    invalid(&entries_of(vec![(
        rmpv::Value::from(9_u64),
        rmpv::Value::from("x"),
    )]));

    // A missing key is a refusal, never a default.
    let mut missing = Vec::new();
    rmpv::encode::write_value(
        &mut missing,
        &rmpv::Value::Map(vec![(rmpv::Value::from("v"), rmpv::Value::from(1_u64))]),
    )
    .expect("encode map");
    invalid(&missing);
    Ok(())
}

// ── H-S3 under the ARCH-0052 overlay model ──────────────────────────────

#[test]
fn a_room_turn_beyond_the_edge_cap_still_refuses_the_mint() -> Result<()> {
    let (_dir, vault) = open_vault();
    let session = mint_session(&vault, 10);
    let actor = loom_actor(&vault, 0x68);
    let mut driver = engine_driver(1_000);

    // A window LONGER than the DerivedFrom cap, with the room turn parked
    // beyond it: no edge is ever emitted for that position, so only the
    // driver's own probe over every covered turn can catch it.
    let span = u64::try_from(EPOCH_SUMMARY_MAX_DERIVED_EDGES).expect("cap fits") + 50;
    let room_turn = EntityId::now();
    let mut window: Vec<CompactionWindowMessage> = (0..span)
        .map(|offset| window_row(EntityId::now(), offset + 1))
        .collect();
    let room_position = EPOCH_SUMMARY_MAX_DERIVED_EDGES + 20;
    window[room_position].turn_id = room_turn;
    assert!(
        room_position >= EPOCH_SUMMARY_MAX_DERIVED_EDGES,
        "the room turn sits beyond the edge cap"
    );

    let room = vault
        .off_record_session_vault()
        .enter("rt05-room", OffRecordBackendClass::Local)?;
    let overlay = room.overlay();
    let segment = overlay.install_txn_segment()?;
    overlay.put(
        crate::session_overlay::OverlayKeyspace::Entities,
        room_turn.as_bytes(),
        b"room turn",
    )?;
    segment.commit()?;

    driver.evaluate_now(&vault, u64::MAX)?;
    let request = driver.request_for(&vault, &session, window)?;
    let product = driver.backend().compact(&request)?;
    let refused = driver
        .integrate(&vault, &session, actor, &request, product, &[])
        .expect_err("a base keyframe derived from room content is refused at creation");
    assert_eq!(refused.kind(), ErrorKind::OffRecordTaintedBaseWrite);
    Ok(())
}

#[test]
fn the_public_batch_path_refuses_a_base_summary_edge_into_a_live_room() -> Result<()> {
    let (_dir, vault) = open_vault();
    let summary = entity(0x21);
    let room_turn = EntityId::now();

    let room = vault
        .off_record_session_vault()
        .enter("rt05-chokepoint", OffRecordBackendClass::Local)?;
    let overlay = room.overlay();
    let segment = overlay.install_txn_segment()?;
    overlay.put(
        crate::session_overlay::OverlayKeyspace::Entities,
        room_turn.as_bytes(),
        b"room turn",
    )?;
    segment.commit()?;

    // The chokepoint defense for NON-driver writers is the landed K4
    // decode-point taint guard: a base edge naming a live overlay member is
    // refused before it can be written, so no separate propagation hook — and
    // no durable fence row — is needed on the public arms.
    let refused = vault
        .batch()
        .edge(&summary, EdgeKind::DerivedFrom, &room_turn, 1.0)
        .commit()
        .expect_err("the public Edge arm refuses");
    assert_eq!(refused.kind(), ErrorKind::OffRecordTaintedBaseWrite);

    let refused_created_at = vault
        .batch()
        .edge_with_created_at(&summary, EdgeKind::DerivedFrom, &room_turn, 1.0, 5)
        .commit()
        .expect_err("the public created-at arm refuses too");
    assert_eq!(
        refused_created_at.kind(),
        ErrorKind::OffRecordTaintedBaseWrite
    );
    Ok(())
}

// ── module hygiene ──────────────────────────────────────────────────────

#[test]
fn the_compaction_module_carries_no_scheduler_primitive() {
    // ARCH-0026 / CROSS-ARCH-0022 / ARCH-0046: the swap facet is event-driven
    // at watermark crossing. The engine owns no thread, task, timer or
    // heartbeat, and `observe_pack` (a raw-pack observation entry) never
    // existed — only the serialized product can drive the threshold.
    const BANNED: [&str; 5] = [
        "tokio::time::interval",
        "thread::spawn",
        "fn observe_pack",
        "std::thread",
        "tokio::spawn",
    ];
    let source = include_str!("../compaction.rs");
    for needle in BANNED {
        assert_eq!(
            source.matches(needle).count(),
            0,
            "compaction.rs must not contain {needle}"
        );
    }
}

// ── the keyframe reaches the embedder ───────────────────────────────────

/// RT-05: the mint writes a pending-embedding marker inside its transaction,
/// and that marker must be READABLE.
///
/// Every marker reader funnels through `Store::embeddable_body_from_record`,
/// which judged CLAIM alone before RT-05. A SUMMARY marker was therefore
/// durably invisible: never matchable, never clearable, never turnable into
/// embed work — the keyframe's ratified "vector-indexed, RAPTOR-retrievable"
/// contract could not be honored, and the marker row leaked in `sync_state`
/// with no reader able to retire it.
#[test]
fn the_minted_keyframe_carries_a_readable_pending_embedding_marker() -> Result<()> {
    let (_dir, vault) = open_vault();
    let session = mint_session(&vault, 10);
    let actor = loom_actor(&vault, 0x6C);
    let mut driver = engine_driver(1_000);
    let window = host_window(&vault, 0xB8, 1, 3);

    let plan = compact_once(&vault, &mut driver, session, actor, window)?;
    let summary_id = plan.summary_id;

    vault.with_write_txn(|wtxn| {
        assert!(
            vault
                .store
                .has_current_pending_embedding_in_txn(&*wtxn, &summary_id)?,
            "the minted keyframe's pending-embedding marker reads back as current"
        );
        Ok(())
    })?;
    Ok(())
}
