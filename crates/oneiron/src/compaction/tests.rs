//! DREAM-008 (ONE-1250) compaction handoff admission fixtures.
//!
//! One fixture per validation axis, each asserting the DISTINCT typed
//! [`CompactionPacketError`] that axis raises. The point of the matrix is
//! that no two axes collapse into one refusal — a caller can always tell
//! "this turn is not in that sitting" from "this turn's sitting was never
//! recorded".

use super::*;
use crate::batch::EntityMetadataHeader;

use crate::config::VaultConfig;
use crate::edge::{EdgeActorClass, EdgeKind};
use crate::error::{Error, ErrorKind};
use crate::memory::{WitnessAuthor, WitnessMessage, WitnessTurn};
use crate::registry::{ENTITY_TYPE_CONVERSATION, ENTITY_TYPE_PERSON};
use crate::session_lifecycle::SessionMintOutcome;
use crate::temporal::TimeRange;
use crate::test_util::{entity, open_test_vault_with};

mod driver_regressions;
mod epoch_regressions;

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
        Error::Maintenance(MaintenanceError::CompactionPacketRejected(axis)) => axis,
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
    assert!(matches!(
        rejection(error),
        CompactionPacketError::SnapshotMalformed(_)
    ));

    let mut zero_len = digest_packet(session, vec![turn]);
    zero_len.snapshot = snapshot(0xAB, 0);
    let error =
        admit_compaction_packet(&vault, zero_len, None).expect_err("zero byte length refused");
    assert!(matches!(
        rejection(error),
        CompactionPacketError::SnapshotMalformed(_)
    ));
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
    assert!(matches!(
        rejection(
            admit_compaction_packet(&vault, missing_digest, None)
                .expect_err("absent digest refused")
        ),
        CompactionPacketError::PayloadShapeViolation(_)
    ));

    let mut empty_digest = digest_packet(session, vec![turn]);
    empty_digest.digest_text = Some(String::new());
    assert!(matches!(
        rejection(
            admit_compaction_packet(&vault, empty_digest, None).expect_err("empty digest refused")
        ),
        CompactionPacketError::PayloadShapeViolation(_)
    ));

    let mut both_families = digest_packet(session, vec![turn]);
    both_families.working_set_refs = vec![entity(0x61)];
    assert!(matches!(
        rejection(
            admit_compaction_packet(&vault, both_families, None)
                .expect_err("mixed payload families refused")
        ),
        CompactionPacketError::PayloadShapeViolation(_)
    ));
}

#[test]
fn admit_refuses_a_working_set_payload_whose_shape_is_wrong() {
    let (_dir, vault, session, turn) = admitted_fixture(0x4E, 0x4F, 0x50);

    let mut empty_refs = working_set_packet(session, vec![turn]);
    empty_refs.working_set_refs = Vec::new();
    assert!(matches!(
        rejection(
            admit_compaction_packet(&vault, empty_refs, None)
                .expect_err("empty working set refused")
        ),
        CompactionPacketError::PayloadShapeViolation(_)
    ));

    let mut both_families = working_set_packet(session, vec![turn]);
    both_families.digest_text = Some("prose that does not belong here".to_owned());
    assert!(matches!(
        rejection(
            admit_compaction_packet(&vault, both_families, None)
                .expect_err("mixed payload families refused")
        ),
        CompactionPacketError::PayloadShapeViolation(_)
    ));
}

// ── the membership carrier itself ───────────────────────────────────────

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
        vault
            .edges_in(&turn)
            .expect("turn messages")
            .into_iter()
            .filter(|edge| edge.kind == EdgeKind::PartOf)
            .count(),
        2,
        "the append adds a distinct message to the existing turn"
    );
    assert_eq!(
        membership_of(&vault, &turn),
        Some(session),
        "a turn never carries two sittings"
    );
}

// ═══════════════════════════════════════════════════════════════════════
// RT-05 (ONE-1687) — the in-engine compaction driver
// ═══════════════════════════════════════════════════════════════════════

use std::sync::Arc;
use std::time::Duration;

use crate::agent_def::{CompactionOwnership, MemoryProfile};
use crate::error::MaintenanceError;
use crate::llm::ModelTierRef;
use crate::off_record::OffRecordBackendClass;
use crate::registry::{ENTITY_TYPE_SUMMARY, ENTITY_TYPE_TURN};
use crate::write_envelope::WriteActor;

const CHEAP_BACKEND: &str = "test.cheap.slm";

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

fn cheap_registry() -> CompactionBackendRegistry {
    let mut registry = CompactionBackendRegistry::new();
    registry
        .register(Arc::new(CheapBackend))
        .expect("a cheap backend registers");
    registry
}

fn profile(budget: u64, ownership: CompactionOwnership) -> MemoryProfile {
    MemoryProfile::new(budget, ModelTierRef(CHEAP_BACKEND.to_owned()), ownership)
}

fn engine_driver(budget: u64) -> CompactionDriver {
    CompactionDriver::for_profile(
        &profile(budget, CompactionOwnership::Engine),
        &cheap_registry(),
    )
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

/// Drives one crossing → request → integrate cycle with a HOST-supplied
/// product, so a test can hand the mint a product no backend would return.
fn integrate_product(
    vault: &Vault,
    driver: &mut CompactionDriver,
    session: EntityId,
    actor: WriteActor,
    window: Vec<CompactionWindowMessage>,
    summary_text: &str,
) -> Result<SwapPlan> {
    let directive = driver.evaluate_now(vault, u64::MAX)?;
    assert!(matches!(directive, CompactionDirective::Begin { .. }));
    let request = driver.request_for(vault, &session, window)?;
    driver.integrate(
        vault,
        &session,
        actor,
        &request,
        CompactionProduct {
            summary_text: summary_text.to_owned(),
            latency: Duration::from_millis(500),
        },
        &[],
    )
}

fn stored_summary_body(vault: &Vault, id: &EntityId) -> EpochSummaryBody {
    let raw = vault
        .get(id)
        .expect("read summary")
        .expect("summary exists");
    decode_epoch_summary_body(&raw).expect("stored body decodes as an epoch summary")
}

/// Every SUMMARY row in the vault, counted off the entity table's own type
/// byte rather than off anything the driver returned.
fn summary_row_count(vault: &Vault) -> usize {
    let rtxn = vault.store.env.read_txn().expect("read txn");
    let mut rows = 0_usize;
    for row in vault.store.entities.iter(&rtxn).expect("entity iter") {
        let (_, raw) = row.expect("entity row");
        let header = EntityMetadataHeader::parse(&raw).expect("entity header parses");
        if header.entity_type == ENTITY_TYPE_SUMMARY {
            rows += 1;
        }
    }
    drop(rtxn);
    rows
}

/// Pending-embedding markers, read through the same `pe:` prefix the
/// embedder's own sweep walks.
fn pending_embedding_marker_count(vault: &Vault) -> usize {
    let rtxn = vault.store.env.read_txn().expect("read txn");
    let mut markers = 0_usize;
    for row in vault
        .store
        .sync_state
        .prefix_iter(&rtxn, "pe:")
        .expect("marker prefix iter")
    {
        row.expect("marker row");
        markers += 1;
    }
    drop(rtxn);
    markers
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

// ── the mint refuses an empty product ───────────────────────────────────

/// An empty product is a FAILED compaction wearing a success's clothes.
/// Minting it would swap a real message-log prefix out for a keyframe holding
/// none of it, and the row is byte-stable with no update path — so the loss
/// would be permanent. The refusal lands before the write transaction opens.
#[test]
fn an_empty_product_mints_nothing_and_leaves_the_compaction_in_flight() -> Result<()> {
    let (_dir, vault) = open_vault();
    let pending_before = pending_embedding_marker_count(&vault);
    let session = mint_session(&vault, 10);
    let actor = loom_actor(&vault, 0x6D);
    let mut driver = engine_driver(1_000);
    let window = host_window(&vault, 0x43, 1, 3);
    let latency_before = driver.margin().measured_latency_ms();

    let refused = integrate_product(&vault, &mut driver, session, actor, window, "")
        .expect_err("an empty product is not a compaction result");
    invariant(refused);

    assert_eq!(
        summary_row_count(&vault),
        0,
        "a refused mint writes no SUMMARY row"
    );
    assert_eq!(
        pending_embedding_marker_count(&vault),
        pending_before,
        "and no pending-embedding marker leaks for a row that never existed"
    );

    // `integrate` returned before any state mutation: the compaction is still
    // in flight, and the margin law never swallowed the failed run's latency.
    assert!(
        driver.is_compacting(),
        "the refusal precedes the state transition, so the driver stays Compacting"
    );
    assert_eq!(driver.margin().measured_latency_ms(), latency_before);

    // The host takes the documented backend-failure exit, and the next
    // threshold crossing re-arms Begin — nothing was minted to block it.
    driver.abandon();
    assert!(!driver.is_compacting(), "abandon returns to Idle");
    assert!(matches!(
        driver.evaluate_now(&vault, 900)?,
        CompactionDirective::Begin { .. }
    ));
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
    let body = sample_body();
    let entries = [
        ("v", rmpv::Value::from(body.v)),
        ("session", rmpv::Value::from(body.session.as_str())),
        ("epoch", rmpv::Value::from(body.epoch)),
        ("turn_start", rmpv::Value::from(body.turn_start)),
        ("turn_end", rmpv::Value::from(body.turn_end)),
        ("level", rmpv::Value::from(body.level)),
        ("text", rmpv::Value::from(body.text.as_str())),
        ("actor", rmpv::Value::from(body.actor.as_str())),
    ]
    .into_iter()
    .map(|(key, value)| (rmpv::Value::from(key), value))
    .collect();
    let mut expected = Vec::new();
    rmpv::encode::write_value(&mut expected, &rmpv::Value::Map(entries))
        .expect("encode the literal canonical key sequence");

    let encoded = encode_epoch_summary_body(&body).expect("encode sample body");
    assert_eq!(encoded, expected);
}

#[test]
fn epoch_summary_strict_decode_rejection_matrix() -> Result<()> {
    let base = encode_epoch_summary_body(&sample_body())?;

    let invalid = |bytes: &[u8]| {
        let error = decode_epoch_summary_body(bytes).expect_err("strict decode refuses");
        assert_eq!(error.kind(), ErrorKind::InvariantViolation);
    };

    // Trailing bytes after the map.
    let mut trailing = base;
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

/// Hand-encodes a body WITHOUT the encoder's validation, so a test can hand
/// the strict decoder exactly the bytes the encoder refused to produce.
fn unvalidated_encode(body: &EpochSummaryBody) -> Vec<u8> {
    let entries = vec![
        (rmpv::Value::from("v"), rmpv::Value::from(body.v)),
        (
            rmpv::Value::from("session"),
            rmpv::Value::from(body.session.as_str()),
        ),
        (rmpv::Value::from("epoch"), rmpv::Value::from(body.epoch)),
        (
            rmpv::Value::from("turn_start"),
            rmpv::Value::from(body.turn_start),
        ),
        (
            rmpv::Value::from("turn_end"),
            rmpv::Value::from(body.turn_end),
        ),
        (rmpv::Value::from("level"), rmpv::Value::from(body.level)),
        (
            rmpv::Value::from("text"),
            rmpv::Value::from(body.text.as_str()),
        ),
        (
            rmpv::Value::from("actor"),
            rmpv::Value::from(body.actor.as_str()),
        ),
    ];
    let mut out = Vec::new();
    rmpv::encode::write_value(&mut out, &rmpv::Value::Map(entries)).expect("encode map");
    out
}

/// The encoder is the decoder's MIRROR: every axis the strict decoder refuses
/// is refused at encode time too, as an invariant violation. A body the codec
/// cannot read back is a body it must never write — otherwise a keyframe
/// could reach storage that its own consumers refuse at render time.
#[test]
fn epoch_summary_encode_refuses_every_axis_the_decoder_refuses() -> Result<()> {
    let axes: [fn(&mut EpochSummaryBody); 5] = [
        |body| {
            body.v = EPOCH_SUMMARY_BODY_VERSION + 1;
        },
        |body| {
            body.turn_end = body.turn_start - 1;
        },
        |body| {
            body.session = "not-a-hex-ref".to_owned();
        },
        |body| {
            body.actor = "zz".repeat(16);
        },
        |body| {
            body.text = String::new();
        },
    ];

    for mutate in axes {
        let mut body = sample_body();
        mutate(&mut body);

        let refused_encode =
            encode_epoch_summary_body(&body).expect_err("the encoder refuses the axis");
        invariant(refused_encode);

        let refused_decode = decode_epoch_summary_body(&unvalidated_encode(&body))
            .expect_err("the decoder refuses the very same bytes");
        invariant(refused_decode);
    }

    // The well-formed sample still encodes, decodes, and round-trips
    // byte-identically, preserving every persisted field.
    let bytes = encode_epoch_summary_body(&sample_body())?;
    let decoded = decode_epoch_summary_body(&bytes)?;
    assert_eq!(unvalidated_encode(&decoded), bytes);
    assert_eq!(unvalidated_encode(&sample_body()), bytes);
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
