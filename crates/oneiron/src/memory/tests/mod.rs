//! BRIDGE-01 acceptance tests, engine side. TS-layer ACs (bun build/test,
//! index.d.ts shape) are owner-deferred with the eiri repo this wave.
//!
//! The harness deliberately KEEPS the default policy manifest seeded by
//! `Vault::open` (unlike the legacy `test_util` opener) so the write gate is
//! live — production reality for the bridge.

mod authority_revocation;
mod commit_claims;
mod delete_tombstone;
mod self_grant;
mod session_witness;
mod support;
mod takes_notes;
mod witness_policy;
mod witness_turns;

use super::reads::*;
use super::structural::*;
use super::support::*;
use super::witness::*;
use super::*;
use crate::batch::{ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader};
use crate::claim::{ClaimApprovalStatus, ClaimLifecycleStatus};
use crate::config::VaultConfig;
// The sole consumer (`a_soft_erase_that_erased_nothing_writes_no_pending_tombstone`)
// carries the same gate, so the import matches it exactly.
#[cfg(not(feature = "sync"))]
use crate::deletion::DeleteReason;
use crate::dreamer_runner::DreamerConsolidationScope;
use crate::edge::{EdgeActorClass, EdgeKind};
use crate::entity_id::EntityId;
use crate::error::{Error, ErrorKind};
use crate::note::{NoteKind, TakeTarget};
use crate::registry::{
    ENTITY_TYPE_ASSET, ENTITY_TYPE_CLAIM, ENTITY_TYPE_CONVERSATION, ENTITY_TYPE_MACHINE,
    ENTITY_TYPE_MESSAGE, ENTITY_TYPE_NOTE, ENTITY_TYPE_PERSON, ENTITY_TYPE_TASK, ENTITY_TYPE_TURN,
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

/// Puts a MACHINE entity usable as a SYSTEM-class facade actor.
///
/// ONE-1686: `system`-authored MESSAGE rows carry no `AuthoredBy` edge, so the
/// witness ceiling door admits them only from an actor whose identity is named
/// by an explicit actor-bound `auto` policy row. A stored MACHINE type alone is
/// not authority. Tooling interleave is therefore witnessed through a machine
/// actor with a deliberate policy grant, not through an implicit class bypass.
pub(super) fn put_machine(vault: &crate::Vault, seed: u8) -> EntityId {
    let id = EntityId::from_bytes([seed; 16]).expect("machine id");
    vault
        .put_entity(&id, ENTITY_TYPE_MACHINE, test_time(1), 1, b"facade machine")
        .expect("put machine");
    id
}

/// A SYSTEM-class facade bound to a freshly provisioned MACHINE actor.
pub(super) fn system_facade_for(vault: &crate::Vault, actor: EntityId) -> Memory<'_> {
    vault.memory(actor, EdgeActorClass::System)
}

/// A SYSTEM-class facade carrying the explicit actor-bound auto ceiling needed
/// to author engine-voice rows. Tests that exercise a permitted system path use
/// this helper; the plain [`system_facade_for`] helper remains available for
/// fail-closed no-row regressions.
pub(super) fn authorized_system_facade_for(vault: &crate::Vault, actor: EntityId) -> Memory<'_> {
    append_actor_ceiling_rows(
        vault,
        vec![("system".to_owned(), actor.to_hex(), "auto".to_owned())],
    );
    system_facade_for(vault, actor)
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
        relationship_ref: None,
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

// ── witness (AC-3, B2 create-or-get) ────────────────────────────────────

// ── ONE-1767 · TURN speaker: single-speaker invariant + append re-dirty ──

/// COUNT of meso PARTITION attempts on the queue (any state). The close also
/// registers its distill job and the substitution-mine pass on this queue,
/// so the attempt KIND alone does not name a consolidation round; the
/// payload's `attempt_type` does.
pub(super) fn meso_partition_attempt_count(vault: &crate::Vault) -> usize {
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
pub(super) fn production_close_wake(vault: &crate::Vault) -> crate::SessionEndWake {
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

pub(super) fn mint_open_session(vault: &crate::Vault, at: u64) -> EntityId {
    match vault.mint_session(at).expect("mint session") {
        crate::session_lifecycle::SessionMintOutcome::Minted(id) => id,
        other => panic!("expected a fresh mint, got {other:?}"),
    }
}

// ── ONE-1686 (RT-04) · the witness MESSAGE approval-ceiling gate ────────────

/// The store as the ceiling door must leave it after a refusal: no MESSAGE,
/// TURN or CONVERSATION row, no edge out of any message id, and no BM25
/// posting for the refused text.
/// Witness assertions exclude only the known house room, not arbitrary channel rows.
pub(super) fn witness_conversations(vault: &crate::Vault) -> crate::Result<Vec<EntityId>> {
    let root = vault
        .project(vault.root_project()?)?
        .ok_or(crate::Error::EntityNotFound)?;
    let house = EntityId::from_hex(&root.home_room)?;
    Ok(vault
        .entities_by_type(ENTITY_TYPE_CONVERSATION)?
        .into_iter()
        .filter(|id| *id != house)
        .collect())
}

pub(super) fn witness_edge_count(vault: &crate::Vault) -> u64 {
    let rtxn = vault.store.env.read_txn().expect("read txn");
    vault.store.edges_out.len(&rtxn).expect("edge count")
}

pub(super) fn assert_witness_left_nothing(
    vault: &crate::Vault,
    refused_text: &str,
    expected_edge_count: u64,
) {
    for (entity_type, label) in [
        (ENTITY_TYPE_MESSAGE, "MESSAGE"),
        (ENTITY_TYPE_TURN, "TURN"),
        (ENTITY_TYPE_CONVERSATION, "CONVERSATION"),
    ] {
        let rows = if entity_type == ENTITY_TYPE_CONVERSATION {
            witness_conversations(vault)
        } else {
            vault.entities_by_type(entity_type)
        }
        .expect("type scan");
        assert!(
            rows.is_empty(),
            "a refused witness left a {label} row behind"
        );
    }
    assert_eq!(
        witness_edge_count(vault),
        expected_edge_count,
        "a refused witness left an edge behind"
    );
    let persons = vault
        .entities_by_type(crate::registry::ENTITY_TYPE_PERSON)
        .expect("persons");
    for person in &persons {
        assert!(
            vault
                .edge_exists(
                    person,
                    crate::EdgeKind::HasFacet,
                    &crate::claim::substrate_facet_id(*person).unwrap()
                )
                .expect("substrate edge")
        );
    }
    assert!(
        vault
            .search_text(refused_text, 10)
            .expect("text search")
            .is_empty(),
        "a refused witness left a text posting behind"
    );
}

/// Installs the default manifest without adding an actor-specific grant.
pub(super) fn install_default_policy_manifest(vault: &crate::Vault) {
    let manifest = crate::gate::default_policy_manifest().unwrap();
    crate::test_util::put_policy_manifest_bytes(
        vault,
        crate::gate::default_policy_manifest_id().expect("default manifest id"),
        &manifest,
    )
    .expect("install default manifest");
}

/// Appends `rows` to the default manifest's `actor_ceilings` and reinstalls it.
/// The owner's lever over the witness ceiling is an ordinary manifest row, not
/// a second policy surface.
pub(super) fn append_actor_ceiling_rows(vault: &crate::Vault, rows: Vec<(String, String, String)>) {
    let mut manifest = crate::gate::default_policy_manifest().unwrap();
    let mut cursor = std::io::Cursor::new(manifest.as_slice());
    let Value::Map(mut entries) = rmpv::decode::read_value(&mut cursor).expect("decode manifest")
    else {
        panic!("default policy manifest is a map");
    };
    for (key, value) in &mut entries {
        if key.as_str() == Some("actor_ceilings") {
            let Value::Array(existing) = value else {
                panic!("actor ceilings are an array");
            };
            for (actor_class, actor_ref, ceiling) in &rows {
                existing.push(Value::Map(vec![
                    (
                        Value::from("actor_class"),
                        Value::from(actor_class.as_str()),
                    ),
                    (Value::from("actor_ref"), Value::from(actor_ref.as_str())),
                    (Value::from("ceiling"), Value::from(ceiling.as_str())),
                ]));
            }
        }
    }
    manifest.clear();
    rmpv::encode::write_value(&mut manifest, &Value::Map(entries)).expect("encode manifest");
    crate::test_util::put_policy_manifest_bytes(
        vault,
        crate::gate::default_policy_manifest_id().expect("default manifest id"),
        &manifest,
    )
    .expect("install actor ceilings");
}

// ── commit / approval policy (AC-4) ─────────────────────────────────────

// ── supersession (AC-2 engine side, B1c) ────────────────────────────────

// ── per-element gating (AC-5) ───────────────────────────────────────────

// ── safe delete (AC-6) ──────────────────────────────────────────────────

// ── error surface (AC-7) ────────────────────────────────────────────────

// ── B2 migrator write-verb group ────────────────────────────────────────

// ── reads: list/history/retract/hydrate ─────────────────────────────────

// ── RT-03 (ONE-1685): turn-witness bumps the open session ───────────────

// ── S-AUTH3: owner-verb authority-log teeth (ONE-1633 / ESB-C) ───────────

/// A single-key authority root. One roster key means no peer cosign is
/// required, so a rooted facade fixture is two entries total.
pub(super) fn authority_root(
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
            recovery: crate::authority::GenesisRecoveryStep::Saved([1; 32]),
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

pub(super) fn sign_authority(
    mut entry: crate::authority::AuthorityLogEntry,
    key: &ed25519_dalek::SigningKey,
) -> crate::authority::AuthorityLogEntry {
    use ed25519_dalek::Signer;
    let transcript = crate::authority::authority_transcript(&entry).expect("transcript");
    entry.signer.signature = key.sign(&transcript).to_bytes().to_vec();
    entry
}

/// Roots `vault` and binds `actor` at `class` in ONE atomic ceremony.
pub(super) fn root_vault_binding(vault: &crate::Vault, seed: u8, actor: EntityId, class: &str) {
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

/// Roots `vault`, binds `actor` as `human`, and returns the SIGNED
/// `RevokeActor` that takes the binding away again — unpersisted, so a caller
/// chooses the exact instant it lands.
pub(super) fn root_binding_with_pending_revocation(
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

// ── ONE-1728 K7 · witness-door ownership backstop (ARCH-0052 D2(a)) ──────

// ── ONE-1728 · witness through the session vault (ARCH-0052 §7) ──────────

/// Enters a room and returns the handle plus a facade bound to a fresh actor.
pub(super) fn session_witness_fixture<'v>(
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

// ── ONE-1767 second cycle · the overlay witness runs the TURN mint contract ──

// ── ONE-1377 · author_take (ARCH-0032 NOTE · OF-330) ────────────────────

pub(super) fn opinion_claim(vault: &crate::Vault, actor: EntityId, subject: EntityId) -> EntityId {
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

pub(super) fn note_body_of(vault: &crate::Vault, note_id: &EntityId) -> crate::note::NoteBody {
    let raw = vault.get_raw(note_id).expect("raw").expect("note exists");
    crate::note::decode_note_body(&raw[crate::batch::ENTITY_METADATA_HEADER_LEN..])
        .expect("note body decodes under the pinned ABI")
}

// ── ONE-1936: write-verb validity guard at the facade doors ──────────

// ── ONE-1414 · `same_as` wire mapping + generic-write refusal ─────────────

// ── T49 · every Memory read verb reads on the bound actor's lane ─────────

/// The shipped default manifest with one `core:read` grant whose selectors
/// name `world`: `reader` may read claims in that world and nothing else.
pub(super) fn grant_world_reads(vault: &crate::Vault, reader: &str, world: EntityId) {
    let grant = Value::Map(vec![
        (Value::from("actor_ref"), Value::from(reader)),
        (Value::from("effector"), Value::from("core:read")),
        (
            Value::from("scope"),
            crate::federation::scope_codec::encode_scope_value(
                &crate::federation::scope_codec::read_preset(),
            )
            .expect("read preset encodes"),
        ),
        (
            Value::from("selectors"),
            Value::Map(vec![(
                Value::from("world_ref"),
                Value::from(world.to_hex()),
            )]),
        ),
        (Value::from("receipt_required"), Value::Boolean(false)),
    ]);
    let Value::Map(mut entries) =
        rmpv::decode::read_value(&mut crate::gate::default_policy_manifest().unwrap().as_slice())
            .expect("default manifest")
    else {
        panic!("default manifest is a map");
    };
    entries.retain(|(key, _)| key.as_str() != Some("scoped_grants"));
    entries.push((Value::from("scoped_grants"), Value::Array(vec![grant])));
    let mut bytes = Vec::new();
    rmpv::encode::write_value(&mut bytes, &Value::Map(entries)).expect("manifest encodes");
    crate::test_util::put_policy_manifest_bytes(
        vault,
        crate::gate::default_policy_manifest_id().expect("manifest id"),
        &bytes,
    )
    .expect("manifest stores");
}

/// An approved, user-stated claim stored directly, optionally in `world`.
fn stored_claim(
    vault: &crate::Vault,
    subject: EntityId,
    world: Option<EntityId>,
    text: &str,
) -> EntityId {
    let id = EntityId::now();
    let mut body = crate::claim::ClaimBody::new(
        "profile.note",
        crate::claim::ClaimSubject::Entity(subject),
        Value::from(text),
        1.0,
        ClaimApprovalStatus::Approved,
        ClaimLifecycleStatus::Active,
    )
    .unwrap();
    body.world = world;
    body.source = Some(crate::claim::ClaimSource::UserStated);
    vault
        .put_claim(&id, &body, test_time(1), 1)
        .expect("put claim");
    id
}

/// ONE-1943's fail-open pair, closed: the Memory facade and the scoped lane
/// give one answer about a claim outside the actor's grant.
#[test]
fn claim_list_and_scoped_get_agree_on_a_claim_outside_the_actors_grant() {
    let (_dir, vault) = open_vault();
    let agent = put_person(&vault, 0x5A);
    let subject = put_person(&vault, 0x5B);
    let world = EntityId::from_bytes([0x5C; 16]).expect("world id");
    let outside = stored_claim(&vault, subject, None, "base reality");
    let inside = stored_claim(&vault, subject, Some(world), "in the world");
    grant_world_reads(&vault, &agent.to_hex(), world);
    let memory = vault.memory(agent, EdgeActorClass::Agent);

    let listed = memory
        .claim_list(&ClaimListFilter {
            subject_ref: Some(subject.to_hex()),
            predicate: None,
            lifecycle: None,
            limit: 10,
        })
        .expect("claim list");
    assert_eq!(
        listed
            .value
            .iter()
            .map(|claim| claim.claim_ref.clone())
            .collect::<Vec<_>>(),
        vec![inside.to_hex()]
    );
    assert_eq!(listed.receipt.suppressed_count, 1);
    assert!(
        listed
            .receipt
            .narrowed_axes
            .contains(&"row_authority".to_owned())
    );

    let key = crate::claim::ScopedReadActorKey::with_actor_class(agent.to_hex(), "agent")
        .expect("agent key");
    let scoped = vault
        .scoped_read(key)
        .read(
            &[
                crate::claim::PointRead::id(outside),
                crate::claim::PointRead::id(inside),
            ],
            None,
        )
        .expect("scoped read");
    assert!(scoped.value[0].is_none());
    assert_eq!(scoped.value[1].as_ref().map(|row| row.id), Some(inside));
    assert_eq!(listed.receipt, scoped.receipt);

    let got = memory.get_entity(&outside.to_hex()).expect("get");
    assert!(got.value.is_none());
    assert_eq!(got.receipt, scoped.receipt);
}

/// Every read verb answers with its lane's receipt: the owner's shows the
/// full ceiling and nothing withheld, a grantless agent's names `deny_all`.
#[test]
fn every_memory_read_verb_returns_a_receipt() {
    let (_dir, vault) = open_vault();
    let owner = put_person(&vault, 0xB1);
    let agent = put_person(&vault, 0xB2);
    let subject = put_person(&vault, 0xB3);
    let claim = facade_for(&vault, owner)
        .claim_upsert(&claim_input(
            "profile.name",
            &subject,
            "user_stated",
            serde_json::json!("Ada"),
        ))
        .expect("claim");
    facade_for(&vault, owner)
        .witness(&WitnessTurn {
            conversation_ref: EntityId::from_bytes([0xB4; 16])
                .expect("conversation id")
                .to_hex(),
            turn_ref: None,
            messages: vec![witness_message(
                0,
                WitnessAuthor::User,
                "receipted solar panels",
            )],
            occurred_at: 100,
        })
        .expect("witness");
    let refs = vec![claim.claim_short_id.clone()];
    let live = crate::vault::ReadMode::Live;
    let list = ClaimListFilter {
        subject_ref: Some(subject.to_hex()),
        predicate: None,
        lifecycle: None,
        limit: 10,
    };
    let neighbors = NeighborOpts {
        limit: 10,
        ..NeighborOpts::default()
    };
    let calendar = crate::CalendarReadRequest {
        event_ref: subject.to_hex(),
    };
    let search = crate::CalendarSearchRequest {
        calendars: Vec::new(),
        range: None,
        text: None,
        limit: 10,
    };
    let window = test_time(0);

    let memory = facade_for(&vault, owner);
    let receipts = [
        memory.get_entity(&claim.claim_short_id).map(|read| {
            assert!(read.value.is_some());
            read.receipt
        }),
        memory
            .get_entity_with_mode(&claim.claim_short_id, live)
            .map(|read| {
                assert!(read.value.is_some());
                read.receipt
            }),
        memory.hydrate(&refs).map(|read| {
            assert_eq!(read.value.len(), 1);
            read.receipt
        }),
        memory.hydrate_with_mode(&refs, live).map(|read| {
            assert_eq!(read.value.len(), 1);
            read.receipt
        }),
        memory.claim_list(&list).map(|read| {
            assert_eq!(read.value.len(), 1);
            read.receipt
        }),
        memory.claim_history(&claim.claim_short_id).map(|read| {
            assert_eq!(read.value.len(), 1);
            read.receipt
        }),
        memory.query_bm25("solar", 10).map(|read| {
            assert_eq!(read.value.len(), 1);
            read.receipt
        }),
        memory.neighbors(&subject.to_hex(), &neighbors).map(|read| {
            assert!(!read.value.is_empty());
            read.receipt
        }),
        memory.calendar_read(&calendar).map(|read| read.receipt),
        memory.calendar_search(&search).map(|read| read.receipt),
        memory
            .calendar_freebusy(&[], window)
            .map(|read| read.receipt),
    ];
    for receipt in receipts {
        let receipt = receipt.expect("owner read");
        assert!(!receipt.actor_ceiling.deny_all);
        assert_eq!(receipt.actor_ceiling.max_sensitivity_band, 3);
        assert_eq!(receipt.suppressed_count, 0);
        assert!(receipt.narrowed_axes.is_empty(), "{receipt:?}");
    }

    let memory = vault.memory(agent, EdgeActorClass::Agent);
    let receipts = [
        memory.get_entity(&claim.claim_short_id).map(|read| {
            assert!(read.value.is_none());
            read.receipt
        }),
        memory
            .get_entity_with_mode(&claim.claim_short_id, live)
            .map(|read| {
                assert!(read.value.is_none());
                read.receipt
            }),
        memory.claim_list(&list).map(|read| {
            assert!(read.value.is_empty());
            read.receipt
        }),
        memory.claim_history(&claim.claim_short_id).map(|read| {
            assert!(read.value.is_empty());
            read.receipt
        }),
        memory.query_bm25("solar", 10).map(|read| {
            assert!(read.value.is_empty());
            read.receipt
        }),
        memory.neighbors(&subject.to_hex(), &neighbors).map(|read| {
            assert!(read.value.is_empty());
            read.receipt
        }),
        memory.calendar_read(&calendar).map(|read| read.receipt),
        memory.calendar_search(&search).map(|read| read.receipt),
        memory
            .calendar_freebusy(&[], window)
            .map(|read| read.receipt),
        // A withheld hydrate is NOT_FOUND, and the refusal carries the receipt.
        Ok(*memory
            .hydrate(&refs)
            .expect_err("withheld hydrate")
            .read_receipt
            .expect("hydrate refusal receipt")),
        Ok(*memory
            .hydrate_with_mode(&refs, live)
            .expect_err("withheld hydrate")
            .read_receipt
            .expect("hydrate refusal receipt")),
    ];
    for receipt in receipts {
        let receipt = receipt.expect("agent read");
        assert!(receipt.applied.deny_all);
        assert!(receipt.narrowed_axes.contains(&"deny_all".to_owned()));
    }
}

/// A soft-deleted claim leaves a header-only shell that no read verb returns.
/// The verbs that still reach the shell (by id, by short ref, by subject
/// index, by timeline, by edge) name it on their receipt as a withheld row.
/// BM25 de-indexes on soft erase (a deleted MESSAGE shows it: found before,
/// gone after, nothing withheld) and the calendar never projects a
/// non-calendar claim, so those verbs never see a shell and withhold nothing.
#[test]
fn a_deleted_shell_is_absent_from_every_memory_read() {
    let (_dir, vault) = open_vault();
    let owner = put_person(&vault, 0xC1);
    let subject = put_person(&vault, 0xC2);
    let memory = facade_for(&vault, owner);
    let claim = memory
        .claim_upsert(&claim_input(
            "profile.name",
            &subject,
            "user_stated",
            serde_json::json!("Shelly"),
        ))
        .expect("claim");
    let id = resolve_entity_ref(&vault, &claim.claim_short_id).expect("claim id");
    let witnessed = memory
        .witness(&WitnessTurn {
            conversation_ref: EntityId::from_bytes([0xC3; 16])
                .expect("conversation id")
                .to_hex(),
            turn_ref: None,
            messages: vec![witness_message(0, WitnessAuthor::User, "Shelly waves")],
            occurred_at: 100,
        })
        .expect("witness");
    let message = resolve_entity_ref(&vault, &witnessed.message_short_ids[0]).expect("message id");
    assert_eq!(
        memory
            .query_bm25("Shelly", 10)
            .expect("bm25 before")
            .value
            .len(),
        1
    );
    for deleted in [id, message] {
        memory
            .safe_delete(&deleted.to_hex(), SafeDeleteReason::UserDelete)
            .expect("soft delete");
        assert!(vault.is_deleted_shell(&deleted).expect("shell"));
    }
    let live = crate::vault::ReadMode::Live;
    let withheld = |receipt: &crate::claim::ScopedReadReceipt| {
        assert_eq!(receipt.suppressed_count, 1, "{receipt:?}");
        assert!(receipt.narrowed_axes.contains(&"row_authority".to_owned()));
    };

    for reference in [id.to_hex(), claim.claim_short_id.clone(), message.to_hex()] {
        let read = memory.get_entity(&reference).expect("get");
        assert!(read.value.is_none());
        withheld(&read.receipt);
        let read = memory
            .get_entity_with_mode(&reference, live)
            .expect("get at live");
        assert!(read.value.is_none());
        withheld(&read.receipt);
        let refused = memory
            .hydrate(std::slice::from_ref(&reference))
            .expect_err("hydrate");
        assert_eq!(refused.code, MEMORY_CODE_NOT_FOUND);
        withheld(&refused.read_receipt.expect("hydrate receipt"));
        let refused = memory
            .hydrate_with_mode(std::slice::from_ref(&reference), live)
            .expect_err("hydrate at live");
        assert_eq!(refused.code, MEMORY_CODE_NOT_FOUND);
        withheld(&refused.read_receipt.expect("hydrate receipt"));
    }
    let listed = memory
        .claim_list(&ClaimListFilter {
            subject_ref: Some(subject.to_hex()),
            predicate: None,
            lifecycle: None,
            limit: 10,
        })
        .expect("claim list");
    assert!(listed.value.is_empty());
    withheld(&listed.receipt);
    let history = memory.claim_history(&id.to_hex()).expect("history");
    assert!(history.value.is_empty());
    withheld(&history.receipt);
    let neighbors = memory
        .neighbors(
            &subject.to_hex(),
            &NeighborOpts {
                limit: 10,
                ..NeighborOpts::default()
            },
        )
        .expect("neighbors");
    assert!(
        neighbors
            .value
            .iter()
            .all(|hit| short_id_part(&hit.short_id) != short_id_part(&claim.claim_short_id))
    );
    withheld(&neighbors.receipt);

    let lexical = memory.query_bm25("Shelly", 10).expect("bm25");
    assert!(lexical.value.is_empty());
    assert_eq!(lexical.receipt.suppressed_count, 0);
    let calendar = memory
        .calendar_read(&crate::CalendarReadRequest {
            event_ref: id.to_hex(),
        })
        .expect("calendar read");
    assert!(calendar.value.is_none());
    assert_eq!(calendar.receipt.suppressed_count, 0);
}
