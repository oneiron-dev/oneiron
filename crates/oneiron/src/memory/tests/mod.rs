//! BRIDGE-01 acceptance tests, engine side. TS-layer ACs (bun build/test,
//! index.d.ts shape) are owner-deferred with the eiri repo this wave.
//!
//! The harness deliberately KEEPS the default policy manifest seeded by
//! `Vault::open` (unlike the legacy `test_util` opener) so the write gate is
//! live — production reality for the bridge.

mod authority_revocation;
mod commit_claims;
mod delete_tombstone;
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
pub(super) fn assert_witness_left_nothing(vault: &crate::Vault, refused_text: &str) {
    for (entity_type, label) in [
        (ENTITY_TYPE_MESSAGE, "MESSAGE"),
        (ENTITY_TYPE_TURN, "TURN"),
        (ENTITY_TYPE_CONVERSATION, "CONVERSATION"),
    ] {
        assert!(
            vault
                .entities_by_type(entity_type)
                .expect("type scan")
                .is_empty(),
            "a refused witness left a {label} row behind"
        );
    }
    let rtxn = vault.store.env.read_txn().expect("read txn");
    assert_eq!(
        vault.store.edges_out.len(&rtxn).expect("edge count"),
        0,
        "a refused witness left an edge behind"
    );
    drop(rtxn);
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
    let manifest = crate::gate::default_policy_manifest();
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
    let mut manifest = crate::gate::default_policy_manifest();
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
