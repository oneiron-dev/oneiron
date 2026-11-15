//! The off-record session's Put arm runs the base SKILL birth and update gates.
//!
//! A room staged a SKILL record after shape validation only: an Active birth, which
//! base refuses ("new skills are born candidate"), landed in the overlay and the raw
//! reader served it; so did an update the base overwrite gate would refuse. The session
//! arm now runs the same two validators promote's replay runs (local, not
//! hub-imported, no admission proof) before a byte stages.
//!
//! Run with `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron
//! --all-features --test session_raw_skill_validators`.
#![cfg(oneiron_test_support)]

use std::sync::Arc;

use oneiron::claim::{ClaimApprovalStatus, ClaimSource};
use oneiron::edge::EdgeActorClass;
use oneiron::off_record::OffRecordBackendClass;
use oneiron::registry::ENTITY_TYPE_SKILL;
use oneiron::skill::{SkillLifecycle, SkillRecord, encode_skill_record};
use oneiron::{EntityId, RawEntityPut, TimeRange, Vault, VaultConfig};
use rmpv::Value;

const NOW: u64 = 1_700_000_000;

fn occurred() -> TimeRange {
    TimeRange {
        start: NOW,
        end: NOW,
    }
}

/// A vault with its owner, who writes in the tests below.
fn fixture() -> (tempfile::TempDir, Vault, EntityId) {
    let dir = tempfile::tempdir().expect("vault dir");
    let vault = Vault::open(dir.path(), VaultConfig::device()).expect("open vault");
    vault.install_device_keystore(Arc::new(oneiron_keystore::MemoryKeystore::new()));
    vault
        .prepare_install_signing()
        .expect("load this install's signing keys");
    let writer = vault.ensure_embedded_owner_actor().expect("owner");
    (dir, vault, writer)
}

/// A shape-valid human-authored skill at `lifecycle`: it passes the raw door's
/// shape check, so only the birth law or the overwrite gate can refuse it.
fn skill_record(lifecycle: SkillLifecycle) -> SkillRecord {
    SkillRecord::new(
        "fixture.room.skill",
        "a skill staged in an off-record room",
        "1",
        ClaimApprovalStatus::Proposed,
        lifecycle,
        ClaimSource::UserStated,
        0.5,
        false,
        true,
        Vec::new(),
        Value::Map(vec![(Value::from("source"), Value::from("fixture"))]),
    )
}

fn put(
    vault: &Vault,
    writer: EntityId,
    room: &str,
    id: EntityId,
    data: &[u8],
) -> Result<(), oneiron::memory::MemoryError> {
    vault
        .memory(writer, EdgeActorClass::Human)
        .in_off_record_session(room)
        .raw_put_entity(RawEntityPut {
            id,
            entity_type: ENTITY_TYPE_SKILL,
            occurred: occurred(),
            learned_at: NOW,
            data,
        })
}

fn room_read(vault: &Vault, writer: EntityId, room: &str, id: &EntityId) -> Option<Vec<u8>> {
    vault
        .memory(writer, EdgeActorClass::Human)
        .in_off_record_session(room)
        .raw_get_entity(id)
        .expect("room read")
}

/// An Active SKILL birth is refused in the room and stages nothing: the birth
/// law runs before a byte stages, as on base.
#[test]
fn active_skill_create_is_refused_in_room() {
    let (_dir, vault, writer) = fixture();
    let room = vault
        .off_record_session_vault()
        .enter("sess-skill-active", OffRecordBackendClass::Local)
        .expect("enter room");
    let id = EntityId::now();
    let bytes = encode_skill_record(&skill_record(SkillLifecycle::Active)).expect("encode skill");
    let refusal = put(&vault, writer, room.session_ref(), id, &bytes)
        .expect_err("an Active SKILL birth staged in the room");
    assert!(
        refusal.message.contains("candidate"),
        "the birth law refuses it: {refusal:?}"
    );
    assert_eq!(
        room_read(&vault, writer, room.session_ref(), &id),
        None,
        "nothing stages beside the refusal"
    );
    assert!(
        vault.get(&id).expect("base read").is_none(),
        "base holds nothing"
    );
}

/// The same body as a Candidate still stages and reads back in the room.
#[test]
fn candidate_skill_create_stages_in_room() {
    let (_dir, vault, writer) = fixture();
    let room = vault
        .off_record_session_vault()
        .enter("sess-skill-candidate", OffRecordBackendClass::Local)
        .expect("enter room");
    let id = EntityId::now();
    let bytes =
        encode_skill_record(&skill_record(SkillLifecycle::Candidate)).expect("encode skill");
    put(&vault, writer, room.session_ref(), id, &bytes)
        .expect("a Candidate SKILL stages in the room");
    assert_eq!(
        room_read(&vault, writer, room.session_ref(), &id),
        Some(bytes),
        "the room serves the staged Candidate"
    );
    assert!(
        vault.get(&id).expect("base read").is_none(),
        "base holds nothing: close drops it"
    );
}

/// A staged Candidate whose body changes without a version bump is refused by
/// the overwrite gate, and the first body still stands.
#[test]
fn skill_update_without_version_bump_is_refused_in_room() {
    let (_dir, vault, writer) = fixture();
    let room = vault
        .off_record_session_vault()
        .enter("sess-skill-update", OffRecordBackendClass::Local)
        .expect("enter room");
    let id = EntityId::now();
    let first = skill_record(SkillLifecycle::Candidate);
    let first_bytes = encode_skill_record(&first).expect("encode skill");
    put(&vault, writer, room.session_ref(), id, &first_bytes)
        .expect("FIXTURE: the Candidate stages");
    let mut second = first.clone();
    second.desc = "a changed description".to_owned();
    let second_bytes = encode_skill_record(&second).expect("encode skill");
    assert_ne!(first_bytes, second_bytes, "FIXTURE: the two bodies differ");
    let refusal = put(&vault, writer, room.session_ref(), id, &second_bytes)
        .expect_err("a content change without a version bump staged in the room");
    assert!(
        refusal.message.contains("version must change"),
        "the overwrite gate refuses it: {refusal:?}"
    );
    assert_eq!(
        room_read(&vault, writer, room.session_ref(), &id),
        Some(first_bytes),
        "the first body still stands"
    );
}
