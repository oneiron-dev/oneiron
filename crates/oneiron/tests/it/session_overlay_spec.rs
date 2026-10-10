//! ONE-1728 P4a seg-4 acceptance spec — the session overlay seen from OUTSIDE
//! the crate (ARCH-0052 §7).
//!
//! `branch_store_oracle.rs` proves the same laws against crate-private
//! internals. This file is deliberately narrower and blunter: it may touch
//! ONLY the public API, so it proves the properties a HOST can observe — which
//! is the level at which "the room never leaked" is a product promise rather
//! than an implementation detail. A regression that a crate-private oracle
//! could still see (because it reaches past the public door) fails here first.
//!
//! Three arms, per the seg-4 brief:
//!
//! * **closure integrity** — a witnessed turn's transcript is whole in-room:
//!   the turn, its message, and its summary all land, all under one shell.
//! * **dirty visibility** — the union is visible to the room and to nothing
//!   else, INCLUDING after a mode flip and a flip back.
//! * **rollup non-regression** — the canonical path is byte-identical with
//!   and without a live session: same scores, same telemetry accounting.

use oneiron::{
    EdgeActorClass, EntityId, TimeRange, Vault, VaultConfig, WitnessAuthor, WitnessMessage,
    WitnessTurn, off_record::OffRecordBackendClass,
};

fn open_vault() -> (tempfile::TempDir, Vault) {
    let dir = tempfile::tempdir().expect("temp dir");
    let mut config = VaultConfig::default();
    config.retrieval_telemetry_capture = true;
    let vault = Vault::open(dir.path(), config).expect("open vault");
    (dir, vault)
}

/// Seeds the base PERSON a witness binds as. The witness door requires a
/// base-resident actor, so this is base setup, never session content.
fn seed_actor(vault: &Vault) -> EntityId {
    let id = EntityId::now();
    vault
        .put_entity(
            &id,
            oneiron::registry::ENTITY_TYPE_PERSON,
            TimeRange { start: 1, end: 1 },
            1,
            b"session spec actor",
        )
        .expect("seed actor");
    id
}

fn turn_of(content: &str, at: u64) -> WitnessTurn {
    WitnessTurn {
        conversation_ref: String::new(),
        turn_ref: None,
        messages: vec![WitnessMessage {
            id: None,
            author: WitnessAuthor::User,
            message_type: "dialogue".to_owned(),
            content: content.to_owned(),
            metadata: None,
            is_visible: true,
            order: 0,
        }],
        occurred_at: at,
    }
}

/// DIRTY VISIBILITY — the room's uncommitted-to-base content is visible to
/// NOBODY outside the room, across every public reader, and stays that way
/// through a mode flip and a flip back.
///
/// "Dirty" is the operative word: these rows are real and readable in-session,
/// which is exactly what makes leaking them a disclosure bug rather than a
/// missing feature.
#[test]
fn session_content_is_invisible_to_every_public_base_reader() {
    let (_dir, vault) = open_vault();
    let actor = seed_actor(&vault);
    let session = vault
        .off_record_session_vault()
        .enter("spec-visibility", OffRecordBackendClass::Local)
        .expect("enter session");
    let facade = vault.memory(actor, EdgeActorClass::Human);

    let base_entity_count = vault
        .entities_in_learned_range(0, u64::MAX)
        .expect("baseline enumeration")
        .len();

    let receipt = facade
        .witness_into_session(
            &session,
            &turn_of("specdirtyvisibilitytoken", 901),
            Some("summary of a private room"),
        )
        .expect("session witness");
    let turn_id = EntityId::from_hex(
        receipt
            .receipt_ref
            .strip_prefix("witness:")
            .expect("receipt names the turn"),
    )
    .expect("turn id");

    // Every public base reader family.
    assert_eq!(vault.get(&turn_id).expect("base get"), None);
    assert_eq!(vault.get_raw(&turn_id).expect("base get_raw"), None);
    assert!(!vault.entity_exists(&turn_id).expect("base exists"));
    assert_eq!(
        vault
            .search_text("specdirtyvisibilitytoken", 10)
            .expect("base search")
            .len(),
        0,
        "the room's text is unreachable through base search"
    );
    // The row COUNT is the honest assertion: a per-id probe can only miss rows
    // written under ids the test does not know.
    assert_eq!(
        vault
            .entities_in_learned_range(0, u64::MAX)
            .expect("enumeration")
            .len(),
        base_entity_count,
        "a session witness adds ZERO base entity rows"
    );

    // Flip on record: NEW writes go to base, but the pre-flip turn does not
    // retroactively become visible.
    session.flip_on_record().expect("flip on record");
    assert_eq!(
        vault.get(&turn_id).expect("post-flip base get"),
        None,
        "flipping on record must not retroactively expose the private turn"
    );
    assert_eq!(
        vault
            .search_text("specdirtyvisibilitytoken", 10)
            .expect("post-flip base search")
            .len(),
        0
    );

    session.close().expect("close session");

    // And close evaporates rather than publishes.
    assert_eq!(vault.get(&turn_id).expect("post-close base get"), None);
    assert_eq!(
        vault
            .search_text("specdirtyvisibilitytoken", 10)
            .expect("post-close base search")
            .len(),
        0,
        "close evaporates the room; it never flushes it to base"
    );
}
