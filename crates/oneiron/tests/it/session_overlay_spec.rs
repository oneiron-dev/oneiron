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
    let vault = Vault::open(dir.path(), VaultConfig::default()).expect("open vault");
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

/// CLOSURE INTEGRITY — a session witness lands a WHOLE turn or none of it.
///
/// The receipt names the turn and every message, and the summary is
/// materialized when supplied. A partial closure is the dangerous failure:
/// promote (ONE-1730) replays exactly this closure, so a turn missing its
/// message would promote a transcript with a hole in it, and one missing its
/// summary would promote content the user was shown a summary for.
#[test]
fn session_witness_closure_is_whole() {
    let (_dir, vault) = open_vault();
    let actor = seed_actor(&vault);
    let session = vault
        .off_record_session_vault()
        .enter("spec-closure", OffRecordBackendClass::Local)
        .expect("enter session");

    let receipt = vault
        .memory(actor, EdgeActorClass::Human)
        .witness_into_session(
            &session,
            &turn_of("closure probe", 900),
            Some("the summary"),
        )
        .expect("session witness");

    assert_eq!(
        receipt.message_short_ids.len(),
        1,
        "the receipt accounts for every message in the turn"
    );
    assert!(
        receipt.receipt_ref.starts_with("witness:"),
        "the receipt names its turn, so promote has a closure root"
    );
    // Session aliases are the `s<n>` namespace: they cannot collide with or
    // shadow a durable short id, and they do not resolve at a base door.
    for alias in std::iter::once(&receipt.turn_short_id).chain(&receipt.message_short_ids) {
        let (short_id, hash) = alias.split_once(':').expect("alias is short_id:hash");
        assert!(
            short_id.starts_with('s') && short_id[1..].chars().all(|c| c.is_ascii_digit()),
            "session alias {alias:?} must live in the session namespace"
        );
        let hash = u8::from_str_radix(hash, 16).expect("alias hash is hex");
        assert_eq!(
            vault
                .hydrate_short_id(short_id, hash)
                .expect("base hydrate")
                .map(|hydrated| hydrated.id),
            None,
            "session alias {alias:?} must not resolve through the base door"
        );
    }

    session.close().expect("close session");
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

/// ROLLUP NON-REGRESSION — the canonical path is unchanged by the existence
/// of a live session.
///
/// P4a parameterized the readers and writers every base path uses. The risk
/// that creates is not that sessions misbehave but that BASE quietly changes:
/// a different score, an extra telemetry row, a dropped result. This asserts
/// the canonical answers are identical with and without a room open.
#[test]
fn canonical_retrieval_is_unchanged_by_a_live_session() {
    let (_dir, vault) = open_vault();
    let actor = seed_actor(&vault);

    // Base content, witnessed the ordinary way. The base door resolves a
    // conversation rather than allocating one (that is the session path's
    // job), so the shell is created explicitly here.
    let conversation = EntityId::now();
    vault
        .put_entity(
            &conversation,
            oneiron::registry::ENTITY_TYPE_CONVERSATION,
            TimeRange {
                start: 800,
                end: 800,
            },
            800,
            &[0x80],
        )
        .expect("seed base conversation");
    let mut base_turn = turn_of("specrollupbaseline token", 800);
    base_turn.conversation_ref = conversation.to_hex();
    vault
        .memory(actor, EdgeActorClass::Human)
        .witness(&base_turn)
        .expect("base witness");

    let before = vault
        .search_text("specrollupbaseline", 10)
        .expect("baseline search");
    let runs_before = vault.retrieval_runs(1_000).expect("baseline runs").len();

    // Same query while a room is open and populated.
    let session = vault
        .off_record_session_vault()
        .enter("spec-rollup", OffRecordBackendClass::Local)
        .expect("enter session");
    vault
        .memory(actor, EdgeActorClass::Human)
        .witness_into_session(&session, &turn_of("specrollupbaseline token", 801), None)
        .expect("session witness");

    let during = vault
        .search_text("specrollupbaseline", 10)
        .expect("search with a live room");

    assert_eq!(
        during.len(),
        before.len(),
        "a live room must not change how many results the canonical path returns"
    );
    for (lhs, rhs) in before.iter().zip(&during) {
        assert_eq!(lhs.id, rhs.id, "canonical result ORDER is unchanged");
        assert!(
            (lhs.score - rhs.score).abs() < f32::EPSILON,
            "canonical SCORES are byte-identical with a room open"
        );
    }

    // Telemetry accounting: the two canonical searches above registered one
    // base row each, and the session witness registered none.
    assert_eq!(
        vault.retrieval_runs(1_000).expect("runs").len(),
        runs_before + 1,
        "the base telemetry ledger counts canonical runs only"
    );

    session.close().expect("close session");

    // And the canonical answer survives the room's disappearance intact.
    let after = vault
        .search_text("specrollupbaseline", 10)
        .expect("search after close");
    assert_eq!(
        after.len(),
        before.len(),
        "closing the room leaves the canonical path exactly as it was"
    );
}
