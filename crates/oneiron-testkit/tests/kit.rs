//! The hashing embedder, the fake clock and fixture copies keep their
//! promises.

use std::cell::Cell;

use oneiron::registry::ENTITY_TYPE_PERSON;
use oneiron::store::embedding::{
    Embedder, EmbedderLocality, PendingEmbeddingInput, PendingEmbeddingPayload,
};
use oneiron::{EntityId, TimeRange};
use oneiron_testkit::fixture::SeedError;
use oneiron_testkit::{FAKE_EPOCH, FakeClock, FixtureVault, HashingEmbedder, fixture_cache};

fn cosine(a: &[f32], b: &[f32]) -> f32 {
    a.iter().zip(b).map(|(x, y)| x * y).sum()
}

#[test]
fn the_hashing_embedder_gives_the_same_unit_vector_for_the_same_text() {
    let embedder = HashingEmbedder::new(64);
    let first = embedder.embed_text("The owner met Ada in Lisbon");
    assert_eq!(first, embedder.embed_text("the OWNER met ada, in lisbon!"));
    assert_eq!(first.len(), 64);
    assert!((cosine(&first, &first) - 1.0).abs() < 1e-5);
    let near = embedder.embed_text("Ada in Lisbon");
    let far = embedder.embed_text("quarterly invoice totals");
    assert!(cosine(&first, &near) > cosine(&first, &far));
    let empty = embedder.embed_text("  ...  ");
    assert_eq!(empty[0], 1.0);
    assert_eq!(embedder.model(), "oneiron-testkit-hashing-64");
}

#[test]
fn the_hashing_embedder_serves_the_engine_seam_on_device() {
    let embedder = HashingEmbedder::new(16);
    assert_eq!(Embedder::dimensions(&embedder), 16);
    assert_eq!(embedder.locality(), EmbedderLocality::OnDevice);
    let input = PendingEmbeddingInput {
        entity_id: EntityId::from_bytes([0x71; 16]).expect("an id"),
        payload: PendingEmbeddingPayload::TurnText("ada lisbon".into()),
        pending_embedding_token: Vec::new(),
    };
    let vectors = embedder.embed(&[input]).expect("embed");
    assert_eq!(vectors, vec![embedder.embed_text("ada lisbon")]);
}

#[test]
fn a_vault_on_the_fake_clock_records_the_fake_time() {
    let clock = FakeClock::default();
    assert_eq!(clock.now(), FAKE_EPOCH);
    let dir = tempfile::tempdir().expect("temp dir");
    let vault = oneiron::Vault::open(dir.path(), clock.vault_config()).expect("open");
    // An open may commit an authorization lease, which runs the store's
    // time at most AUTHORIZATION_LEASE_SECS (5 s) ahead of its clock.
    let opened = vault.now_recorded_at();
    assert!((FAKE_EPOCH..=FAKE_EPOCH + 5).contains(&opened), "{opened}");
    assert_eq!(clock.advance(90), FAKE_EPOCH + 90);
    assert_eq!(vault.now_recorded_at(), FAKE_EPOCH + 90);
    // Back in time: the vault's floor holds.
    clock.set(FAKE_EPOCH);
    assert!(vault.now_recorded_at() >= FAKE_EPOCH + 90);
}

#[test]
fn each_test_gets_its_own_copy_of_a_fixture_seeded_once() {
    let cache = fixture_cache!();
    let person = EntityId::from_bytes([0x71, 0, 0, 0, 0, 0, 0x71, 0, 0x80, 0, 0, 0, 0, 0, 0, 1])
        .expect("an id");
    let seeded = Cell::new(0);
    let seed = |vault: &oneiron::Vault, clock: &FakeClock| -> Result<(), SeedError> {
        seeded.set(seeded.get() + 1);
        let now = clock.advance(10);
        vault.put_entity(
            &person,
            ENTITY_TYPE_PERSON,
            TimeRange {
                start: now,
                end: now,
            },
            1,
            b"Ada",
        )?;
        Ok(())
    };
    let fixture = FixtureVault::build(&cache, "kit-one-person", seed).expect("build");
    let again = FixtureVault::build(&cache, "kit-one-person", |_, _| {
        panic!("a built fixture is not seeded again")
    })
    .expect("reuse");
    assert_eq!(fixture, again);
    assert!(seeded.get() <= 1, "seeded at most once in this process");
    assert_eq!(fixture.ended_at(), FAKE_EPOCH + 10);

    let first = fixture.copy().expect("copy");
    let second = fixture.copy().expect("copy");
    assert_ne!(first.path(), second.path());
    assert_eq!(first.clock().now(), FAKE_EPOCH + 10);
    let other = EntityId::from_bytes([0x71, 0, 0, 0, 0, 0, 0x71, 0, 0x80, 0, 0, 0, 0, 0, 0, 2])
        .expect("an id");
    {
        let vault = first.open().expect("open the first copy");
        assert_eq!(vault.get(&person).expect("read"), Some(b"Ada".to_vec()));
        vault
            .put_entity(
                &other,
                ENTITY_TYPE_PERSON,
                TimeRange { start: 1, end: 1 },
                1,
                b"Bo",
            )
            .expect("write to the first copy");
    }
    // The existing-only door binds the root by descriptor, which only Linux
    // offers; elsewhere the engine refuses it by design.
    #[cfg(target_os = "linux")]
    let vault = second
        .open_existing()
        .expect("open the second copy, existing only");
    #[cfg(not(target_os = "linux"))]
    let vault = second.open().expect("open the second copy");
    assert_eq!(vault.get(&person).expect("read"), Some(b"Ada".to_vec()));
    assert_eq!(
        vault.get(&other).expect("read"),
        None,
        "copies share nothing"
    );
}
