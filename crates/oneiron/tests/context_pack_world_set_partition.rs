//! ARCH-0004 #world-scope: a context pack whose scope selects base reality
//! beside a named world partitions its claims, base section first, with the
//! non-base claims held to the same world share as the `All` scope
//! (FIX [RECALL-WORLD-PARTITION-ALL-SCOPE-ONLY]). A scope that selects one
//! side only stays flat and keeps every claim it selects.
//!
//! Public crate surface only: `Vault::put_claim`, a vector batch, and the
//! context pack builder.

use oneiron::pipeline::{WorldAuthoritySet, WorldScope};
use oneiron::registry::ENTITY_TYPE_PERSON;
use oneiron::{
    ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus, ClaimSource, ClaimSubject, EntityId,
    TimeRange, Vault, VaultConfig,
};

const LEARNED_AT: u64 = 1_780_000_000;
const QUERY: [f32; 4] = [1.0, 0.0, 0.0, 0.0];

/// One vault: three story-world claims that outrank two base claims, and one
/// claim in a second world that no scope here selects.
struct Fixture {
    _dir: tempfile::TempDir,
    vault: Vault,
    story_world: EntityId,
    story: [EntityId; 3],
    base: [EntityId; 2],
    other_world_claim: EntityId,
}

fn seed_id(byte: u8) -> EntityId {
    EntityId::from_bytes([byte; 16]).expect("valid entity id")
}

fn fixture() -> Fixture {
    let dir = tempfile::tempdir().expect("temporary vault");
    let mut config = VaultConfig::device();
    config.dimensions = QUERY.len();
    config.embedding_model = Some("test/model@v1".to_owned());
    config.map_size = 16 * 1024 * 1024;
    let vault = Vault::open(dir.path(), config).expect("open vault");

    let occurred = TimeRange {
        start: LEARNED_AT,
        end: LEARNED_AT,
    };
    let subject = seed_id(0x21);
    vault
        .put_entity(
            &subject,
            ENTITY_TYPE_PERSON,
            occurred,
            LEARNED_AT,
            b"subject",
        )
        .expect("subject entity");

    let story_world = seed_id(0x5E);
    let other_world = seed_id(0x5F);
    let story = [seed_id(0x31), seed_id(0x32), seed_id(0x33)];
    let base = [seed_id(0x41), seed_id(0x42)];
    let other_world_claim = seed_id(0x51);
    // Cosine to QUERY: other 1.0 > story 0.99, 0.98, 0.97 > base 0.90, 0.80.
    let rows: [(EntityId, Option<EntityId>, [f32; 4]); 6] = [
        (other_world_claim, Some(other_world), [1.0, 0.0, 0.0, 0.0]),
        (story[0], Some(story_world), [0.99, 0.141, 0.0, 0.0]),
        (story[1], Some(story_world), [0.98, 0.199, 0.0, 0.0]),
        (story[2], Some(story_world), [0.97, 0.243, 0.0, 0.0]),
        (base[0], None, [0.9, 0.436, 0.0, 0.0]),
        (base[1], None, [0.8, 0.6, 0.0, 0.0]),
    ];
    for &(id, world, _) in &rows {
        let mut body = ClaimBody::new(
            "profile.note",
            ClaimSubject::Entity(subject),
            rmpv::Value::from(format!("harbor note {}", id.to_hex())),
            1.0,
            ClaimApprovalStatus::Auto,
            ClaimLifecycleStatus::Active,
        )
        .expect("claim body");
        body.source = Some(ClaimSource::UserStated);
        body.world = world;
        vault
            .put_claim(&id, &body, occurred, LEARNED_AT)
            .expect("seed claim");
    }
    let mut vectors = vault.batch();
    for (id, _, vector) in &rows {
        vectors = vectors.vector(id, vector);
    }
    vectors.commit().expect("seed vectors");

    Fixture {
        _dir: dir,
        vault,
        story_world,
        story,
        base,
        other_world_claim,
    }
}

impl Fixture {
    /// The seeded claim ids of one pack's results, in pack order.
    fn pack(&self, scope: WorldScope, non_base_fraction: Option<f32>) -> Vec<EntityId> {
        let mut builder = self
            .vault
            .context_pack()
            .search_vector(&QUERY, 10)
            .world(scope)
            .limit(10);
        if let Some(fraction) = non_base_fraction {
            builder = builder.non_base_world_claim_fraction(fraction);
        }
        let pack = builder.run().expect("context pack");
        let seeded: Vec<EntityId> = self
            .story
            .iter()
            .chain(&self.base)
            .chain([&self.other_world_claim])
            .copied()
            .collect();
        pack.results
            .iter()
            .map(|entity| entity.id)
            .filter(|id| seeded.contains(id))
            .collect()
    }

    fn story_world_set(&self, include_base: bool) -> WorldScope {
        WorldScope::WorldSet(
            WorldAuthoritySet::new(include_base, [self.story_world]).expect("world set"),
        )
    }
}

/// P-RECALL-011: "World sections are labeled and presented base-first within
/// their budgets." The story claims outrank both base claims, yet the base
/// section comes first, then the story section in score order. Under the
/// default share (0.5) two base claims leave room for two story claims; the
/// lowest-ranked story claim stays out. The other world is never selected.
#[test]
fn world_set_with_base_puts_base_section_first_and_caps_the_story_world() {
    let fixture = fixture();
    let [story_1, story_2, story_3] = fixture.story;
    let [base_1, base_2] = fixture.base;

    let unshared = fixture.pack(fixture.story_world_set(true), Some(1.0));
    assert_eq!(
        unshared,
        [base_1, base_2, story_1, story_2, story_3],
        "base section first, then the story section in score order"
    );

    let shared = fixture.pack(fixture.story_world_set(true), None);
    assert_eq!(
        shared,
        [base_1, base_2, story_1, story_2],
        "the default share keeps two story claims beside two base claims"
    );
    assert!(!shared.contains(&fixture.other_world_claim));
}

/// A scope that selects the story world without base has no base section to
/// share with: it keeps every story claim, in score order.
#[test]
fn world_only_scopes_keep_every_world_claim() {
    let fixture = fixture();
    let story = fixture.story.to_vec();

    let world_set = fixture.pack(fixture.story_world_set(false), None);
    assert_eq!(world_set, story, "a world set without base");

    let world = fixture.pack(WorldScope::World(fixture.story_world), None);
    let world_claims: Vec<EntityId> = world.into_iter().filter(|id| story.contains(id)).collect();
    assert_eq!(world_claims, story, "World(id) keeps every story claim");
}
