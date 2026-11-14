//! CROSS-ARCH-0011 amendment "workingSet" (CROSS-ARCH-0002b #ep-6-2-3): a
//! context pack seeded with the rows a host carried across a compaction
//! serves them first, in the caller's order, before the ranked fill. Each ref
//! is admitted on its own: a superseded claim resolves forward, a dead or
//! out-of-scope ref is dropped while the rest still seed, the fill never
//! repeats a seed, the seeds take at most half of a serialized pack's token
//! budget, an ASSET crosses as a handle, and an unseeded pack is today's pack.
//!
//! Public crate surface only: `Vault::put_claim`, `Vault::put_entity`,
//! `Vault::supersede_claim`, a vector batch, and the context pack builder.

use oneiron::context_pack::MAX_WORKING_SET_REFS;
use oneiron::pipeline::WorldScope;
use oneiron::registry::{ENTITY_TYPE_ASSET, ENTITY_TYPE_PERSON};
use oneiron::{
    ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus, ClaimSource, ClaimSubject,
    ContextPackBuilder, EntityId, TimeRange, Vault, VaultConfig,
};

const LEARNED_AT: u64 = 1_780_000_000;
const QUERY: [f32; 4] = [1.0, 0.0, 0.0, 0.0];

/// One vault: three ranked claims the query finds (`fill`, best first), and
/// rows only a working set reaches: two base claims with no vector, a claim
/// in another world, and an ASSET.
struct Fixture {
    _dir: tempfile::TempDir,
    vault: Vault,
    subject: EntityId,
    fill: [EntityId; 3],
    carried: [EntityId; 2],
    other_world_claim: EntityId,
    asset: EntityId,
}

fn fixture_id(byte: u8) -> EntityId {
    EntityId::from_bytes([byte; 16]).expect("valid entity id")
}

fn occurred() -> TimeRange {
    TimeRange {
        start: LEARNED_AT,
        end: LEARNED_AT,
    }
}

fn put_claim(vault: &Vault, subject: EntityId, id: EntityId, value: &str, world: Option<EntityId>) {
    let mut body = ClaimBody::new(
        "profile.note",
        ClaimSubject::Entity(subject),
        rmpv::Value::from(value),
        1.0,
        ClaimApprovalStatus::Auto,
        ClaimLifecycleStatus::Active,
    )
    .expect("claim body");
    body.source = Some(ClaimSource::UserStated);
    body.world = world;
    vault
        .put_claim(&id, &body, occurred(), LEARNED_AT)
        .expect("fixture claim");
}

fn fixture() -> Fixture {
    let dir = tempfile::tempdir().expect("temporary vault");
    let mut config = VaultConfig::device();
    config.dimensions = QUERY.len();
    config.embedding_model = Some("test/model@v1".to_owned());
    config.map_size = 16 * 1024 * 1024;
    let vault = Vault::open(dir.path(), config).expect("open vault");

    let subject = fixture_id(0x21);
    vault
        .put_entity(
            &subject,
            ENTITY_TYPE_PERSON,
            occurred(),
            LEARNED_AT,
            b"subject",
        )
        .expect("subject entity");

    let fill = [fixture_id(0x31), fixture_id(0x32), fixture_id(0x33)];
    let fill_rows: [(EntityId, &str, [f32; 4]); 3] = [
        (fill[0], "fill row alpha", [0.99, 0.141, 0.0, 0.0]),
        (fill[1], "fill row beta", [0.9, 0.436, 0.0, 0.0]),
        (fill[2], "fill row gamma", [0.8, 0.6, 0.0, 0.0]),
    ];
    for (id, value, _) in &fill_rows {
        put_claim(&vault, subject, *id, value, None);
    }
    let mut vectors = vault.batch();
    for (id, _, vector) in &fill_rows {
        vectors = vectors.vector(id, vector);
    }
    vectors.commit().expect("fill vectors");

    let carried = [fixture_id(0x41), fixture_id(0x42)];
    put_claim(&vault, subject, carried[0], "carried row one", None);
    put_claim(&vault, subject, carried[1], "carried row two", None);
    let other_world_claim = fixture_id(0x51);
    put_claim(
        &vault,
        subject,
        other_world_claim,
        "carried row in another world",
        Some(fixture_id(0x5F)),
    );

    let asset = fixture_id(0x61);
    let asset_body = rmpv::Value::Map(vec![
        (
            rmpv::Value::from("title"),
            rmpv::Value::from("carried asset"),
        ),
        (
            rmpv::Value::from("body"),
            rmpv::Value::from("carried asset body text"),
        ),
    ]);
    let mut encoded = Vec::new();
    rmpv::encode::write_value(&mut encoded, &asset_body).expect("encode the asset body");
    vault
        .put_entity(&asset, ENTITY_TYPE_ASSET, occurred(), LEARNED_AT, &encoded)
        .expect("asset entity");

    Fixture {
        _dir: dir,
        vault,
        subject,
        fill,
        carried,
        other_world_claim,
        asset,
    }
}

impl Fixture {
    fn builder(&self) -> ContextPackBuilder<'_> {
        self.vault
            .context_pack()
            .search_vector(&QUERY, 10)
            .limit(10)
    }

    fn seeded(&self, refs: &[EntityId]) -> ContextPackBuilder<'_> {
        self.builder().working_set(refs).expect("working set")
    }

    /// The fixture rows of a pack's results, in pack order.
    fn rows(&self, pack: &oneiron::ContextPack) -> Vec<EntityId> {
        let known: Vec<EntityId> = self
            .fill
            .iter()
            .chain(&self.carried)
            .chain([&self.other_world_claim, &self.asset])
            .copied()
            .collect();
        pack.results
            .iter()
            .map(|entity| entity.id)
            .filter(|id| known.contains(id))
            .collect()
    }
}

#[test]
fn seeds_lead_the_pack_before_the_ranked_fill() {
    let fixture = fixture();
    let unseeded = fixture.builder().run().expect("unseeded pack");
    assert_eq!(
        fixture.rows(&unseeded),
        fixture.fill.to_vec(),
        "the ranked fill alone"
    );

    let pack = fixture.seeded(&fixture.carried).run().expect("seeded pack");
    let mut expected = fixture.carried.to_vec();
    expected.extend(fixture.fill);
    assert_eq!(fixture.rows(&pack), expected);
    let working_set = &pack.stats.working_set;
    assert_eq!(working_set.asked, 2);
    assert_eq!(working_set.served, fixture.carried.to_vec());
    assert_eq!(working_set.dropped, 0);
    assert_eq!(working_set.overlap, 0);
}

#[test]
fn a_superseded_seed_resolves_to_its_live_successor() {
    let fixture = fixture();
    let successor = fixture_id(0x43);
    put_claim(
        &fixture.vault,
        fixture.subject,
        successor,
        "carried row one, revised",
        None,
    );
    fixture
        .vault
        .supersede_claim(&successor, &fixture.carried[0], LEARNED_AT + 1)
        .expect("supersede the carried claim");

    let pack = fixture
        .seeded(&[fixture.carried[0]])
        .run()
        .expect("seeded pack");
    let rows: Vec<EntityId> = pack.results.iter().map(|entity| entity.id).collect();
    assert_eq!(rows.first(), Some(&successor), "the successor leads");
    assert!(
        !rows.contains(&fixture.carried[0]),
        "the superseded claim is never served"
    );
    assert_eq!(pack.stats.working_set.served, vec![successor]);
    assert_eq!(pack.stats.working_set.dropped, 0);
}

#[test]
fn a_dead_or_unreadable_seed_is_dropped_and_never_served() {
    let fixture = fixture();
    let dead = fixture_id(0x7E);
    let base_pack = |refs: &[EntityId]| {
        fixture
            .builder()
            .world(WorldScope::Base)
            .working_set(refs)
            .expect("working set")
            .run()
            .expect("seeded pack")
    };

    let pack = base_pack(&[fixture.carried[0], dead, fixture.other_world_claim]);
    let rows: Vec<EntityId> = pack.results.iter().map(|entity| entity.id).collect();
    let mut expected = vec![fixture.carried[0]];
    expected.extend(fixture.fill);
    assert_eq!(fixture.rows(&pack), expected);
    assert!(!rows.contains(&dead));
    assert!(!rows.contains(&fixture.other_world_claim));
    assert_eq!(pack.stats.working_set.asked, 3);
    assert_eq!(pack.stats.working_set.served, vec![fixture.carried[0]]);
    assert_eq!(pack.stats.working_set.dropped, 2);

    // One count for every reason: a dead ref and a row outside the pack's
    // worlds are told apart by nothing.
    let dead_only = base_pack(&[fixture.carried[0], dead]);
    let hidden_only = base_pack(&[fixture.carried[0], fixture.other_world_claim]);
    assert_eq!(dead_only.stats.working_set, hidden_only.stats.working_set);
    assert_eq!(dead_only.stats.working_set.dropped, 1);
}

#[test]
fn seeds_past_half_the_token_budget_are_cut() {
    let fixture = fixture();
    let filler = " the".repeat(300);
    let seeds = [fixture_id(0x44), fixture_id(0x45), fixture_id(0x46)];
    for (id, name) in seeds.iter().zip(["seed one", "seed two", "seed three"]) {
        put_claim(
            &fixture.vault,
            fixture.subject,
            *id,
            &format!("{name}{filler}"),
            None,
        );
    }

    let serialized = fixture
        .seeded(&seeds)
        .max_field_chars(0)
        .token_budget(1000)
        .run_serialized_with_stats()
        .expect("serialized pack")
        .value;
    let text = String::from_utf8(serialized.bytes).expect("utf-8 pack");
    let working_set = &serialized.stats.working_set;
    assert_eq!(working_set.served, vec![seeds[0]], "{text}");
    assert_eq!(working_set.over_cap, 2, "{text}");
    assert!(text.contains("seed one"), "{text}");
    assert!(!text.contains("seed two"), "{text}");
    assert!(!text.contains("seed three"), "{text}");
    assert!(
        text.contains("fill row alpha"),
        "the fill spends the rest of the budget: {text}"
    );
}

#[test]
fn a_seed_the_fill_also_finds_is_served_once() {
    let fixture = fixture();
    let pack = fixture
        .seeded(&[fixture.fill[1]])
        .run()
        .expect("seeded pack");
    let rows: Vec<EntityId> = pack.results.iter().map(|entity| entity.id).collect();
    assert_eq!(rows.first(), Some(&fixture.fill[1]));
    assert_eq!(
        rows.iter().filter(|id| **id == fixture.fill[1]).count(),
        1,
        "served once"
    );
    assert_eq!(
        fixture.rows(&pack),
        vec![fixture.fill[1], fixture.fill[0], fixture.fill[2]]
    );
    assert_eq!(pack.stats.working_set.overlap, 1);
    assert_eq!(pack.stats.working_set.served, vec![fixture.fill[1]]);
}

#[test]
fn no_working_set_is_todays_pack() {
    let fixture = fixture();
    let today = fixture.builder().run_serialized().expect("today's pack");
    let empty = fixture
        .seeded(&[])
        .run_serialized()
        .expect("pack with an empty working set");
    assert_eq!(
        String::from_utf8_lossy(&empty),
        String::from_utf8_lossy(&today)
    );
    let pack = fixture.seeded(&[]).run().expect("typed pack");
    assert_eq!(
        pack.stats.working_set,
        oneiron::context_pack::PackWorkingSetStats::default()
    );
}

#[test]
fn a_seeded_asset_crosses_as_a_stub() {
    let fixture = fixture();
    let pack = fixture.seeded(&[fixture.asset]).run().expect("seeded pack");
    let first = pack.results.first().expect("the asset leads");
    assert_eq!(first.id, fixture.asset);
    assert!(
        first.fields.is_none(),
        "an ASSET seed carries no body: {:?}",
        first.fields
    );
    assert_eq!(pack.stats.working_set.served, vec![fixture.asset]);
}

#[test]
fn a_working_set_over_the_cap_is_refused() {
    let fixture = fixture();
    let refs: Vec<EntityId> = (0..=MAX_WORKING_SET_REFS)
        .map(|index| {
            let mut bytes = [0x90_u8; 16];
            bytes[14] = u8::try_from(index / 256).expect("small index");
            bytes[15] = u8::try_from(index % 256).expect("small index");
            EntityId::from_bytes(bytes).expect("valid entity id")
        })
        .collect();
    let Err(error) = fixture.builder().working_set(&refs) else {
        panic!("a working set of {} refs was accepted", refs.len());
    };
    assert!(error.to_string().contains("at most 64 refs"), "{error}");
    // Duplicates count once: the same ref named past the cap is one ref.
    let repeated = vec![fixture.carried[0]; MAX_WORKING_SET_REFS + 1];
    assert!(fixture.builder().working_set(&repeated).is_ok());
}
