//! ARCH-0004 #world-scope: "The context pack MUST partition claims by world -
//! the base-reality section first, labeled per-world sections after" and
//! "Retrieval MUST NOT mix worlds *unlabeled*". A rendered pack (the text a
//! recall with `format` returns) whose scope reads base beside a named world
//! names each row's world before the row's text: `world_section` is `base` on
//! a base-reality row and the world's id hex on a story-world row
//! (FIX [RECALL-RENDERED-PACK-WORLD-UNLABELED], E2E MUSE-RECALL-03). A pack
//! that holds one side only carries no label.
//!
//! Public crate surface only: `Vault::put_claim`, a vector batch, the context
//! pack builder and `serialize::serialize_pack`, configured as a light
//! `vault.recall` with `format` configures them (Minimal profile, hydrated).
//! The label key and value are spelled out here, not imported, so this file
//! builds where the engine does not label yet.

use oneiron::context_pack::{ContextPack, DEFAULT_MAX_FIELD_CHARS, TokenAllocation};
use oneiron::pipeline::{WorldAuthoritySet, WorldScope};
use oneiron::registry::ENTITY_TYPE_PERSON;
use oneiron::serialize::pack_format::{FieldProfile, PackFormat};
use oneiron::serialize::{SerializeConfig, project_pack_for_json_response, serialize_pack};
use oneiron::{
    ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus, ClaimSource, ClaimSubject, EntityId,
    TimeRange, Vault, VaultConfig,
};

const LEARNED_AT: u64 = 1_780_000_000;
const QUERY: [f32; 4] = [1.0, 0.0, 0.0, 0.0];
const LABEL_KEY: &str = "world_section";
const BASE_LABEL: &str = "base";
const TEXT_FORMATS: [PackFormat; 4] = [
    PackFormat::Toon,
    PackFormat::Yaml,
    PackFormat::Markdown,
    PackFormat::Plaintext,
];

/// One vault: three story-world claims that outrank two base claims.
struct Fixture {
    _dir: tempfile::TempDir,
    vault: Vault,
    story_world: EntityId,
    story: [EntityId; 3],
    base: [EntityId; 2],
}

fn seed_id(byte: u8) -> EntityId {
    EntityId::from_bytes([byte; 16]).expect("valid entity id")
}

/// The claim text of a seeded row. No entity id inside: a rendered pack
/// rewrites an in-pack entity's id hex to its short id.
fn claim_text(id: EntityId) -> String {
    let words = match id.as_bytes()[0] {
        0x31 => "tale one",
        0x32 => "tale two",
        0x33 => "tale three",
        0x41 => "quay one",
        0x42 => "quay two",
        _ => "unseeded",
    };
    format!("harbor note {words}")
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
    let story = [seed_id(0x31), seed_id(0x32), seed_id(0x33)];
    let base = [seed_id(0x41), seed_id(0x42)];
    // Cosine to QUERY: story 0.99, 0.98, 0.97 > base 0.90, 0.80.
    let rows: [(EntityId, Option<EntityId>, [f32; 4]); 5] = [
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
            rmpv::Value::from(claim_text(id)),
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
    }
}

impl Fixture {
    /// A hydrated Minimal-profile pack, as a light rendered recall builds it.
    fn pack(&self, scope: WorldScope, non_base_fraction: Option<f32>) -> ContextPack {
        let mut builder = self
            .vault
            .context_pack()
            .search_vector(&QUERY, 10)
            .world(scope)
            .limit(10)
            .hydrate(true)
            .field_profile(FieldProfile::Minimal);
        if let Some(fraction) = non_base_fraction {
            builder = builder.non_base_world_claim_fraction(fraction);
        }
        builder.run().expect("context pack")
    }

    fn story_world_set(&self, include_base: bool) -> WorldScope {
        WorldScope::WorldSet(
            WorldAuthoritySet::new(include_base, [self.story_world]).expect("world set"),
        )
    }
}

fn config(format: PackFormat) -> SerializeConfig {
    SerializeConfig {
        format,
        profile: FieldProfile::Minimal,
        budget: 8192,
        allocation: TokenAllocation::default(),
        include_stats: false,
        merge_neighbors: true,
        max_field_chars: DEFAULT_MAX_FIELD_CHARS,
        max_item_tokens: 0,
    }
}

fn render(pack: &ContextPack, format: PackFormat) -> String {
    String::from_utf8(serialize_pack(pack, &config(format))).expect("rendered pack is UTF-8")
}

/// Every rendered JSON row that carries a claim value (`val`), by that value.
fn json_claim_rows(rendered: &str) -> Vec<serde_json::Map<String, serde_json::Value>> {
    fn walk(value: &serde_json::Value, out: &mut Vec<serde_json::Map<String, serde_json::Value>>) {
        match value {
            serde_json::Value::Object(object) if object.contains_key("val") => {
                out.push(object.clone());
            }
            serde_json::Value::Object(object) => object.values().for_each(|inner| walk(inner, out)),
            serde_json::Value::Array(items) => items.iter().for_each(|inner| walk(inner, out)),
            _ => {}
        }
    }
    let root: serde_json::Value = serde_json::from_str(rendered).expect("rendered JSON pack");
    let mut rows = Vec::new();
    walk(&root, &mut rows);
    rows
}

/// P-RECALL-011 / ARCH-0004 #world-scope. Under `{story, include_base}` the
/// pack keeps both base claims and the three story claims (share 1.0). Each
/// rendered JSON row carries `world_section` as its first field: `base` on a
/// base claim, the story world's id hex on a story claim. The structured JSON
/// response keeps the base rows first. In every text format the story world's
/// id precedes each story claim's text, and no story label precedes a base
/// claim's text (the base section comes first, although every story claim
/// outranks every base claim).
#[test]
fn partitioned_pack_renders_each_rows_world_before_its_text() {
    let fixture = fixture();
    let story_hex = fixture.story_world.to_hex();
    let pack = fixture.pack(fixture.story_world_set(true), Some(1.0));

    let rows = json_claim_rows(&render(&pack, PackFormat::Json));
    let base_rows = fixture
        .base
        .map(|id| (claim_text(id), BASE_LABEL.to_owned()));
    let story_rows = fixture.story.map(|id| (claim_text(id), story_hex.clone()));
    for (text, label) in base_rows.into_iter().chain(story_rows) {
        let row = rows
            .iter()
            .find(|row| row.get("val").and_then(serde_json::Value::as_str) == Some(text.as_str()))
            .unwrap_or_else(|| panic!("JSON pack holds the claim {text}; rows {rows:?}"));
        assert_eq!(
            row.get(LABEL_KEY).and_then(serde_json::Value::as_str),
            Some(label.as_str()),
            "JSON row {text} names its world section; row {row:?}"
        );
        let first_field = row
            .keys()
            .find(|key| !matches!(key.as_str(), "id" | "score"))
            .map(String::as_str);
        assert_eq!(
            first_field,
            Some(LABEL_KEY),
            "the world section comes before the row's text; row {row:?}"
        );
    }

    // The structured JSON response a context-pack door returns keeps the
    // partition's order although every story claim outranks every base claim.
    let projected = project_pack_for_json_response(pack.clone(), &config(PackFormat::Json));
    let position = |id: EntityId| {
        projected
            .results
            .iter()
            .position(|row| row.id == id)
            .unwrap_or_else(|| panic!("projected JSON pack holds {id:?}"))
    };
    let last_base = fixture
        .base
        .iter()
        .map(|id| position(*id))
        .max()
        .expect("two base claims");
    for id in fixture.story {
        assert!(
            position(id) > last_base,
            "projected JSON pack: the base section comes first; story claim {id:?} at {}, last base claim at {last_base}",
            position(id)
        );
    }

    for format in TEXT_FORMATS {
        let rendered = render(&pack, format);
        let first_base = fixture
            .base
            .iter()
            .filter_map(|id| rendered.find(&claim_text(*id)))
            .min()
            .unwrap_or_else(|| panic!("{format:?} pack holds the base claims: {rendered}"));
        assert!(
            !rendered[..first_base].contains(&story_hex),
            "{format:?}: no story label before the base section: {rendered}"
        );
        for id in fixture.story {
            let at = rendered
                .find(&claim_text(id))
                .unwrap_or_else(|| panic!("{format:?} pack holds story claim {id:?}: {rendered}"));
            assert!(
                at > first_base,
                "{format:?}: base section first: {rendered}"
            );
            assert!(
                rendered[first_base..at].contains(&story_hex),
                "{format:?}: the story world's id precedes story claim {id:?}: {rendered}"
            );
        }
    }
}

/// A pack that holds one side only mixes no worlds and carries no label: a
/// base-only pack, a story world set without base, and a `{story, base}` pack
/// whose share (0.0) keeps no story claim.
#[test]
fn one_sided_pack_renders_no_world_label() {
    let fixture = fixture();
    let packs = [
        ("base", fixture.pack(WorldScope::Base, None)),
        (
            "story without base",
            fixture.pack(fixture.story_world_set(false), None),
        ),
        (
            "story share 0",
            fixture.pack(fixture.story_world_set(true), Some(0.0)),
        ),
    ];
    for (name, pack) in &packs {
        for format in [PackFormat::Json, PackFormat::Toon] {
            let rendered = render(pack, format);
            assert!(
                rendered.contains("harbor note"),
                "{name} {format:?} pack renders its claims: {rendered}"
            );
            assert!(
                !rendered.contains(LABEL_KEY),
                "{name} {format:?} pack carries no world label: {rendered}"
            );
        }
    }
}
