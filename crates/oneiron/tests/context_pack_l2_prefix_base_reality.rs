//! ARCH-0004 #world-scope: "The context pack MUST partition claims by world -
//! the base-reality section first, labeled per-world sections after". The L2
//! prefix a pack carries for its L2 subject (the vault owner by default) is
//! that subject's base-reality profile: it holds no claim of a named world.
//! The owner's story-world claims stay delta rows, which the pack partitions,
//! labels (`world_section`) and renders after the base rows (FIX-LIST
//! [RECALL-L2-PREFIX-WORLDS-UNPARTITIONED], Engine ruling
//! E2E4-L2-WORLD-PARTITION = C, E2E MUSE-RECALL-03).
//!
//! Public crate surface only: `Vault::ensure_embedded_owner_actor`,
//! `Vault::put_claim`, a vector batch, the context pack builder with its
//! implicit L2 subjects, and `serialize::serialize_pack`, configured as a
//! light `vault.recall` with `format` configures them (Minimal profile,
//! hydrated). The story claims are written first and carry the lower ids, so
//! claim-id order alone would put them ahead of the base claims. The label key
//! is spelled out here, not imported.

use oneiron::context_pack::{ContextPack, DEFAULT_MAX_FIELD_CHARS, TokenAllocation};
use oneiron::pipeline::{WorldAuthoritySet, WorldScope};
use oneiron::serialize::pack_format::{FieldProfile, PackFormat};
use oneiron::serialize::{SerializeConfig, serialize_pack};
use oneiron::{
    ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus, ClaimSource, ClaimSubject, EntityId,
    TimeRange, Vault, VaultConfig,
};

const LEARNED_AT: u64 = 1_780_000_000;
const QUERY: [f32; 4] = [1.0, 0.0, 0.0, 0.0];
const LABEL_KEY: &str = "world_section";
const TEXT_FORMATS: [PackFormat; 4] = [
    PackFormat::Toon,
    PackFormat::Yaml,
    PackFormat::Markdown,
    PackFormat::Plaintext,
];

/// One vault: three story-world claims and two base claims, all about the
/// embedded owner, the story claims written first.
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
    let owner = vault
        .ensure_embedded_owner_actor()
        .expect("embedded owner PERSON");

    let occurred = TimeRange {
        start: LEARNED_AT,
        end: LEARNED_AT,
    };
    let story_world = seed_id(0x5E);
    let story = [seed_id(0x31), seed_id(0x32), seed_id(0x33)];
    let base = [seed_id(0x41), seed_id(0x42)];
    // Story first, in write order and in id order. Cosine to QUERY: story
    // 0.99, 0.98, 0.97 > base 0.90, 0.80.
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
            ClaimSubject::Entity(owner),
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
    /// No explicit L2 subject: the pack selects the embedded owner itself.
    fn pack(&self, scope: WorldScope) -> ContextPack {
        self.vault
            .context_pack()
            .search_vector(&QUERY, 10)
            .world(scope)
            .limit(10)
            .hydrate(true)
            .field_profile(FieldProfile::Minimal)
            .non_base_world_claim_fraction(1.0)
            .run()
            .expect("context pack")
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

/// The rendered L2 prefix of a text or JSON pack: everything before the delta
/// marker `serialize::l2_prefix` frames it with.
fn rendered_prefix(rendered: &str, format: PackFormat) -> &str {
    let marker = match format {
        PackFormat::Json => "\"delta\":",
        PackFormat::Markdown | PackFormat::Plaintext => "\n---delta\n",
        _ => "\ndelta:\n",
    };
    let end = rendered
        .find(marker)
        .unwrap_or_else(|| panic!("{format:?} pack frames an L2 prefix: {rendered}"));
    &rendered[..end]
}

/// Every rendered JSON delta row that carries a claim value (`val`). The L2
/// prefix body is a JSON string, so its rows are not walked here.
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

/// The JSON pack's L2 prefix rows (`l2_base.body`, a JSON array string).
fn json_l2_rows(rendered: &str) -> Vec<serde_json::Value> {
    let root: serde_json::Value = serde_json::from_str(rendered).expect("rendered JSON pack");
    let body = root["l2_base"]["body"]
        .as_str()
        .unwrap_or_else(|| panic!("JSON pack carries an L2 prefix body: {rendered}"));
    serde_json::from_str(body).expect("L2 prefix body is a JSON array")
}

/// P-RECALL-011 / ARCH-0004 #world-scope. The owner's L2 prefix holds the two
/// base claims and none of the three story claims, under `{story, base}` and
/// under the story world alone (which leaves no prefix at all). The story
/// claims stay in the pack's results, the delta.
#[test]
fn owner_l2_prefix_holds_no_story_world_claim() {
    let fixture = fixture();
    let pack = fixture.pack(fixture.story_world_set(true));
    let l2 = pack
        .l2_base
        .as_ref()
        .expect("the owner's base claims make an L2 prefix");
    for id in fixture.base {
        assert!(
            l2.evidence_ids().contains(&id),
            "base claim {} is an L2 prefix row; prefix {}",
            claim_text(id),
            l2.body
        );
    }
    for id in fixture.story {
        assert!(
            !l2.evidence_ids().contains(&id),
            "story claim {} is no L2 prefix row; prefix {}",
            claim_text(id),
            l2.body
        );
        assert!(
            pack.results.iter().any(|row| row.id == id),
            "story claim {} stays a delta row; results {:?}",
            claim_text(id),
            pack.results.iter().map(|row| row.id).collect::<Vec<_>>()
        );
    }

    let story_only = fixture.pack(fixture.story_world_set(false));
    let story_only_l2: &[EntityId] = story_only
        .l2_base
        .as_ref()
        .map(|l2| l2.evidence_ids())
        .unwrap_or_default();
    assert!(
        fixture.story.iter().all(|id| !story_only_l2.contains(id)),
        "a story-world-only pack carries no story claim in its L2 prefix; prefix {:?}",
        story_only.l2_base.as_ref().map(|l2| &*l2.body)
    );
    for id in fixture.story {
        assert!(
            story_only.results.iter().any(|row| row.id == id),
            "story-world-only pack: story claim {} is a delta row",
            claim_text(id)
        );
    }
}

/// A rendered `{story, base}` recall of the owner's claims: the L2 prefix
/// renders the base rows and no story row. Each story row renders after the
/// last base row, as a delta row whose `world_section` names the story world
/// (JSON), and the story world's id precedes its text (every text format).
#[test]
fn owner_story_claims_render_after_the_base_rows_labeled() {
    let fixture = fixture();
    let story_hex = fixture.story_world.to_hex();
    let pack = fixture.pack(fixture.story_world_set(true));

    let json = render(&pack, PackFormat::Json);
    let l2_values: Vec<String> = json_l2_rows(&json)
        .iter()
        .filter_map(|row| row["val"].as_str().map(str::to_owned))
        .collect();
    for id in fixture.base {
        assert!(
            l2_values.contains(&claim_text(id)),
            "JSON L2 prefix renders base claim {}; prefix values {l2_values:?}",
            claim_text(id)
        );
    }
    for id in fixture.story {
        assert!(
            !l2_values.contains(&claim_text(id)),
            "JSON L2 prefix renders no story claim; found {} in {l2_values:?}",
            claim_text(id)
        );
    }
    let delta_rows = json_claim_rows(&json);
    for id in fixture.story {
        let text = claim_text(id);
        let row = delta_rows
            .iter()
            .find(|row| row.get("val").and_then(serde_json::Value::as_str) == Some(text.as_str()))
            .unwrap_or_else(|| panic!("JSON delta holds story claim {text}; rows {delta_rows:?}"));
        assert_eq!(
            row.get(LABEL_KEY).and_then(serde_json::Value::as_str),
            Some(story_hex.as_str()),
            "JSON delta row {text} names the story world; row {row:?}"
        );
    }

    for format in TEXT_FORMATS {
        let rendered = render(&pack, format);
        let prefix = rendered_prefix(&rendered, format);
        for id in fixture.story {
            assert!(
                !prefix.contains(&claim_text(id)),
                "{format:?}: the L2 prefix renders no story row; found {}: {rendered}",
                claim_text(id)
            );
        }
        let last_base = fixture
            .base
            .iter()
            .map(|id| {
                rendered.find(&claim_text(*id)).unwrap_or_else(|| {
                    panic!("{format:?} pack renders base claim {id:?}: {rendered}")
                })
            })
            .max()
            .expect("two base claims");
        for id in fixture.story {
            let at = rendered.find(&claim_text(id)).unwrap_or_else(|| {
                panic!("{format:?} pack renders story claim {id:?}: {rendered}")
            });
            assert!(
                at > last_base,
                "{format:?}: story claim {} renders after the base rows: {rendered}",
                claim_text(id)
            );
            assert!(
                rendered[last_base..at].contains(&story_hex),
                "{format:?}: the story world's id precedes story claim {}: {rendered}",
                claim_text(id)
            );
        }
    }
}
