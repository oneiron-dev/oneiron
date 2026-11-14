//! L10-09 PR 2 (CROSS-ARCH-0013 `#ladder` rung 2): the caller's vector of a
//! name searches the stored name vectors of its model, as one more ranked
//! list of the phonetic channel, through the pipeline and the hybrid search;
//! every filter of the run applies, a vector of another width is refused,
//! and an erased entity is never served. The doors are new, so at the base
//! this file's red is a compile red.

use std::collections::BTreeSet;
use std::hash::{Hash, Hasher};

use oneiron::embed::EmbedderLocality;
use oneiron::memory::{HybridPhoneticVectorQuery, HybridSearchRequest, ReadFilterInput};
use oneiron::phonetic_learned::PhoneticEmbedder;
use oneiron::registry::{ENTITY_TYPE_ORG, ENTITY_TYPE_PERSON};
use oneiron::{EdgeActorClass, EntityId, TimeRange, Vault, VaultConfig};

const MODEL: &str = "fixture-phonetic-v1";
const WIDTH: usize = 8;

/// The fixture model's vector of `name`: 小明, しょうめい and Showming sit at
/// cosine >= 0.98 to each other; Siobhan and Shivon at 0.9; every other name
/// on axes 5..8 only, orthogonal to all of them.
fn fixture_vector(name: &str) -> Vec<f32> {
    let mut vector = vec![0.0_f32; WIDTH];
    match name {
        "小明" => vector[..3].copy_from_slice(&[1.0, 0.1, 0.0]),
        "しょうめい" => vector[..3].copy_from_slice(&[1.0, 0.0, 0.1]),
        "Showming" => vector[..3].copy_from_slice(&[1.0, 0.05, 0.05]),
        "Siobhan" => vector[3] = 1.0,
        "Shivon" => vector[3..5].copy_from_slice(&[0.9, 0.435_89]),
        other => {
            for (axis, value) in vector.iter_mut().enumerate().skip(5) {
                let mut hasher = std::hash::DefaultHasher::new();
                (other, axis).hash(&mut hasher);
                let bits = u16::try_from(hasher.finish() % 1000).expect("in range");
                *value = f32::from(bits) / 1000.0 + 0.1;
            }
        }
    }
    vector
}

struct FixtureModel;

impl PhoneticEmbedder for FixtureModel {
    fn model_id(&self) -> &str {
        MODEL
    }

    fn dimensions(&self) -> usize {
        WIDTH
    }

    fn locality(&self) -> EmbedderLocality {
        EmbedderLocality::OnDevice
    }

    fn embed_names(&self, names: &[&str]) -> oneiron::Result<Vec<Vec<f32>>> {
        Ok(names.iter().map(|name| fixture_vector(name)).collect())
    }
}

struct Fixture {
    _dir: tempfile::TempDir,
    vault: Vault,
}

fn fixture() -> Fixture {
    let dir = tempfile::tempdir().expect("temporary vault");
    let vault = Vault::open(dir.path(), VaultConfig::default()).expect("open vault");
    Fixture { _dir: dir, vault }
}

impl Fixture {
    fn named(&self, entity_type: u8, name: &str) -> EntityId {
        let id = EntityId::now();
        self.vault
            .put_entity(
                &id,
                entity_type,
                TimeRange { start: 1, end: 1 },
                1,
                &rmp_serde::to_vec_named(&serde_json::json!({ "name": name })).expect("body"),
            )
            .expect("put the entity");
        id
    }

    fn person(&self, name: &str) -> EntityId {
        self.named(ENTITY_TYPE_PERSON, name)
    }

    /// Twenty people whose names sound like none of the fixture's pairs.
    fn distractors(&self) {
        for n in 0..20 {
            self.person(&format!("Distractor {n}"));
        }
    }

    fn reconcile(&self) {
        self.vault
            .reconcile_phonetic_embeddings(&FixtureModel, 1000)
            .expect("reconcile");
    }

    fn request(
        &self,
        query: Option<&str>,
        model_id: &str,
        vector: Vec<f32>,
    ) -> HybridSearchRequest {
        HybridSearchRequest {
            query: query.map(str::to_owned),
            query_vector: None,
            phonetic_codes: Vec::new(),
            phonetic_mentions: Vec::new(),
            phonetic_vector: Some(HybridPhoneticVectorQuery {
                model_id: model_id.to_owned(),
                vector,
                limit: None,
            }),
            ppr: None,
            temporal: None,
            replay: None,
            limit: 10,
            filter: None,
        }
    }

    /// The owner's hybrid search, as entity ids best first.
    fn hybrid(&self, request: &HybridSearchRequest) -> oneiron::memory::MemoryResult<Vec<String>> {
        let owner = self.vault.ensure_embedded_owner_actor().expect("the owner");
        Ok(self
            .vault
            .memory(owner, EdgeActorClass::Human)
            .query_hybrid(request)?
            .value
            .into_iter()
            .map(|hit| hit.entity_ref)
            .collect())
    }

    fn learned(&self, name: &str) -> Vec<String> {
        self.hybrid(&self.request(None, MODEL, fixture_vector(name)))
            .expect("hybrid search")
    }
}

/// Canon `#test-accuracy` "Latin → Han (cross)": a Latin spelling finds a
/// Han name that has no Latin alias, on the learned rung alone.
#[test]
fn latin_query_finds_cjk_entity_through_learned_rung() {
    let fixture = fixture();
    let xiaoming = fixture.person("小明");
    fixture.distractors();
    fixture.reconcile();

    let found = fixture.learned("Showming");
    assert_eq!(found.first(), Some(&xiaoming.to_hex()), "{found:?}");

    // The control: the same vector under a model the vault never embedded
    // with finds nothing, so the hit is the stored vectors'.
    let other_model = fixture
        .hybrid(&fixture.request(None, "another-model", fixture_vector("Showming")))
        .expect("hybrid search");
    assert!(other_model.is_empty(), "{other_model:?}");
}

/// The pipeline door: the same query through `Vault::query`.
#[test]
fn the_pipeline_takes_a_learned_query() {
    let fixture = fixture();
    let xiaoming = fixture.person("小明");
    fixture.distractors();
    fixture.reconcile();

    let found: Vec<EntityId> = fixture
        .vault
        .query()
        .search_phonetic_vector(MODEL, &fixture_vector("Showming"), 200)
        .limit(5)
        .run()
        .expect("learned query")
        .into_iter()
        .map(|row| row.id)
        .collect();
    assert_eq!(found.first(), Some(&xiaoming), "{found:?}");
}

/// Canon `#test-regression`: exact text still ranks first; the sound-alike
/// follows it.
#[test]
fn exact_text_match_still_ranks_first() {
    let fixture = fixture();
    let shivon = fixture.person("Shivon");
    let siobhan = fixture.person("Siobhan");
    fixture.reconcile();

    let found = fixture
        .hybrid(&fixture.request(Some("Shivon"), MODEL, fixture_vector("Shivon")))
        .expect("hybrid search");
    assert_eq!(found, [shivon.to_hex(), siobhan.to_hex()]);
}

/// A vector of another width than the model's stored vectors is a typed bad
/// request, not an empty answer.
#[test]
fn a_vector_of_another_width_is_refused() {
    let fixture = fixture();
    fixture.person("小明");
    fixture.reconcile();

    let refused = fixture.hybrid(&fixture.request(None, MODEL, vec![1.0, 0.0, 0.0, 0.0]));
    let error = refused.expect_err("a 4-wide vector against 8-wide rows");
    assert_eq!(error.code, "BAD_REQUEST", "{error:?}");
}

/// The caller's filter narrows the learned list too: a PERSON outside it is
/// never served, an ORG inside it is.
#[test]
fn rows_outside_the_callers_filter_are_not_served() {
    let fixture = fixture();
    let person = fixture.person("小明");
    let org = fixture.named(ENTITY_TYPE_ORG, "しょうめい");
    fixture.reconcile();

    let mut request = fixture.request(None, MODEL, fixture_vector("Showming"));
    request.filter = Some(ReadFilterInput {
        entity_types: Some(BTreeSet::from([ENTITY_TYPE_ORG])),
        ..ReadFilterInput::default()
    });
    let found = fixture.hybrid(&request).expect("hybrid search");
    assert!(found.contains(&org.to_hex()), "{found:?}");
    assert!(!found.contains(&person.to_hex()), "{found:?}");
}

/// Canon `#open` Q5: an erased entity's names are never served by sound.
#[test]
fn an_erased_entity_is_not_served() {
    let fixture = fixture();
    let xiaoming = fixture.person("小明");
    fixture.distractors();
    fixture.reconcile();
    assert_eq!(
        fixture.learned("Showming").first(),
        Some(&xiaoming.to_hex())
    );

    assert!(fixture.vault.delete_entity(&xiaoming).expect("delete"));
    let found = fixture.learned("Showming");
    assert!(!found.contains(&xiaoming.to_hex()), "{found:?}");
}
