//! L10-09 PR 1 (CROSS-ARCH-0013 `#ladder` rung 2, the learned phonetic
//! embedding): the reconcile door embeds each entity name once per model,
//! outside any transaction, at the revision the code rung publishes; the
//! vectors go wherever the entity's codes go, so an erased or renamed name
//! keeps none; a third-party model reads only what the host's gate admits.
//! Every door here is new, so at the base the file does not build.

use std::hash::{Hash, Hasher};
use std::sync::Mutex;

use oneiron::embed::{EgressDecision, EgressPredicate, EmbedderLocality, MediaEmbeddingInput};
use oneiron::phonetic_learned::{PhoneticEmbedReport, PhoneticEmbedder};
use oneiron::registry::ENTITY_TYPE_PERSON;
use oneiron::store::embedding::PendingEmbeddingInput;
use oneiron::{EntityId, Error, TimeRange, Vault, VaultConfig};

const WIDTH: usize = 8;

/// A fixture model: each name maps to a fixed unit vector; every call and
/// name it was sent is recorded.
struct NameModel {
    model_id: &'static str,
    locality: EmbedderLocality,
    answer_width: usize,
    sent: Mutex<Vec<Vec<String>>>,
}

impl NameModel {
    fn new(model_id: &'static str) -> Self {
        Self {
            model_id,
            locality: EmbedderLocality::OnDevice,
            answer_width: WIDTH,
            sent: Mutex::new(Vec::new()),
        }
    }

    fn at(mut self, locality: EmbedderLocality) -> Self {
        self.locality = locality;
        self
    }

    /// Every name sent so far, in order.
    fn names_sent(&self) -> Vec<String> {
        self.sent.lock().expect("sent").concat()
    }

    fn calls(&self) -> usize {
        self.sent.lock().expect("sent").len()
    }
}

fn unit_vector(name: &str, width: usize) -> Vec<f32> {
    let mut vector: Vec<f32> = (0..width)
        .map(|axis| {
            let mut hasher = std::hash::DefaultHasher::new();
            (name, axis).hash(&mut hasher);
            let bits = u16::try_from(hasher.finish() % 2001).expect("in range");
            f32::from(bits) / 1000.0 - 1.0
        })
        .collect();
    let norm = vector.iter().map(|value| value * value).sum::<f32>().sqrt();
    for value in &mut vector {
        *value /= norm;
    }
    vector
}

impl PhoneticEmbedder for NameModel {
    fn model_id(&self) -> &str {
        self.model_id
    }

    fn dimensions(&self) -> usize {
        WIDTH
    }

    fn locality(&self) -> EmbedderLocality {
        self.locality
    }

    fn embed_names(&self, names: &[&str]) -> oneiron::Result<Vec<Vec<f32>>> {
        self.sent
            .lock()
            .expect("sent")
            .push(names.iter().map(|name| (*name).to_owned()).collect());
        Ok(names
            .iter()
            .map(|name| unit_vector(name, self.answer_width))
            .collect())
    }
}

/// A host gate that allows every name, or none.
struct NameGate(EgressDecision);

impl EgressPredicate for NameGate {
    fn decide(&self, _input: &PendingEmbeddingInput) -> EgressDecision {
        EgressDecision::NoVerdict
    }

    fn decide_media(&self, _input: &MediaEmbeddingInput<'_>) -> EgressDecision {
        self.0
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
    /// Writes PERSON `id` with `name` and `aliases`: a birth, or an edit
    /// that the idle indexer publishes later.
    fn put_person(&self, id: &EntityId, name: &str, aliases: &[&str]) {
        let body = serde_json::json!({ "name": name, "aliases": aliases });
        self.vault
            .put_entity(
                id,
                ENTITY_TYPE_PERSON,
                TimeRange { start: 1, end: 1 },
                1,
                &rmp_serde::to_vec_named(&body).expect("body"),
            )
            .expect("put the person");
    }

    fn person(&self, name: &str, aliases: &[&str]) -> EntityId {
        let id = EntityId::now();
        self.put_person(&id, name, aliases);
        id
    }

    /// Publishes every pending edit, as the host's idle loop does.
    fn publish_edits(&self) {
        self.vault
            .set_indexed_idle_delay_ms(0)
            .expect("idle delay row");
        self.vault
            .refresh_staged_indexed_at_idle(u64::MAX)
            .expect("publish at idle");
    }

    fn reconcile(&self, model: &NameModel) -> PhoneticEmbedReport {
        self.vault
            .reconcile_phonetic_embeddings(model, 100)
            .expect("reconcile")
    }
}

/// Canon `#v2-stack`: each name gets one vector of the bound model; a second
/// pass sends the model nothing.
#[test]
fn reconcile_embeds_each_name_once() {
    let fixture = fixture();
    fixture.person("小明", &["Xiao Ming"]);
    let model = NameModel::new("m1");

    let first = fixture.reconcile(&model);
    assert_eq!((first.scanned, first.embedded, first.unchanged), (1, 2, 0));
    assert_eq!(model.names_sent(), ["小明", "Xiao Ming"]);

    let second = fixture.reconcile(&model);
    assert_eq!(
        (second.embedded, second.unchanged, second.removed),
        (0, 2, 0)
    );
    assert_eq!(model.calls(), 1, "a pass with nothing owed sends nothing");
}

/// An edited alias is embedded once its edit publishes; the dropped alias is
/// never sent again, and no vector of it is left for a pass to remove.
#[test]
fn an_edited_alias_is_embedded_again() {
    let fixture = fixture();
    let id = fixture.person("小明", &["Xiao Ming"]);
    let model = NameModel::new("m1");
    assert_eq!(fixture.reconcile(&model).embedded, 2);

    fixture.put_person(&id, "小明", &["Showming"]);
    fixture.publish_edits();
    let sent_before = model.names_sent().len();
    let after_edit = fixture.reconcile(&model);
    let sent: Vec<String> = model.names_sent().split_off(sent_before);
    assert!(
        sent.iter().any(|name| name == "Showming"),
        "the new alias is embedded: {sent:?}"
    );
    assert!(
        !sent.iter().any(|name| name == "Xiao Ming"),
        "the dropped alias is not embedded again: {sent:?}"
    );
    assert_eq!(
        after_edit.removed, 0,
        "the publication dropped the old vectors in its own write"
    );

    let settled = fixture.reconcile(&model);
    assert_eq!(
        (settled.embedded, settled.unchanged, settled.removed),
        (0, 2, 0)
    );
}

/// A new model id makes every vector stale: each name is embedded again and
/// replaces its old model's vector.
#[test]
fn a_new_model_embeds_every_name_again() {
    let fixture = fixture();
    fixture.person("小明", &["Xiao Ming"]);
    assert_eq!(fixture.reconcile(&NameModel::new("m1")).embedded, 2);

    let second = NameModel::new("m2");
    let moved = fixture.reconcile(&second);
    assert_eq!((moved.embedded, moved.removed, moved.unchanged), (2, 2, 0));
    let settled = fixture.reconcile(&second);
    assert_eq!((settled.embedded, settled.unchanged), (0, 2));
}

/// Canon `#open` Q5: an erased entity keeps no vector. The delete drops
/// them in its own write, so the next pass finds none to remove and embeds
/// nothing.
#[test]
fn an_erased_entity_keeps_no_phonetic_vector() {
    let fixture = fixture();
    let id = fixture.person("小明", &["Xiao Ming"]);
    let model = NameModel::new("m1");
    assert_eq!(fixture.reconcile(&model).embedded, 2);

    assert!(fixture.vault.delete_entity(&id).expect("delete"));
    let after = fixture.reconcile(&model);
    assert_eq!(
        (after.embedded, after.unchanged, after.removed),
        (0, 0, 0),
        "{after:?}"
    );
    assert_eq!(model.calls(), 1);
}

/// FIX 382 for names: a third-party model with no gate is refused, and one
/// with a gate reads only what it allows.
#[test]
fn a_third_party_embedder_without_a_gate_is_refused() {
    let fixture = fixture();
    fixture.person("小明", &["Xiao Ming"]);
    let model = NameModel::new("m1").at(EmbedderLocality::ThirdParty);

    let refused = fixture.vault.reconcile_phonetic_embeddings(&model, 100);
    assert!(
        matches!(refused, Err(Error::InvalidConfig(_))),
        "{refused:?}"
    );

    let held = fixture
        .vault
        .reconcile_phonetic_embeddings_admitted(
            &model,
            100,
            Some(&NameGate(EgressDecision::NoVerdict)),
        )
        .expect("gated pass");
    assert_eq!((held.withheld, held.embedded), (2, 0));
    assert_eq!(model.calls(), 0, "a withheld name is never sent");

    let allowed = fixture
        .vault
        .reconcile_phonetic_embeddings_admitted(&model, 100, Some(&NameGate(EgressDecision::Allow)))
        .expect("allowed pass");
    assert_eq!((allowed.withheld, allowed.embedded), (0, 2));
}

/// At most sixteen names an entity are embedded; the rest are counted.
#[test]
fn more_than_sixteen_names_are_counted_not_embedded() {
    let fixture = fixture();
    let aliases: Vec<String> = (1..20).map(|n| format!("Alias {n}")).collect();
    let aliases: Vec<&str> = aliases.iter().map(String::as_str).collect();
    fixture.person("Main Name", &aliases);

    let report = fixture.reconcile(&NameModel::new("m1"));
    assert_eq!((report.embedded, report.over_name_cap), (16, 4));
}

/// A model answer of another width stores nothing; a later good pass embeds
/// every name.
#[test]
fn an_answer_of_another_width_stores_nothing() {
    let fixture = fixture();
    fixture.person("小明", &["Xiao Ming"]);
    let mut narrow = NameModel::new("m1");
    narrow.answer_width = 4;

    let refused = fixture.vault.reconcile_phonetic_embeddings(&narrow, 100);
    assert!(
        matches!(
            refused,
            Err(Error::DimensionMismatch {
                expected: WIDTH,
                got: 4
            })
        ),
        "{refused:?}"
    );
    assert_eq!(fixture.reconcile(&NameModel::new("m1")).embedded, 2);
}
