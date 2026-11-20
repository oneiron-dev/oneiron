//! [MADE-BY-BOUNDED-CHANNELS]: a call's `made_by` predicate (Rule A, OF-466)
//! decides inside the bounded vector, text and temporal channels, so a row
//! the call drops takes no place in their fetch. Before, the predicate ran
//! only after the blend: a stated-only call whose channel fetched only
//! concluded rows returned nothing while a stated row sat just past the cut.
//! Births are stamped through a test door: run the file with
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron
//! --all-features --test made_by_bounded_channels`.
#![cfg(oneiron_test_support)]

use oneiron::registry::ENTITY_TYPE_PERSON;
use oneiron::test_doors::sound_match_birth::put_born_at;
use oneiron::write_envelope::provenance::made_by::{MadeByClass, MadeByPredicate};
use oneiron::{
    ClaimApprovalStatus, ClaimCandidate, ClaimSource, ClaimSubject, EdgeActorClass, EntityId,
    TimeRange, Vault, VaultConfig, WriteActor, WriteEnvelope, WriteProvenance,
};

const DAY: u64 = 86_400;
const NOW: u64 = 1_800_000_000;
const ANCHOR: u64 = NOW - 10 * DAY;
/// More concluded rows than a channel fetches while its scope does not
/// widen it (the fusion floor, 80 rows), and fewer than a widened window
/// holds (vector 1,000 rows; temporal the vault's entity count, up to 4,000).
const CONCLUDED_ROWS: usize = 100;
const DIMENSIONS: usize = 4;
const WORD: &str = "quokka";
/// Every concluded row says the query word three times in three words.
const CONCLUDED_TEXT: &str = "quokka quokka quokka";
/// The stated row says it once among eight words, so BM25 ranks it below
/// every concluded row.
const STATED_TEXT: &str = "quokka wombat wallaby numbat bilby dingo echidna platypus";

struct Fixture {
    _dir: tempfile::TempDir,
    vault: Vault,
    concluded: Vec<EntityId>,
}

fn fixture() -> Fixture {
    let dir = tempfile::tempdir().expect("temporary vault");
    let mut config = VaultConfig::device();
    config.dimensions = DIMENSIONS;
    config.embedding_model = None;
    let vault = Vault::open(dir.path(), config).expect("open vault");
    Fixture {
        _dir: dir,
        vault,
        concluded: Vec::new(),
    }
}

fn unit(vector: [f32; DIMENSIONS]) -> Vec<f32> {
    let norm = vector.iter().map(|value| value * value).sum::<f32>().sqrt();
    vector.iter().map(|value| value / norm).collect()
}

/// The query vector every vector test asks with.
fn query_vector() -> Vec<f32> {
    unit([1.0, 0.0, 0.0, 0.0])
}

/// A vector at cosine 0.707 to the query: farther than every concluded row.
fn far_vector() -> Vec<f32> {
    unit([1.0, 0.0, 1.0, 0.0])
}

fn person_body(name: &str) -> Vec<u8> {
    rmp_serde::to_vec_named(&serde_json::json!({ "name": name })).expect("body")
}

impl Fixture {
    /// One PERSON born as `class` at `at`, with `vector` and the lexical
    /// body `text`. A concluded row names `inputs`.
    fn born(
        &self,
        name: &str,
        class: MadeByClass,
        inputs: &[EntityId],
        (at, vector, text): (u64, &[f32], &str),
    ) -> EntityId {
        let id = put_born_at(
            &self.vault,
            ENTITY_TYPE_PERSON,
            &person_body(name),
            class,
            inputs,
            at,
        )
        .expect("FIXTURE: put the born person");
        self.vault
            .put_vector(&id, vector)
            .expect("FIXTURE: put the vector");
        self.vault
            .batch()
            .text(&id, &[("body", text)])
            .commit()
            .expect("FIXTURE: index the text");
        id
    }

    /// `CONCLUDED_ROWS` concluded rows made from `input`, each nearer the
    /// query than the stated row on every channel: a vector at cosine 0.92
    /// or more, the query word three times, and a time within
    /// `CONCLUDED_ROWS` minutes of the anchor.
    fn concluded_rows(&mut self, input: EntityId) {
        for index in 0..CONCLUDED_ROWS {
            let step = u64::try_from(index + 1).expect("small index");
            let lean = 0.005 * f32::from(u16::try_from(index + 1).expect("small index"));
            let id = self.born(
                &format!("concluded {index}"),
                MadeByClass::Concluded,
                &[input],
                (
                    ANCHOR + 60 * step,
                    &unit([1.0, lean, 0.0, 0.0]),
                    CONCLUDED_TEXT,
                ),
            );
            self.concluded.push(id);
        }
    }

    /// The stated row, farther from the query than every concluded row on
    /// every channel, then the concluded rows made from it.
    fn stated_behind_concluded(&mut self) -> EntityId {
        let past = u64::try_from(CONCLUDED_ROWS + 1).expect("small count");
        let stated = self.born(
            "stated",
            MadeByClass::Stated,
            &[],
            (ANCHOR + 60 * past, &far_vector(), STATED_TEXT),
        );
        self.concluded_rows(stated);
        stated
    }

    fn vector(&self, made_by: MadeByPredicate, query: &[f32]) -> Vec<EntityId> {
        ids(self
            .vault
            .query()
            .search_vector(query, 1)
            .made_by(made_by)
            .limit(1)
            .run())
    }

    /// A text query with no recency blend: the blend's recency widens the
    /// text fetch fourfold, past every concluded row.
    fn text(&self, made_by: MadeByPredicate) -> Vec<EntityId> {
        ids(self
            .vault
            .query()
            .search_text(WORD, 1)
            .boost_recency(0.0)
            .made_by(made_by)
            .limit(1)
            .run())
    }

    fn temporal(&self, made_by: MadeByPredicate) -> Vec<EntityId> {
        ids(self
            .vault
            .query()
            .with_temporal_now(NOW)
            .search_temporal(ANCHOR, ANCHOR, 1)
            .boost_recency(0.0)
            .made_by(made_by)
            .limit(1)
            .run())
    }
}

fn ids(rows: oneiron::Result<Vec<oneiron::ScoredEntity>>) -> Vec<EntityId> {
    rows.expect("query").into_iter().map(|row| row.id).collect()
}

/// A stated-only vector query finds the stated row behind more concluded
/// rows than the channel fetches. Before, the channel fetched only
/// concluded rows and the post-blend filter dropped them all: no hit.
#[test]
fn a_stated_row_past_the_vector_fetch_is_found() {
    let mut fixture = fixture();
    let stated = fixture.stated_behind_concluded();
    assert_eq!(
        fixture.vector(MadeByPredicate::All, &far_vector()),
        [stated],
        "FIXTURE: the run reads the stated row's vector"
    );
    assert_eq!(
        fixture.vector(MadeByPredicate::Stated, &query_vector()),
        [stated],
        "a stated-only call finds the stated row past the concluded ones"
    );
}

/// A claim with no stamped birth takes its class from its source: the
/// bounded channel reads the admitted claim body for it, as the post-blend
/// filter does, so an unborn UserStated claim behind concluded rows is
/// still found.
#[test]
fn an_unborn_stated_claim_past_the_vector_fetch_is_found() {
    let mut fixture = fixture();
    let claim = put_stated_claim(&fixture.vault);
    fixture
        .vault
        .put_vector(&claim, &far_vector())
        .expect("FIXTURE: put the claim's vector");
    assert!(
        fixture
            .vault
            .row_birth(&claim)
            .expect("FIXTURE: read the birth")
            .is_none(),
        "FIXTURE: the claim has no stamped birth"
    );
    fixture.concluded_rows(claim);
    assert_eq!(
        fixture.vector(MadeByPredicate::All, &far_vector()),
        [claim],
        "FIXTURE: the run reads the claim"
    );
    assert_eq!(
        fixture.vector(MadeByPredicate::Stated, &query_vector()),
        [claim],
        "a stated-only call finds the unborn stated claim past the concluded rows"
    );
}

/// The text channel: the stated row ranks below every concluded row, and a
/// stated-only query still finds it.
#[test]
fn a_stated_row_past_the_text_fetch_is_found() {
    let mut fixture = fixture();
    let stated = fixture.stated_behind_concluded();
    let unsliced = fixture.text(MadeByPredicate::All);
    assert!(
        unsliced.len() == 1 && fixture.concluded.contains(&unsliced[0]),
        "FIXTURE: a concluded row ranks first, got {unsliced:?}"
    );
    assert_eq!(
        fixture.text(MadeByPredicate::Stated),
        [stated],
        "a stated-only call finds the stated row past the concluded ones"
    );
}

/// The temporal channel: the stated row is farther from the anchor than
/// every concluded row, and a stated-only query still finds it.
#[test]
fn a_stated_row_past_the_temporal_fetch_is_found() {
    let mut fixture = fixture();
    let stated = fixture.stated_behind_concluded();
    let unsliced = fixture.temporal(MadeByPredicate::All);
    assert!(
        unsliced.len() == 1 && fixture.concluded.contains(&unsliced[0]),
        "FIXTURE: a concluded row ranks first, got {unsliced:?}"
    );
    assert_eq!(
        fixture.temporal(MadeByPredicate::Stated),
        [stated],
        "a stated-only call finds the stated row past the concluded ones"
    );
}

/// Guard: a call with no predicate, or one the nearest rows match, still
/// finds a concluded row first on each channel (the nearest one by vector).
#[test]
fn a_call_the_nearest_rows_match_keeps_its_nearest_row() {
    let mut fixture = fixture();
    fixture.stated_behind_concluded();
    let nearest = fixture.concluded[0];
    for made_by in [MadeByPredicate::All, MadeByPredicate::Concluded] {
        assert_eq!(
            fixture.vector(made_by, &query_vector()),
            [nearest],
            "vector, {made_by:?}"
        );
        for (channel, found) in [
            ("temporal", fixture.temporal(made_by)),
            ("text", fixture.text(made_by)),
        ] {
            assert!(
                found.len() == 1 && fixture.concluded.contains(&found[0]),
                "{channel}, {made_by:?}: {found:?}"
            );
        }
    }
}

/// One live, UserStated claim by a human writer about a person, written
/// through the public batch (no birth stamp), as
/// `tests/vault_embedding_spaces_doors.rs` writes it.
fn put_stated_claim(vault: &Vault) -> EntityId {
    let actor = WriteActor::new(EntityId::now(), EdgeActorClass::Human);
    let subject = EntityId::now();
    for id in [actor.entity_ref(), subject] {
        vault
            .put_entity(
                &id,
                ENTITY_TYPE_PERSON,
                TimeRange { start: 1, end: 1 },
                1,
                b"",
            )
            .expect("FIXTURE: put person");
    }
    let envelope = WriteEnvelope::new(
        actor,
        ClaimSource::UserStated,
        WriteProvenance::new(rmpv::Value::from("made_by bounded channels"))
            .expect("FIXTURE: provenance"),
        ClaimApprovalStatus::Auto,
    );
    let claim = EntityId::now();
    vault
        .batch()
        .claim_candidate(
            &claim,
            ClaimCandidate::new(
                "profile.made_by_bounded",
                ClaimSubject::Entity(subject),
                rmpv::Value::from("fact"),
                1.0,
            ),
            &envelope,
            TimeRange { start: 10, end: 99 },
            10,
        )
        .commit()
        .expect("FIXTURE: write the claim");
    claim
}
