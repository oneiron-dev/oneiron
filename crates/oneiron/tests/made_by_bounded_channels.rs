//! [MADE-BY-BOUNDED-CHANNELS]: a call's `made_by` predicate (Rule A, OF-466)
//! decides inside the bounded vector, text and temporal channels, so a row
//! the call drops takes no place in their fetch. Before, the predicate ran
//! only after the blend: a stated-only call whose channel fetched only
//! concluded rows returned nothing while a stated row sat just past the cut.
//! The temporal window's bound counts only the slice's rows, and a PPR
//! walk's results and the phonetic exact-code hits take the slice before
//! the blend, so a dropped row neither counts as a candidate nor seeds an
//! implicit expansion (REVIEW-9842).
//! Births are stamped through a test door: run the file with
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron
//! --all-features --test made_by_bounded_channels`.
#![cfg(oneiron_test_support)]

use oneiron::batch::generate_phonetic_codes;
use oneiron::pipeline::RetrievalParams;
use oneiron::registry::ENTITY_TYPE_PERSON;
use oneiron::test_doors::sound_match_birth::put_born_at;
use oneiron::write_envelope::provenance::made_by::{MadeByClass, MadeByPredicate};
use oneiron::{
    ClaimApprovalStatus, ClaimCandidate, ClaimSource, ClaimSubject, EdgeActorClass, EdgeKind,
    EntityId, PipelineBuilder, TimeRange, Vault, VaultConfig, WriteActor, WriteEnvelope,
    WriteProvenance,
};
use oneiron_retrieval::fusion::FUSION_LIST_LENGTH;

const DAY: u64 = 86_400;
const NOW: u64 = 1_700_000_000;
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
/// What a one-row call's temporal channel fetches: the fusion floor. With a
/// widening multiple of 1 and no floor, a sliced call's window keeps at
/// most this many rows, fewer than `CONCLUDED_ROWS`, and its scan reads up
/// to four times as many per axis.
const CHANNEL_FETCH_FLOOR: usize = FUSION_LIST_LENGTH;
/// The walk fixture's names: no phonetic code of one is a code of the other.
const WALK_STATED_NAME: &str = "Bilby";
const WALK_CONCLUDED_NAME: &str = "Numbat";

struct Fixture {
    _dir: tempfile::TempDir,
    vault: Vault,
    concluded: Vec<EntityId>,
}

fn fixture() -> Fixture {
    fixture_with_capture(false)
}

/// A fixture whose runs record their telemetry when `capture` is set, so a
/// test reads the run's candidate count.
fn fixture_with_capture(capture: bool) -> Fixture {
    let dir = tempfile::tempdir().expect("temporary vault");
    let mut config = VaultConfig::device();
    config.dimensions = DIMENSIONS;
    // A vector write needs a declared embedding model.
    config.embedding_model = Some("test/model@v1".to_owned());
    config.retrieval_telemetry_capture = capture;
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

    /// `CONCLUDED_ROWS` concluded rows made from `input`, each ranked above
    /// the stated row on every channel: a vector at cosine 0.89 or more, the
    /// query word three times, and a time within `CONCLUDED_ROWS` minutes
    /// before the anchor. Before it, a row nearer the anchor is also learned
    /// later, so the temporal channel's own recency term ranks it higher too.
    fn concluded_rows(&mut self, input: EntityId) {
        for index in 0..CONCLUDED_ROWS {
            let step = u64::try_from(index + 1).expect("small index");
            let lean = 0.005 * f32::from(u16::try_from(index + 1).expect("small index"));
            let id = self.born(
                &format!("concluded {index}"),
                MadeByClass::Concluded,
                &[input],
                (
                    ANCHOR - 60 * step,
                    &unit([1.0, lean, 0.0, 0.0]),
                    CONCLUDED_TEXT,
                ),
            );
            self.concluded.push(id);
        }
    }

    /// The stated row, ranked below every concluded row on every channel,
    /// then the concluded rows made from it.
    fn stated_behind_concluded(&mut self) -> EntityId {
        let past = u64::try_from(CONCLUDED_ROWS + 1).expect("small count");
        let stated = self.born(
            "stated",
            MadeByClass::Stated,
            &[],
            (ANCHOR - 60 * past, &far_vector(), STATED_TEXT),
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
        self.temporal_with(made_by, RetrievalParams::shipped())
    }

    fn temporal_with(&self, made_by: MadeByPredicate, params: RetrievalParams) -> Vec<EntityId> {
        ids(self
            .vault
            .query()
            .with_temporal_now(NOW)
            .search_temporal(ANCHOR, ANCHOR, 1)
            .boost_recency(0.0)
            .retrieval_params(params)
            .made_by(made_by)
            .limit(1)
            .run())
    }

    /// A stated row and a concluded row made from it, with an edge from the
    /// concluded row to the stated one for a walk to follow.
    fn concluded_about_stated(&self) -> (EntityId, EntityId) {
        let stated = self.born(
            WALK_STATED_NAME,
            MadeByClass::Stated,
            &[],
            (ANCHOR, &far_vector(), STATED_TEXT),
        );
        let concluded = self.born(
            WALK_CONCLUDED_NAME,
            MadeByClass::Concluded,
            &[stated],
            (ANCHOR, &query_vector(), CONCLUDED_TEXT),
        );
        self.vault
            .put_edge(&concluded, EdgeKind::About, &stated, 1.0)
            .expect("FIXTURE: link the concluded row to the stated one");
        (stated, concluded)
    }

    /// A PPR search of `searched` at depth 0, run as [`Self::counted`].
    fn walk(
        &self,
        made_by: MadeByPredicate,
        searched: &[EntityId],
        expand: Option<&[EntityId]>,
    ) -> (Vec<EntityId>, usize) {
        self.counted(self.vault.query().search_ppr(searched, 0), made_by, expand)
    }

    /// A phonetic search for `codes`, run as [`Self::counted`].
    fn phonetic(
        &self,
        made_by: MadeByPredicate,
        codes: &[String],
        expand: Option<&[EntityId]>,
    ) -> (Vec<EntityId>, usize) {
        let codes: Vec<&str> = codes.iter().map(String::as_str).collect();
        self.counted(self.vault.query().search_phonetic(&codes), made_by, expand)
    }

    /// Runs `query` under `made_by`, then, when `expand` is `Some`, an
    /// expansion one hop out from those seeds and the query's top results.
    /// Returns the result ids and the run's recorded count of candidates in
    /// scope.
    fn counted(
        &self,
        query: PipelineBuilder<'_>,
        made_by: MadeByPredicate,
        expand: Option<&[EntityId]>,
    ) -> (Vec<EntityId>, usize) {
        let query = match expand {
            Some(seeds) => query.expand_ppr(seeds, 1),
            None => query,
        };
        let run = query
            .made_by(made_by)
            .limit(10)
            .capture_retrieval_trace(true)
            .run_with_telemetry()
            .expect("query");
        let run_id = run
            .run_id
            .expect("FIXTURE: a captured run names its record");
        let record = self
            .vault
            .retrieval_run(run_id)
            .expect("read the run record")
            .expect("FIXTURE: the run record is readable");
        (
            run.value.into_iter().map(|row| row.id).collect(),
            record.total_in_scope,
        )
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

/// The temporal channel: the stated row is farther before the anchor than
/// every concluded row, so it ranks below them all, and a stated-only query
/// still finds it.
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

/// The temporal window's bound counts only the slice's rows: with a bound
/// of `CHANNEL_FETCH_FLOOR` rows, below the concluded rows nearer the anchor,
/// a stated-only call still finds the stated row. Before, the window kept
/// its nearest rows up to the bound and the slice then dropped them all
/// (REVIEW-9842 P1 1).
#[test]
fn a_stated_row_past_the_temporal_window_bound_is_found() {
    let mut fixture = fixture();
    let stated = fixture.stated_behind_concluded();
    let tight = RetrievalParams {
        temporal_widening_multiple: 1,
        temporal_widening_floor: 0,
        ..RetrievalParams::shipped()
    };
    assert!(
        CHANNEL_FETCH_FLOOR < CONCLUDED_ROWS,
        "FIXTURE: more concluded rows than the window keeps"
    );
    let unsliced = fixture.temporal_with(MadeByPredicate::All, tight);
    assert!(
        unsliced.len() == 1 && fixture.concluded.contains(&unsliced[0]),
        "FIXTURE: a concluded row ranks first, got {unsliced:?}"
    );
    assert_eq!(
        fixture.temporal_with(MadeByPredicate::Stated, tight),
        [stated],
        "a stated-only call finds the stated row past the window's bound"
    );
}

/// A PPR result the slice drops neither counts as a candidate nor seeds an
/// implicit expansion (REVIEW-9842 P1 2): a stated-only call that searches
/// from a concluded row finds nothing, counts nothing, and does not expand
/// from it to the stated row it is about. Before, the concluded row counted
/// as one candidate and seeded the expansion that found the stated row.
#[test]
fn an_out_of_slice_walk_result_neither_counts_nor_seeds() {
    let fixture = fixture_with_capture(true);
    let (stated, concluded) = fixture.concluded_about_stated();
    let (searched, _) = fixture.walk(MadeByPredicate::All, &[concluded], None);
    assert_eq!(
        searched,
        [concluded],
        "FIXTURE: a depth-0 search returns its seed"
    );
    let (expanded, _) = fixture.walk(MadeByPredicate::All, &[concluded], Some(&[]));
    assert!(
        expanded.contains(&stated),
        "FIXTURE: the expansion from the search's result reaches the stated row, got {expanded:?}"
    );
    assert_eq!(
        fixture.walk(MadeByPredicate::Stated, &[concluded], None),
        (Vec::new(), 0),
        "a stated-only search counts no concluded candidate"
    );
    assert_eq!(
        fixture
            .walk(MadeByPredicate::Stated, &[concluded], Some(&[]))
            .0,
        Vec::<EntityId>::new(),
        "a concluded row the call drops seeds no implicit expansion"
    );
}

/// The phonetic channel's exact codes have no cut, so their hits reached
/// the blend unasked: under a stated-only call, a concluded row holding the
/// query's exact code counted as a candidate and seeded an implicit
/// expansion to the stated row it is about. Now the slice keeps such a hit
/// out of the blend (REVIEW-9842 P1 2, its phonetic path).
#[test]
fn an_out_of_slice_exact_phonetic_hit_neither_counts_nor_seeds() {
    let fixture = fixture_with_capture(true);
    let (stated, concluded) = fixture.concluded_about_stated();
    let exact: Vec<String> = generate_phonetic_codes(WALK_CONCLUDED_NAME)
        .into_iter()
        .filter(|code| !code.starts_with("ipa:"))
        .collect();
    assert!(!exact.is_empty(), "FIXTURE: the name has exact codes");
    let (found, _) = fixture.phonetic(MadeByPredicate::All, &exact, None);
    assert_eq!(
        found,
        [concluded],
        "FIXTURE: the exact codes find the concluded row alone"
    );
    let (expanded, _) = fixture.phonetic(MadeByPredicate::All, &exact, Some(&[]));
    assert!(
        expanded.contains(&stated),
        "FIXTURE: the expansion from the hit reaches the stated row, got {expanded:?}"
    );
    assert_eq!(
        fixture.phonetic(MadeByPredicate::Stated, &exact, None),
        (Vec::new(), 0),
        "a stated-only phonetic search counts no concluded candidate"
    );
    assert_eq!(
        fixture
            .phonetic(MadeByPredicate::Stated, &exact, Some(&[]))
            .0,
        Vec::<EntityId>::new(),
        "a concluded exact hit the call drops seeds no implicit expansion"
    );
}

/// Guard: an explicit expansion seed is the caller's own, so a stated-only
/// call still expands from a concluded seed and finds the stated row.
#[test]
fn an_explicit_out_of_slice_seed_still_expands() {
    let fixture = fixture_with_capture(true);
    let (stated, concluded) = fixture.concluded_about_stated();
    assert_eq!(
        fixture
            .walk(MadeByPredicate::Stated, &[concluded], Some(&[concluded]))
            .0,
        [stated]
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
