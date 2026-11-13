//! The PERSON-vector producer (FIX LINKER-PERSON-VECTOR-PRODUCER, ruling
//! PERSON-VECTOR-CHOICES = A): a PERSON embeds its public (band 0) `about`
//! line, the line the Dreamer writes from only the person's public facts.
//! A landing of the lines and the owner's revert of one mark the person in
//! their own write; the embed worker reads the line at lease and fills the
//! vector; idle publication never embeds a PERSON's body.
//!
//! Needs the doors:
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron
//! --all-features --test person_vector_producer`.
#![cfg(oneiron_test_support)]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::sync::{Arc, Mutex};

use oneiron::claim::{
    ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus, ClaimSource, ClaimSubject,
};
use oneiron::embed::{
    Embedder, EmbedderLocality, PendingEmbeddingInput, PendingEmbeddingPayload,
    PendingEmbeddingReconcileReport, PendingEmbeddingReconciler,
};
use oneiron::memory::{IndexedRevisionEmbedder, IndexedRevisionInput};
use oneiron::registry::ENTITY_TYPE_PERSON;
use oneiron::temporal::TimeRange;
use oneiron::test_doors::consolidation::open_dreamer_vault_with;
use oneiron::test_doors::derive::{About, Derived, Named, about_facts, commit, revert};
use oneiron::test_doors::steward::dreamer;
use oneiron::{EdgeActorClass, EntityId, Vault, VaultConfig};

const READER: &str = "reader";
const MODEL: &str = "fixture/vectors@v1";
/// Four dimensions, so each test vector is exact in the stored f16 row.
const DIMENSIONS: usize = 4;
/// The public line, and the vector the test embedder gives it.
const PUBLIC_LINE: &str = "Owen climbs mountains on weekends.";
const PUBLIC_VECTOR: [f32; DIMENSIONS] = [1.0, 0.0, 0.0, 0.0];
/// A line of a band above the public one.
const PRIVATE_LINE: &str = "Owen keeps a private diary.";
const PRIVATE_VECTOR: [f32; DIMENSIONS] = [0.0, 1.0, 0.0, 0.0];
/// A later landing's public line.
const NEW_LINE: &str = "Owen runs the budget forecast.";
const NEW_VECTOR: [f32; DIMENSIONS] = [0.0, 0.0, 1.0, 0.0];
/// Any other text: a claim body, a PERSON body's fields.
const OTHER_VECTOR: [f32; DIMENSIONS] = [0.0, 0.0, 0.0, 1.0];

type Hook = Box<dyn FnOnce() + Send>;

/// An on-device embedder that answers each line with its fixed vector and
/// records every input it was sent. `during_embed` runs once, inside the
/// first `embed` call, after the pass leased its work and before it fills.
#[derive(Default)]
struct LineVectors {
    sent: Mutex<Vec<PendingEmbeddingInput>>,
    during_embed: Mutex<Option<Hook>>,
}

fn vector_of(text: &str) -> [f32; DIMENSIONS] {
    match text {
        PUBLIC_LINE => PUBLIC_VECTOR,
        PRIVATE_LINE => PRIVATE_VECTOR,
        NEW_LINE => NEW_VECTOR,
        _ => OTHER_VECTOR,
    }
}

impl Embedder for LineVectors {
    fn model_id(&self) -> &str {
        MODEL
    }

    fn dimensions(&self) -> usize {
        DIMENSIONS
    }

    fn locality(&self) -> EmbedderLocality {
        EmbedderLocality::OnDevice
    }

    fn embed(&self, inputs: &[PendingEmbeddingInput]) -> oneiron::Result<Vec<Vec<f32>>> {
        self.sent.lock().unwrap().extend(inputs.iter().cloned());
        let hook = self.during_embed.lock().unwrap().take();
        if let Some(hook) = hook {
            hook();
        }
        Ok(inputs
            .iter()
            .map(|input| match &input.payload {
                PendingEmbeddingPayload::SummaryText(text)
                | PendingEmbeddingPayload::TurnText(text) => vector_of(text).to_vec(),
                PendingEmbeddingPayload::ClaimBody(_) => OTHER_VECTOR.to_vec(),
            })
            .collect())
    }
}

/// The idle publisher's embedder: records each record it embeds.
#[derive(Default)]
struct BodyVectors {
    embedded: Mutex<Vec<EntityId>>,
}

impl IndexedRevisionEmbedder for BodyVectors {
    fn embed_revision(&self, input: &IndexedRevisionInput) -> oneiron::Result<Vec<f32>> {
        self.embedded.lock().unwrap().push(input.entity);
        Ok(OTHER_VECTOR.to_vec())
    }
}

struct Fixture {
    _dir: tempfile::TempDir,
    vault: Arc<Vault>,
    dreamer: EntityId,
    person: EntityId,
    embedder: Arc<LineVectors>,
}

/// A Dreamer vault with an embedding model over [`DIMENSIONS`], and one
/// person with one stated, approved fact whose sensitivity stamp is `band`.
fn fixture(band: &str) -> Fixture {
    let dir = tempfile::tempdir().expect("tempdir");
    let mut config = VaultConfig::device();
    config.dimensions = DIMENSIONS;
    config.embedding_model = Some(MODEL.to_owned());
    let vault = Arc::new(open_dreamer_vault_with(dir.path(), READER, config).expect("vault"));
    let dreamer = dreamer(&vault).expect("the Dreamer");
    let at = vault.now_recorded_at();
    let person = EntityId::now();
    vault
        .put_entity(
            &person,
            ENTITY_TYPE_PERSON,
            TimeRange { start: at, end: at },
            at,
            b"someone",
        )
        .expect("a person");
    let mut body = ClaimBody::new(
        "profile.hobby",
        ClaimSubject::Entity(person),
        rmpv::Value::from("climbing"),
        0.9,
        ClaimApprovalStatus::Approved,
        ClaimLifecycleStatus::Active,
    )
    .expect("a claim body");
    body.source = Some(ClaimSource::UserStated);
    body.scope = Some(rmpv::Value::Map(vec![(
        rmpv::Value::from("sensitivity"),
        rmpv::Value::from(band),
    )]));
    vault
        .put_claim(
            &EntityId::now(),
            &body,
            TimeRange { start: at, end: at },
            at,
        )
        .expect("a fact about the person");
    Fixture {
        _dir: dir,
        vault,
        dreamer,
        person,
        embedder: Arc::new(LineVectors::default()),
    }
}

/// Lands the person's `about` lines as the Dreamer, `line(band)` for each
/// band that takes one, after checking the bands the facts give. Returns the
/// batch.
fn land(fixture: &Fixture, bands: &[u8], line: fn(u8) -> &'static str) -> EntityId {
    let (digest, found) = about_facts(
        &fixture.vault,
        fixture.dreamer,
        EdgeActorClass::System,
        fixture.person,
    )
    .expect("facts");
    assert_eq!(found, bands, "FIXTURE: the bands the person's facts give");
    let committed = commit(
        &fixture.vault,
        fixture.dreamer,
        EdgeActorClass::System,
        "run-person-vector",
        &[Derived::About(About {
            local: "about",
            person: Named::Stored(fixture.person),
            written_from: digest,
            lines: bands.iter().map(|band| (*band, line(*band))).collect(),
        })],
    )
    .expect("commit");
    let [item] = committed.items.as_slice() else {
        panic!("FIXTURE: one item: {:?}", committed.items);
    };
    assert!(item.landed, "FIXTURE: the lines land: {:?}", item.reasons);
    committed.batch
}

fn public_then_private(band: u8) -> &'static str {
    if band == 0 { PUBLIC_LINE } else { PRIVATE_LINE }
}

fn new_then_private(band: u8) -> &'static str {
    if band == 0 { NEW_LINE } else { PRIVATE_LINE }
}

fn private(_band: u8) -> &'static str {
    PRIVATE_LINE
}

/// One embed worker pass over the fixture's vault.
fn reconcile(fixture: &Fixture) -> PendingEmbeddingReconcileReport {
    let embedder: Arc<dyn Embedder> = fixture.embedder.clone();
    PendingEmbeddingReconciler::new(Arc::clone(&fixture.vault), embedder)
        .reconcile_once()
        .expect("one embed pass")
}

/// Every payload the embed worker sent for the person, in order.
fn sent_for_person(fixture: &Fixture) -> Vec<PendingEmbeddingPayload> {
    fixture
        .embedder
        .sent
        .lock()
        .unwrap()
        .iter()
        .filter(|input| input.entity_id == fixture.person)
        .map(|input| input.payload.clone())
        .collect()
}

fn line_payload(line: &str) -> PendingEmbeddingPayload {
    PendingEmbeddingPayload::SummaryText(line.to_owned())
}

fn person_vector(fixture: &Fixture) -> Option<Vec<f32>> {
    fixture
        .vault
        .get_vector(&fixture.person)
        .expect("vector read")
}

/// The person's lines land, one public and three above it: the worker sends
/// the public line alone and stores its vector. RED on 261646dcccd: no
/// PERSON is embeddable there, so the person is sent nothing.
#[test]
fn a_landed_public_line_is_what_the_person_embeds() {
    let fixture = fixture("public");
    land(&fixture, &[0, 1, 2, 3], public_then_private);

    reconcile(&fixture);

    assert_eq!(
        sent_for_person(&fixture),
        vec![line_payload(PUBLIC_LINE)],
        "the worker sends the public line, never a line of a higher band"
    );
    assert_eq!(
        person_vector(&fixture),
        Some(PUBLIC_VECTOR.to_vec()),
        "the person holds the public line's vector"
    );
}

/// D1: a person whose only fact is above the public band has no public
/// line, so the worker sends it nothing and it holds no vector, whatever its
/// higher lines say. Green on 261646dcccd as well: a guard.
#[test]
fn a_person_with_no_public_fact_gets_no_vector() {
    let fixture = fixture("private");
    land(&fixture, &[1, 2, 3], private);

    reconcile(&fixture);

    assert!(
        sent_for_person(&fixture).is_empty(),
        "the person is sent nothing"
    );
    assert_eq!(person_vector(&fixture), None);
}

/// A later landing marks the person at its new line, and the next pass
/// replaces the vector. RED on 261646dcccd at the first vector.
#[test]
fn a_new_landing_replaces_the_vector() {
    let fixture = fixture("public");
    land(&fixture, &[0, 1, 2, 3], public_then_private);
    reconcile(&fixture);
    assert_eq!(person_vector(&fixture), Some(PUBLIC_VECTOR.to_vec()));

    land(&fixture, &[0, 1, 2, 3], new_then_private);
    reconcile(&fixture);

    assert_eq!(
        person_vector(&fixture),
        Some(NEW_VECTOR.to_vec()),
        "the vector follows the line the newest landing wrote"
    );
}

/// A landing that lands while the worker embeds the line before it: the
/// fill for the old line no longer matches the person's marker and is
/// dropped, and the next pass embeds the new line. RED on 261646dcccd: the
/// person is sent nothing and holds no vector after either pass.
#[test]
fn a_fill_for_a_replaced_line_is_dropped_and_the_new_line_embeds() {
    let fixture = fixture("public");
    land(&fixture, &[0, 1, 2, 3], public_then_private);
    {
        let vault = Arc::clone(&fixture.vault);
        let (dreamer, person) = (fixture.dreamer, fixture.person);
        *fixture.embedder.during_embed.lock().unwrap() = Some(Box::new(move || {
            let (digest, bands) =
                about_facts(&vault, dreamer, EdgeActorClass::System, person).expect("facts");
            let committed = commit(
                &vault,
                dreamer,
                EdgeActorClass::System,
                "run-person-vector-2",
                &[Derived::About(About {
                    local: "about",
                    person: Named::Stored(person),
                    written_from: digest,
                    lines: bands
                        .iter()
                        .map(|band| (*band, new_then_private(*band)))
                        .collect(),
                })],
            )
            .expect("commit");
            assert!(
                committed.items.iter().all(|item| item.landed),
                "FIXTURE: the new line lands mid-pass: {:?}",
                committed.items
            );
        }));
    }

    let first = reconcile(&fixture);

    assert_eq!(
        sent_for_person(&fixture),
        vec![line_payload(PUBLIC_LINE)],
        "FIXTURE: the pass leased the old line"
    );
    assert!(
        first.stale_fills >= 1,
        "the old line's fill is dropped as stale: {first:?}"
    );
    assert_eq!(
        person_vector(&fixture),
        None,
        "no vector of a line the person no longer has"
    );

    reconcile(&fixture);

    assert_eq!(
        person_vector(&fixture),
        Some(NEW_VECTOR.to_vec()),
        "the next pass embeds the new line"
    );
}

/// The Dreamer reverts its newest landing: the line it replaced stands
/// again, so the person is marked at that line and its vector comes back.
/// RED on 261646dcccd at the first vector.
#[test]
fn a_reverted_landing_puts_back_the_vector_of_the_line_it_restores() {
    let fixture = fixture("public");
    land(&fixture, &[0, 1, 2, 3], public_then_private);
    let newest = land(&fixture, &[0, 1, 2, 3], new_then_private);
    reconcile(&fixture);
    assert_eq!(person_vector(&fixture), Some(NEW_VECTOR.to_vec()));

    let (reverted, left) = revert(
        &fixture.vault,
        fixture.dreamer,
        EdgeActorClass::System,
        newest,
    )
    .expect("revert")
    .expect("FIXTURE: the Dreamer may revert its own batch");
    assert_eq!(reverted, vec!["about".to_owned()], "{left:?}");
    assert_eq!(
        fixture
            .vault
            .person_about(fixture.person, Some(0))
            .expect("read")
            .as_deref(),
        Some(PUBLIC_LINE),
        "FIXTURE: the revert shows the line it restored"
    );
    reconcile(&fixture);

    assert_eq!(
        person_vector(&fixture),
        Some(PUBLIC_VECTOR.to_vec()),
        "the vector follows the line the revert restored"
    );
}

/// D2: a PERSON body edit published at idle is never embedded from the
/// body's fields. Idle drops the vector beside it and marks the person
/// again, and the worker fills it from the public line. RED on 261646dcccd
/// at the first vector; past it there, idle embeds the body's fields.
#[test]
fn a_person_body_edit_is_refilled_from_the_line_not_the_body() {
    let fixture = fixture("public");
    land(&fixture, &[0, 1, 2, 3], public_then_private);
    reconcile(&fixture);
    assert_eq!(person_vector(&fixture), Some(PUBLIC_VECTOR.to_vec()));

    fixture
        .vault
        .set_indexed_idle_delay_ms(0)
        .expect("idle delay");
    let mut edited = Vec::new();
    rmpv::encode::write_value(
        &mut edited,
        &rmpv::Value::Map(vec![
            (rmpv::Value::from("name"), rmpv::Value::from("Owen")),
            (
                rmpv::Value::from("description"),
                rmpv::Value::from("Owen from the climbing club."),
            ),
        ]),
    )
    .expect("a PERSON body");
    let at = fixture.vault.now_recorded_at();
    fixture
        .vault
        .put_entity(
            &fixture.person,
            ENTITY_TYPE_PERSON,
            TimeRange { start: at, end: at },
            at,
            &edited,
        )
        .expect("the body edit");
    let idle = BodyVectors::default();
    let now_ms = u64::try_from(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock")
            .as_millis(),
    )
    .expect("ms")
        + 3_600_000;
    let published = fixture
        .vault
        .refresh_indexed_at_idle(now_ms, &idle)
        .expect("idle publication");

    assert!(
        published
            .refreshed
            .iter()
            .any(|(entity, _)| *entity == fixture.person),
        "FIXTURE: idle publishes the body edit: {published:?}"
    );
    assert!(
        !idle.embedded.lock().unwrap().contains(&fixture.person),
        "idle publication never embeds a PERSON's body"
    );
    reconcile(&fixture);
    assert_eq!(
        sent_for_person(&fixture),
        vec![line_payload(PUBLIC_LINE), line_payload(PUBLIC_LINE)],
        "the worker embeds the public line again, never the body"
    );
    assert_eq!(
        person_vector(&fixture),
        Some(PUBLIC_VECTOR.to_vec()),
        "the person's vector is its line's again"
    );
}

/// D3: a PERSON's vector is a hit of the shared vector index, as main's
/// type-agnostic vector channel already admits: a query at the public
/// line's vector finds the person first. RED on 261646dcccd: the person
/// holds no vector there, so the nearest hit is the fact.
#[test]
fn a_query_at_the_public_line_finds_the_person_in_the_vector_index() {
    let fixture = fixture("public");
    land(&fixture, &[0, 1, 2, 3], public_then_private);
    reconcile(&fixture);

    let hits = fixture
        .vault
        .search_vector(&PUBLIC_VECTOR, 3)
        .expect("vector search");

    assert_eq!(
        hits.first().map(|hit| hit.id),
        Some(fixture.person),
        "the person is the nearest hit: {hits:?}"
    );
}
