//! The PERSON-vector producer (FIX LINKER-PERSON-VECTOR-PRODUCER, ruling
//! PERSON-VECTOR-CHOICES = A): a PERSON embeds its public (band 0) `about`
//! line, the line the Dreamer writes from only the person's public facts.
//! A landing of the lines and the owner's revert of one mark the person in
//! their own write; the embed worker reads the line at lease and fills the
//! vector; idle publication never embeds a PERSON's body.
//!
//! The vector stays while a plain CLAIM write hides the line, and goes where
//! the facts its line was written from go (ruling D4): an erase, a door that
//! drops a fact (the Dreamer's archive), and the wake pass that clears the
//! lines of a person with no facts left. A wake pass that shows a line again
//! with no landing marks a person whose vector went while it was hidden.
//!
//! Needs the doors and the embed worker (`sync`):
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron
//! --all-features --test person_vector_producer`.
#![cfg(all(oneiron_test_support, feature = "sync"))]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::sync::{Arc, Mutex};

use oneiron::claim::{
    ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus, ClaimSource, ClaimSubject,
};
use oneiron::embed::{
    Embedder, EmbedderLocality, PendingEmbeddingInput, PendingEmbeddingPayload,
    PendingEmbeddingReconcileReport, PendingEmbeddingReconciler,
};
use oneiron::memory::{IndexedRefreshReport, IndexedRevisionEmbedder, IndexedRevisionInput};
use oneiron::registry::ENTITY_TYPE_PERSON;
use oneiron::temporal::TimeRange;
use oneiron::test_doors::consolidation::{consolidate_unbound_turn, open_dreamer_vault_with};
use oneiron::test_doors::derive::{
    About, Archive, Derived, Named, about_facts, claim_subject, commit, commit_in_attempt, revert,
    wake_reads_about_facts,
};
use oneiron::test_doors::steward::{
    STEWARD_VERBS, archive_every_quiet_claim, dreamer, revoke_base_agent_bindings,
    stand_steward_grant,
};
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
    /// The person's stated fact.
    fact: EntityId,
    embedder: Arc<LineVectors>,
}

/// A Dreamer vault with an embedding model over [`DIMENSIONS`].
fn open_vault(dir: &tempfile::TempDir) -> Arc<Vault> {
    let mut config = VaultConfig::device();
    config.dimensions = DIMENSIONS;
    config.embedding_model = Some(MODEL.to_owned());
    Arc::new(open_dreamer_vault_with(dir.path(), READER, config).expect("vault"))
}

/// Puts a stated, approved fact `predicate: value` about `person`, whose
/// sensitivity stamp is `band`. Returns the fact.
fn put_fact(vault: &Vault, person: EntityId, predicate: &str, value: &str, band: &str) -> EntityId {
    let mut body = ClaimBody::new(
        predicate,
        ClaimSubject::Entity(person),
        rmpv::Value::from(value),
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
    let at = vault.now_recorded_at();
    let fact = EntityId::now();
    vault
        .put_claim(&fact, &body, TimeRange { start: at, end: at }, at)
        .expect("a fact about the person");
    fact
}

/// A Dreamer vault with an embedding model over [`DIMENSIONS`], and one
/// person with one stated, approved fact whose sensitivity stamp is `band`.
fn fixture(band: &str) -> Fixture {
    fixture_with_body(band, b"someone")
}

/// [`fixture`] with the person's body `body`: an empty one is a live
/// zero-byte payload.
fn fixture_with_body(band: &str, body: &[u8]) -> Fixture {
    let dir = tempfile::tempdir().expect("tempdir");
    let vault = open_vault(&dir);
    let dreamer = dreamer(&vault).expect("the Dreamer");
    let at = vault.now_recorded_at();
    let person = EntityId::now();
    vault
        .put_entity(
            &person,
            ENTITY_TYPE_PERSON,
            TimeRange { start: at, end: at },
            at,
            body,
        )
        .expect("a person");
    let fact = put_fact(&vault, person, "profile.hobby", "climbing", band);
    Fixture {
        _dir: dir,
        vault,
        dreamer,
        person,
        fact,
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

/// Embed worker passes until one leases nothing: a swap queues every
/// embeddable record again, more than one pass may lease.
fn reconcile_all(fixture: &Fixture) {
    for _ in 0..20 {
        let report = reconcile(fixture);
        if report.leased == 0 && report.stale_jobs == 0 {
            return;
        }
    }
    panic!("FIXTURE: the queue drains in 20 passes");
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

/// One idle publication pass, an hour on, with no idle delay.
fn publish_at_idle(fixture: &Fixture, idle: &BodyVectors) -> IndexedRefreshReport {
    fixture
        .vault
        .set_indexed_idle_delay_ms(0)
        .expect("idle delay");
    let now_ms = u64::try_from(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock")
            .as_millis(),
    )
    .expect("ms")
        + 3_600_000;
    fixture
        .vault
        .refresh_indexed_at_idle(now_ms, idle)
        .expect("idle publication")
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

    let idle = publish_body_edit_at_idle(&fixture);

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

/// Edits the person's body and publishes the edit at idle. Returns the idle
/// publisher's embedder.
fn publish_body_edit_at_idle(fixture: &Fixture) -> BodyVectors {
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
    let published = publish_at_idle(fixture, &idle);

    assert!(
        published
            .refreshed
            .iter()
            .any(|(entity, _)| *entity == fixture.person),
        "FIXTURE: idle publishes the body edit: {published:?}"
    );
    idle
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

/// The person's public line as a public reader sees it now.
fn public_line(fixture: &Fixture) -> Option<String> {
    fixture
        .vault
        .person_about(fixture.person, Some(0))
        .expect("read")
}

/// D4, the erase: deleting the fact the public line was written from takes
/// the lines (FIX 3155) and, in the same write, the person's vector. RED on
/// 62fd682 (#7438's head): the vector of the erased fact's line stays.
#[test]
fn an_erased_fact_drops_the_persons_vector() {
    let fixture = fixture("public");
    land(&fixture, &[0, 1, 2, 3], public_then_private);
    reconcile(&fixture);
    assert_eq!(
        person_vector(&fixture),
        Some(PUBLIC_VECTOR.to_vec()),
        "FIXTURE: the person holds its line's vector"
    );
    // A delete needs this install's keystore, as a host installs it.
    fixture
        .vault
        .install_device_keystore(Arc::new(oneiron_keystore::MemoryKeystore::default()));
    fixture
        .vault
        .prepare_install_signing()
        .expect("install signing");

    let existed = fixture.vault.delete_entity(&fixture.fact).expect("erase");

    assert!(existed, "FIXTURE: the fact is erased");
    assert_eq!(
        public_line(&fixture),
        None,
        "FIXTURE: the erase takes the lines"
    );
    assert_eq!(
        person_vector(&fixture),
        None,
        "the erase takes the vector of the erased fact's line"
    );
    reconcile(&fixture);
    assert_eq!(
        person_vector(&fixture),
        None,
        "no pass fills it again: the person has no line"
    );
}

/// The model's reply to the consolidation pass: one new person, named in T1.
fn named_owen() -> String {
    serde_json::json!({
        "persons": [{"id": "new:P1", "name": "Owen", "evidence_turn_refs": ["T1"]}],
        "candidates": [{
            "subject": "new:P1",
            "predicate": "profile.name",
            "value": "Owen",
            "confidence": 0.8,
            "evidence_refs": [{"source": "T1", "quote": "Owen"}],
        }],
    })
    .to_string()
}

/// D4, a drop (FIX 3196): the Dreamer archives its own weak fact about the
/// person, a door that drops the fact without a new body. The lines hide and
/// the person's vector goes in the archive's write. The person also has a
/// stated public fact, so it has a public line and a vector to drop. RED on
/// 62fd682: the vector stays.
#[test]
fn an_archived_fact_drops_the_persons_vector() {
    let dir = tempfile::tempdir().expect("tempdir");
    let vault = open_vault(&dir);
    let dreamer = dreamer(&vault).expect("the Dreamer");
    let pass = consolidate_unbound_turn(&vault, "call me Owen", None, None, &named_owen())
        .expect("one consolidation pass");
    let [extracted] = pass.landed.as_slice() else {
        panic!("FIXTURE: one landed claim, found {}", pass.landed.len());
    };
    let extracted = *extracted;
    let person = claim_subject(&vault, extracted)
        .expect("read")
        .expect("FIXTURE: the extracted fact is about a person");
    let fact = put_fact(&vault, person, "profile.hobby", "climbing", "public");
    let fixture = Fixture {
        _dir: dir,
        vault,
        dreamer,
        person,
        fact,
        embedder: Arc::new(LineVectors::default()),
    };
    land(&fixture, &[0, 1, 2, 3], public_then_private);
    reconcile(&fixture);
    assert_eq!(
        person_vector(&fixture),
        Some(PUBLIC_VECTOR.to_vec()),
        "FIXTURE: the person holds its line's vector"
    );
    // Every landed claim is quiet and weak; the vault's second-grained clock
    // passes the policy's 1 ms window.
    archive_every_quiet_claim(&fixture.vault).expect("strength policy");
    std::thread::sleep(std::time::Duration::from_millis(2_100));

    let committed = commit_in_attempt(
        &fixture.vault,
        fixture.dreamer,
        EdgeActorClass::System,
        "run-archive",
        Some(pass.attempt),
        &[Derived::Archive(Archive {
            local: "archive",
            claim: Named::Stored(extracted),
            score: 0.1,
        })],
    )
    .expect("commit");

    let [item] = committed.items.as_slice() else {
        panic!("FIXTURE: one item: {:?}", committed.items);
    };
    assert!(
        item.landed,
        "FIXTURE: the archive lands: {:?}",
        item.reasons
    );
    assert_eq!(
        public_line(&fixture),
        None,
        "FIXTURE: the archive hides the lines"
    );
    assert_eq!(
        person_vector(&fixture),
        None,
        "the archive takes the vector of a line the archived fact backed"
    );
}

/// D4, the wake: the owner retracts the person's only fact. That plain CLAIM
/// write hides the line and keeps its vector; the next wake pass finds no
/// fact left, clears the lines, and drops the vector with them. RED on
/// 62fd682: the vector stays after the pass.
#[test]
fn a_wake_that_clears_a_person_with_no_facts_drops_its_vector() {
    let fixture = fixture("public");
    land(&fixture, &[0, 1, 2, 3], public_then_private);
    reconcile(&fixture);
    assert_eq!(
        person_vector(&fixture),
        Some(PUBLIC_VECTOR.to_vec()),
        "FIXTURE: the person holds its line's vector"
    );

    fixture
        .vault
        .retract_claim(&fixture.fact, fixture.vault.now_recorded_at())
        .expect("the retract");

    assert_eq!(
        public_line(&fixture),
        None,
        "FIXTURE: the retract hides the line"
    );
    assert_eq!(
        person_vector(&fixture),
        Some(PUBLIC_VECTOR.to_vec()),
        "a plain CLAIM write keeps the vector until the wake pass (D4)"
    );
    wake_reads_about_facts(&fixture.vault).expect("a wake pass");
    let (_, bands) = about_facts(
        &fixture.vault,
        fixture.dreamer,
        EdgeActorClass::System,
        fixture.person,
    )
    .expect("facts");
    assert!(bands.is_empty(), "FIXTURE: no fact is left: {bands:?}");
    assert_eq!(
        person_vector(&fixture),
        None,
        "the pass that clears the lines drops their vector"
    );
}

/// FIX PERSON-VECTOR-IDLE-EDIT-WHILE-HIDDEN: a body edit published at idle
/// while a CLAIM write hides the line drops the vector and cannot mark the
/// person. When the facts are back where the line was written from, the
/// next wake pass shows the line again with no landing, and marks the
/// person, which holds no vector. RED on 62fd682: the person holds no
/// vector after the pass.
#[test]
fn a_line_shown_again_after_a_hidden_body_edit_embeds_again() {
    let fixture = fixture("public");
    land(&fixture, &[0, 1, 2, 3], public_then_private);
    reconcile(&fixture);
    assert_eq!(
        person_vector(&fixture),
        Some(PUBLIC_VECTOR.to_vec()),
        "FIXTURE: the person holds its line's vector"
    );
    let second = put_fact(
        &fixture.vault,
        fixture.person,
        "profile.city",
        "Lyon",
        "public",
    );
    assert_eq!(
        public_line(&fixture),
        None,
        "FIXTURE: the new fact hides the line"
    );

    publish_body_edit_at_idle(&fixture);
    reconcile(&fixture);
    assert_eq!(
        person_vector(&fixture),
        None,
        "FIXTURE: idle dropped the vector while the line was hidden"
    );
    fixture
        .vault
        .retract_claim(&second, fixture.vault.now_recorded_at())
        .expect("the retract");

    wake_reads_about_facts(&fixture.vault).expect("a wake pass");

    assert_eq!(
        public_line(&fixture).as_deref(),
        Some(PUBLIC_LINE),
        "FIXTURE: the pass shows the line again, with no landing"
    );
    reconcile(&fixture);
    assert_eq!(
        person_vector(&fixture),
        Some(PUBLIC_VECTOR.to_vec()),
        "the line shown again is embedded again"
    );
}

/// A live PERSON may carry an empty body (a live zero-byte payload): its
/// marker commits to its line, not its body, so the worker leases it and
/// fills the line's vector. RED on 62fd6825062: the marker of a header-only
/// PERSON never reads as current, so the worker drops the job unsent and the
/// person never holds a vector.
#[test]
fn a_person_with_an_empty_body_embeds_its_public_line() {
    let fixture = fixture_with_body("public", b"");
    land(&fixture, &[0, 1, 2, 3], public_then_private);

    reconcile(&fixture);

    assert_eq!(
        sent_for_person(&fixture),
        vec![line_payload(PUBLIC_LINE)],
        "the worker sends an empty-bodied person's public line"
    );
    assert_eq!(person_vector(&fixture), Some(PUBLIC_VECTOR.to_vec()));
}

/// The host revokes the Dreamer's MACHINE binding after a landing queued the
/// person: the Dreamer's reader reads nothing, so the person shows no line
/// and is sent nothing, and the pass goes on with its other work. RED on
/// 62fd6825062: the line read fails with the refused read, which fails the
/// whole pass, so no record in it is embedded.
#[test]
fn a_revoked_dreamer_binding_hides_the_line_and_the_pass_goes_on() {
    let fixture = fixture("public");
    land(&fixture, &[0, 1, 2, 3], public_then_private);
    stand_steward_grant(&fixture.vault, fixture.dreamer, &STEWARD_VERBS).expect("full grant");
    let revoked = revoke_base_agent_bindings(&fixture.vault, fixture.dreamer).expect("revoke");
    assert!(revoked >= 1, "FIXTURE: a live binding stood");

    let embedder: Arc<dyn Embedder> = fixture.embedder.clone();
    PendingEmbeddingReconciler::new(Arc::clone(&fixture.vault), embedder)
        .reconcile_once()
        .expect("a refused line read fails no pass");

    assert!(
        sent_for_person(&fixture).is_empty(),
        "the person is sent nothing"
    );
    assert_eq!(person_vector(&fixture), None);
    assert_eq!(
        fixture
            .vault
            .get_vector(&fixture.fact)
            .expect("vector read"),
        Some(OTHER_VECTOR.to_vec()),
        "the pass embeds the rest of its work"
    );
}

/// A fact write hides the person's line, and an embedding-space swap comes
/// before the Dreamer writes it again. The next landing's line fills the
/// person's vector in the new space, and idle publication leaves it: the
/// worker is the one producer of a PERSON's vector (D2). RED on
/// 62fd6825062: the swap marks the person for an idle refill, which finds
/// nothing to embed for a PERSON and drops the new vector.
#[test]
fn a_swap_while_the_line_is_hidden_leaves_no_idle_refill_over_the_next_line() {
    let mut fixture = fixture("public");
    land(&fixture, &[0, 1, 2, 3], public_then_private);
    reconcile(&fixture);
    assert_eq!(person_vector(&fixture), Some(PUBLIC_VECTOR.to_vec()));
    put_fact(
        &fixture.vault,
        fixture.person,
        "profile.hobby",
        "hiking",
        "public",
    );
    assert_eq!(
        fixture
            .vault
            .person_about(fixture.person, Some(0))
            .expect("read"),
        None,
        "FIXTURE: the fact write hides the line"
    );

    Arc::get_mut(&mut fixture.vault)
        .expect("FIXTURE: the one handle")
        .refill_embedding_space()
        .expect("the swap");
    land(&fixture, &[0, 1, 2, 3], new_then_private);
    reconcile_all(&fixture);
    assert_eq!(
        person_vector(&fixture),
        Some(NEW_VECTOR.to_vec()),
        "FIXTURE: the new line fills the vector in the new space"
    );
    let idle = BodyVectors::default();
    publish_at_idle(&fixture, &idle);

    assert_eq!(
        person_vector(&fixture),
        Some(NEW_VECTOR.to_vec()),
        "idle publication leaves the vector the worker filled"
    );
    assert!(
        !idle.embedded.lock().unwrap().contains(&fixture.person),
        "idle never embeds a PERSON"
    );
}
