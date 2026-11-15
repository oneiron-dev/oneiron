//! A canonical capture of an entity document reads the text of every version
//! it retains (FIX 275). It forked the whole document once per retained
//! version, and each fork rebuilds the state from the whole history, so a
//! document with thousands of receipts cost versions x history to capture.
//! These tests build one ASSET document with N merged whole-text updates
//! (each writes a receipt, so each is a retained version), capture it through
//! the public window capture, and check every version's text. The timed test
//! prints the capture time at each stated size, the measurement main and the
//! fix are compared by; the purged case covers a shallow document's walk.
//!
//! Fleet: `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron --all-features --test entity_doc_capture_retained_versions`
#![cfg(feature = "test-support")]

use std::time::{Duration, Instant};

use loro::LoroDoc;
use oneiron::consent::AuthenticatedOwner;
use oneiron::entity_doc::{DocAuthorization, TextField, TextUpdateOutcome, TextUpdateRequest};
use oneiron::recovery::capture_canonical_window;
use oneiron::registry::ENTITY_TYPE_ASSET;
use oneiron::store::GateDecisionId;
use oneiron::store::canonical_document::CanonicalEntityDocumentHistory;
use oneiron::test_support::{bind_host_owner, provision_engine_machines, test_host_issuer};
use oneiron::{EdgeActorClass, EntityId, TimeRange, Vault, VaultConfig, WriteActor};

/// Merged updates the timed test captures after, each a retained version.
const SIZES: [usize; 4] = [150, 300, 600, 1200];

struct Fixture {
    _directory: tempfile::TempDir,
    vault: Vault,
    owner: WriteActor,
    proof: AuthenticatedOwner,
    asset: EntityId,
}

fn text_of(version: usize) -> String {
    format!("capture fixture text, version {version:05}")
}

fn fixture() -> Fixture {
    let directory = tempfile::tempdir().expect("temporary vault");
    let vault = Vault::open(directory.path(), VaultConfig::device()).expect("fresh vault");
    provision_engine_machines(&vault);
    let person = vault.ensure_embedded_owner_actor().expect("owner PERSON");
    bind_host_owner(&vault, &test_host_issuer(), person).expect("owner host binding");
    let proof = vault
        .authenticate_owner(person, &person.to_hex(), true, GateDecisionId::now())
        .expect("owner proof");
    let owner = WriteActor::new(person, EdgeActorClass::Human);
    let asset = EntityId::now();
    vault
        .put_entity(
            &asset,
            ENTITY_TYPE_ASSET,
            TimeRange { start: 7, end: 7 },
            9,
            text_of(0).as_bytes(),
        )
        .expect("text asset");
    vault
        .migrate_entity_text(
            &asset,
            &TextField::Utf8Body,
            owner,
            &DocAuthorization::Owner(&proof),
        )
        .expect("the owner migrates the text to a document");
    Fixture {
        _directory: directory,
        vault,
        owner,
        proof,
        asset,
    }
}

/// Merges version `version`'s text over the live head: one receipt.
fn update(fixture: &Fixture, version: usize) {
    let base = fixture
        .vault
        .entity_text_frontier(&fixture.asset)
        .expect("live frontier");
    let request = TextUpdateRequest {
        entity: fixture.asset,
        proposal: EntityId::now(),
        base,
        text: text_of(version),
        actor: fixture.owner,
        timeout_ms: 60_000,
        at: 100 + u64::try_from(version).expect("version count"),
    };
    let outcome = fixture
        .vault
        .update_entity_text(&request, &DocAuthorization::Owner(&fixture.proof))
        .expect("the owner updates the text");
    assert!(
        matches!(outcome, TextUpdateOutcome::Merged { .. }),
        "update {version} merges into the live head: {outcome:?}"
    );
}

/// A window naming the owner and the asset, as a window snapshot carries them.
fn window(fixture: &Fixture) -> LoroDoc {
    let window = LoroDoc::new();
    let entities = window.get_map("entities");
    let person = fixture
        .vault
        .ensure_embedded_owner_actor()
        .expect("owner PERSON");
    for id in [person, fixture.asset] {
        let raw = fixture
            .vault
            .get_raw(&id)
            .expect("raw row read")
            .expect("row present");
        entities
            .insert(&id.to_hex(), raw.as_slice())
            .expect("window row");
    }
    window
}

/// The asset's captured history, and the fastest of three captures.
fn capture(fixture: &Fixture) -> (Duration, CanonicalEntityDocumentHistory) {
    let window = window(fixture);
    let mut fastest = Duration::MAX;
    let mut history = None;
    for _ in 0..3 {
        let started = Instant::now();
        let snapshot =
            capture_canonical_window(&fixture.vault, "2026-09", &window).expect("window capture");
        fastest = fastest.min(started.elapsed());
        let document = snapshot
            .entity_documents
            .into_iter()
            .find(|row| row.entity_id == *fixture.asset.as_bytes())
            .expect("the asset's document is captured");
        history = document.history;
    }
    (
        fastest,
        history.expect("a document with receipts carries its history"),
    )
}

#[test]
fn capture_reads_every_retained_version_at_each_size() {
    let fixture = fixture();
    let mut versions = 0;
    let mut timings = Vec::with_capacity(SIZES.len());
    for size in SIZES {
        while versions < size {
            versions += 1;
            update(&fixture, versions);
        }
        let (elapsed, history) = capture(&fixture);
        let expected: Vec<String> = (0..=size).map(text_of).collect();
        assert_eq!(
            history.texts().expect("captured versions rebuild"),
            expected,
            "the capture carries every retained version's text, in order, at {size} updates"
        );
        assert_eq!(history.receipts.len(), size, "one receipt per update");
        let millis = elapsed.as_secs_f64() * 1000.0;
        println!(
            "FIX275-CAPTURE versions={} updates={size} capture_ms={millis:.1}",
            size + 1
        );
        timings.push((size, millis));
    }
    let (first, first_ms) = timings[0];
    let (last, last_ms) = timings[timings.len() - 1];
    println!(
        "FIX275-SCALING updates {first}->{last} (x{}) capture x{:.1}",
        last / first,
        last_ms / first_ms
    );
}

#[test]
fn a_purged_document_captures_each_version_its_receipts_keep() {
    let fixture = fixture();
    let updates = 40;
    for version in 1..=updates {
        update(&fixture, version);
    }
    let requested = fixture
        .vault
        .entity_text_frontier(&fixture.asset)
        .expect("live frontier");
    // Every receipt protects its versions, so the floor stays at the oldest
    // one; the document still becomes shallow there.
    fixture
        .vault
        .purge_entity_text_history(
            &fixture.asset,
            &requested,
            &DocAuthorization::Owner(&fixture.proof),
            1_000,
        )
        .expect("the owner purges the text history");
    let (_, history) = capture(&fixture);
    let texts = history.texts().expect("captured versions rebuild");
    let expected: Vec<String> = (0..=updates).map(text_of).collect();
    println!(
        "FIX275-PURGED shallow={} versions={} receipts={}",
        history.shallow,
        texts.len(),
        history.receipts.len()
    );
    assert!(
        !texts.is_empty() && expected.ends_with(&texts),
        "a purged capture carries the versions from its floor to the head in order: {texts:?}"
    );
    assert_eq!(
        texts.last(),
        Some(&text_of(updates)),
        "the head is the last version"
    );
}
