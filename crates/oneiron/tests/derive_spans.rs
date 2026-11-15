//! Optional span locators on derive items: a Claim or Evidence item may
//! cite byte ranges of a TURN as the committing actor reads them. Every commit
//! goes through the JSON wire on a leased live run; served spans are read
//! through `oneiron::verbs::vault_evidence_spans`.
//!
//! Needs the doors:
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron
//! --all-features --test derive_spans`.
#![cfg(oneiron_test_support)]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use oneiron::registry::ENTITY_TYPE_PERSON;
use oneiron::snapshot_read::{EvidenceRange, EvidenceSourceStatus, EvidenceSpansRequest};
use oneiron::temporal::TimeRange;
use oneiron::test_doors::consolidation::open_dreamer_vault;
use oneiron::test_doors::derive::{batches_of, claim_lifecycle, source_version, witness_turn};
use oneiron::test_doors::derive_spans::{claim_locators, support_locators};
use oneiron::test_doors::derive_verbs::{LiveRun, define_agent, grant_derive_rows, lease_run};
use oneiron::{EdgeActorClass, EntityId, Vault};
use serde_json::{Value, json};

const READER: &str = "reader";
const SPAN_UNBOUND: &str = "gate.deny.derive.evidence_span_unbound";
const SOURCE_MOVED: &str = "gate.deny.derive.source_moved";

fn put(vault: &Vault, entity_type: u8, body: &[u8]) -> EntityId {
    let id = EntityId::now();
    let at = vault.now_recorded_at();
    vault
        .put_entity(&id, entity_type, TimeRange { start: at, end: at }, at, body)
        .expect("a row");
    id
}

struct Fixture {
    _dir: tempfile::TempDir,
    vault: Vault,
    agent: EntityId,
    run: LiveRun,
    owen: EntityId,
    yuki: EntityId,
}

/// A vault with one agent the owner's policy lets derive, on a leased run,
/// and two persons, owen and yuki.
fn fixture() -> Fixture {
    let dir = tempfile::tempdir().expect("tempdir");
    let vault = open_dreamer_vault(dir.path(), READER).expect("vault");
    let agent = define_agent(&vault, "oneiron.agent.derive-spans").expect("an agent");
    grant_derive_rows(&vault, &[agent]).expect("the agent's policy rows");
    let run = lease_run(&vault, agent).expect("the agent's live run");
    let owen = put(&vault, ENTITY_TYPE_PERSON, b"owen");
    let yuki = put(&vault, ENTITY_TYPE_PERSON, b"yuki");
    Fixture {
        _dir: dir,
        vault,
        agent,
        run,
        owen,
        yuki,
    }
}

/// The version of `id` as the fixture's agent reads it now.
fn version(fixture: &Fixture, id: EntityId) -> Value {
    let version = source_version(&fixture.vault, fixture.agent, EdgeActorClass::Agent, id)
        .expect("read")
        .expect("the agent reads the row");
    serde_json::to_value(version).expect("a version")
}

/// The spans `source` serves the fixture's agent for `ranges`.
fn served(
    fixture: &Fixture,
    source: EntityId,
    ranges: &[(u64, u64)],
) -> oneiron::snapshot_read::EvidenceSpans {
    let memory = fixture.vault.memory(fixture.agent, EdgeActorClass::Agent);
    let ranges = ranges
        .iter()
        .map(|&(start, end)| EvidenceRange { start, end })
        .collect();
    oneiron::verbs::vault_evidence_spans(
        &memory,
        EvidenceSpansRequest {
            source,
            version: None,
            ranges,
        },
    )
    .expect("spans")
    .value
}

fn id_of(value: &Value) -> EntityId {
    EntityId::from_hex(value.as_str().expect("an id")).expect("a 32-character hex id")
}

/// Commits one claim without spans about owen, citing `turn`; its id.
fn land_claim(fixture: &Fixture, local: &str, turn: EntityId) -> EntityId {
    let answer = fixture
        .run
        .commit(
            &fixture.vault,
            json!({
                "items": [{
                    "kind": "claim",
                    "spec": {
                        "local": local,
                        "predicate": "profile.drink",
                        "subject": { "stored": fixture.owen },
                        "value": "an oat milk flat white",
                        "confidence": 0.9,
                        "evidence": [{ "stored": turn }],
                    },
                }],
                "sources": [version(fixture, turn)],
            }),
        )
        .expect("the setup claim commits");
    assert_eq!(answer["items"][0]["landed"], true, "{answer}");
    id_of(&answer["items"][0]["rows"][0])
}

#[test]
fn t1_an_evidence_item_with_one_range_lands_its_stored_locator() {
    let fixture = fixture();
    let turn = witness_turn(&fixture.vault, "owen loves yuki").expect("a TURN");
    let head = land_claim(&fixture, "drink", turn);
    let shown = served(&fixture, turn, &[(0, 4)]);
    assert_eq!(shown.status, EvidenceSourceStatus::Current);
    assert!(!shown.masked);
    assert_eq!(shown.spans[0].text, "owen");

    let answer = fixture
        .run
        .commit(
            &fixture.vault,
            json!({
                "items": [{
                    "kind": "evidence",
                    "spec": {
                        "local": "support",
                        "head": { "stored": head },
                        "sources": [{ "stored": turn }],
                        "spans": [{
                            "source": turn,
                            "ranges": [{ "start": 0, "end": 4 }],
                        }],
                    },
                }],
                "sources": [version(fixture, turn)],
            }),
        )
        .expect("the batch commits");
    assert_eq!(answer["items"][0]["landed"], true, "{answer}");
    let record = id_of(&answer["items"][0]["rows"][0]);
    let stored = support_locators(&fixture.vault, record).expect("read");
    assert_eq!(stored.len(), 1, "{stored:?}");
    assert_eq!(stored[0].source, turn);
    assert_eq!(stored[0].byte_range, Some((0, 4)));
    assert_eq!(stored[0].content_hash, shown.spans[0].content_hash);
    assert_eq!(stored[0].messages.len(), shown.spans[0].messages.len());
    for (got, want) in stored[0]
        .messages
        .iter()
        .zip(shown.spans[0].messages.iter())
    {
        assert_eq!(got.message, want.message);
        assert_eq!((got.start, got.end), (want.start, want.end));
        assert_eq!(got.revision, want.revision);
        assert_eq!(got.frontier, want.frontier);
    }
}

#[test]
fn t2_a_claim_item_with_spans_stores_locators_for_every_cited_row() {
    let fixture = fixture();
    let ranged = witness_turn(&fixture.vault, "owen loves yuki").expect("a TURN");
    let whole = witness_turn(&fixture.vault, "yuki loves owen").expect("a TURN");
    let served_ranged = served(&fixture, ranged, &[(5, 10)]);
    assert_eq!(served_ranged.spans[0].text, "loves");
    let served_whole = served(&fixture, whole, &[]);
    assert_eq!(served_whole.spans.len(), 1);
    let whole_len = u64::try_from(served_whole.spans[0].text.len()).expect("a len");

    let answer = fixture
        .run
        .commit(
            &fixture.vault,
            json!({
                "items": [{
                    "kind": "claim",
                    "spec": {
                        "local": "drink",
                        "predicate": "profile.drink",
                        "subject": { "stored": fixture.owen },
                        "value": "an oat milk flat white",
                        "confidence": 0.9,
                        "evidence": [{ "stored": ranged }, { "stored": whole }],
                        "spans": [{
                            "source": ranged,
                            "ranges": [{ "start": 5, "end": 10 }],
                        }],
                    },
                }],
                "sources": [version(fixture, ranged), version(fixture, whole)],
            }),
        )
        .expect("the batch commits");
    assert_eq!(answer["items"][0]["landed"], true, "{answer}");
    let claim = id_of(&answer["items"][0]["rows"][0]);
    let stored = claim_locators(&fixture.vault, claim).expect("read");
    assert_eq!(stored.len(), 2, "{stored:?}");
    let first = stored
        .iter()
        .find(|loc| loc.source == ranged)
        .expect("the ranged TURN");
    assert_eq!(first.byte_range, Some((5, 10)));
    assert_eq!(first.content_hash, served_ranged.spans[0].content_hash);
    let second = stored
        .iter()
        .find(|loc| loc.source == whole)
        .expect("the whole TURN");
    assert_eq!(second.byte_range, Some((0, whole_len)));
    assert_eq!(second.content_hash, served_whole.spans[0].content_hash);
}

#[test]
fn t3_items_without_spans_store_what_they_store_today() {
    let fixture = fixture();
    let turn = witness_turn(&fixture.vault, "owen owen@example.com").expect("a TURN");
    let whole = served(&fixture, turn, &[]).spans[0].text.len();
    let whole = u64::try_from(whole).expect("a len");

    let answer = fixture
        .run
        .commit(
            &fixture.vault,
            json!({
                "items": [{
                    "kind": "claim",
                    "spec": {
                        "local": "drink",
                        "predicate": "profile.drink",
                        "subject": { "stored": fixture.owen },
                        "value": "an oat milk flat white",
                        "confidence": 0.9,
                        "evidence": [{ "stored": turn }],
                    },
                }],
                "sources": [version(fixture, turn)],
            }),
        )
        .expect("the claim commits");
    assert_eq!(answer["items"][0]["landed"], true, "{answer}");
    let claim = id_of(&answer["items"][0]["rows"][0]);
    assert!(
        claim_locators(&fixture.vault, claim)
            .expect("read")
            .is_empty(),
        "a claim without spans stores no locators"
    );

    let answer = fixture
        .run
        .commit(
            &fixture.vault,
            json!({
                "items": [{
                    "kind": "evidence",
                    "spec": {
                        "local": "support",
                        "head": { "stored": claim },
                        "sources": [{ "stored": turn }],
                    },
                }],
                "sources": [version(fixture, turn)],
            }),
        )
        .expect("the evidence commits");
    assert_eq!(answer["items"][0]["landed"], true, "{answer}");
    let record = id_of(&answer["items"][0]["rows"][0]);
    let stored = support_locators(&fixture.vault, record).expect("read");
    assert_eq!(stored.len(), 1);
    assert_eq!(stored[0].byte_range, Some((0, whole)));
}

#[test]
fn t4_a_range_the_actor_is_not_served_refuses_only_its_item() {
    let fixture = fixture();
    let turn = witness_turn(&fixture.vault, "owen loves yuki").expect("a TURN");
    let answer = fixture
        .run
        .commit(
            &fixture.vault,
            json!({
                "items": [
                    {
                        "kind": "evidence",
                        "spec": {
                            "local": "bad",
                            "head": { "stored": land_claim(&fixture, "drink", turn) },
                            "sources": [{ "stored": turn }],
                            "spans": [{
                                "source": turn,
                                "ranges": [{ "start": 0, "end": 1000 }],
                            }],
                        },
                    },
                    {
                        "kind": "claim",
                        "spec": {
                            "local": "good",
                            "predicate": "profile.drink",
                            "subject": { "stored": fixture.yuki },
                            "value": "a green tea",
                            "confidence": 0.9,
                            "evidence": [{ "stored": turn }],
                        },
                    },
                ],
                "sources": [version(fixture, turn)],
            }),
        )
        .expect("the batch commits");
    assert_eq!(answer["items"][0]["landed"], false, "{answer}");
    assert_eq!(
        answer["items"][0]["reasons"],
        json!([SPAN_UNBOUND]),
        "{answer}"
    );
    assert_eq!(answer["items"][1]["landed"], true, "{answer}");

    let split = witness_turn(&fixture.vault, "owen café yuki").expect("a TURN");
    let head = land_claim(&fixture, "split", split);
    let answer = fixture
        .run
        .commit(
            &fixture.vault,
            json!({
                "items": [
                    {
                        "kind": "evidence",
                        "spec": {
                            "local": "bad",
                            "head": { "stored": head },
                            "sources": [{ "stored": split }],
                            "spans": [{
                                "source": split,
                                "ranges": [{ "start": 8, "end": 9 }],
                            }],
                        },
                    },
                    {
                        "kind": "claim",
                        "spec": {
                            "local": "good",
                            "predicate": "profile.drink",
                            "subject": { "stored": fixture.yuki },
                            "value": "a green tea",
                            "confidence": 0.9,
                            "evidence": [{ "stored": split }],
                        },
                    },
                ],
                "sources": [version(fixture, split)],
            }),
        )
        .expect("the batch commits");
    assert_eq!(answer["items"][0]["landed"], false, "{answer}");
    assert_eq!(
        answer["items"][0]["reasons"],
        json!([SPAN_UNBOUND]),
        "{answer}"
    );
    assert_eq!(answer["items"][1]["landed"], true, "{answer}");
}

#[test]
fn t5_a_spans_entry_over_a_cited_claim_is_refused() {
    let fixture = fixture();
    let turn = witness_turn(&fixture.vault, "owen loves yuki").expect("a TURN");
    let cited = land_claim(&fixture, "cited", turn);
    let answer = fixture
        .run
        .commit(
            &fixture.vault,
            json!({
                "items": [{
                    "kind": "claim",
                    "spec": {
                        "local": "drink",
                        "predicate": "profile.drink",
                        "subject": { "stored": fixture.owen },
                        "value": "an oat milk flat white",
                        "confidence": 0.9,
                        "evidence": [{ "stored": turn }, { "stored": cited }],
                        "spans": [{
                            "source": cited,
                            "ranges": [{ "start": 0, "end": 4 }],
                        }],
                    },
                }],
                "sources": [version(fixture, turn), version(fixture, cited)],
            }),
        )
        .expect("the batch commits");
    assert_eq!(answer["items"][0]["landed"], false, "{answer}");
    assert_eq!(
        answer["items"][0]["reasons"],
        json!([SPAN_UNBOUND]),
        "{answer}"
    );
}

#[test]
fn t6_a_malformed_spans_entry_aborts_the_whole_batch() {
    let fixture = fixture();
    let turn = witness_turn(&fixture.vault, "owen loves yuki").expect("a TURN");
    let other = witness_turn(&fixture.vault, "yuki loves owen").expect("a TURN");
    let good = json!({
        "items": [{
            "kind": "claim",
            "spec": {
                "local": "drink",
                "predicate": "profile.drink",
                "subject": { "stored": fixture.owen },
                "value": "an oat milk flat white",
                "confidence": 0.9,
                "evidence": [{ "stored": turn }],
                "spans": [{
                    "source": turn,
                    "ranges": [{ "start": 0, "end": 4 }],
                }],
            },
        }],
        "sources": [version(fixture, turn)],
    });
    let answer = fixture
        .run
        .commit(&fixture.vault, good)
        .expect("the good batch commits");
    assert_eq!(answer["items"][0]["landed"], true, "{answer}");
    let batches = batches_of(&fixture.vault, fixture.agent)
        .expect("read")
        .len();

    let many: Vec<Value> = (0..65).map(|_| json!({ "start": 0, "end": 1 })).collect();
    for (name, spans, sources, why) in [
        (
            "uncited source",
            json!([{ "source": other, "ranges": [{ "start": 0, "end": 4 }] }]),
            vec![version(&fixture, turn), version(&fixture, other)],
            "names a stored source the item cites",
        ),
        (
            "no range",
            json!([{ "source": turn, "ranges": [] }]),
            vec![version(&fixture, turn)],
            "one to sixty-four ranges",
        ),
        (
            "empty range",
            json!([{ "source": turn, "ranges": [{ "start": 4, "end": 4 }] }]),
            vec![version(&fixture, turn)],
            "start < end",
        ),
        (
            "too many ranges",
            Value::Array(vec![json!({ "source": turn, "ranges": many })]),
            vec![version(&fixture, turn)],
            "one to sixty-four ranges",
        ),
        (
            "duplicate source",
            json!([{ "source": turn, "ranges": [{ "start": 0, "end": 1 }] }, { "source": turn, "ranges": [{ "start": 2, "end": 3 }] }]),
            vec![version(&fixture, turn)],
            "names its source once",
        ),
    ] {
        let refusal = fixture
            .run
            .commit(
                &fixture.vault,
                json!({
                    "items": [{
                        "kind": "claim",
                        "spec": {
                            "local": "drink",
                            "predicate": "profile.drink",
                            "subject": { "stored": fixture.owen },
                            "value": "an oat milk flat white",
                            "confidence": 0.9,
                            "evidence": [{ "stored": turn }],
                            "spans": spans,
                        },
                    }],
                    "sources": sources,
                }),
            )
            .expect_err(name);
        assert!(format!("{refusal:?}").contains(why), "{name}: {refusal:?}");
        assert_eq!(
            batches_of(&fixture.vault, fixture.agent)
                .expect("read")
                .len(),
            batches,
            "{name} lands nothing"
        );
    }
}

#[test]
fn t7_a_moved_turn_aborts_a_batch_that_cites_a_range_of_it() {
    let fixture = fixture();
    let turn = witness_turn(&fixture.vault, "owen loves yuki").expect("a TURN");
    let mut moved: Value = version(&fixture, turn);
    moved["revision"] = json!(format!("blake3:{}", "1".repeat(64)));
    let refusal = fixture
        .run
        .commit(
            &fixture.vault,
            json!({
                "items": [{
                    "kind": "claim",
                    "spec": {
                        "local": "drink",
                        "predicate": "profile.drink",
                        "subject": { "stored": fixture.owen },
                        "value": "an oat milk flat white",
                        "confidence": 0.9,
                        "evidence": [{ "stored": turn }],
                        "spans": [{
                            "source": turn,
                            "ranges": [{ "start": 0, "end": 4 }],
                        }],
                    },
                }],
                "sources": [moved],
            }),
        )
        .expect_err("a moved source aborts the batch");
    assert!(format!("{refusal:?}").contains(SOURCE_MOVED), "{refusal:?}");
    assert!(
        batches_of(&fixture.vault, fixture.agent)
            .expect("read")
            .is_empty(),
        "nothing is committed"
    );
}

#[test]
fn t8_a_masked_reader_cites_in_the_coordinates_it_was_served() {
    let fixture = fixture();
    let secret = "locker-4471-quartz";
    let words = format!("owen code {secret} today yuki");
    let turn = witness_turn(&fixture.vault, &words).expect("a TURN");
    let handle =
        oneiron::test_doors::lifted_text::mark_lifted_key(&fixture.vault, turn, &words, secret)
            .expect("a lifted key");
    let shown = served(&fixture, turn, &[]);
    assert_eq!(shown.status, EvidenceSourceStatus::Current);
    assert!(shown.masked, "the agent reads keys masked");
    let masked = shown.spans[0].text.clone();
    assert!(masked.contains(&handle), "{masked}");
    assert!(!masked.contains(secret), "{masked}");

    let owner = fixture
        .vault
        .ensure_embedded_owner_actor()
        .expect("the owner");
    let owner_memory = fixture.vault.memory(owner, EdgeActorClass::Human);
    let stored = oneiron::verbs::vault_evidence_spans(
        &owner_memory,
        EvidenceSpansRequest {
            source: turn,
            version: None,
            ranges: vec![],
        },
    )
    .expect("the owner's spans")
    .value;
    assert!(!stored.masked);
    let stored_text = stored.spans[0].text.clone();
    assert!(stored_text.contains(secret), "{stored_text}");

    let after = |word: &str| {
        let at = u64::try_from(masked.find(word).expect("the word is served")).expect("a pos");
        (at, at + u64::try_from(word.len()).expect("a len"))
    };
    let (start, end) = after("today");
    let at = u64::try_from(masked.find(&handle).expect("the handle is shown")).expect("a pos");
    let handle_end = at + u64::try_from(handle.len()).expect("a len");
    let answer = fixture
        .run
        .commit(
            &fixture.vault,
            json!({
                "items": [{
                    "kind": "evidence",
                    "spec": {
                        "local": "support",
                        "head": { "stored": land_claim(&fixture, "drink", turn) },
                        "sources": [{ "stored": turn }],
                        "spans": [{
                            "source": turn,
                            "ranges": [
                                { "start": start, "end": end },
                                { "start": at + 2, "end": handle_end - 1 },
                            ],
                        }],
                    },
                }],
                "sources": [version(fixture, turn)],
            }),
        )
        .expect("the batch commits");
    assert_eq!(answer["items"][0]["landed"], true, "{answer}");
    let record = id_of(&answer["items"][0]["rows"][0]);
    let stored_locs = support_locators(&fixture.vault, record).expect("read");
    assert_eq!(stored_locs.len(), 2, "{stored_locs:?}");

    let today_at =
        u64::try_from(stored_text.find("today").expect("the word is stored")).expect("a pos");
    let today = stored_locs
        .iter()
        .find(|loc| loc.byte_range == Some((today_at, today_at + 5)))
        .expect("the stored range of the same words");
    let want = oneiron::verbs::vault_evidence_spans(
        &owner_memory,
        EvidenceSpansRequest {
            source: turn,
            version: None,
            ranges: vec![EvidenceRange {
                start: today_at,
                end: today_at + 5,
            }],
        },
    )
    .expect("the owner's span")
    .value;
    assert_eq!(today.content_hash, want.spans[0].content_hash);

    let key_at =
        u64::try_from(stored_text.find(secret).expect("the key is stored")).expect("a pos");
    let key_end = key_at + u64::try_from(secret.len()).expect("a len");
    assert!(
        stored_locs
            .iter()
            .any(|loc| loc.byte_range == Some((key_at, key_end))),
        "an end inside the handle widens to the whole stored key: {stored_locs:?}"
    );
}

#[test]
fn t9_a_claim_landed_with_spans_is_taken_back() {
    let fixture = fixture();
    let turn = witness_turn(&fixture.vault, "owen loves yuki").expect("a TURN");
    let answer = fixture
        .run
        .commit(
            &fixture.vault,
            json!({
                "items": [{
                    "kind": "claim",
                    "spec": {
                        "local": "drink",
                        "predicate": "profile.drink",
                        "subject": { "stored": fixture.owen },
                        "value": "an oat milk flat white",
                        "confidence": 0.9,
                        "evidence": [{ "stored": turn }],
                        "spans": [{
                            "source": turn,
                            "ranges": [{ "start": 0, "end": 4 }],
                        }],
                    },
                }],
                "sources": [version(fixture, turn)],
            }),
        )
        .expect("the batch commits");
    assert_eq!(answer["items"][0]["landed"], true, "{answer}");
    let batch = id_of(&answer["batch"]);
    let claim = id_of(&answer["items"][0]["rows"][0]);
    assert_eq!(
        claim_lifecycle(&fixture.vault, claim).expect("read"),
        Some("active".to_owned())
    );
    let answer = fixture
        .run
        .revert(&fixture.vault, batch)
        .expect("the actor reverts its batch");
    assert_eq!(answer["reverted"], json!(["drink"]), "{answer}");
    assert_eq!(answer["left"], json!([]), "{answer}");
    assert_ne!(
        claim_lifecycle(&fixture.vault, claim).expect("read"),
        Some("active".to_owned())
    );
}
