//! FIX DREAMER-EXTRACTION-HANDS-UNDATED-REVISIONS: a fact revised twice,
//! three CLAIMs about one person on one predicate each superseding the one
//! before, reaches a reader's recall as its head alone. That holds for the
//! typed items and for the rendered pack a model reads, at Light and at
//! Medium. Medium's one edge hop would reach the closed versions over their
//! `Supersedes` edges. The whole chain stays stored and dated behind the
//! claim history door, which no recall render reads.
//!
//! The lead it pins (society-ai-scientists 20 Nov, rank 3): a reader handed
//! only the latest record of a revised fact, or dated records, answered
//! updated-fact questions 45 points better than one handed an undated log
//! of every version. The engine resolves versions before the model reads:
//! every recall path admits only an `active` claim (`claim_surfaceable`).
//!
//! Public crate surface only: `Vault::put_claim`, `Vault::supersede_claim`,
//! `Vault::ensure_embedded_owner_actor`, `Memory::recall` and
//! `Memory::claim_history`.
//! `cargo test --locked -p oneiron --all-features --test
//! revised_fact_recall_serves_head_only`.

use oneiron::memory::{Effort, MemoryPack, RecallScope};
use oneiron::{
    ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus, ClaimSource, ClaimSubject,
    EdgeActorClass, EntityId, TimeRange, Vault, VaultConfig,
};

const PREDICATE: &str = "home.city";
const QUERY: &str = "hometown";
const LEARNED_AT: u64 = 1_780_000_000;

/// The fact's versions, oldest first: each value names its city once.
const VERSIONS: [(&str, &str); 3] = [
    ("hometown Tokyo", "Tokyo"),
    ("hometown Osaka", "Osaka"),
    ("hometown Kyoto", "Kyoto"),
];

/// One vault whose owner's PERSON holds the fact in three versions, the
/// last one live.
struct Fixture {
    _dir: tempfile::TempDir,
    vault: Vault,
    owner: EntityId,
    versions: [EntityId; 3],
}

impl Fixture {
    fn new() -> Self {
        let dir = tempfile::tempdir().expect("temporary vault");
        let vault = Vault::open(dir.path(), VaultConfig::device()).expect("open vault");
        let owner = vault
            .ensure_embedded_owner_actor()
            .expect("the embedded owner");
        let versions = [EntityId::now(), EntityId::now(), EntityId::now()];
        for (step, (id, (value, _))) in versions.iter().zip(VERSIONS).enumerate() {
            let at = LEARNED_AT + 100 * step as u64;
            let mut body = ClaimBody::new(
                PREDICATE,
                ClaimSubject::Entity(owner),
                rmpv::Value::from(value),
                1.0,
                ClaimApprovalStatus::Auto,
                ClaimLifecycleStatus::Active,
            )
            .expect("claim body");
            body.source = Some(ClaimSource::UserStated);
            body.valid_from = Some(at);
            vault
                .put_claim(id, &body, TimeRange { start: at, end: at }, at)
                .expect("write a version of the fact");
            if step > 0 {
                vault
                    .supersede_claim(id, &versions[step - 1], at + 1)
                    .expect("the new version supersedes the one before");
            }
        }
        Self {
            _dir: dir,
            vault,
            owner,
            versions,
        }
    }

    /// The owner's recall of the fact at `effort`, rendered as markdown.
    fn recall(&self, effort: Effort) -> MemoryPack {
        self.vault
            .memory(self.owner, EdgeActorClass::Human)
            .recall(QUERY, effort, &RecallScope::default(), 20, Some("md"), None)
            .expect("the owner's recall")
    }
}

/// The fact's items in `pack`, as (record id, value text).
fn fact_items(pack: &MemoryPack) -> Vec<(Option<String>, String)> {
    pack.items
        .iter()
        .filter(|item| item.predicate.as_deref() == Some(PREDICATE))
        .map(|item| {
            (
                item.record.as_ref().map(|record| record.id.clone()),
                item.value_text.clone(),
            )
        })
        .collect()
}

fn assert_head_only(fixture: &Fixture, effort: Effort) {
    let pack = fixture.recall(effort);
    let head = fixture.versions[2].to_hex();
    let items = fact_items(&pack);
    assert_eq!(
        items.len(),
        1,
        "{effort:?} recall serves one item for the revised fact: {items:?}"
    );
    assert_eq!(
        items[0].0.as_deref(),
        Some(head.as_str()),
        "{effort:?} recall serves the head: {items:?}"
    );
    assert!(
        items[0].1.contains(VERSIONS[2].1),
        "{effort:?} recall serves the head's value: {items:?}"
    );
    let rendered = pack
        .rendered
        .as_deref()
        .unwrap_or_else(|| panic!("{effort:?} recall renders the pack it was asked for"));
    assert!(
        rendered.contains(VERSIONS[2].1),
        "the {effort:?} render holds the head's value:\n{rendered}"
    );
    for (_, closed) in &VERSIONS[..2] {
        assert!(
            !rendered.contains(closed),
            "the {effort:?} render holds no superseded value ({closed}):\n{rendered}"
        );
    }
}

/// A Light recall, the lexical pack with no edges, serves the head alone.
#[test]
fn a_light_recall_of_a_revised_fact_serves_only_its_head() {
    assert_head_only(&Fixture::new(), Effort::Light);
}

/// A Medium recall walks one edge hop from each result; the head's
/// `Supersedes` edges name both closed versions, and neither reaches the
/// items or the render.
#[test]
fn a_medium_recall_of_a_revised_fact_serves_only_its_head_past_its_supersedes_edges() {
    assert_head_only(&Fixture::new(), Effort::Medium);
}

/// The closed versions stay stored: the claim history door reads the whole
/// chain oldest first, each version with its validity start and lifecycle.
#[test]
fn the_claim_history_keeps_every_version_of_the_revised_fact_dated() {
    let fixture = Fixture::new();
    let history = fixture
        .vault
        .memory(fixture.owner, EdgeActorClass::Human)
        .claim_history(&fixture.versions[2].to_hex())
        .expect("the owner's claim history")
        .value;
    let chain: Vec<(String, String, Option<u64>)> = history
        .iter()
        .map(|view| {
            (
                view.claim_ref.clone(),
                view.lifecycle.clone(),
                view.valid_from,
            )
        })
        .collect();
    let expected: Vec<(String, String, Option<u64>)> = fixture
        .versions
        .iter()
        .enumerate()
        .map(|(step, id)| {
            let lifecycle = if step < 2 {
                ClaimLifecycleStatus::Superseded
            } else {
                ClaimLifecycleStatus::Active
            };
            (
                id.to_hex(),
                lifecycle.as_str().to_owned(),
                Some(LEARNED_AT + 100 * step as u64),
            )
        })
        .collect();
    assert_eq!(chain, expected, "the history holds the whole dated chain");
}
