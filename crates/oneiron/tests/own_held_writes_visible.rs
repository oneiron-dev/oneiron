//! A writer can find its held claim without making it a retrieval result.

mod common;

use oneiron::memory::{
    ClaimFilteredListRequest, ClaimFilteredReadRequest, ClaimInput, ClaimListFilter,
    ClaimProposalReviewRequest, ClaimSettleDecision, ClaimSettleRequest, ClaimSettlementVerdict,
    ClaimView, CommitReceipt, Memory, MemoryPack, ProducerRows, QueryBm25Request, RecallEffort,
    RecallRequest, RecallScope,
};
use oneiron::policy_model::SecretScanMode;
use oneiron::registry::ENTITY_TYPE_PERSON;
use oneiron::store::GateDecisionId;
use oneiron::task_verb::sdk::{Bm25Search, recall_unembedded, search_bm25};
use oneiron::{EdgeActorClass, EntityId, TimeRange, Vault, VaultConfig, WriteActor};

const MARKER: &str = "ownheldmark9v2z";
const NON_MATCH: &str = "otherheldmark6r3x";
// A word stored only beside a credential-shaped token, so the view redacts it.
const HIDDEN_MARKER: &str = "hiddenheldmark8k4w";
// The stock policy marks profile.* Normal, so the owner can settle it.
const PREDICATE: &str = "profile.own_held_writes";

struct Fixture {
    vault: Vault,
    owner: EntityId,
    writer: EntityId,
    other: EntityId,
    claim_ref: String,
    receipt: CommitReceipt,
    _dir: tempfile::TempDir,
}

impl Fixture {
    fn new() -> Self {
        let dir = tempfile::tempdir().expect("held writes tempdir");
        let vault = Vault::open(dir.path(), VaultConfig::device()).expect("open held writes vault");
        let owner = vault
            .ensure_embedded_owner_actor()
            .expect("embedded owner actor");
        let writer = put_person(&vault, 0xB1);
        let other = put_person(&vault, 0xB2);
        let subject = put_person(&vault, 0xB3);
        // Install both permits at once; the fixture door requires the stock manifest.
        vault
            .install_read_permits_for_test(&[
                WriteActor::new(writer, EdgeActorClass::Agent),
                WriteActor::new(other, EdgeActorClass::Agent),
            ])
            .expect("give both agents read permits without an Auto write grant");
        let claim_ref = common::entity(0xB4).to_hex();
        let receipt = vault
            .memory(writer, EdgeActorClass::Agent)
            .claim_upsert(&held_input(&claim_ref, subject, serde_json::json!(MARKER)))
            .expect("agent upserts its generated claim");
        Self {
            vault,
            owner,
            writer,
            other,
            claim_ref,
            receipt,
            _dir: dir,
        }
    }

    fn writer(&self) -> Memory<'_> {
        self.vault.memory(self.writer, EdgeActorClass::Agent)
    }

    fn other(&self) -> Memory<'_> {
        self.vault.memory(self.other, EdgeActorClass::Agent)
    }

    /// The owner turns write scanning off, so a credential-shaped token is
    /// stored as given and every view of its claim redacts it.
    fn scan_off(&self) {
        let proof = self
            .vault
            .authenticate_owner(
                self.owner,
                "principal:held-scan-off",
                true,
                GateDecisionId::now(),
            )
            .expect("owner proof for the scan switch");
        self.vault
            .set_secret_scan_mode(&proof, SecretScanMode::Off, 10)
            .expect("owner turns write scanning off");
    }

    fn approve(&self) {
        let proof = self
            .vault
            .authenticate_owner(self.owner, "principal:owner", true, GateDecisionId::now())
            .expect("owner proof");
        let owner = self.vault.memory(self.owner, EdgeActorClass::Human);
        let review = owner
            .claim_review_as_owner(
                &proof,
                &ClaimProposalReviewRequest {
                    claim_ref: self.claim_ref.clone(),
                    grant_ref: None,
                },
            )
            .expect("owner reviews the proposal");
        let settled = owner
            .claim_settle_as_owner(
                &proof,
                &ClaimSettleRequest {
                    claim_ref: self.claim_ref.clone(),
                    review_id: review.review_id,
                    decision: ClaimSettleDecision::Approve,
                    grant_ref: None,
                },
            )
            .expect("owner approves the proposal");
        assert!(
            settled.verdict == ClaimSettlementVerdict::Landed,
            "owner approval lands"
        );
    }
}

/// The agent's generated claim `claim_ref` about `subject`, under the held
/// predicate.
fn held_input(claim_ref: &str, subject: EntityId, value: serde_json::Value) -> ClaimInput {
    ClaimInput {
        id: Some(claim_ref.to_owned()),
        predicate: PREDICATE.to_owned(),
        subject_ref: subject.to_hex(),
        value,
        confidence: 0.8,
        source: "generated".to_owned(),
        world_ref: None,
        relationship_ref: None,
        scope: None,
        valid_from: None,
        valid_to: None,
        occurred_at: None,
        learned_at: None,
        salience: None,
        confidence_details: None,
    }
}

fn put_person(vault: &Vault, seed: u8) -> EntityId {
    let id = common::entity(seed);
    vault
        .put_entity(
            &id,
            ENTITY_TYPE_PERSON,
            TimeRange { start: 1, end: 1 },
            1,
            b"held writer fixture",
        )
        .expect("put fixture person");
    id
}

fn list(memory: &Memory<'_>) -> Vec<ClaimView> {
    memory
        .claim_list_filtered(&ClaimFilteredListRequest {
            predicate: Some(PREDICATE.to_owned()),
            limit: 10,
            ..Default::default()
        })
        .expect("list claims with the held predicate")
        .value
}

fn read(memory: &Memory<'_>, claim_ref: &str) -> Option<ClaimView> {
    memory
        .claim_read_filtered(&ClaimFilteredReadRequest {
            claim_ref: claim_ref.to_owned(),
            filter: None,
            project_refs: Vec::new(),
        })
        .expect("read the claim by ref")
        .value
}

fn bm25(memory: &Memory<'_>, query: &str) -> Bm25Search {
    search_bm25(
        memory,
        QueryBm25Request {
            query: query.to_owned(),
            limit: 10,
            filter: None,
        },
    )
    .expect("BM25 verb answers")
}

fn recall(memory: &Memory<'_>, query: &str) -> MemoryPack {
    recall_in(memory, query, None)
}

fn recall_in(memory: &Memory<'_>, query: &str, scope: Option<RecallScope>) -> MemoryPack {
    recall_unembedded(
        memory,
        RecallRequest {
            query: query.to_owned(),
            effort: Some(RecallEffort::Light),
            format: Some("md".to_owned()),
            scope,
            ..RecallRequest::default()
        },
    )
    .expect("explicit recall verb answers")
}

#[test]
fn held_remember_reply_names_its_reason_codes() {
    let fixture = Fixture::new();
    assert!(
        fixture.receipt.approval == "proposed",
        "remember reports proposed approval"
    );
    assert!(
        !fixture.receipt.reason_codes.is_empty(),
        "held remember reply names its reason codes"
    );
    let pending = fixture
        .writer()
        .pending_writes(10)
        .expect("read the pending tray");
    let held = pending
        .iter()
        .find(|row| row.claim_ref == fixture.claim_ref)
        .expect("the writer's proposed claim has a tray entry");
    assert!(
        fixture
            .receipt
            .reason_codes
            .iter()
            .all(|code| held.reason_codes.contains(code)),
        "every remember reason is in the claim's pending_writes entry"
    );
}

#[test]
fn writer_lists_and_reads_its_own_held_claim() {
    let fixture = Fixture::new();
    let writer = fixture.writer();
    let listed = list(&writer)
        .into_iter()
        .find(|view| view.claim_ref == fixture.claim_ref);
    let read = read(&writer, &fixture.claim_ref);
    assert!(
        listed.is_some() && read.is_some(),
        "writer list and point read must find held claim {} (list: {}, read: {})",
        fixture.claim_ref,
        listed.is_some(),
        read.is_some(),
    );
    let pending = writer.pending_writes(10).expect("read pending writes");
    let held = pending
        .iter()
        .find(|row| row.claim_ref == fixture.claim_ref)
        .expect("the claim is held in the tray");
    assert!(
        listed
            .as_ref()
            .is_some_and(|view| view.held.as_ref().is_some_and(|mark| {
                mark.reason_codes == held.reason_codes && mark.decision_ref == held.decision_ref
            })),
        "writer list marks the held claim with its tray reasons and decision ref"
    );
    assert!(
        read.is_some_and(|view| view.claim_ref == fixture.claim_ref && view.held.is_some()),
        "writer point read marks the held claim as held"
    );
}

#[test]
fn writer_finds_its_own_held_claim_in_bm25_and_recall_held_lists() {
    let fixture = Fixture::new();
    let writer = fixture.writer();
    let bm25_match = bm25(&writer, MARKER);
    let recalled = recall(&writer, MARKER);
    let bm25_held = bm25_match
        .held
        .iter()
        .any(|view| view.claim_ref == fixture.claim_ref);
    let recall_held = recalled
        .held
        .iter()
        .any(|view| view.claim_ref == fixture.claim_ref);
    assert!(
        bm25_held && recall_held,
        "matching BM25 and recall must find held claim {} in held (BM25: {bm25_held}, recall: {recall_held})",
        fixture.claim_ref,
    );
    assert!(
        !bm25_match.value.iter().any(|hit| hit
            .record
            .as_ref()
            .is_some_and(|r| r.id == fixture.claim_ref)),
        "a held claim must not join ranked BM25 hits"
    );
    assert!(
        !recalled.items.iter().any(|item| item
            .record
            .as_ref()
            .is_some_and(|r| r.id == fixture.claim_ref)),
        "held claim {} must not join ranked recall items",
        fixture.claim_ref,
    );
    assert!(
        recalled
            .rendered
            .as_deref()
            .is_none_or(|text| !text.contains(MARKER)),
        "recall's rendered text must not carry the held claim's marker"
    );
    assert!(
        bm25(&writer, NON_MATCH).held.is_empty(),
        "non-matching BM25 leaves held empty"
    );
    assert!(
        recall(&writer, NON_MATCH).held.is_empty(),
        "non-matching recall leaves held empty"
    );
}

#[test]
fn another_actor_does_not_see_a_held_claim() {
    let fixture = Fixture::new();
    let other = fixture.other();
    assert!(
        list(&other)
            .iter()
            .all(|view| view.claim_ref != fixture.claim_ref),
        "another actor's list must not show the writer's held claim"
    );
    assert!(
        read(&other, &fixture.claim_ref).is_none(),
        "another actor's point read is absent"
    );
    assert!(
        bm25(&other, MARKER).held.is_empty(),
        "another actor's BM25 held list is empty"
    );
    assert!(
        recall(&other, MARKER).held.is_empty(),
        "another actor's recall held list is empty"
    );
}

#[test]
fn settled_claim_reads_as_ordinary() {
    let fixture = Fixture::new();
    fixture.approve();
    let listed = list(&fixture.writer());
    assert!(
        listed.iter().any(|view| {
            view.claim_ref == fixture.claim_ref
                && view.approval == "approved"
                && view.held.is_none()
        }),
        "the settled claim {} appears in the writer's list without a held mark",
        fixture.claim_ref,
    );
}

#[test]
fn held_lists_name_each_served_claim_as_a_producer() {
    let fixture = Fixture::new();
    let claim = EntityId::from_hex(&fixture.claim_ref).expect("fixture claim id");
    let producers = ProducerRows::default();
    let writer = fixture.writer().listing_producers(&producers);
    let found = bm25(&writer, MARKER)
        .held
        .iter()
        .any(|view| view.claim_ref == fixture.claim_ref);
    assert!(
        found && producers.take().contains(&claim),
        "BM25's held claim {} is a producer of its answer (held: {found})",
        fixture.claim_ref,
    );
    let producers = ProducerRows::default();
    let writer = fixture.writer().listing_producers(&producers);
    let found = recall(&writer, MARKER)
        .held
        .iter()
        .any(|view| view.claim_ref == fixture.claim_ref);
    assert!(
        found && producers.take().contains(&claim),
        "recall's held claim {} is a producer of its answer (held: {found})",
        fixture.claim_ref,
    );
}

#[test]
fn only_the_writer_reads_the_held_mark() {
    let fixture = Fixture::new();
    fn find(memory: &Memory<'_>, claim_ref: &str) -> Option<ClaimView> {
        let filter = ClaimListFilter {
            predicate: Some(PREDICATE.to_owned()),
            limit: 10,
            ..Default::default()
        };
        memory
            .claim_list(&filter)
            .expect("record list of the held predicate")
            .value
            .into_iter()
            .find(|view| view.claim_ref == claim_ref)
    }
    let claim_ref = fixture.claim_ref.as_str();
    let owner = find(
        &fixture.vault.memory(fixture.owner, EdgeActorClass::Human),
        claim_ref,
    );
    assert!(
        owner
            .as_ref()
            .is_some_and(|view| view.approval == "proposed" && view.held.is_none()),
        "the owner's record list serves the proposal without the tray's reasons"
    );
    assert!(
        find(&fixture.other(), claim_ref).is_none_or(|view| view.held.is_none()),
        "another agent's record list never carries the writer's held mark"
    );
    assert!(
        find(&fixture.writer(), claim_ref).is_some_and(|view| view.held.is_some()),
        "the writer's record list marks its own held claim"
    );
}

#[test]
fn held_query_matches_only_the_served_value() {
    let fixture = Fixture::new();
    fixture.scan_off();
    let hidden_ref = common::entity(0xB5).to_hex();
    let hidden = format!("{HIDDEN_MARKER} ghp_{}", "a".repeat(36));
    let writer = fixture.writer();
    writer
        .claim_upsert(&held_input(
            &hidden_ref,
            fixture.other,
            serde_json::json!(hidden),
        ))
        .expect("agent upserts a claim holding a credential-shaped token");
    let listed = list(&writer)
        .into_iter()
        .find(|view| view.claim_ref == hidden_ref);
    assert!(
        listed.is_some_and(
            |view| view.held.is_some() && !view.value.to_string().contains(HIDDEN_MARKER)
        ),
        "the writer's list serves its held claim {hidden_ref} with the token's words redacted"
    );
    assert!(
        bm25(&writer, HIDDEN_MARKER)
            .held
            .iter()
            .all(|view| view.claim_ref != hidden_ref),
        "a query matching only redacted words finds no held claim"
    );
    assert!(
        recall(&writer, HIDDEN_MARKER)
            .held
            .iter()
            .all(|view| view.claim_ref != hidden_ref),
        "a recall matching only redacted words finds no held claim"
    );
}

#[test]
fn recall_held_list_keeps_the_recall_kinds() {
    let fixture = Fixture::new();
    let writer = fixture.writer();
    let held = |kinds: &[&str]| {
        recall_in(
            &writer,
            MARKER,
            Some(RecallScope {
                kinds: Some(kinds.iter().map(|kind| (*kind).to_owned()).collect()),
                ..RecallScope::default()
            }),
        )
        .held
    };
    assert!(
        held(&["TURN"]).is_empty(),
        "a recall of TURNs alone holds no claim"
    );
    assert!(
        held(&["CLAIM"])
            .iter()
            .any(|view| view.claim_ref == fixture.claim_ref),
        "a recall of CLAIMs keeps the writer's held claim {}",
        fixture.claim_ref,
    );
}
