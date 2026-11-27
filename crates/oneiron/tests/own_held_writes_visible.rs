//! A writer can find its held claim without making it a retrieval result.

mod common;

use oneiron::memory::{ClaimDemoteActionInput, ClaimDemoteRequest, ReadFilterInput};
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

fn bm25_with_filter(memory: &Memory<'_>, query: &str, filter: ReadFilterInput) -> Bm25Search {
    search_bm25(
        memory,
        QueryBm25Request {
            query: query.to_owned(),
            limit: 10,
            filter: Some(filter),
        },
    )
    .expect("BM25 verb answers")
}

fn recall_with_filter(memory: &Memory<'_>, query: &str, filter: ReadFilterInput) -> MemoryPack {
    recall_unembedded(
        memory,
        RecallRequest {
            query: query.to_owned(),
            effort: Some(RecallEffort::Light),
            format: Some("md".to_owned()),
            scope: None,
            filter: Some(filter),
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

#[cfg(oneiron_test_support)]
#[test]
fn held_candidates_not_served_are_not_charged_to_read_exposure() {
    use oneiron::authority::HostSlipIssuer;
    use oneiron::federation::ScopeAxis;
    use oneiron::test_doors::read_exposure::exposed_records;
    use std::collections::BTreeSet;
    let fixture = Fixture::new();
    let second_ref = common::entity(0xB6).to_hex();
    let second_receipt = fixture
        .writer()
        .claim_upsert(&held_input(
            &second_ref,
            fixture.other,
            serde_json::json!(NON_MATCH),
        ))
        .expect("agent upserts a second held claim holding NON_MATCH");
    assert!(
        second_receipt.approval == "proposed",
        "second remember reports proposed approval for {second_ref}"
    );
    let issuer =
        HostSlipIssuer::from_secret(b"own-held-exposure-test-host").expect("test host issuer");
    let mut claims = fixture
        .vault
        .ensure_host_root_slip(&issuer)
        .expect("host root slip")
        .claims;
    claims.slip_id = [0xC1; 32];
    claims.holder_ref = fixture.writer.to_hex();
    claims.actor_class = Some("agent".to_owned());
    claims.scope.verbs = ScopeAxis::Some(BTreeSet::from(["read".to_owned()]));
    claims.expires_at = claims.issued_at + 600;
    claims.ttl_secs = 600;
    let slip = fixture
        .vault
        .mint_capability_slip(&issuer, claims)
        .expect("mint the writer's read slip");
    let challenge = b"own-held-exposure";
    let signature = issuer
        .binding_proof(&slip, challenge)
        .expect("prove the writer holds its slip");
    let proof = fixture
        .vault
        .verify_capability_slip(&issuer.public_key(), &slip, challenge, &signature)
        .expect("verify the writer's read slip");
    assert_eq!(
        proof.claims().holder_ref,
        fixture.writer.to_hex(),
        "the verified slip names the writer {}",
        fixture.writer.to_hex()
    );
    let reader = fixture.writer().with_read_proof(&proof);
    let answer = bm25(&reader, MARKER);
    assert!(
        answer.held.iter().any(|v| v.claim_ref == fixture.claim_ref),
        "BM25 for MARKER must list held {} in held",
        fixture.claim_ref
    );
    assert!(
        !answer.held.iter().any(|v| v.claim_ref == second_ref),
        "BM25 for MARKER must not list NON_MATCH held {second_ref}"
    );
    fixture
        .vault
        .with_write_txn_grouped(|_| Ok(()))
        .expect("the vault's next write keeps the served records");
    let marker_id = EntityId::from_hex(&fixture.claim_ref).expect("fixture MARKER claim id");
    let second_id = EntityId::from_hex(&second_ref).expect("second NON_MATCH claim id");
    let exposed = exposed_records(&fixture.vault, &fixture.writer)
        .expect("read the writer's kept exposure rows");
    assert!(
        exposed.contains(&marker_id),
        "exposure must hold served MARKER {} ({} rows)",
        fixture.claim_ref,
        exposed.len()
    );
    assert!(
        !exposed.contains(&second_id),
        "exposure must not hold unserved NON_MATCH {second_ref}"
    );
    let exposure = fixture
        .vault
        .actor_read_exposure(&fixture.writer)
        .expect("read the writer's exposure")
        .expect("the writer was served a record");
    assert_eq!(
        exposure.distinct_records, 1,
        "one record served, the MARKER claim {}",
        fixture.claim_ref
    );
    let fresh = "freshnomatch4x7q";
    assert!(
        bm25(&reader, fresh).held.is_empty(),
        "BM25 for fresh word {fresh} leaves held empty"
    );
    fixture
        .vault
        .with_write_txn_grouped(|_| Ok(()))
        .expect("next write after the fresh query");
    let exposed =
        exposed_records(&fixture.vault, &fixture.writer).expect("exposure after the fresh query");
    assert!(
        exposed == BTreeSet::from([marker_id]),
        "fresh query gains neither ({} rows, MARKER {}, NON_MATCH {second_ref})",
        exposed.len(),
        fixture.claim_ref
    );
}

#[test]
fn a_held_producer_reads_again_for_its_writer_alone() {
    let fixture = Fixture::new();
    let claim = EntityId::from_hex(&fixture.claim_ref).expect("fixture claim id");
    let writer_key = fixture.writer().read_key().expect("the writer's read key");
    let readable = fixture
        .vault
        .own_held_claim_readable(writer_key.clone(), &claim)
        .expect("judge the writer's held claim");
    let surfaceable = fixture
        .vault
        .scoped_read(writer_key)
        .is_entity_readable(&claim)
        .expect("judge the held claim on the Surfaceable lane");
    assert!(
        readable,
        "own held {} must read again for its writer",
        fixture.claim_ref
    );
    assert!(
        !surfaceable,
        "Surfaceable must refuse held {} (the retry bug's cause)",
        fixture.claim_ref
    );
    let other_key = fixture
        .other()
        .read_key()
        .expect("the other agent's read key");
    let other_readable = fixture
        .vault
        .own_held_claim_readable(other_key.clone(), &claim)
        .expect("judge the held claim for the other agent");
    let other_surfaceable = fixture
        .vault
        .scoped_read(other_key)
        .is_entity_readable(&claim)
        .expect("judge the held claim on the other's lane");
    assert!(
        !other_readable,
        "held {} must not read for the other agent",
        fixture.claim_ref
    );
    assert!(
        !other_surfaceable,
        "other's Surfaceable must not read held {}",
        fixture.claim_ref
    );
    fixture.approve();
    let writer_key = fixture
        .writer()
        .read_key()
        .expect("the writer's read key after settle");
    let settled_own = fixture
        .vault
        .own_held_claim_readable(writer_key.clone(), &claim)
        .expect("judge the settled claim as own held");
    let settled_plain = fixture
        .vault
        .scoped_read(writer_key)
        .is_entity_readable(&claim)
        .expect("judge the settled claim on the plain lane");
    assert!(
        !settled_own,
        "settled {} is ordinary, not own held",
        fixture.claim_ref
    );
    assert!(
        settled_plain,
        "settled {} must read on the plain lane",
        fixture.claim_ref
    );
}

#[test]
fn held_lists_keep_the_applied_stale_selector() {
    let fixture = Fixture::new();
    let writer = fixture.writer();
    let demoted = writer
        .claim_demote(&ClaimDemoteRequest {
            claim_ref: fixture.claim_ref.clone(),
            action: ClaimDemoteActionInput::Stale,
        })
        .expect("mark the writer's held proposal stale");
    assert!(
        demoted.stale,
        "demoting held {} must mark stale (rung {})",
        fixture.claim_ref, demoted.rung
    );
    let pending = writer.pending_writes(10).expect("read the pending tray");
    assert!(
        pending.iter().any(|row| row.claim_ref == fixture.claim_ref),
        "stale {} keeps its tray row, so still held",
        fixture.claim_ref
    );
    let stale_filter = || ReadFilterInput {
        include_stale: Some(true),
        ..Default::default()
    };
    let search = bm25_with_filter(&writer, MARKER, stale_filter());
    assert!(
        !search.receipt.actor_ceiling.include_stale,
        "agent ceiling must exclude stale (claim {})",
        fixture.claim_ref
    );
    assert!(
        !search.receipt.applied.include_stale,
        "BM25 include_stale=true under ceiling false must apply false (claim {})",
        fixture.claim_ref
    );
    assert!(
        !search.held.iter().any(|v| v.claim_ref == fixture.claim_ref),
        "BM25 applied false must not list stale held {}",
        fixture.claim_ref
    );
    let pack = recall_with_filter(&writer, MARKER, stale_filter());
    assert!(
        !pack.narrowing.applied.include_stale,
        "recall include_stale=true under ceiling false must apply false (claim {})",
        fixture.claim_ref
    );
    assert!(
        !pack.held.iter().any(|v| v.claim_ref == fixture.claim_ref),
        "recall applied false must not list stale held {}",
        fixture.claim_ref
    );
    {
        use oneiron::policy_manifest_doors::{
            PolicyGrantMapEntry, PolicyGrantValue, PolicyManifestPut, PolicyManifestRead,
            policy_manifests_as_owner, put_policy_manifest_as_owner,
        };
        let proof = fixture
            .vault
            .authenticate_owner(
                fixture.owner,
                "principal:held-stale-true",
                true,
                GateDecisionId::now(),
            )
            .expect("owner proof for the stale ceiling");
        let view = policy_manifests_as_owner(
            &fixture.vault,
            &proof,
            &PolicyManifestRead { manifest_ref: None },
        )
        .expect("read the policy manifests");
        let default = view
            .manifests
            .iter()
            .find(|e| e.manifest_ref == view.default_manifest_ref)
            .expect("default policy manifest");
        let mut manifest = default.manifest.clone();
        let mut rows = manifest.scoped_grants.clone().unwrap_or_default();
        let writer_hex = fixture.writer.to_hex();
        let mut patched = false;
        for row in rows.iter_mut() {
            if row.actor_ref.as_deref() == Some(writer_hex.as_str()) {
                row.selectors = Some(PolicyGrantValue::Map(vec![PolicyGrantMapEntry {
                    key: PolicyGrantValue::String("include_stale".to_owned()),
                    value: PolicyGrantValue::Boolean(true),
                }]));
                patched = true;
            }
        }
        assert!(
            patched,
            "writer permit row must exist to patch stale true (claim {})",
            fixture.claim_ref
        );
        manifest.scoped_grants = Some(rows);
        put_policy_manifest_as_owner(
            &fixture.vault,
            &proof,
            PolicyManifestPut {
                manifest_ref: Some(default.manifest_ref.clone()),
                expected_body_hash: Some(default.body_hash.clone()),
                manifest,
            },
        )
        .expect("patch the writer's ceiling to include stale");
    }
    let search = bm25_with_filter(&writer, MARKER, stale_filter());
    assert!(
        search.receipt.applied.include_stale,
        "BM25 include_stale=true under ceiling true must apply true (claim {})",
        fixture.claim_ref
    );
    assert!(
        search.held.iter().any(|v| v.claim_ref == fixture.claim_ref),
        "BM25 applied true must list stale held {}",
        fixture.claim_ref
    );
    let pack = recall_with_filter(&writer, MARKER, stale_filter());
    assert!(
        pack.narrowing.applied.include_stale,
        "recall include_stale=true under ceiling true must apply true (claim {})",
        fixture.claim_ref
    );
    assert!(
        pack.held.iter().any(|v| v.claim_ref == fixture.claim_ref),
        "recall applied true must list stale held {}",
        fixture.claim_ref
    );
}
