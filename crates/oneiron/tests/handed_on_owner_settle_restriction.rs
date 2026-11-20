// Integration-test helpers (non-#[test] fns) are not covered by allow-unwrap-in-tests.
#![allow(clippy::unwrap_used, clippy::expect_used)]
//! [OWNER-DOOR-HANDED-ON-SLIP-SETTLE-LIFT]: the owner doors that settle a
//! proposal never lift a restriction for a handle that acts as no person.
//! RULING HANDED-ON-SLIP-PERSON Q1 = A: a person's slip handed on to another
//! key (`attenuate_to`) is no person's act; RULING
//! RESTRICTION-CLOSE-BY-CONFLICT-SETTLE = A: a settlement by no person never
//! lifts a restriction. The conflict door asks this of the owner too
//! (`tests/retained_curator_keep_restriction.rs`); `vault.claims.settle` asked
//! it only on its Grant arm.
//!
//! The settler that is no person here is the vault owner's handle with an
//! owner proof from `Vault::authenticate_owner`, presenting his slip handed on
//! to another key, as the conflict test builds it. A served request never
//! gets this pair (the owner proof needs his own unattenuated slip), but an
//! embedding host reaches each door through public calls. The restriction is
//! a Proposed `comm.do_not_contact` bar on a PERSON, which bars contact at any
//! approval, so a reject closes it.
//!
//! Three doors, each with a red, a guard and a control:
//! * `vault.claims.settle`, owner arm (`claim_settle_as_owner`): the red is
//!   refused and the bar stays open; the owner's own reject lands; the
//!   handed-on reject of a proposal that restricts no one lands.
//! * the run review (`settle_run_as_owner`): the run's reject is refused whole
//!   (a run settles once) and the bar stays open; the owner's own reject
//!   lands; the handed-on reject of a run over a note lands.
//! * a restore group's reject-all (`resolve_inbox_group_of_kind`, kind
//!   `restore`): the bar's member waits, refused, and stays Proposed while
//!   the note's member is rejected in the same act; the owner then rejects
//!   the waiting bar alone, on his own handle.
//!
//! Each vault is rooted under a host (the run review doors act only for the
//! root owner), with the shipped default manifest. Restore destinations open
//! at least one wall-clock second after their source (sleep 1100 ms), as in
//! `archive_restore_inbox_group.rs`.
//!
//! Run: `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron
//! --all-features --no-fail-fast --test handed_on_owner_settle_restriction`.
#![cfg(oneiron_test_support)]

use std::io::Cursor;

use ed25519_dalek::Signer;
use oneiron::agent_inbox_lens::InboxRunGroupsRequest;
use oneiron::authority::{HostSlipIssuer, SlipCaveat, VerifiedSlip};
use oneiron::campaign::claims::{
    CommDoNotContactValue, DO_NOT_CONTACT_SCOPE_ALL, PREDICATE_COMM_DO_NOT_CONTACT,
    encode_do_not_contact_value,
};
use oneiron::consent::AuthenticatedOwner;
use oneiron::inbox::InboxGroupResolveRequest;
use oneiron::memory::run_review::{
    RunChangeVerdict, RunReviewChange, RunReviewRequest, RunSettleDecision, RunSettleRequest,
    RunSettlement,
};
use oneiron::memory::{
    ClaimInput, ClaimProposalReviewRequest, ClaimSettleDecision, ClaimSettleRequest,
    ClaimSettlement, ClaimSettlementVerdict, MEMORY_CODE_FORBIDDEN, MemoryResult,
    resolve_entity_ref,
};
use oneiron::registry::ENTITY_TYPE_PERSON;
use oneiron::store::GateDecisionId;
use oneiron::test_doors::comm_claim_rows::put_comm_claim_row;
use oneiron::{
    ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus, ClaimSource, ClaimSubject,
    EdgeActorClass, EntityId, Memory, TimeRange, Vault, VaultConfig,
};
use rmpv::Value;
use serde_json::json;

const LEARNED_AT: u64 = 1_780_000_000;

/// A row that restricts no one. The shipped manifest rates `profile.` normal.
const NOTE: &str = "profile.note";

/// The refusal of a settlement by no person that lifts a restriction.
const LIFTS_A_RESTRICTION: &str = "a claim that restricts someone's access";

/// A vault rooted under `issuer`, which binds its embedded owner under the
/// root, with this install's signing keys loaded. Returns the owner.
fn root_under(vault: &Vault, issuer: &HostSlipIssuer) -> EntityId {
    vault.install_device_keystore(std::sync::Arc::new(oneiron_keystore::MemoryKeystore::new()));
    vault
        .prepare_install_signing()
        .expect("load this install's signing keys");
    let owner = vault.ensure_embedded_owner_actor().expect("owner");
    vault
        .ensure_host_root_slip(issuer)
        .expect("the host root binds the owner");
    owner
}

fn owner_proof(vault: &Vault, owner: EntityId) -> AuthenticatedOwner {
    vault
        .authenticate_owner(owner, &owner.to_hex(), true, GateDecisionId::now())
        .expect("owner proof")
}

/// The owner's Human slip from the host root, handed on to another key (as
/// `tests/retained_curator_keep_restriction.rs` hands it on).
fn owner_slip_handed_on(vault: &Vault, issuer: &HostSlipIssuer, owner: EntityId) -> VerifiedSlip {
    let mut claims = vault
        .ensure_host_root_slip(issuer)
        .expect("the host root")
        .claims;
    claims.slip_id = slip_id();
    claims.holder_ref = owner.to_hex();
    claims.actor_class = Some("human".to_owned());
    let mut handed = vault
        .mint_capability_slip(issuer, claims)
        .expect("the owner's slip");
    let next = ed25519_dalek::SigningKey::from_bytes(
        blake3::hash(b"handed-on owner settle holder").as_bytes(),
    );
    issuer
        .attenuate_to(
            &mut handed,
            SlipCaveat::default(),
            next.verifying_key().to_bytes(),
        )
        .expect("the slip is handed on");
    let challenge = b"handed-on owner settle slip";
    let binding = next
        .sign(
            &handed
                .binding_transcript(challenge)
                .expect("the transcript"),
        )
        .to_bytes();
    let handed = vault
        .verify_capability_slip(&issuer.public_key(), &handed, challenge, &binding)
        .expect("the handed slip verifies");
    assert!(handed.is_transferred(), "control: the slip was handed on");
    handed
}

/// A fresh slip id from two UUIDv7 stamps.
fn slip_id() -> [u8; 32] {
    let mut id = [0_u8; 32];
    id[..16].copy_from_slice(EntityId::now().as_bytes());
    id[16..].copy_from_slice(EntityId::now().as_bytes());
    id
}

fn at() -> TimeRange {
    TimeRange {
        start: LEARNED_AT,
        end: LEARNED_AT,
    }
}

/// A live PERSON with a name.
fn person(vault: &Vault, name: &str) -> EntityId {
    let mut body = Vec::new();
    rmpv::encode::write_value(
        &mut body,
        &Value::Map(vec![(Value::from("name"), Value::from(name))]),
    )
    .expect("encode person body");
    let person = EntityId::now();
    vault
        .put_entity(&person, ENTITY_TYPE_PERSON, at(), LEARNED_AT, &body)
        .expect("a live person");
    person
}

/// The row stored at `id`.
fn stored(vault: &Vault, id: EntityId) -> ClaimBody {
    vault
        .get_claim(&id)
        .expect("claim read")
        .expect("the row stands")
}

/// The bar at `id` still holds and waits.
fn assert_open(vault: &Vault, id: EntityId, why: &str) {
    let body = stored(vault, id);
    assert_eq!(
        (body.lifecycle, body.approval),
        (ClaimLifecycleStatus::Active, ClaimApprovalStatus::Proposed),
        "{why}"
    );
}

/// The refusal names the restriction rule.
fn assert_refused_as_a_restriction_close<T: std::fmt::Debug>(settled: MemoryResult<T>, why: &str) {
    let refused = settled.expect_err(why);
    assert_eq!(refused.code, MEMORY_CODE_FORBIDDEN, "{refused:?}");
    assert!(
        refused.message.contains(LIFTS_A_RESTRICTION),
        "the refusal names its reason: {refused:?}"
    );
}

/// A rooted vault with an agent that reads and proposes, so each proposal
/// waits for the owner.
struct Fixture {
    vault: Vault,
    owner: EntityId,
    issuer: HostSlipIssuer,
    proposer: EntityId,
    facet: EntityId,
    owner_proof: AuthenticatedOwner,
    // Dropped after the vault.
    _directory: tempfile::TempDir,
}

impl Fixture {
    fn new() -> Self {
        let directory = tempfile::tempdir().expect("vault dir");
        let vault = Vault::open(directory.path(), VaultConfig::device()).expect("open vault");
        let issuer =
            HostSlipIssuer::from_secret(b"handed-on-owner-settle").expect("fixture host issuer");
        let owner = root_under(&vault, &issuer);
        let proposer = vault
            .ensure_agent_principal("handed-on-settle-proposer")
            .expect("proposer");
        let facet = vault.default_facet().expect("default facet");
        let owner_proof = owner_proof(&vault, owner);
        vault
            .grant_foreign_principal(&owner_proof, &proposer.to_hex())
            .expect("the owner grants the proposer read and propose");
        Self {
            vault,
            owner,
            issuer,
            proposer,
            facet,
            owner_proof,
            _directory: directory,
        }
    }

    /// The owner's own handle.
    fn owner_memory(&self) -> Memory<'_> {
        self.vault.memory(self.owner, EdgeActorClass::Human)
    }

    /// The owner's handle presenting his slip handed on to another key.
    fn handed_on_memory(&self) -> Memory<'_> {
        let handed = owner_slip_handed_on(&self.vault, &self.issuer, self.owner);
        self.owner_memory().with_read_proof(&handed)
    }

    /// The proposer's `vault.claims.propose` of `predicate` about `subject`
    /// holding `value`, in the default facet. Returns the proposal's id.
    fn proposes(&self, predicate: &str, subject: EntityId, value: serde_json::Value) -> EntityId {
        let receipt = self
            .vault
            .memory(self.proposer, EdgeActorClass::Agent)
            .claim_propose(&ClaimInput {
                id: None,
                predicate: predicate.to_owned(),
                subject_ref: subject.to_hex(),
                value,
                confidence: 1.0,
                confidence_details: None,
                source: "inferred".to_owned(),
                world_ref: None,
                relationship_ref: None,
                scope: Some(json!({ "facet": self.facet.to_hex() })),
                valid_from: Some(100),
                valid_to: None,
                occurred_at: None,
                learned_at: None,
                salience: None,
            })
            .unwrap_or_else(|error| panic!("the proposer's {predicate} proposal: {error:?}"));
        assert_eq!(receipt.approval, "proposed", "the {predicate} proposal");
        resolve_entity_ref(&self.vault, &receipt.claim_short_id).expect("the proposal's id")
    }

    /// The proposer's Proposed do-not-contact bar on a new PERSON.
    fn proposed_do_not_contact(&self) -> EntityId {
        let person = person(&self.vault, "dana");
        self.proposes(
            PREDICATE_COMM_DO_NOT_CONTACT,
            person,
            json!({ "scope": DO_NOT_CONTACT_SCOPE_ALL }),
        )
    }

    /// The proposer's Proposed note on a new PERSON: it restricts no one.
    fn proposed_note(&self) -> EntityId {
        let person = person(&self.vault, "noor");
        self.proposes(NOTE, person, json!("a note"))
    }

    /// `memory`'s `vault.claims.review` then `vault.claims.settle` of `id`
    /// on the owner's arm, with the owner's proof.
    fn claims_settle(
        &self,
        memory: &Memory<'_>,
        id: EntityId,
        decision: ClaimSettleDecision,
    ) -> MemoryResult<ClaimSettlement> {
        let review = memory
            .claim_review_as_owner(
                &self.owner_proof,
                &ClaimProposalReviewRequest {
                    claim_ref: id.to_hex(),
                    grant_ref: None,
                },
            )
            .expect("the owner reviews the proposal");
        memory.claim_settle_as_owner(
            &self.owner_proof,
            &ClaimSettleRequest {
                claim_ref: id.to_hex(),
                review_id: review.review_id,
                decision,
                grant_ref: None,
            },
        )
    }

    /// `memory`'s run review of a run whose one member is `id`, then its
    /// settlement by `decision`, with the owner's proof.
    fn run_settle(
        &self,
        memory: &Memory<'_>,
        id: EntityId,
        decision: RunSettleDecision,
    ) -> MemoryResult<RunSettlement> {
        let request = RunReviewRequest {
            run_id: format!("run:handed-on-settle-{}", id.to_hex()),
            changes: vec![RunReviewChange::Claim {
                claim_ref: id.to_hex(),
            }],
        };
        let review = memory
            .review_run_as_owner(&self.owner_proof, &request)
            .expect("the owner reviews the run");
        assert_eq!(review.changes.len(), 1);
        assert_eq!(review.changes[0].verdict, RunChangeVerdict::Waiting);
        memory.settle_run_as_owner(
            &self.owner_proof,
            &RunSettleRequest {
                review: request,
                review_id: review.review_id,
                decision,
            },
        )
    }
}

/// `vault.claims.settle`, red: the handed-on owner's reject retracted the
/// Proposed bar. It is refused and the bar stays open for the owner, whose
/// own reject then lands.
#[test]
fn a_handed_on_owner_slip_never_rejects_a_do_not_contact_on_claims_settle() {
    let f = Fixture::new();
    let bar = f.proposed_do_not_contact();

    let settled = f.claims_settle(&f.handed_on_memory(), bar, ClaimSettleDecision::Reject);

    assert_open(
        &f.vault,
        bar,
        &format!("the do-not-contact bar still holds and waits (settle: {settled:?})"),
    );
    assert_refused_as_a_restriction_close(settled, "no person lifts a bar");
    let own = f
        .claims_settle(&f.owner_memory(), bar, ClaimSettleDecision::Reject)
        .expect("the proposal stays open for the owner's own reject");
    assert_eq!(own.verdict, ClaimSettlementVerdict::Rejected);
    assert_eq!(
        stored(&f.vault, bar).lifecycle,
        ClaimLifecycleStatus::Retracted
    );
}

/// `vault.claims.settle`, control: the handed-on owner's reject of a
/// proposal that restricts no one still lands.
#[test]
fn a_handed_on_owner_slip_still_rejects_a_note_on_claims_settle() {
    let f = Fixture::new();
    let note = f.proposed_note();

    let settled = f
        .claims_settle(&f.handed_on_memory(), note, ClaimSettleDecision::Reject)
        .expect("the handed-on reject of a note lands");

    assert_eq!(settled.verdict, ClaimSettlementVerdict::Rejected);
    assert_eq!(
        stored(&f.vault, note).lifecycle,
        ClaimLifecycleStatus::Retracted
    );
}

/// The run review, red: the handed-on owner's reject of a run over the bar
/// retracted it. The run's answer is refused whole and the bar stays open;
/// the owner's own reject of the same run then lands.
#[test]
fn a_handed_on_owner_slip_never_rejects_a_do_not_contact_in_a_run_review() {
    let f = Fixture::new();
    let bar = f.proposed_do_not_contact();

    let settled = f.run_settle(&f.handed_on_memory(), bar, RunSettleDecision::Reject);

    assert_open(
        &f.vault,
        bar,
        &format!("the do-not-contact bar still holds and waits (run settle: {settled:?})"),
    );
    assert_refused_as_a_restriction_close(settled, "no person lifts a bar in a run");
    let own = f
        .run_settle(&f.owner_memory(), bar, RunSettleDecision::Reject)
        .expect("the run stays open for the owner's own reject");
    assert_eq!(own.changes[0].verdict, RunChangeVerdict::Rejected);
    assert_eq!(
        stored(&f.vault, bar).lifecycle,
        ClaimLifecycleStatus::Retracted
    );
}

/// The run review, control: the handed-on owner's reject of a run over a
/// note still lands.
#[test]
fn a_handed_on_owner_slip_still_rejects_a_note_in_a_run_review() {
    let f = Fixture::new();
    let note = f.proposed_note();

    let settled = f
        .run_settle(&f.handed_on_memory(), note, RunSettleDecision::Reject)
        .expect("the handed-on reject of a run over a note lands");

    assert_eq!(settled.changes[0].verdict, RunChangeVerdict::Rejected);
    assert_eq!(
        stored(&f.vault, note).lifecycle,
        ClaimLifecycleStatus::Retracted
    );
}

/// A source vault holding a do-not-contact bar and a note, each about its
/// own PERSON, exported whole: the bar's and the note's ids and the archive.
fn restore_source() -> (EntityId, EntityId, Vec<u8>) {
    let dir = tempfile::tempdir().expect("source dir");
    let vault = Vault::open(dir.path(), VaultConfig::device()).expect("open source");
    vault.install_device_keystore(std::sync::Arc::new(oneiron_keystore::MemoryKeystore::new()));
    vault
        .prepare_install_signing()
        .expect("load this install's signing keys");
    vault.ensure_embedded_owner_actor().expect("source owner");
    let facet = vault.default_facet().expect("default facet");
    let mut bar_body = ClaimBody::new(
        PREDICATE_COMM_DO_NOT_CONTACT,
        ClaimSubject::Entity(person(&vault, "dana")),
        encode_do_not_contact_value(&CommDoNotContactValue {
            channel: None,
            scope: DO_NOT_CONTACT_SCOPE_ALL.to_owned(),
        }),
        1.0,
        ClaimApprovalStatus::Auto,
        ClaimLifecycleStatus::Active,
    )
    .expect("the bar's body");
    bar_body.source = Some(ClaimSource::Generated);
    bar_body.scope = None;
    bar_body.scope_facet = facet;
    let bar = EntityId::now();
    put_comm_claim_row(&vault, &bar, &bar_body, at(), LEARNED_AT).expect("the bar lands");
    let mut note_body = ClaimBody::new(
        NOTE,
        ClaimSubject::Entity(person(&vault, "noor")),
        Value::from("a note"),
        0.9,
        ClaimApprovalStatus::Auto,
        ClaimLifecycleStatus::Active,
    )
    .expect("the note's body");
    note_body.scope_facet = facet;
    let note = EntityId::now();
    vault
        .put_claim(&note, &note_body, at(), LEARNED_AT)
        .expect("the note lands");
    let archive = vault
        .export_whole_vault(true)
        .expect("whole-vault export")
        .bytes()
        .to_vec();
    (bar, note, archive)
}

/// A restore destination rooted under a host, opened at least one
/// wall-clock second after its source, with `archive` restored as its owner.
struct Restored {
    vault: Vault,
    owner: EntityId,
    issuer: HostSlipIssuer,
    owner_proof: AuthenticatedOwner,
    group_key: String,
    _directory: tempfile::TempDir,
}

impl Restored {
    fn new(archive: &[u8]) -> Self {
        std::thread::sleep(std::time::Duration::from_millis(1100));
        let directory = tempfile::tempdir().expect("destination dir");
        let vault = Vault::open(directory.path(), VaultConfig::device()).expect("open vault");
        let issuer = HostSlipIssuer::from_secret(b"handed-on-owner-settle-destination")
            .expect("destination host issuer");
        let owner = root_under(&vault, &issuer);
        let owner_proof = owner_proof(&vault, owner);
        let receipt = vault
            .import_whole_vault_archive_from_as_owner(Cursor::new(archive), &owner_proof)
            .unwrap_or_else(|error| panic!("the owner's whole archive restores: {error:?}"));
        let receipt_ref = receipt
            .owner_restore_receipt_ref
            .expect("the owner door names its restore receipt");
        let page = vault
            .memory(owner, EdgeActorClass::Human)
            .inbox_groups_page(
                &owner_proof,
                &InboxRunGroupsRequest {
                    limit: Some(200),
                    after: None,
                },
            )
            .expect("the owner's inbox page");
        let page = serde_json::to_value(page).expect("the page as JSON");
        let group_key = page["groups"]
            .as_array()
            .expect("the page's groups")
            .iter()
            .filter(|group| group["kind"] == "restore")
            .map(|group| &group["group"])
            .find(|group| group["receipt_ref"] == receipt_ref.as_str())
            .unwrap_or_else(|| panic!("the restore is one inbox group: {page:#}"))["group_key"]
            .as_str()
            .expect("group_key")
            .to_owned();
        Self {
            vault,
            owner,
            issuer,
            owner_proof,
            group_key,
            _directory: directory,
        }
    }

    /// `memory`'s reject-all of the restore group, with the owner's proof,
    /// as JSON.
    fn reject_all(&self, memory: &Memory<'_>) -> serde_json::Value {
        let request: InboxGroupResolveRequest = serde_json::from_value(json!({
            "kind": "restore",
            "group_key": self.group_key,
            "verb": "reject_all",
        }))
        .expect("restore is an inbox group kind");
        let resolution = memory
            .resolve_inbox_group_of_kind(&self.owner_proof, None, &request)
            .unwrap_or_else(|error| panic!("the restore group's reject-all: {error:?}"));
        serde_json::to_value(resolution).expect("the resolution as JSON")["resolution"].clone()
    }
}

/// The member of `resolution` that names `claim`.
fn member<'r>(resolution: &'r serde_json::Value, claim: EntityId) -> &'r serde_json::Value {
    resolution["members"]
        .as_array()
        .expect("the members")
        .iter()
        .find(|member| member["claim_ref"] == claim.to_hex())
        .unwrap_or_else(|| panic!("{} is a member: {resolution:#}", claim.to_hex()))
}

/// The restore group, red: the handed-on owner's reject-all retracted the
/// restored bar. Its member now waits, refused, and the bar stays Proposed,
/// while the note's member is rejected in the same act; the owner's own
/// reject of the waiting bar then lands.
#[test]
fn a_handed_on_owner_slip_never_rejects_a_restored_do_not_contact() {
    let (bar, note, archive) = restore_source();
    let r = Restored::new(&archive);
    assert_open(&r.vault, bar, "control: the bar restores Proposed");
    let handed = owner_slip_handed_on(&r.vault, &r.issuer, r.owner);
    let handed_memory = r
        .vault
        .memory(r.owner, EdgeActorClass::Human)
        .with_read_proof(&handed);

    let resolution = r.reject_all(&handed_memory);

    assert_eq!(
        member(&resolution, note)["verdict"],
        "rejected",
        "control: the note's member settles: {resolution:#}"
    );
    let waiting = member(&resolution, bar);
    assert_eq!(waiting["verdict"], "waiting", "{resolution:#}");
    assert_eq!(waiting["waiting"], "refused", "{resolution:#}");
    assert!(
        waiting["detail"]
            .as_str()
            .is_some_and(|detail| detail.contains(LIFTS_A_RESTRICTION)),
        "the wait names its reason: {resolution:#}"
    );
    assert_open(&r.vault, bar, "the restored bar still holds and waits");

    // A member left waiting is settled alone (review-each).
    let memory = r.vault.memory(r.owner, EdgeActorClass::Human);
    let review = memory
        .claim_review_as_owner(
            &r.owner_proof,
            &ClaimProposalReviewRequest {
                claim_ref: bar.to_hex(),
                grant_ref: None,
            },
        )
        .expect("the owner reviews the waiting bar");
    let own = memory
        .claim_settle_as_owner(
            &r.owner_proof,
            &ClaimSettleRequest {
                claim_ref: bar.to_hex(),
                review_id: review.review_id,
                decision: ClaimSettleDecision::Reject,
                grant_ref: None,
            },
        )
        .expect("the owner's own reject of the waiting bar lands");
    assert_eq!(own.verdict, ClaimSettlementVerdict::Rejected);
    assert_eq!(
        stored(&r.vault, bar).approval,
        ClaimApprovalStatus::Rejected
    );
}
