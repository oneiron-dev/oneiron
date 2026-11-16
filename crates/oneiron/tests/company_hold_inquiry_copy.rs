//! A company hold names an inquiry (ARCH-0038 #company-hold): it holds the
//! receipt, and the answer only as the kept copy. With `copy`, the hold's
//! Records capture holds the copied CLAIMs and its Inquiries capture the
//! receipt and the delivery rows. With `task`, only the receipt. An inquiry
//! this vault never sent is refused, and a host order never names one.
//!
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron --all-features --test company_hold_inquiry_copy`
#![cfg(oneiron_test_support)]

use std::collections::BTreeSet;
use std::sync::{Arc, Mutex};

use oneiron::authority::{
    AuthorityVaultId, CapabilitySlip, HOST_ISSUER_SEED_BYTES, HostSlipIssuer, MachineRole,
};
use oneiron::consent::AuthenticatedOwner;
use oneiron::deletion::{HostOrderHold, LegalHoldTarget};
use oneiron::federation::FederationGrantRole;
use oneiron::inquiry::{
    Inquiry, InquiryAnswer, InquiryEdge, InquiryEdgeRequest, InquiryKeep, InquiryOutcome,
    InquiryRouteRequest, InquirySendRequest, InquirySent, InquiryStatement, InquiryTransport,
    InquiryTransportError, StatementSource,
};
use oneiron::store::GateDecisionId;
use oneiron::task_verb::TaskCreateSpec;
use oneiron::test_doors::legal_hold::{open_clone, open_production};
use oneiron::test_doors::membership::stand_member_grant;
use oneiron::{EdgeActorClass, EntityId, HostingPrivacyPosture, TimeRange, Vault, VaultConfig};
use oneiron_crypto::HybridSecretKey;

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

fn at<E: std::fmt::Debug>(step: &'static str) -> impl FnOnce(E) -> Box<dyn std::error::Error> {
    move |error| format!("{step}: {error:?}").into()
}

const SHARED: u64 = 42;
const ASKER_BYTES: [u8; 16] = [0xE1; 16];
const COMPANY: &str = "Acme";
const MEMBER: &str = "owen";
const MEMBER_HOST: &str = "https://member.example";
const QUESTION: &str = "Is owen in the office on Thursday?";
const OUT_THURSDAY: &str = "Out Thursday. Back Friday.";
const BUSY_THURSDAY: &str = "Busy Thursday.";
const STATEMENT_PREDICATE: &str = "profile.statement";

struct Side {
    vault: Vault,
    proof: AuthenticatedOwner,
    issuer: HostSlipIssuer,
    vault_id: AuthorityVaultId,
    _dir: tempfile::TempDir,
}

fn open_vault() -> (tempfile::TempDir, Vault) {
    let dir = tempfile::tempdir().expect("vault directory");
    let vault = Vault::open(dir.path(), VaultConfig::device()).expect("fresh vault");
    (dir, vault)
}

fn open_company_vault() -> (tempfile::TempDir, tempfile::TempDir, Vault) {
    let dir = tempfile::tempdir().expect("vault directory");
    let store = tempfile::tempdir().expect("hold store directory");
    let config = VaultConfig::device().with_legal_hold_store(store.path().to_path_buf());
    let vault = Vault::open_owned(dir.path(), config).expect("fresh company vault");
    (dir, store, vault)
}

fn root(dir: tempfile::TempDir, vault: Vault, seed: u8) -> Side {
    vault.install_device_keystore(Arc::new(oneiron_keystore::MemoryKeystore::default()));
    let issuer = HostSlipIssuer::from_seed(&[seed; HOST_ISSUER_SEED_BYTES]).expect("host issuer");
    vault.ensure_host_root_slip(&issuer).expect("host root");
    vault
        .provision_engine_machine_identities(&issuer)
        .expect("engine machine identities");
    vault
        .ensure_serving_install_profile(&issuer, MachineRole::Unanswered)
        .expect("this install's machine profile");
    let owner = vault.ensure_embedded_owner_actor().expect("owner actor");
    oneiron::test_support::bind_host_owner(&vault, &issuer, owner).expect("owner bound");
    let proof = vault
        .authenticate_owner(owner, &owner.to_hex(), true, GateDecisionId::now())
        .expect("owner proof");
    let vault_id = vault
        .authority_fold()
        .expect("authority fold")
        .vault_id
        .expect("a rooted vault has an id");
    Side {
        vault,
        proof,
        issuer,
        vault_id,
        _dir: dir,
    }
}

fn person(vault: &Vault, id: EntityId) -> EntityId {
    vault
        .put_entity(
            &id,
            oneiron::registry::ENTITY_TYPE_PERSON,
            TimeRange { start: 1, end: 1 },
            1,
            b"a person of the company",
        )
        .expect("person");
    id
}

fn open_task(vault: &Vault, actor: EntityId, title: &str) -> EntityId {
    vault
        .memory(actor, EdgeActorClass::Agent)
        .tasks_create(&TaskCreateSpec::new(
            rmpv::Value::from(title),
            None,
            None,
            Some(3_600),
        ))
        .expect("the agent creates its TASK")
        .task_ref
        .expect("the TASK is minted")
}

#[allow(dead_code)]
struct Asking {
    member: Side,
    company: Side,
    asker: EntityId,
    task: EntityId,
    seat: EntityId,
    edge: InquiryEdge,
    slip: CapabilitySlip,
    _store_dir: tempfile::TempDir,
}

fn asking() -> Asking {
    let (member_dir, member_vault) = open_vault();
    let member = root(member_dir, member_vault, 0x11);
    let (dir, store_dir, vault) = open_company_vault();
    let asker = person(&vault, EntityId::from_bytes(ASKER_BYTES).expect("asker id"));
    let task = open_task(&vault, asker, "plan the Thursday visit");
    let company = root(dir, vault, 0x22);
    company
        .vault
        .initialize_shared_vault(
            &company.proof,
            SHARED,
            None,
            &[],
            company.vault.now_recorded_at(),
        )
        .expect("the company's shared vault");
    let seat = seat(&company);
    let edge = activate_edge(&member, &company, MEMBER);
    let slip = mint_slip(&member, &edge, company.issuer.binding_key());
    let fixture = Asking {
        member,
        company,
        asker,
        task,
        seat,
        edge,
        slip,
        _store_dir: store_dir,
    };
    fixture
        .company
        .vault
        .open_inquiry_route(
            &fixture.company.proof,
            &fixture.company.issuer,
            &fixture.route_request(fixture.seat, fixture.slip.clone()),
        )
        .expect("the company Owner opens the route");
    fixture
}

fn seat(company: &Side) -> EntityId {
    let seat = person(&company.vault, EntityId::now());
    stand_member_grant(&company.vault, seat, SHARED, FederationGrantRole::Member)
        .expect("the member's seat");
    seat
}

fn activate_edge(member: &Side, company: &Side, name: &str) -> InquiryEdge {
    let edge = member
        .vault
        .mint_inquiry_edge(
            &member.proof,
            &InquiryEdgeRequest::member_defaults(company.vault_id, COMPANY),
        )
        .expect("the member mints the inquiry edge");
    let reciprocal = company
        .vault
        .mint_inquiry_edge_reciprocal_grant(&company.proof, member.vault_id, name)
        .expect("the company Owner mints the reciprocal grant");
    let offer = member
        .vault
        .propose_connect_as(
            &member.proof,
            &member.issuer,
            edge.grant,
            company.vault_id,
            edge.pact_direction().expect("the edge's direction"),
            reciprocal
                .pact_direction()
                .expect("the reciprocal grant's direction"),
        )
        .expect("the member offers the Connect");
    let (_, counter) = company
        .vault
        .accept_connect_as(&company.proof, &company.issuer, reciprocal.grant, &offer)
        .expect("the company Owner accepts");
    member
        .vault
        .accept_connect_as(&member.proof, &member.issuer, edge.grant, &counter)
        .expect("the member accepts the company's half");
    edge
}

fn mint_slip(member: &Side, edge: &InquiryEdge, holder_key: [u8; 32]) -> CapabilitySlip {
    member
        .vault
        .mint_guest_slip(
            &member.proof,
            &member.issuer,
            edge.grant,
            Some(holder_key),
            member.vault.now_recorded_at() + 3_600,
            None,
        )
        .expect("the member's vault mints the company host's slip")
}

impl Asking {
    fn route_request(&self, seat: EntityId, slip: CapabilitySlip) -> InquiryRouteRequest {
        InquiryRouteRequest {
            shared_vault_id: SHARED,
            member: seat,
            member_vault_id: self.member.vault_id,
            member_host: MEMBER_HOST.to_owned(),
            slip,
        }
    }

    fn request(&self, task: EntityId, inquiry_id: Option<EntityId>) -> InquirySendRequest {
        InquirySendRequest {
            shared_vault_id: SHARED,
            member: self.seat,
            asker: self.asker,
            asker_role: "scheduling agent".to_owned(),
            task,
            purpose: "plan the Thursday visit".to_owned(),
            question: QUESTION.to_owned(),
            expires_at: self.company.vault.now_recorded_at() + 600,
            inquiry_id,
        }
    }

    fn send(&self, host: &MemberHost, task: EntityId) -> InquirySent {
        self.company
            .vault
            .send_inquiry(&self.request(task, None), host)
            .expect("the send")
    }

    fn install_keep(&self, keep: &str) {
        let policy = serde_json::json!({
            "schema_version": "1.2",
            "pack_id": "inquiry-asking-side",
            "pack_version": "1.0.0",
            "min_engine_version": "0.0.0",
            "defaults": {},
            "rules": [],
            "actor_ceilings": [],
            "inquiry": { "version": 1, "keep": keep },
        });
        self.company
            .vault
            .install_owner_policy_manifest(
                &self.company.proof,
                EntityId::now(),
                rmp_serde::to_vec_named(&policy).expect("encode"),
                self.company.vault.now_recorded_at(),
            )
            .expect("the company Owner installs the inquiry row");
    }

    fn copies(&self) -> Vec<(EntityId, oneiron::claim::ClaimBody)> {
        let mut copies: Vec<_> = self
            .company
            .vault
            .claims_for_subject(&self.seat)
            .expect("claims about the member")
            .into_iter()
            .filter_map(|id| {
                let body = self.company.vault.get_claim(&id).expect("claim read")?;
                (body.predicate == STATEMENT_PREDICATE).then_some((id, body))
            })
            .collect();
        copies.sort_by_key(|(id, _)| *id);
        copies
    }
}

struct MemberHost {
    valid_until: u64,
    calls: Mutex<usize>,
}

impl MemberHost {
    fn answering(company: &Side) -> Self {
        Self {
            valid_until: company.vault.now_recorded_at() + 3_600,
            calls: Mutex::new(0),
        }
    }

    fn call_count(&self) -> usize {
        *self.calls.lock().expect("calls")
    }
}

impl InquiryTransport for MemberHost {
    fn exchange(
        &self,
        _member_host: &str,
        _member_vault_id: &AuthorityVaultId,
        _slip_token: &str,
        inquiry: &[u8],
    ) -> Result<Vec<u8>, InquiryTransportError> {
        let inquiry = Inquiry::decode_wire(inquiry).expect("the inquiry crosses in its wire shape");
        let answer = InquiryAnswer::answered(
            &inquiry,
            vec![
                InquiryStatement::new(OUT_THURSDAY, StatementSource::MemberWord)
                    .expect("statement"),
                InquiryStatement::new(BUSY_THURSDAY, StatementSource::CompanionOfMember)
                    .expect("statement"),
            ],
            self.valid_until,
        )
        .expect("answer");
        *self.calls.lock().expect("calls") += 1;
        Ok(answer.encode_wire().expect("encode"))
    }
}

#[test]
fn a_company_hold_on_a_copy_inquiry_holds_the_receipt_and_the_copied_answer() -> TestResult {
    let fixture = asking();
    fixture.install_keep("copy");
    let host = MemberHost::answering(&fixture.company);
    let sent = fixture.send(&host, fixture.task);
    assert_eq!(
        sent.outcome,
        InquiryOutcome::Answered,
        "the copy send is answered"
    );
    assert_eq!(
        sent.inquiry.keep,
        InquiryKeep::Copy,
        "the inquiry keeps a copy"
    );
    assert!(!sent.held, "a copied answer is not held with the task");
    let copies = fixture.copies();
    assert_eq!(copies.len(), 2, "the two statements land as two CLAIMs");
    let copy_ids: BTreeSet<[u8; 16]> = copies.iter().map(|(id, _)| *id.as_bytes()).collect();
    let calls_after_send = host.call_count();
    assert_eq!(calls_after_send, 1, "the send went out once");

    let vault = &fixture.company.vault;
    let hold = vault
        .place_legal_hold(
            &fixture.company.proof,
            vec![LegalHoldTarget::Inquiry(sent.inquiry.id)],
            None,
            None,
        )
        .map_err(at("the company places its hold on the inquiry"))?;
    assert_eq!(
        host.call_count(),
        calls_after_send,
        "the hold makes no call to the member host"
    );
    let components = open_clone(vault, hold.hold_id).map_err(at("open the sealed copy"))?;
    assert!(
        !components.is_empty(),
        "the sealed copy opens under the company vault"
    );

    let inquiry_hex = sent.inquiry.id.to_hex();
    let record_sources: BTreeSet<[u8; 16]> = components
        .iter()
        .filter(|component| component.family == "entities")
        .map(|component| component.source)
        .collect();
    assert_eq!(
        record_sources, copy_ids,
        "the Records capture holds exactly the two copy CLAIM ids"
    );
    for id in &copy_ids {
        let row = components
            .iter()
            .find(|component| component.family == "entities" && &component.source == id)
            .ok_or("the Records capture holds each copy CLAIM's entity row")?;
        assert_eq!(
            row.key,
            id.to_vec(),
            "each copy CLAIM's entity row key is its id"
        );
    }
    let record_text: Vec<u8> = components
        .iter()
        .filter(|component| component.family == "entities")
        .flat_map(|component| component.value.clone())
        .collect();
    assert!(
        record_text
            .windows(OUT_THURSDAY.len())
            .any(|window| window == OUT_THURSDAY.as_bytes()),
        "the Records capture carries the member's word"
    );
    assert!(
        record_text
            .windows(BUSY_THURSDAY.len())
            .any(|window| window == BUSY_THURSDAY.as_bytes()),
        "the Records capture carries the companion's answer"
    );

    let receipts: Vec<_> = components
        .iter()
        .filter(|component| component.family == "inquiry_receipt")
        .collect();
    assert!(
        !receipts.is_empty(),
        "the Inquiries capture holds the receipt row"
    );
    for receipt in &receipts {
        assert_eq!(
            receipt.source,
            *sent.inquiry.id.as_bytes(),
            "each receipt row's source is the inquiry"
        );
        let key = String::from_utf8_lossy(&receipt.key);
        assert!(
            key.contains(&format!("inquiry:{inquiry_hex}:")),
            "each receipt row key names the inquiry: {key}"
        );
    }
    let ledgers: Vec<_> = components
        .iter()
        .filter(|component| component.family == "federation_delivered_record")
        .collect();
    assert_eq!(
        ledgers.len(),
        2,
        "the Inquiries capture holds exactly two ledger rows"
    );
    for ledger in &ledgers {
        assert_eq!(
            ledger.source,
            *sent.inquiry.id.as_bytes(),
            "each ledger row's source is the inquiry"
        );
        assert_eq!(
            ledger.value.get(16..48),
            Some(&fixture.member.vault_id[..]),
            "each ledger row names the member's vault as the copy's source"
        );
    }
    // A ledger row is grant (16), source vault (32), then the BLAKE3 of the
    // CLAIM row it delivered (32): the held rows are the delivered copies.
    let delivered_hashes: BTreeSet<Vec<u8>> = ledgers
        .iter()
        .filter_map(|ledger| ledger.value.get(48..80).map(<[u8]>::to_vec))
        .collect();
    let held_hashes: BTreeSet<Vec<u8>> = components
        .iter()
        .filter(|component| component.family == "entities")
        .map(|component| blake3::hash(&component.value).as_bytes().to_vec())
        .collect();
    assert_eq!(
        held_hashes, delivered_hashes,
        "each held CLAIM row is byte for byte the row its ledger row delivered"
    );

    let deleted = copies[0].0;
    let removed = vault
        .delete_entity(&deleted)
        .map_err(at("the company deletes one copy CLAIM"))?;
    assert!(removed, "the ordinary delete of one copy CLAIM succeeds");
    let recipient = HybridSecretKey::from_seed(&[0x5c; 32], b"test/legal-hold-recipient")
        .map_err(at("the recipient's key"))?;
    let production = vault
        .produce_legal_hold(&fixture.company.proof, hold.hold_id, recipient.public_key())
        .map_err(at("produce the hold after the delete"))?;
    let produced =
        open_production(vault, &production, &recipient).map_err(at("open the production"))?;
    assert!(
        produced.iter().any(|component| {
            component.family == "entities"
                && component.source == *deleted.as_bytes()
                && component.key == deleted.as_bytes().to_vec()
        }),
        "a new produce still opens the deleted CLAIM's row"
    );
    Ok(())
}

#[test]
fn a_company_hold_on_a_task_inquiry_holds_the_receipt_only() -> TestResult {
    let fixture = asking();
    let host = MemberHost::answering(&fixture.company);
    let sent = fixture.send(&host, fixture.task);
    assert_eq!(
        sent.outcome,
        InquiryOutcome::Answered,
        "the task send is answered"
    );
    assert_eq!(
        sent.inquiry.keep,
        InquiryKeep::Task,
        "no inquiry row means the keep is task"
    );
    assert!(fixture.copies().is_empty(), "a task answer lands no CLAIM");

    let vault = &fixture.company.vault;
    let hold = vault
        .place_legal_hold(
            &fixture.company.proof,
            vec![LegalHoldTarget::Inquiry(sent.inquiry.id)],
            None,
            None,
        )
        .map_err(at("the company places its hold on the task inquiry"))?;
    let components = open_clone(vault, hold.hold_id).map_err(at("open the sealed copy"))?;
    let entities: Vec<_> = components
        .iter()
        .filter(|component| component.family == "entities")
        .collect();
    assert!(
        entities.is_empty(),
        "the hold has no Records capture with a CLAIM"
    );
    let receipts: Vec<_> = components
        .iter()
        .filter(|component| component.family == "inquiry_receipt")
        .collect();
    assert!(
        !receipts.is_empty(),
        "the Inquiries capture holds the receipt row"
    );
    let ledgers = components
        .iter()
        .filter(|component| component.family == "federation_delivered_record")
        .count();
    assert_eq!(
        ledgers, 0,
        "the Inquiries capture holds no ledger row for a task keep"
    );
    for component in &components {
        assert!(
            !component
                .value
                .windows(OUT_THURSDAY.len())
                .any(|window| window == OUT_THURSDAY.as_bytes()),
            "no opened plaintext carries the member's word"
        );
        assert!(
            !component
                .value
                .windows(BUSY_THURSDAY.len())
                .any(|window| window == BUSY_THURSDAY.as_bytes()),
            "no opened plaintext carries the companion's answer"
        );
    }
    Ok(())
}

#[test]
fn a_hold_naming_an_inquiry_this_vault_never_sent_is_refused() -> TestResult {
    let fixture = asking();
    let vault = &fixture.company.vault;
    let fresh = EntityId::now();
    let refused = match vault.place_legal_hold(
        &fixture.company.proof,
        vec![LegalHoldTarget::Inquiry(fresh)],
        None,
        None,
    ) {
        Ok(_) => return Err("a hold on an unsent inquiry must be refused".into()),
        Err(error) => error,
    };
    match refused {
        oneiron::Error::InvalidConfig(message) => assert!(
            message.contains("a legal hold names an inquiry this vault never sent"),
            "the refusal names the unsent inquiry: {message}"
        ),
        other => return Err(format!("the refusal is InvalidConfig, not {other:?}").into()),
    }
    assert!(
        vault
            .legal_holds(&fixture.company.proof)
            .map_err(at("list the holds after the refusal"))?
            .is_empty(),
        "the vault lists no hold after the refusal"
    );

    // A host order is placed only where Oneiron hosts the bytes: a hosted
    // vault, so the refusal read is the inquiry one.
    let hosted_dir = tempfile::tempdir().map_err(at("hosted vault directory"))?;
    let mut config = VaultConfig::device();
    config.privacy.posture = HostingPrivacyPosture::Hosted;
    let hosted = Vault::open(hosted_dir.path(), config).map_err(at("open a hosted vault"))?;
    let order = HostOrderHold {
        targets: vec![LegalHoldTarget::Inquiry(fresh)],
        order_ref: "order-1".to_owned(),
        ends_at: hosted.now_recorded_at() + 3_600,
        secret_until: None,
        placed_by: "host-operator".to_owned(),
        legal_basis_ref: None,
        jurisdiction: None,
        issuing_authority_ref: None,
        requires_non_use: false,
    };
    match hosted.place_host_order_hold(order) {
        Ok(_) => return Err("a host order naming an inquiry must be refused".into()),
        Err(oneiron::Error::InvalidConfig(message)) => assert_eq!(
            message, "a host order names records, not inquiries",
            "a host order naming an inquiry is refused before any write"
        ),
        Err(other) => {
            return Err(format!("the host refusal is InvalidConfig, not {other:?}").into());
        }
    }
    Ok(())
}
