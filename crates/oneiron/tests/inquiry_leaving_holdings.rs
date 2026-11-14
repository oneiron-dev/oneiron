//! L7-09, leaving a company, engine half (ARCH-0043 #leaving-a-company: "The
//! member seat and the inquiry edge end together." "Each side gets a list of
//! what it holds from the other, by attribution, and one action to send
//! erase requests. Nothing is erased by force in either direction."):
//! - the company lists the member's copied inquiry answer by the member's
//!   attribution, and the member's vault holds nothing from the company;
//! - after the company's leave writer ends the seat, the member's own action
//!   ends its inquiry edge to that company (and no other), so both pacts are
//!   ended and an inquiry answers unavailable; a repeat ends nothing;
//! - one action queues an erase ask per ended pact; the company files it,
//!   it covers the copy, and nothing is erased; a repeat queues no second
//!   ask; the company's own action asks the member's vault the same way.
//!
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron --all-features --test inquiry_leaving_holdings`.

use std::sync::{Arc, Mutex};

use oneiron::authority::{
    AuthorityVaultId, FederationPactStatus, HOST_ISSUER_SEED_BYTES, HostSlipIssuer, MachineRole,
};
use oneiron::consent::AuthenticatedOwner;
use oneiron::deletion::{
    COOP_DELETION_PEER_PATH, CooperativeDeletionDeliveryStatus, CooperativeDeletionIngress,
};
use oneiron::federation::{FederationGrantRole, SharedVaultChange, pact_foreign_world};
use oneiron::inquiry::{
    Inquiry, InquiryAnswer, InquiryJoinPrepared, InquiryOutcome, InquiryRouteRequest,
    InquirySendRequest, InquirySent, InquiryStatement, InquiryTransport, InquiryTransportError,
    StatementSource,
};
use oneiron::store::GateDecisionId;
use oneiron::task_verb::TaskCreateSpec;
use oneiron::{EdgeActorClass, EntityId, TimeRange, Vault, VaultConfig};

/// The company's shared vault the member joins.
const SHARED: u64 = 42;
/// The first-party actor the default policy manifest grants an Auto
/// ceiling, so its TASK create takes direct effect: the asking agent.
const ASKER_BYTES: [u8; 16] = [0xE1; 16];
const COMPANY: &str = "Acme";
const MEMBER: &str = "owen";
const MEMBER_HOST: &str = "https://member.example";
const COMPANY_HOST: &str = "https://company.example";
const QUESTION: &str = "Is owen in the office on Thursday?";
/// The predicate an inquiry statement is a CLAIM of.
const STATEMENT_PREDICATE: &str = "profile.statement";
/// A company vault no fixture opens.
const ELSEWHERE: AuthorityVaultId = [0xbd; 32];

/// One rooted vault with its owner bound to its own host.
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

/// Roots `vault` under a host of its own (`seed`), its engine machines and
/// install profile provisioned and its owner bound, as a host does.
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

/// An open TASK `actor` creates for itself.
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

/// The member host double: it answers every inquiry with the member's word
/// and the companion's answer.
struct MemberHost {
    valid_until: u64,
    calls: Mutex<usize>,
}

impl MemberHost {
    fn new(company: &Side) -> Self {
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
        *self.calls.lock().expect("calls") += 1;
        let answer = InquiryAnswer::answered(
            &inquiry,
            vec![
                InquiryStatement::new("Out Thursday. Back Friday.", StatementSource::MemberWord)
                    .expect("statement"),
                InquiryStatement::new("Busy Thursday.", StatementSource::CompanionOfMember)
                    .expect("statement"),
            ],
            self.valid_until,
        )
        .expect("answer");
        Ok(answer.encode_wire().expect("encode"))
    }
}

/// The member joined the company with its inquiry edge (L7-04): the seat,
/// the company's half and the member's edge over one Active Connect pact,
/// and the route the company Owner opened, with the company keeping copies
/// of answers.
struct Leaving {
    member: Side,
    company: Side,
    asker: EntityId,
    task: EntityId,
    seat: EntityId,
    seat_proof: AuthenticatedOwner,
    prepared: InquiryJoinPrepared,
}

fn leaving() -> Leaving {
    let (member_dir, member_vault) = open_vault();
    let member = root(member_dir, member_vault, 0x11);
    let (dir, vault) = open_vault();
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
    let seat = person(&company.vault, EntityId::now());
    let seat_proof = company
        .vault
        .authenticate_owner(seat, &seat.to_hex(), true, GateDecisionId::now())
        .expect("the member's proof");
    let invited = company
        .vault
        .add_shared_member(
            &company.proof,
            SHARED,
            seat,
            Some(FederationGrantRole::Member),
        )
        .expect("the company Owner invites the member");
    let SharedVaultChange::MemberInvited { invitation, .. } = invited.change else {
        panic!("the Owner's add is an invitation");
    };
    let prepared = member
        .vault
        .prepare_inquiry_edge_for_join(
            &member.proof,
            &member.issuer,
            company.vault_id,
            COMPANY,
            MEMBER,
        )
        .expect("the member's vault prepares the edge");
    let (_, counter) = company
        .vault
        .accept_shared_invitation_with_inquiry_edge(
            &seat_proof,
            SHARED,
            &invitation,
            &company.issuer,
            &prepared.offer,
        )
        .expect("the member joins with the edge");
    let (pact, _) = member
        .vault
        .accept_connect_as(&member.proof, &member.issuer, prepared.edge.grant, &counter)
        .expect("the member's vault applies the company's counter");
    assert_eq!(pact.status, FederationPactStatus::Active);
    let slip = member
        .vault
        .mint_guest_slip(
            &member.proof,
            &member.issuer,
            prepared.edge.grant,
            Some(company.issuer.binding_key()),
            member.vault.now_recorded_at() + 3_600,
            None,
        )
        .expect("the member's vault mints the company host's slip");
    company
        .vault
        .open_inquiry_route(
            &company.proof,
            &company.issuer,
            &InquiryRouteRequest {
                shared_vault_id: SHARED,
                member: seat,
                member_vault_id: member.vault_id,
                member_host: MEMBER_HOST.to_owned(),
                slip,
            },
        )
        .expect("the company Owner opens the route");
    let fixture = Leaving {
        member,
        company,
        asker,
        task,
        seat,
        seat_proof,
        prepared,
    };
    fixture.install_keep_copy();
    fixture
}

impl Leaving {
    /// The Connect pact of the member's edge, one id in both vaults.
    fn pact(&self) -> [u8; 32] {
        self.prepared.offer.connect.pact_id
    }

    /// Installs the company's `inquiry` policy row: keep a copy.
    fn install_keep_copy(&self) {
        let policy = serde_json::json!({
            "schema_version": "1.2",
            "pack_id": "inquiry-leaving-holdings",
            "pack_version": "1.0.0",
            "min_engine_version": "0.0.0",
            "defaults": {},
            "rules": [],
            "actor_ceilings": [],
            "inquiry": { "version": 1, "keep": "copy" },
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

    fn send(&self, host: &MemberHost) -> InquirySent {
        self.company
            .vault
            .send_inquiry(
                &InquirySendRequest {
                    shared_vault_id: SHARED,
                    member: self.seat,
                    asker: self.asker,
                    asker_role: "scheduling agent".to_owned(),
                    task: self.task,
                    purpose: "plan the Thursday visit".to_owned(),
                    question: QUESTION.to_owned(),
                    expires_at: self.company.vault.now_recorded_at() + 600,
                    inquiry_id: None,
                },
                host,
            )
            .expect("the send")
    }

    /// The company asks and lands the member's answer as a copy; the
    /// copies' CLAIM ids, in id order.
    fn land_copy(&self) -> Vec<EntityId> {
        let sent = self.send(&MemberHost::new(&self.company));
        assert_eq!(sent.outcome, InquiryOutcome::Answered);
        let mut copies: Vec<EntityId> = self
            .company
            .vault
            .claims_for_subject(&self.seat)
            .expect("claims about the member")
            .into_iter()
            .filter(|id| {
                self.company
                    .vault
                    .get_claim(id)
                    .expect("claim read")
                    .is_some_and(|body| body.predicate == STATEMENT_PREDICATE)
            })
            .collect();
        copies.sort();
        assert_eq!(copies.len(), 2, "one CLAIM per statement: {copies:?}");
        copies
    }

    /// The foreign WORLD the member's copies land in at the company.
    fn copy_world(&self) -> EntityId {
        pact_foreign_world(
            &self.company.vault.authority_fold().expect("fold"),
            &self.pact(),
            self.prepared.edge.terms.opened_world,
        )
        .expect("derive")
        .expect("the pact")
        .entity_id()
    }

    /// The member leaves at the company (the company's writer ends the seat
    /// and the company's half), then ends its own edge.
    fn leave(&self) -> Vec<oneiron::receipt::GuestRevokeOutcome> {
        self.company
            .vault
            .leave_shared_vault(&self.seat_proof, SHARED, Some(&self.company.issuer))
            .expect("the member leaves");
        self.member
            .vault
            .end_inquiry_edges_with(
                &self.member.proof,
                &self.member.issuer,
                &self.company.vault_id,
            )
            .expect("the member ends its edge to the company")
    }

    fn pact_status(vault: &Vault, pact: &[u8; 32]) -> FederationPactStatus {
        vault
            .authority_fold()
            .expect("authority fold")
            .federation_pacts
            .get(pact)
            .expect("the pact stays logged")
            .status
    }
}

fn courtesy_route(host: &str) -> String {
    format!("{host}{COOP_DELETION_PEER_PATH}")
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[test]
fn the_company_lists_the_copied_answer_by_the_members_attribution() {
    let fx = leaving();
    let copies = fx.land_copy();

    let held = fx
        .company
        .vault
        .holdings_from(&fx.company.proof, &fx.member.vault_id)
        .expect("the company's holdings");
    assert_eq!(held.peer_vault_id, fx.member.vault_id);
    let copy_world = fx.copy_world();
    let world = held
        .worlds
        .iter()
        .find(|world| world.world == copy_world)
        .unwrap_or_else(|| panic!("the copy's foreign world is listed: {:?}", held.worlds));
    assert_eq!(
        world.records, copies,
        "each copied statement, by attribution"
    );
    assert_eq!(world.pacts, vec![fx.pact()]);
    assert!(
        !world.registered,
        "a copied answer's world is not registered to the pact"
    );
    assert!(
        held.worlds
            .iter()
            .all(|other| other.world == copy_world || other.records.is_empty()),
        "no other record is attributed to the member: {:?}",
        held.worlds
    );

    let held_by_member = fx
        .member
        .vault
        .holdings_from(&fx.member.proof, &fx.company.vault_id)
        .expect("the member's holdings");
    assert!(
        held_by_member
            .worlds
            .iter()
            .all(|world| world.records.is_empty()),
        "the member's vault holds no record the company delivered: {:?}",
        held_by_member.worlds
    );
}

#[test]
fn leaving_ends_the_members_edge_in_one_member_action() {
    let fx = leaving();
    let elsewhere = fx
        .member
        .vault
        .prepare_inquiry_edge_for_join(
            &fx.member.proof,
            &fx.member.issuer,
            ELSEWHERE,
            "Elsewhere",
            MEMBER,
        )
        .expect("an edge to another company");

    let ended = fx.leave();
    assert_eq!(ended.len(), 1, "one edge to the company: {ended:?}");
    assert_eq!(ended[0].grant_ref, fx.prepared.edge.grant);
    assert!(ended[0].changed);
    assert!(
        fx.member
            .vault
            .inquiry_edge(&fx.prepared.edge.grant)
            .expect("edge read")
            .is_none(),
        "the member's edge ended with the seat"
    );
    assert!(
        fx.member
            .vault
            .inquiry_edge(&elsewhere.edge.grant)
            .expect("edge read")
            .is_some(),
        "an edge to another company stays"
    );
    let pact = fx.pact();
    for (side, vault) in [("company", &fx.company.vault), ("member", &fx.member.vault)] {
        let status = Leaving::pact_status(vault, &pact);
        assert!(status.is_terminal(), "the {side}'s pact ended: {status:?}");
    }

    let host = MemberHost::new(&fx.company);
    let sent = fx.send(&host);
    assert_eq!(sent.outcome, InquiryOutcome::Unavailable);
    assert_eq!(host.call_count(), 0, "nothing goes out after the leave");

    let again = fx
        .member
        .vault
        .end_inquiry_edges_with(&fx.member.proof, &fx.member.issuer, &fx.company.vault_id)
        .expect("a repeat");
    assert!(again.is_empty(), "nothing is left to end: {again:?}");
}

#[test]
fn one_action_queues_an_erase_request_the_company_files_and_does_not_apply() {
    let fx = leaving();
    let copies = fx.land_copy();
    let ended = fx.leave();
    assert_eq!(ended.len(), 1);
    let pact = fx.pact();
    let now = fx.member.vault.now_recorded_at();

    let asked = fx
        .member
        .vault
        .send_leave_erase_requests(
            &fx.member.proof,
            &fx.member.issuer,
            &fx.company.vault_id,
            &courtesy_route(COMPANY_HOST),
            now,
        )
        .expect("the member's one action");
    assert_eq!(asked.len(), 1, "one ask for the one ended pact: {asked:?}");
    assert_eq!(asked[0].connection_id, hex(&pact));
    assert!(matches!(
        asked[0].status,
        CooperativeDeletionDeliveryStatus::Queued
    ));
    let sent: Vec<String> = fx
        .member
        .vault
        .cooperative_deletion_notices()
        .expect("the member's sent asks")
        .into_iter()
        .map(|notice| notice.request_id)
        .collect();
    assert_eq!(sent, vec![asked[0].request_id.clone()]);

    let delivery = fx
        .member
        .vault
        .claim_cooperative_deletion_delivery("leave-test", now, Some(&fx.member.issuer))
        .expect("claim")
        .expect("the queued ask is due");
    assert_eq!(delivery.destination, courtesy_route(COMPANY_HOST));
    assert_eq!(
        fx.company
            .vault
            .receive_cooperative_deletion_request(&delivery.bytes, now)
            .expect("the company receives the ask"),
        CooperativeDeletionIngress::Filed
    );
    let filed = fx
        .company
        .vault
        .incoming_cooperative_deletions()
        .expect("the company's filed asks");
    assert_eq!(filed.len(), 1);
    assert!(
        filed[0].worlds.is_empty(),
        "the ask is about all the pact delivered"
    );
    assert_eq!(
        fx.company
            .vault
            .cooperative_deletion_candidates(&pact, &[], filed[0].epoch_cutoff)
            .expect("the ask's candidates"),
        copies,
        "the ask covers the copied answer"
    );
    let held = fx
        .company
        .vault
        .holdings_from(&fx.company.proof, &fx.member.vault_id)
        .expect("the company's holdings");
    assert_eq!(
        held.worlds
            .iter()
            .flat_map(|world| world.records.clone())
            .collect::<Vec<_>>(),
        copies,
        "nothing is erased by force"
    );

    let again = fx
        .member
        .vault
        .send_leave_erase_requests(
            &fx.member.proof,
            &fx.member.issuer,
            &fx.company.vault_id,
            &courtesy_route(COMPANY_HOST),
            now,
        )
        .expect("a repeat");
    assert_eq!(
        again
            .iter()
            .map(|notice| &notice.request_id)
            .collect::<Vec<_>>(),
        vec![&asked[0].request_id],
        "a repeat answers the first ask"
    );
    assert_eq!(
        fx.member
            .vault
            .cooperative_deletion_notices()
            .expect("sent asks")
            .len(),
        1,
        "no second ask"
    );

    let company_asked = fx
        .company
        .vault
        .send_leave_erase_requests(
            &fx.company.proof,
            &fx.company.issuer,
            &fx.member.vault_id,
            &courtesy_route(MEMBER_HOST),
            fx.company.vault.now_recorded_at(),
        )
        .expect("the company's one action");
    assert_eq!(company_asked.len(), 1);
    assert_eq!(company_asked[0].connection_id, hex(&pact));
}
