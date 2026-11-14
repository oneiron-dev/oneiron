//! L7-04 (federation.md #inquiry-first-build: "the edge is created at
//! joining"; ARCH-0043 #inquiry-edge: "every member seat carries an inquiry
//! edge"; Engine rulings L7-04-COMPANY-HALF = A, L7-04-NO-PERSONAL-VAULT = A):
//! - the member's vault prepares the edge on the member defaults and offers
//!   its Connect; the company's accept writes the seat, the company's
//!   propose-only grant and the Connect in one writer, approved by the seat;
//!   the member applies the counter, and both pacts are Active, so the
//!   company Owner can open the seat's inquiry route;
//! - a refused company half leaves no seat and no pact, and the invitation
//!   still accepts;
//! - a second prepare offers the same unbound edge again; a live Connect
//!   with the company refuses a prepare;
//! - the member's leave ends the company's half with the seat;
//! - a seat accepted without an offer takes its edge later on the member's
//!   own proof, a repeat answers the same counter, and a person with no seat
//!   is refused.
//!
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron --all-features --test inquiry_edge_at_join`.

use std::collections::BTreeSet;
use std::sync::Arc;

use oneiron::authority::{
    AuthorityVaultId, CapabilitySlip, ConnectOffer, FederationPactStatus, HOST_ISSUER_SEED_BYTES,
    HostSlipIssuer, MachineRole,
};
use oneiron::consent::AuthenticatedOwner;
use oneiron::federation::{
    ConnectMemberLeaveBinding, FederationGrantRole, ScopeAxis, SharedActExecutionReceipt,
    SharedVaultChange, decode_federation_grant_body,
};
use oneiron::inquiry::{
    InquiryEdgeRequest, InquiryJoinOffer, InquiryJoinPrepared, InquiryRouteRequest,
};
use oneiron::store::GateDecisionId;
use oneiron::{EntityId, TimeRange, Vault, VaultConfig};

/// The company's shared vault the member joins.
const SHARED: u64 = 42;
const COMPANY: &str = "Acme";
const MEMBER: &str = "owen";
const MEMBER_HOST: &str = "https://member.example";
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

/// A vault rooted under a host of its own (`seed`), its engine machines and
/// install profile provisioned and its owner bound, as a host does.
fn side(seed: u8) -> Side {
    let dir = tempfile::tempdir().expect("vault directory");
    let vault = Vault::open(dir.path(), VaultConfig::device()).expect("fresh vault");
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

/// A live PERSON of `vault` and their person proof.
fn person(vault: &Vault) -> (EntityId, AuthenticatedOwner) {
    let id = EntityId::now();
    vault
        .put_entity(
            &id,
            oneiron::registry::ENTITY_TYPE_PERSON,
            TimeRange { start: 1, end: 1 },
            1,
            b"a person of the company",
        )
        .expect("person");
    let proof = vault
        .authenticate_owner(id, &id.to_hex(), true, GateDecisionId::now())
        .expect("a person proof");
    (id, proof)
}

/// The member's vault, the company's, and the member's pending invitation
/// to a Member seat in the company's shared vault.
struct Joining {
    member: Side,
    company: Side,
    seat: EntityId,
    seat_proof: AuthenticatedOwner,
    invitation: String,
}

fn joining() -> Joining {
    let member = side(0x11);
    let company = side(0x22);
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
    let (seat, seat_proof) = person(&company.vault);
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
    Joining {
        member,
        company,
        seat,
        seat_proof,
        invitation,
    }
}

impl Joining {
    /// The member's vault prepares its edge to `company`, named `name`.
    fn prepare_to(&self, company: AuthorityVaultId, name: &str) -> InquiryJoinPrepared {
        self.member
            .vault
            .prepare_inquiry_edge_for_join(
                &self.member.proof,
                &self.member.issuer,
                company,
                name,
                MEMBER,
            )
            .expect("the member's vault prepares the edge")
    }

    fn prepare(&self) -> InquiryJoinPrepared {
        self.prepare_to(self.company.vault_id, COMPANY)
    }

    /// The member accepts the invitation with `offer`.
    fn accept(
        &self,
        offer: &InquiryJoinOffer,
    ) -> oneiron::Result<(SharedActExecutionReceipt, ConnectOffer)> {
        self.company
            .vault
            .accept_shared_invitation_with_inquiry_edge(
                &self.seat_proof,
                SHARED,
                &self.invitation,
                &self.company.issuer,
                offer,
            )
    }

    /// The member's vault applies the company's counter on its edge.
    fn apply(
        &self,
        prepared: &InquiryJoinPrepared,
        counter: &ConnectOffer,
    ) -> FederationPactStatus {
        self.member
            .vault
            .accept_connect_as(
                &self.member.proof,
                &self.member.issuer,
                prepared.edge.grant,
                counter,
            )
            .expect("the member's vault applies the company's counter")
            .0
            .status
    }

    /// The company's pact `pact_id`, when its log holds one.
    fn company_pact(&self, pact_id: &[u8; 32]) -> Option<oneiron::authority::FederationPactState> {
        self.company
            .vault
            .authority_fold()
            .expect("the company's authority fold")
            .federation_pacts
            .get(pact_id)
            .cloned()
    }

    /// Whether the company's log holds any pact with the member's vault.
    fn company_has_pact_with_member(&self) -> bool {
        self.company
            .vault
            .authority_fold()
            .expect("the company's authority fold")
            .federation_pacts
            .values()
            .any(|pact| pact.peer_vault_id == self.member.vault_id)
    }

    /// The member vault's guest slip on its edge for the company host.
    fn slip(&self, prepared: &InquiryJoinPrepared) -> CapabilitySlip {
        self.member
            .vault
            .mint_guest_slip(
                &self.member.proof,
                &self.member.issuer,
                prepared.edge.grant,
                Some(self.company.issuer.binding_key()),
                self.member.vault.now_recorded_at() + 3_600,
                None,
            )
            .expect("the member's vault mints the company host's slip")
    }
}

#[test]
fn joining_with_the_members_offer_creates_the_edge_and_its_pact() {
    let fx = joining();
    let prepared = fx.prepare();
    let defaults = InquiryEdgeRequest::member_defaults(fx.company.vault_id, COMPANY);
    assert_eq!(prepared.edge.company_vault_id, fx.company.vault_id);
    assert_eq!(prepared.edge.terms.tier_ceiling, defaults.tier_ceiling);
    assert_eq!(prepared.edge.terms.check_in_modes, defaults.check_in_modes);
    assert_eq!(prepared.edge.terms.keep_allowed, defaults.keep_allowed);
    assert_eq!(prepared.edge.expires_at, None);

    let (receipt, counter) = fx
        .accept(&prepared.offer)
        .expect("the member joins with the edge");
    assert!(
        matches!(
            receipt.change,
            SharedVaultChange::InvitationAccepted {
                role: FederationGrantRole::Member,
                ..
            }
        ),
        "the accept gives the Member seat: {:?}",
        receipt.change
    );
    let pact_id = prepared.offer.connect.pact_id;
    let company_pact = fx
        .company_pact(&pact_id)
        .expect("the company logged the Connect with the seat");
    assert_eq!(company_pact.status, FederationPactStatus::Active);
    assert_eq!(company_pact.peer_vault_id, fx.member.vault_id);

    // The company's half: propose alone, released when the seat ends.
    let body = fx
        .company
        .vault
        .get(&company_pact.grant_ref)
        .expect("the company's grant row")
        .expect("the company's grant is live");
    let grant = decode_federation_grant_body(&body).expect("a grant");
    assert_eq!(
        grant.authority_scope.verbs,
        ScopeAxis::Some(BTreeSet::from(["propose".to_owned()])),
        "the company's half proposes and reads nothing"
    );
    assert_eq!(
        grant.detach_on_member_leave,
        Some(ConnectMemberLeaveBinding {
            shared_vault_id: SHARED,
            person_ref: fx.seat,
        }),
        "the company's half ends with the seat"
    );

    assert_eq!(fx.apply(&prepared, &counter), FederationPactStatus::Active);
    assert_eq!(
        fx.member
            .vault
            .inquiry_edge(&prepared.edge.grant)
            .expect("edge read")
            .expect("the member's edge stands"),
        prepared.edge
    );

    // The seat's edge is a route: the company Owner opens it with the
    // member's slip.
    fx.company
        .vault
        .open_inquiry_route(
            &fx.company.proof,
            &fx.company.issuer,
            &InquiryRouteRequest {
                shared_vault_id: SHARED,
                member: fx.seat,
                member_vault_id: fx.member.vault_id,
                member_host: MEMBER_HOST.to_owned(),
                slip: fx.slip(&prepared),
            },
        )
        .expect("the company Owner opens the seat's inquiry route");
}

#[test]
fn a_refused_company_half_leaves_no_seat() {
    let fx = joining();
    // An offer the member's vault made for another company: the company's
    // half refuses it after the seat was written in the same writer.
    let misdirected = fx.prepare_to(ELSEWHERE, "Elsewhere");
    fx.accept(&misdirected.offer)
        .expect_err("an offer for another vault refuses the accept");
    assert!(
        !fx.company_has_pact_with_member(),
        "no Connect stands without the seat"
    );

    // The invitation was not spent and no seat was written: a correct
    // offer accepts it, which a spent invitation or a standing seat refuses.
    let prepared = fx.prepare();
    let (_, counter) = fx
        .accept(&prepared.offer)
        .expect("the invitation still accepts");
    assert_eq!(fx.apply(&prepared, &counter), FederationPactStatus::Active);
}

#[test]
fn a_repeated_prepare_reuses_the_unbound_edge() {
    let fx = joining();
    let first = fx.prepare();
    let second = fx.prepare();
    assert_eq!(second.edge, first.edge, "one edge, offered again");
    assert_ne!(
        second.offer.connect.pact_id, first.offer.connect.pact_id,
        "each offer is a new pact"
    );
    let (_, counter) = fx.accept(&second.offer).expect("the second offer joins");
    assert_eq!(fx.apply(&second, &counter), FederationPactStatus::Active);
}

#[test]
fn a_live_connect_refuses_the_join_offer() {
    let fx = joining();
    let prepared = fx.prepare();
    let (_, counter) = fx.accept(&prepared.offer).expect("the member joins");
    assert_eq!(fx.apply(&prepared, &counter), FederationPactStatus::Active);
    let refused = fx
        .member
        .vault
        .prepare_inquiry_edge_for_join(
            &fx.member.proof,
            &fx.member.issuer,
            fx.company.vault_id,
            COMPANY,
            MEMBER,
        )
        .expect_err("a live Connect with the company refuses a prepare");
    assert!(
        refused
            .to_string()
            .contains("disconnect that Connect first"),
        "the INQUIRE-EDGE-JOIN sentence: {refused}"
    );
}

#[test]
fn leaving_ends_the_companys_half_with_the_seat() {
    let fx = joining();
    let prepared = fx.prepare();
    let (_, counter) = fx.accept(&prepared.offer).expect("the member joins");
    assert_eq!(fx.apply(&prepared, &counter), FederationPactStatus::Active);
    let pact_id = prepared.offer.connect.pact_id;
    let grant = fx
        .company_pact(&pact_id)
        .expect("the company's pact")
        .grant_ref;

    let left = fx
        .company
        .vault
        .leave_shared_vault(&fx.seat_proof, SHARED, Some(&fx.company.issuer))
        .expect("the member leaves");
    assert!(
        left.grants.contains(&grant.to_hex()),
        "the leave withdraws the company's half: {:?}",
        left.grants
    );
    let pact = fx.company_pact(&pact_id).expect("the pact stays logged");
    assert!(
        pact.status.is_terminal(),
        "the company's pact ends with the seat: {:?}",
        pact.status
    );
}

#[test]
fn a_seat_without_an_offer_takes_its_edge_later() {
    let fx = joining();
    fx.company
        .vault
        .accept_shared_invitation(&fx.seat_proof, SHARED, &fx.invitation)
        .expect("the member joins without an edge");
    assert!(
        !fx.company_has_pact_with_member(),
        "a seat accepted without an offer has no edge"
    );

    let prepared = fx.prepare();
    let (stranger, stranger_proof) = person(&fx.company.vault);
    assert_ne!(stranger, fx.seat);
    fx.company
        .vault
        .attach_inquiry_edge_to_seat(&stranger_proof, &fx.company.issuer, SHARED, &prepared.offer)
        .expect_err("a person with no seat attaches no edge");

    let counter = fx
        .company
        .vault
        .attach_inquiry_edge_to_seat(&fx.seat_proof, &fx.company.issuer, SHARED, &prepared.offer)
        .expect("the member attaches the edge to the seat");
    let repeat = fx
        .company
        .vault
        .attach_inquiry_edge_to_seat(&fx.seat_proof, &fx.company.issuer, SHARED, &prepared.offer)
        .expect("an exact repeat answers again");
    assert_eq!(repeat, counter, "a repeat answers the same counter");
    assert_eq!(fx.apply(&prepared, &counter), FederationPactStatus::Active);
    assert_eq!(
        fx.company_pact(&prepared.offer.connect.pact_id)
            .expect("the company's pact")
            .status,
        FederationPactStatus::Active
    );
}
