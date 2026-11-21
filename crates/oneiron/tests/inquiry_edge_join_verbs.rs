//! L7-04 PR 2: the join rows (federation.md #inquiry-first-build: "the edge
//! is created at joining"; Engine rulings L7-04-COMPANY-HALF = A,
//! L7-04-NO-PERSONAL-VAULT = A, L7-04-PREPARE-VERB = A), through the fns
//! each row calls and the wire its offer and counter travel on:
//! - `vault.inquiry.edge.prepare_join` on the member's vault, then
//!   `vault.members.accept_with_inquiry_edge` on the company's, then the
//!   member's Connect accept of the counter: both pacts are Active, and the
//!   receipt carries no scope opening key;
//! - a seat accepted plain takes its edge through
//!   `vault.members.inquiry_edge.attach`, and a repeat answers the same
//!   counter;
//! - an offer or a company vault that does not parse is refused before any
//!   writer, and the invitation still accepts.
//!
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron --all-features --test inquiry_edge_join_verbs`.

use std::sync::Arc;

use oneiron::authority::{
    AuthorityVaultId, FederationPactStatus, HOST_ISSUER_SEED_BYTES, HostSlipIssuer, MachineRole,
};
use oneiron::consent::AuthenticatedOwner;
use oneiron::federation::{FederationGrantRole, SharedVaultChange};
use oneiron::store::GateDecisionId;
use oneiron::task_verb::sdk::{
    self, InquiryEdgeOffer, InquiryEdgePrepareJoinRequest, InquiryJoinPreparedView,
    SharedInquiryEdgeAttachRequest, SharedInvitationAcceptWithInquiryEdgeRequest,
    SharedInvitationRequest,
};
use oneiron::{EntityId, TimeRange, Vault, VaultConfig};

/// The company's shared vault the member joins.
const SHARED: u64 = 42;
const COMPANY: &str = "Acme";
const MEMBER: &str = "owen";

/// A vault id as the rows carry it: 64 lower hex.
fn hex(id: &AuthorityVaultId) -> String {
    id.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// `offer` after a trip over the wire: the JSON a host sends, parsed as the
/// other host's row parses its input.
fn over_the_wire(offer: &InquiryEdgeOffer) -> InquiryEdgeOffer {
    let json = serde_json::to_string(offer).expect("the offer serializes");
    serde_json::from_str(&json).expect("the offer parses")
}

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
        seat_proof,
        invitation,
    }
}

impl Joining {
    /// `vault.inquiry.edge.prepare_join` on the member's vault.
    fn prepare(&self) -> InquiryJoinPreparedView {
        sdk::prepare_inquiry_edge_join_as(
            &self.member.vault,
            &self.member.proof,
            &self.member.issuer,
            InquiryEdgePrepareJoinRequest {
                company_vault: hex(&self.company.vault_id),
                company_name: COMPANY.to_owned(),
                member_name: MEMBER.to_owned(),
            },
        )
        .expect("the member's vault prepares the edge")
    }

    /// `vault.members.accept_with_inquiry_edge` on the company's vault.
    fn accept_with(
        &self,
        offer: InquiryEdgeOffer,
    ) -> oneiron::memory::MemoryResult<sdk::SharedInvitationAcceptedWithInquiryEdge> {
        sdk::accept_shared_invitation_with_inquiry_edge_as(
            &self.company.vault,
            &self.seat_proof,
            &self.company.issuer,
            SharedInvitationAcceptWithInquiryEdgeRequest {
                vault_id: SHARED,
                invitation: self.invitation.clone(),
                inquiry_edge: offer,
            },
        )
    }

    /// The member's vault applies the company's counter, as it came over
    /// the wire, on its edge's grant.
    fn apply(
        &self,
        prepared: &InquiryJoinPreparedView,
        counter: &sdk::Offer,
    ) -> FederationPactStatus {
        let counter = sdk::connect_offer_from_wire(counter).expect("the counter parses");
        self.member
            .vault
            .accept_connect_as(
                &self.member.proof,
                &self.member.issuer,
                prepared.edge.grant,
                &counter,
            )
            .expect("the member's vault applies the company's counter")
            .0
            .status
    }

    /// The status of the company's pact with the member's vault.
    fn company_pact_status(&self) -> Option<FederationPactStatus> {
        self.company
            .vault
            .authority_fold()
            .expect("the company's authority fold")
            .federation_pacts
            .values()
            .find(|pact| pact.peer_vault_id == self.member.vault_id)
            .map(|pact| pact.status)
    }
}

#[test]
fn joining_through_the_rows_makes_the_edge_and_both_pacts_active() {
    let fx = joining();
    let prepared = fx.prepare();
    assert_eq!(prepared.edge.company_vault, hex(&fx.company.vault_id));
    assert_eq!(prepared.offer.member_name, MEMBER);
    assert!(
        fx.member
            .vault
            .inquiry_edge(&prepared.edge.grant)
            .expect("the member's edge read")
            .is_some(),
        "the prepare mints the member's edge"
    );

    let accepted = fx
        .accept_with(over_the_wire(&prepared.offer))
        .expect("the member joins with the edge");
    assert!(
        matches!(
            accepted.receipt.change,
            SharedVaultChange::InvitationAccepted {
                role: FederationGrantRole::Member,
                ..
            }
        ),
        "the accept gives the Member seat: {:?}",
        accepted.receipt.change
    );
    assert_eq!(
        fx.company_pact_status(),
        Some(FederationPactStatus::Active),
        "the company logged the Connect with the seat"
    );
    let receipt = serde_json::to_string(&accepted.receipt).expect("the receipt serializes");
    assert!(
        !receipt.contains(&accepted.inquiry_edge_counter.key)
            && !receipt.contains(&prepared.offer.connect.key),
        "the receipt carries no scope opening key"
    );

    assert_eq!(
        fx.apply(&prepared, &accepted.inquiry_edge_counter),
        FederationPactStatus::Active,
        "the member's vault takes the company's counter"
    );
}

#[test]
fn a_seat_accepted_plain_attaches_its_edge_through_the_row() {
    let fx = joining();
    sdk::accept_shared_invitation_as(
        &fx.company.vault,
        &fx.seat_proof,
        SharedInvitationRequest {
            vault_id: SHARED,
            invitation: fx.invitation.clone(),
        },
    )
    .expect("the member joins without an edge");
    assert_eq!(fx.company_pact_status(), None, "a plain seat has no edge");

    let prepared = fx.prepare();
    let attach = || {
        sdk::attach_inquiry_edge_to_seat_as(
            &fx.company.vault,
            &fx.seat_proof,
            &fx.company.issuer,
            SharedInquiryEdgeAttachRequest {
                vault_id: SHARED,
                inquiry_edge: over_the_wire(&prepared.offer),
            },
        )
    };
    let attached = attach().expect("the member attaches the edge to the seat");
    let repeat = attach().expect("an exact repeat answers again");
    assert_eq!(
        serde_json::to_value(&repeat.counter).expect("the repeat's counter"),
        serde_json::to_value(&attached.counter).expect("the counter"),
        "a repeat answers the same counter"
    );
    assert_eq!(
        fx.apply(&prepared, &attached.counter),
        FederationPactStatus::Active
    );
    assert_eq!(fx.company_pact_status(), Some(FederationPactStatus::Active));
}

#[test]
fn an_offer_that_does_not_parse_is_refused_before_any_writer() {
    let fx = joining();
    let refused = sdk::prepare_inquiry_edge_join_as(
        &fx.member.vault,
        &fx.member.proof,
        &fx.member.issuer,
        InquiryEdgePrepareJoinRequest {
            company_vault: COMPANY.to_owned(),
            company_name: COMPANY.to_owned(),
            member_name: MEMBER.to_owned(),
        },
    )
    .expect_err("a company vault that is not 64 hex is refused");
    assert!(
        format!("{refused:?}").contains("company_vault"),
        "{refused:?}"
    );

    let prepared = fx.prepare();
    let mut broken = prepared.offer.clone();
    broken.connect.key = "zz".to_owned();
    let refused = fx
        .accept_with(broken)
        .expect_err("an offer whose key is not hex is refused");
    assert!(
        format!("{refused:?}").contains("inquiry_edge.connect.key"),
        "{refused:?}"
    );
    assert_eq!(fx.company_pact_status(), None, "no Connect was logged");

    fx.accept_with(prepared.offer.clone())
        .expect("the invitation still accepts with the member's offer");
    assert_eq!(fx.company_pact_status(), Some(FederationPactStatus::Active));
}
