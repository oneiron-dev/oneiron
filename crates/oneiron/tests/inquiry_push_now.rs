//! L7-03 (federation.md #inquiry, line 95; lead rulings L7-03-LANDING = A
//! and L7-03-SCOPE = A): the member's [Now]. The member tells the company of
//! one inquiry edge a statement unasked, in the member's own words.
//! - the push is one send on the internal channel `inquiry_push`, scheduled
//!   through the schedule door as the owner's own act; once the executor
//!   runs it, the company lands the words once, at once, as a copy: one
//!   CLAIM about the member's seat in the foreign WORLD of the member's
//!   vault and opened world, its source the member's word, its evidence the
//!   push, attributed by a delivery record, with one `inquiry` receipt that
//!   holds no question or task. Nothing of the private claim the words were
//!   drawn from crosses, and the link to it stays in the member's vault;
//! - the owner's undo-send window holds the push: the owner lists it and
//!   takes it back, and it never leaves the vault; a second push, not taken
//!   back, lands once the window closes;
//! - a push whose answer was lost is sent again and still lands once;
//! - a push over a revoked edge, with no push route, or with words over
//!   their cap is refused before any send;
//! - the company lands a push only under its reciprocal grant's slip, over
//!   an edge it holds a route for, as the member's word; the generic Connect
//!   mint refuses the class `inquiry_push`.
//!
//! Two vaults in this process on one manual clock; the company host is a
//! double that verifies the member host's credential and calls the
//! company's landing.
//!
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron --all-features --test inquiry_push_now`.

use std::sync::{Arc, Mutex};

use oneiron::authority::{
    AuthorityVaultId, CapabilitySlip, FederationPactStatus, HOST_ISSUER_SEED_BYTES, HostSlipIssuer,
    MachineRole,
};
use oneiron::consent::AuthenticatedOwner;
use oneiron::federation::{FederationGrantRole, INQUIRY_PUSH_VERB_CLASS, Scope, ScopeAxis};
use oneiron::inquiry::{
    INQUIRY_PUSH_CHANNEL, InquiryEdge, InquiryEdgeReciprocalGrant, InquiryEdgeRequest,
    InquiryPushRequest, InquiryPushRouteRequest, InquiryPushSink, InquiryPushState,
    InquiryPushTransport, InquiryPushWire, InquiryPushed, InquiryRouteRequest, InquiryStatement,
    InquiryTransportError, MAX_INQUIRY_PUSH_STATEMENT_BYTES, StatementSource,
};
use oneiron::outbound::UndoSendOutcome;
use oneiron::receipt::{ReceiptKind, ReceiptQuery, ReceiptRecord};
use oneiron::settings::undo_send::{UndoSendChannelLength, UndoSendSetting};
use oneiron::store::GateDecisionId;
use oneiron::test_doors::membership::stand_member_grant;
use oneiron::{
    ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus, ClaimSubject, EntityId, TimeRange, Vault,
    VaultConfig,
};
use oneiron_store::ports::manual_clock::ManualClock;
use rmpv::Value;

/// The clock both vaults start on.
const T0: u64 = 1_790_000_000;
/// The company's shared vault the member holds a seat in.
const SHARED: u64 = 42;
const COMPANY: &str = "Acme";
const MEMBER: &str = "owen";
const MEMBER_HOST: &str = "https://member.example";
const COMPANY_HOST: &str = "https://company.example";
/// The challenge the member host signs on each call to the company host.
const CHALLENGE: &[u8] = b"inquiry-push-now-test";
/// The member's private claim: it never crosses.
const PRIVATE_NEED: &str = "I have chemo on Thursday";
const PRIVATE_WORD: &str = "chemo";
/// What the member tells the company.
const OUT_THURSDAY: &str = "Out Thursday";
/// The predicate a landed statement is a CLAIM of.
const STATEMENT_PREDICATE: &str = "profile.statement";
/// The owner's undo-send window on `inquiry_push`, in seconds.
const WINDOW_SECS: u32 = 60;
/// A peer vault no fixture opens.
const UNOPENED_PEER: AuthorityVaultId = [0xbd; 32];

/// One rooted vault with its owner bound to its own host.
struct Side {
    vault: Vault,
    owner: EntityId,
    proof: AuthenticatedOwner,
    issuer: HostSlipIssuer,
    vault_id: AuthorityVaultId,
    _dir: tempfile::TempDir,
}

/// A vault on `clock`, rooted under a host of its own (`seed`), its engine
/// machines and install profile provisioned and its owner bound.
fn side(seed: u8, clock: &Arc<ManualClock>) -> Side {
    let dir = tempfile::tempdir().expect("vault directory");
    let mut config = VaultConfig::device();
    config.store_clock = clock.bundle();
    let vault = Vault::open(dir.path(), config).expect("fresh vault");
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
        owner,
        proof,
        issuer,
        vault_id,
        _dir: dir,
    }
}

/// A PERSON of `vault`: the member's seat in the company.
fn person(vault: &Vault) -> EntityId {
    let id = EntityId::now();
    vault
        .put_entity(
            &id,
            oneiron::registry::ENTITY_TYPE_PERSON,
            TimeRange { start: T0, end: T0 },
            T0,
            b"a person of the company",
        )
        .expect("person");
    id
}

/// The member's vault and the company's on one clock: the member's seat in
/// the shared vault, the inquiry edge Active over the Connect pact, the
/// company's route to the member, and, when `push_route`, the member's push
/// route with the slip the company minted for the member host.
struct Telling {
    clock: Arc<ManualClock>,
    member: Side,
    company: Side,
    seat: EntityId,
    edge: InquiryEdge,
    reciprocal: InquiryEdgeReciprocalGrant,
    company_slip: CapabilitySlip,
}

fn telling() -> Telling {
    telling_with(true)
}

fn telling_with(push_route: bool) -> Telling {
    let clock = ManualClock::new(T0);
    let member = side(0x11, &clock);
    let company = side(0x22, &clock);
    company
        .vault
        .initialize_shared_vault(&company.proof, SHARED, None, &[], T0)
        .expect("the company's shared vault");
    let seat = person(&company.vault);
    stand_member_grant(&company.vault, seat, SHARED, FederationGrantRole::Member)
        .expect("the member's seat");
    let edge = member
        .vault
        .mint_inquiry_edge(
            &member.proof,
            &InquiryEdgeRequest::member_defaults(company.vault_id, COMPANY),
        )
        .expect("the member mints the inquiry edge");
    let reciprocal = company
        .vault
        .mint_inquiry_edge_reciprocal_grant(&company.proof, member.vault_id, MEMBER)
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
    let member_slip = member
        .vault
        .mint_guest_slip(
            &member.proof,
            &member.issuer,
            edge.grant,
            Some(company.issuer.binding_key()),
            T0 + 86_400,
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
                slip: member_slip,
            },
        )
        .expect("the company Owner opens the route to the member");
    let company_slip = company
        .vault
        .mint_guest_slip(
            &company.proof,
            &company.issuer,
            reciprocal.grant,
            Some(member.issuer.binding_key()),
            T0 + 86_400,
            None,
        )
        .expect("the company's vault mints the member host's slip on its reciprocal grant");
    if push_route {
        member
            .vault
            .open_inquiry_push_route(
                &member.proof,
                &member.issuer,
                &InquiryPushRouteRequest {
                    edge_grant: edge.grant,
                    company_host: COMPANY_HOST.to_owned(),
                    slip: company_slip.clone(),
                },
            )
            .expect("the member Owner opens the push route");
    }
    Telling {
        clock,
        member,
        company,
        seat,
        edge,
        reciprocal,
        company_slip,
    }
}

impl Telling {
    /// The member's private claim `text`, in the member's base world.
    fn private_claim(&self, text: &str) -> EntityId {
        let id = EntityId::now();
        let body = ClaimBody::new(
            "profile.appointment",
            ClaimSubject::Entity(self.member.owner),
            Value::from(text),
            1.0,
            ClaimApprovalStatus::Approved,
            ClaimLifecycleStatus::Active,
        )
        .expect("claim body");
        let now = self.now();
        self.member
            .vault
            .put_claim(
                &id,
                &body,
                TimeRange {
                    start: now,
                    end: now,
                },
                now,
            )
            .expect("the member's own claim");
        id
    }

    fn now(&self) -> u64 {
        self.member.vault.now_recorded_at()
    }

    fn push(
        &self,
        statement: &str,
        drawn_from: Option<EntityId>,
    ) -> oneiron::Result<InquiryPushed> {
        self.member.vault.push_inquiry_statement(
            &self.member.proof,
            &InquiryPushRequest {
                edge_grant: self.edge.grant,
                statement: statement.to_owned(),
                drawn_from,
            },
        )
    }

    /// Runs the member vault's connector executor once at the clock's time.
    fn run(&self, host: &CompanyHost<'_>) -> usize {
        let mut sink = InquiryPushSink::new(&self.member.vault, host);
        self.member
            .vault
            .run_connector_task_executor(&mut sink, self.now())
            .expect("the executor runs")
    }

    fn state(&self, pushed: &InquiryPushed) -> InquiryPushState {
        self.member
            .vault
            .inquiry_push(&pushed.push)
            .expect("read the push")
            .expect("the push stands")
            .state
    }

    fn set_window(&self, secs: u32) {
        self.member
            .vault
            .set_undo_send(
                &self.member.proof,
                None,
                &UndoSendSetting {
                    all_channels_secs: 0,
                    channels: vec![UndoSendChannelLength {
                        channel: INQUIRY_PUSH_CHANNEL.to_owned(),
                        secs,
                    }],
                },
            )
            .expect("the owner sets the window on inquiry_push");
    }

    /// Every statement CLAIM about the member's seat in the company vault.
    fn copies(&self) -> Vec<(EntityId, ClaimBody)> {
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

    /// The company's Active Connect pact with the member's vault.
    fn company_pact(&self) -> [u8; 32] {
        let fold = self.company.vault.authority_fold().expect("authority fold");
        let mut live = fold.federation_pacts.iter().filter(|(_, state)| {
            state.peer_vault_id == self.member.vault_id
                && state.status == FederationPactStatus::Active
        });
        let (Some((pact, _)), None) = (live.next(), live.next()) else {
            panic!("one Active pact with the member's vault");
        };
        *pact
    }

    /// The foreign WORLD the member's copies land in.
    fn copy_world(&self) -> EntityId {
        oneiron::federation::pact_foreign_world(
            &self.company.vault.authority_fold().expect("fold"),
            &self.company_pact(),
            self.edge.terms.opened_world,
        )
        .expect("derive")
        .expect("the pact")
        .entity_id()
    }

    /// The `inquiry` receipts of the push `push` on the company vault.
    fn push_receipts(&self, push: EntityId) -> Vec<ReceiptRecord> {
        let mut query = ReceiptQuery::new(100);
        query.kinds = [ReceiptKind::Inquiry].into();
        query.job_ref = Some(push.to_hex());
        self.company.vault.receipts(query).expect("receipts")
    }

    /// The member host's credential on the company's reciprocal grant, as
    /// the company host verifies it.
    fn credential(&self, slip: &CapabilitySlip) -> oneiron::authority::VerifiedSlip {
        let signature = self
            .member
            .issuer
            .binding_proof(slip, CHALLENGE)
            .expect("the member host signs");
        self.company
            .vault
            .verify_capability_slip(
                &self.company.issuer.public_key(),
                slip,
                CHALLENGE,
                &signature,
            )
            .expect("the member host's credential verifies")
    }

    fn wire(
        &self,
        push: EntityId,
        edge_grant: EntityId,
        source: StatementSource,
    ) -> InquiryPushWire {
        InquiryPushWire {
            push,
            edge_grant: edge_grant.to_hex(),
            statement: InquiryStatement::new(OUT_THURSDAY, source).expect("statement"),
            told_at: self.now(),
        }
    }
}

/// The company host, in this process: it verifies the member host's
/// credential on each call and calls the company's landing. With
/// `lose_answers`, that many calls land and then answer nothing.
struct CompanyHost<'a> {
    company: &'a Vault,
    company_issuer: &'a HostSlipIssuer,
    member_issuer: &'a HostSlipIssuer,
    lose_answers: Mutex<usize>,
    wires: Mutex<Vec<Vec<u8>>>,
}

impl<'a> CompanyHost<'a> {
    fn new(fixture: &'a Telling) -> Self {
        Self {
            company: &fixture.company.vault,
            company_issuer: &fixture.company.issuer,
            member_issuer: &fixture.member.issuer,
            lose_answers: Mutex::new(0),
            wires: Mutex::new(Vec::new()),
        }
    }

    fn losing_answers(self, count: usize) -> Self {
        *self.lose_answers.lock().expect("lose") = count;
        self
    }

    fn wires(&self) -> Vec<Vec<u8>> {
        self.wires.lock().expect("wires").clone()
    }
}

impl InquiryPushTransport for CompanyHost<'_> {
    fn push(
        &self,
        company_host: &str,
        company_vault_id: &AuthorityVaultId,
        slip_token: &str,
        wire: &[u8],
    ) -> Result<(), InquiryTransportError> {
        assert_eq!(company_host, COMPANY_HOST);
        self.wires.lock().expect("wires").push(wire.to_vec());
        let refused = |why: String| InquiryTransportError::Refused(why);
        let slip = CapabilitySlip::from_token(slip_token).map_err(|e| refused(e.to_string()))?;
        assert_eq!(slip.claims.vault_id, *company_vault_id);
        let signature = self
            .member_issuer
            .binding_proof(&slip, CHALLENGE)
            .map_err(|e| refused(e.to_string()))?;
        let proof = self
            .company
            .verify_capability_slip(
                &self.company_issuer.public_key(),
                &slip,
                CHALLENGE,
                &signature,
            )
            .map_err(|e| refused(e.to_string()))?;
        let grant = slip
            .claims
            .grant_ref
            .as_deref()
            .and_then(|hex| EntityId::from_hex(hex).ok())
            .ok_or_else(|| refused("the slip names no grant".to_owned()))?;
        let wire = InquiryPushWire::decode_wire(wire).map_err(|e| refused(e.to_string()))?;
        self.company
            .land_pushed_inquiry_statement(grant, &proof, &wire)
            .map_err(|e| refused(e.to_string()))?;
        let mut lose = self.lose_answers.lock().expect("lose");
        if *lose > 0 {
            *lose -= 1;
            return Err(InquiryTransportError::Unreachable("timeout".to_owned()));
        }
        Ok(())
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn evidence_field(body: &ClaimBody, name: &str) -> Option<String> {
    body.evidence
        .as_ref()?
        .as_map()?
        .iter()
        .find(|(key, _)| key.as_str() == Some(name))
        .and_then(|(_, value)| value.as_str())
        .map(str::to_owned)
}

#[test]
fn now_tells_the_company_once_and_lands_attributed() {
    let fixture = telling();
    let need = fixture.private_claim(PRIVATE_NEED);
    let pushed = fixture
        .push(OUT_THURSDAY, Some(need))
        .expect("the member tells the company now");
    let told = fixture
        .member
        .vault
        .inquiry_push(&pushed.push)
        .expect("read the push")
        .expect("the push stands");
    assert_eq!(told.push.statement, OUT_THURSDAY);
    assert_eq!(told.push.drawn_from, Some(need));
    assert_eq!(told.push.task_ref, Some(pushed.task_ref));
    assert_eq!(told.state, InquiryPushState::Queued);
    assert!(
        fixture.copies().is_empty(),
        "nothing lands before the executor runs"
    );

    let host = CompanyHost::new(&fixture);
    assert_eq!(fixture.run(&host), 1, "the executor runs the push");
    let wires = host.wires();
    assert_eq!(wires.len(), 1, "one call to the company host");
    let wire = String::from_utf8(wires[0].clone()).expect("JSON");
    assert!(wire.contains(OUT_THURSDAY), "{wire}");
    assert!(wire.contains("member_word"), "{wire}");
    for private in [
        PRIVATE_WORD.to_owned(),
        need.to_hex(),
        fixture.edge.terms.opened_world.to_hex(),
    ] {
        assert!(!wire.contains(&private), "{private} never crosses: {wire}");
    }

    let copies = fixture.copies();
    assert_eq!(copies.len(), 1, "one CLAIM lands: {copies:?}");
    let (claim, body) = &copies[0];
    assert_eq!(body.value, Value::from(OUT_THURSDAY));
    assert_eq!(body.world, Some(fixture.copy_world()));
    assert_eq!(
        body.valid_to, None,
        "no task or inquiry bounds a told statement"
    );
    assert_eq!(
        evidence_field(body, "inquiry_push"),
        Some(pushed.push.to_hex())
    );
    assert_eq!(
        evidence_field(body, "statement_source").as_deref(),
        Some("member_word")
    );
    assert_eq!(evidence_field(body, "inquiry"), None);
    assert!(!format!("{body:?}").contains(PRIVATE_WORD));

    let history = fixture
        .company
        .vault
        .federation_delivery_history(&[*claim])
        .expect("delivery history");
    assert_eq!(history.len(), 1, "one delivery record: {history:?}");
    assert_eq!(history[0].source_ref, *claim);
    assert_eq!(history[0].delivering_pact, fixture.company_pact());
    assert_eq!(history[0].source_vault, fixture.member.vault_id);
    assert_eq!(
        history[0].grant_ref, fixture.edge.grant,
        "the member's edge grant"
    );
    assert_eq!(history[0].world, Some(fixture.copy_world()));

    let receipts = fixture.push_receipts(pushed.push);
    assert_eq!(receipts.len(), 1, "one receipt: {receipts:?}");
    let receipt = &receipts[0];
    assert_eq!(receipt.receipt_kind, ReceiptKind::Inquiry);
    assert_eq!(
        receipt.receipt_id,
        format!("inquiry_push:{}:000000", pushed.push.to_hex())
    );
    assert_eq!(receipt.outcome, "told");
    assert_eq!(receipt.trigger_ref, None, "no task");
    assert_eq!(
        receipt.fields.get("member"),
        Some(&fixture.seat.to_hex()),
        "the member's seat"
    );
    for absent in ["question", "purpose", "keep"] {
        assert!(
            !receipt.fields.contains_key(absent),
            "no {absent}: {receipt:?}"
        );
    }
    assert!(
        !format!("{receipt:?}").contains(OUT_THURSDAY),
        "no text in the receipt"
    );

    let told = fixture
        .member
        .vault
        .inquiry_push(&pushed.push)
        .expect("read the push")
        .expect("the push stands");
    assert_eq!(told.state, InquiryPushState::Sent);
    assert_eq!(
        told.push.drawn_from,
        Some(need),
        "the link stays in the member's vault"
    );
    assert!(
        fixture
            .member
            .vault
            .inquiry_scope_items(&fixture.member.proof, fixture.edge.grant)
            .expect("the opened scope")
            .is_empty(),
        "[Now] files nothing in the opened scope (L7-03-SCOPE = A)"
    );
}

#[test]
fn now_waits_out_the_owner_window_and_undo_keeps_it_home() {
    let fixture = telling();
    fixture.set_window(WINDOW_SECS);
    let host = CompanyHost::new(&fixture);

    let first = fixture
        .push(OUT_THURSDAY, None)
        .expect("the member tells the company now");
    let held = fixture
        .member
        .vault
        .undo_send_held(&fixture.member.proof)
        .expect("the owner lists held sends")
        .sends;
    assert_eq!(held.len(), 1, "the push waits in the window: {held:?}");
    assert_eq!(held[0].channel, INQUIRY_PUSH_CHANNEL);
    assert_eq!(held[0].target, hex(&fixture.company.vault_id));
    assert_eq!(held[0].task_ref, first.task_ref);
    assert_eq!(held[0].release_at, T0 + u64::from(WINDOW_SECS));
    assert_eq!(fixture.run(&host), 0, "nothing goes inside the window");

    fixture.clock.set(T0 + 30);
    let undone = fixture
        .member
        .vault
        .undo_send(&fixture.member.proof, first.task_ref)
        .expect("the owner takes the push back");
    assert!(
        matches!(undone, UndoSendOutcome::Undone { .. }),
        "{undone:?}"
    );
    fixture.clock.set(T0 + u64::from(WINDOW_SECS) + 1);
    fixture.run(&host);
    assert!(
        host.wires().is_empty(),
        "the undone push never left the vault"
    );
    assert!(fixture.copies().is_empty(), "the company holds nothing");
    assert_eq!(fixture.state(&first), InquiryPushState::Undone);

    let second = fixture
        .push(OUT_THURSDAY, None)
        .expect("the member tells the company again");
    assert_eq!(fixture.run(&host), 0, "the second push waits in its window");
    fixture.clock.set(T0 + 2 * (u64::from(WINDOW_SECS) + 1));
    assert_eq!(fixture.run(&host), 1, "past the window the push goes");
    assert_eq!(host.wires().len(), 1);
    let copies = fixture.copies();
    assert_eq!(copies.len(), 1, "{copies:?}");
    assert_eq!(
        evidence_field(&copies[0].1, "inquiry_push"),
        Some(second.push.to_hex())
    );
    assert_eq!(fixture.state(&second), InquiryPushState::Sent);
    assert_eq!(fixture.state(&first), InquiryPushState::Undone);
}

#[test]
fn a_re_delivered_push_lands_once() {
    let fixture = telling();
    let host = CompanyHost::new(&fixture).losing_answers(1);
    let pushed = fixture
        .push(OUT_THURSDAY, None)
        .expect("the member tells the company now");
    fixture.run(&host);
    assert_eq!(
        host.wires().len(),
        1,
        "the first call landed, and its answer was lost"
    );
    assert_eq!(fixture.copies().len(), 1);

    // The executor sends it again once its retry edge passes.
    let mut now = fixture.now();
    for _ in 0..120 {
        if host.wires().len() >= 2 {
            break;
        }
        now += 60;
        fixture.clock.set(now);
        fixture.run(&host);
    }
    assert_eq!(host.wires().len(), 2, "the executor sent the push again");
    assert_eq!(host.wires()[0], host.wires()[1], "the same push");
    let copies = fixture.copies();
    assert_eq!(copies.len(), 1, "it still lands once: {copies:?}");
    assert_eq!(fixture.push_receipts(pushed.push).len(), 1, "one receipt");
    assert_eq!(fixture.state(&pushed), InquiryPushState::Sent);
}

#[test]
fn a_push_with_no_active_edge_or_no_route_is_refused_before_any_send() {
    let fixture = telling();
    let host = CompanyHost::new(&fixture);
    let too_long = "a".repeat(MAX_INQUIRY_PUSH_STATEMENT_BYTES + 1);
    assert!(
        fixture.push(&too_long, None).is_err(),
        "words over their cap"
    );
    assert!(fixture.push("   ", None).is_err(), "no words");

    fixture
        .member
        .vault
        .revoke_inquiry_edge(
            &fixture.member.proof,
            &fixture.member.issuer,
            fixture.edge.grant,
        )
        .expect("the member revokes the edge");
    assert!(
        fixture
            .member
            .vault
            .inquiry_push_route(&fixture.edge.grant)
            .expect("read the push route")
            .is_none(),
        "the push route ends with the edge"
    );
    let refused = fixture
        .push(OUT_THURSDAY, None)
        .expect_err("no push over a revoked edge");
    assert!(refused.to_string().contains("inquiry"), "{refused}");
    assert!(
        fixture
            .member
            .vault
            .undo_send_held(&fixture.member.proof)
            .expect("held sends")
            .sends
            .is_empty(),
        "nothing was scheduled"
    );
    assert_eq!(fixture.run(&host), 0, "the executor finds nothing");
    assert!(host.wires().is_empty());

    let unrouted = telling_with(false);
    let refused = unrouted
        .push(OUT_THURSDAY, None)
        .expect_err("no push without a push route");
    assert!(refused.to_string().contains("push route"), "{refused}");
    let unrouted_host = CompanyHost::new(&unrouted);
    assert_eq!(
        unrouted.run(&unrouted_host),
        0,
        "the executor finds nothing"
    );
    assert!(unrouted_host.wires().is_empty());
}

#[test]
fn the_company_lands_a_push_only_on_its_reciprocal_grant_over_an_open_route() {
    let fixture = telling();
    assert!(
        matches!(&fixture.reciprocal.authority_scope.verbs, ScopeAxis::Some(verbs)
            if verbs.contains(INQUIRY_PUSH_VERB_CLASS)),
        "the reciprocal grant carries the push class"
    );
    let proof = fixture.credential(&fixture.company_slip);

    // The generic Connect mint never carries the class.
    let scope: Scope = fixture.reciprocal.authority_scope.clone();
    let refused = fixture
        .company
        .vault
        .mint_connect_grant(&fixture.company.proof, UNOPENED_PEER, scope, None, None)
        .expect_err("the generic Connect mint refuses inquiry_push");
    assert!(refused.to_string().contains("inquiry_push"), "{refused}");

    // A push under another grant than the slip's, over an edge the company
    // holds no route for, or as the companion's word lands nothing.
    let push = EntityId::now();
    let wire = fixture.wire(push, fixture.edge.grant, StatementSource::MemberWord);
    assert!(
        fixture
            .company
            .vault
            .land_pushed_inquiry_statement(fixture.reciprocal.world, &proof, &wire)
            .is_err(),
        "a grant the slip does not name"
    );
    let unrouted = fixture.wire(push, EntityId::now(), StatementSource::MemberWord);
    assert!(
        fixture
            .company
            .vault
            .land_pushed_inquiry_statement(fixture.reciprocal.grant, &proof, &unrouted)
            .is_err(),
        "an edge the company holds no route for"
    );
    let companion = fixture.wire(push, fixture.edge.grant, StatementSource::CompanionOfMember);
    assert!(
        fixture
            .company
            .vault
            .land_pushed_inquiry_statement(fixture.reciprocal.grant, &proof, &companion)
            .is_err(),
        "a told statement is the member's word"
    );
    assert!(fixture.copies().is_empty(), "nothing landed");

    // The slip on the reciprocal grant lands it, once.
    let landed = fixture
        .company
        .vault
        .land_pushed_inquiry_statement(fixture.reciprocal.grant, &proof, &wire)
        .expect("the company lands the push");
    assert!(landed.landed_now);
    let again = fixture
        .company
        .vault
        .land_pushed_inquiry_statement(fixture.reciprocal.grant, &proof, &wire)
        .expect("a re-delivery answers the first landing");
    assert!(!again.landed_now);
    assert_eq!(again.claim, landed.claim);
    assert_eq!(fixture.copies().len(), 1);

    // Once the company revokes its reciprocal grant, the slip lands nothing.
    fixture
        .company
        .vault
        .revoke_guest_access(
            &fixture.company.proof,
            &fixture.company.issuer,
            fixture.reciprocal.grant,
        )
        .expect("the company Owner revokes the reciprocal grant");
    let later = fixture.wire(
        EntityId::now(),
        fixture.edge.grant,
        StatementSource::MemberWord,
    );
    assert!(
        fixture
            .company
            .vault
            .land_pushed_inquiry_statement(fixture.reciprocal.grant, &proof, &later)
            .is_err(),
        "a revoked grant admits nothing"
    );
    assert_eq!(fixture.copies().len(), 1);
}
