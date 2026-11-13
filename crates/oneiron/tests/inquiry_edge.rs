//! INQUIRE-1 PR 2 (federation.md #inquiry-scope, #inquiry-first-build;
//! Engine ruling INQUIRE-SHAPE Q1 = A): the inquiry edge and its opened
//! scope.
//! - the member's edge is a Connect guest grant with the class `inquire`
//!   alone over the empty WORLD "What <company> can ask about", with its
//!   terms at the member defaults; it stands and confers no read;
//! - the terms ride exactly the grants that carry `inquire`: a body that
//!   breaks that, or names an unknown token, refuses, and the generic
//!   Connect mint refuses the class while a read/propose grant mints as
//!   before;
//! - the opened scope starts empty; a statement opens, lists and closes,
//!   and its link to the claim it was drawn from stays out of the statement
//!   and goes with an erase of that claim; closing a statement keeps the
//!   link another edge's statement holds to it;
//! - revoking the edge withdraws the grant and leaves the member's
//!   statements;
//! - the company's reciprocal grant (`propose` alone over "Inquiry edge:
//!   <member>") and the member's edge make the existing Connect pact Active
//!   on both vaults, neither grant confers read, and a second edge to the
//!   company refuses while that Connect stands.
//!
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron --all-features --test inquiry_edge`.

use std::collections::BTreeSet;
use std::sync::Arc;

use oneiron::authority::{
    AuthorityVaultId, FederationPactStatus, HOST_ISSUER_SEED_BYTES, HostSlipIssuer, MachineRole,
};
use oneiron::consent::AuthenticatedOwner;
use oneiron::federation::{
    FederationGrant, FederationGrantKind, FederationGrantPreset, FederationGrantRole,
    FederationGrantScope, INQUIRE_VERB_CLASS, Scope, ScopeAxis, ScopeId, Sensitivity,
    SensitivityCeiling, decode_federation_grant_body, encode_federation_grant_body,
};
use oneiron::inquiry::{
    INQUIRY_STATEMENT_PREDICATE, InquiryCheckInMode, InquiryEdge, InquiryEdgeRequest, InquiryKeep,
    InquiryScopeItem, InquiryTerms, InquiryTierCeiling,
};
use oneiron::registry::ENTITY_TYPE_CLAIM;
use oneiron::store::GateDecisionId;
use oneiron::write_envelope::claim_body::encode_claim_body;
use oneiron::{
    ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus, ClaimSource, ClaimSubject, EntityId,
    TimeRange, Vault, VaultConfig,
};
use rmpv::Value;

/// The second the fixture's claims are dated at.
const T0: u64 = 1_790_000_000;
/// The company's name, as the opened scope's title reads it.
const COMPANY: &str = "Acme";
/// The member's name, as the company's reciprocal WORLD reads it.
const MEMBER: &str = "owen";
/// A company vault no fixture opens: the edge mints before any pact.
const UNOPENED_COMPANY: AuthorityVaultId = [0xac; 32];
/// Another peer vault no fixture opens.
const UNOPENED_PEER: AuthorityVaultId = [0xbd; 32];
/// The member's word the company may ask about.
const OUT_THURSDAY: &str = "Out Thursday. Back Friday.";

/// One rooted vault with its owner bound to its own host.
struct Side {
    vault: Vault,
    owner: EntityId,
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
        owner,
        proof,
        issuer,
        vault_id,
        _dir: dir,
    }
}

fn mint_edge(member: &Side, company: AuthorityVaultId) -> InquiryEdge {
    member
        .vault
        .mint_inquiry_edge(
            &member.proof,
            &InquiryEdgeRequest::member_defaults(company, COMPANY),
        )
        .expect("the member mints the inquiry edge")
}

/// The grant the edge stores, as its fields read back.
fn edge_grant(edge: &InquiryEdge) -> FederationGrant {
    FederationGrant {
        authority_scope: edge.authority_scope.clone(),
        scope: FederationGrantScope::Connect {
            peer_vault_id: edge.company_vault_id,
        },
        member_ref: edge.guest_actor,
        role: FederationGrantRole::Guest,
        preset: FederationGrantPreset::Guest,
        expires_at: edge.expires_at,
        delegated_by: None,
        guest: None,
        owner_agent: false,
        repo_bounds: None,
        kind: FederationGrantKind::Access,
        git_push_bounds: None,
        detach_on_member_leave: None,
        verb_classes: BTreeSet::new(),
        wallet_ref: None,
        inquiry_terms: Some(edge.terms),
        working_view_bounds: None,
    }
}

fn verbs(classes: &[&str]) -> ScopeAxis<String> {
    ScopeAxis::Some(classes.iter().map(|class| (*class).to_owned()).collect())
}

/// The smallest live Connect scope over `world` with `classes`.
fn connect_scope(world: EntityId, classes: &[&str]) -> Scope {
    Scope {
        worlds: ScopeAxis::Some(BTreeSet::from([ScopeId(world)])),
        facets: ScopeAxis::Bottom,
        bands: ScopeAxis::Some(BTreeSet::from([ENTITY_TYPE_CLAIM])),
        audience: ScopeAxis::Some(BTreeSet::from([ScopeId(
            oneiron::claim::default_project_id(),
        )])),
        verbs: verbs(classes),
        sensitivity: SensitivityCeiling::AtMost(Sensitivity::Public),
    }
}

/// A live claim of the member's outside any opened scope.
fn source_claim(side: &Side, text: &str) -> EntityId {
    let id = EntityId::now();
    let body = ClaimBody::new(
        "profile.appointment",
        ClaimSubject::Entity(side.owner),
        Value::from(text),
        1.0,
        ClaimApprovalStatus::Approved,
        ClaimLifecycleStatus::Active,
    )
    .expect("claim body");
    side.vault
        .put_claim(&id, &body, TimeRange { start: T0, end: T0 }, T0)
        .expect("the member's own claim");
    id
}

/// `bytes` with the `inquiry_terms` map's `key` set to `value`.
fn with_terms_entry(bytes: &[u8], key: &str, value: Value) -> Vec<u8> {
    let mut body = rmpv::decode::read_value(&mut &bytes[..]).expect("grant body");
    let Value::Map(entries) = &mut body else {
        panic!("a grant body is a map");
    };
    let (_, terms) = entries
        .iter_mut()
        .find(|(entry, _)| entry.as_str() == Some("inquiry_terms"))
        .expect("the body carries inquiry_terms");
    let Value::Map(terms) = terms else {
        panic!("inquiry_terms is a map");
    };
    match terms
        .iter_mut()
        .find(|(entry, _)| entry.as_str() == Some(key))
    {
        Some((_, slot)) => *slot = value,
        None => terms.push((Value::from(key), value)),
    }
    let mut out = Vec::new();
    rmpv::encode::write_value(&mut out, &body).expect("re-encode");
    out
}

fn holds(haystack: &[u8], needle: &[u8]) -> bool {
    haystack
        .windows(needle.len())
        .any(|window| window == needle)
}

#[test]
fn minted_edge_is_inquire_alone_over_an_empty_opened_world_at_the_member_defaults() {
    let member = side(0x11);
    let edge = mint_edge(&member, UNOPENED_COMPANY);

    assert_eq!(edge.company_vault_id, UNOPENED_COMPANY);
    assert_eq!(edge.authority_scope.verbs, verbs(&[INQUIRE_VERB_CLASS]));
    assert_eq!(
        edge.authority_scope.worlds,
        ScopeAxis::Some(BTreeSet::from([ScopeId(edge.terms.opened_world)])),
    );
    assert_eq!(edge.terms.tier_ceiling, InquiryTierCeiling::Unstamped);
    assert_eq!(edge.terms.check_in_mode, InquiryCheckInMode::AskWhenUnsure);
    assert_eq!(edge.terms.keep_allowed, InquiryKeep::Task);
    assert_eq!(edge.expires_at, None);
    assert_eq!(
        member
            .vault
            .inquiry_edge(&edge.grant)
            .expect("read the edge"),
        Some(edge.clone()),
        "the stored grant reads back as the edge minted",
    );
    assert!(
        member
            .vault
            .inquiry_scope_items(&member.proof, edge.grant)
            .expect("list the opened scope")
            .is_empty(),
        "the opened scope starts empty",
    );
    let grant = edge_grant(&edge);
    assert!(grant.is_live_at(T0), "the edge stands");
    assert!(!grant.confers_at(T0), "inquire confers no read");
    // An edge to a second company opens a scope of its own.
    let other = member
        .vault
        .mint_inquiry_edge(
            &member.proof,
            &InquiryEdgeRequest::member_defaults(UNOPENED_PEER, "Globex"),
        )
        .expect("an edge to a second company");
    assert_ne!(other.terms.opened_world, edge.terms.opened_world);
}

#[test]
fn inquiry_terms_ride_exactly_the_grants_that_carry_inquire() {
    let member = side(0x11);
    let edge = mint_edge(&member, UNOPENED_COMPANY);
    let grant = edge_grant(&edge);
    let bytes = encode_federation_grant_body(&grant).expect("an inquiry edge encodes");
    assert_eq!(
        decode_federation_grant_body(&bytes).expect("and decodes"),
        grant,
    );

    let mut no_terms = grant.clone();
    no_terms.inquiry_terms = None;
    assert!(
        encode_federation_grant_body(&no_terms).is_err(),
        "inquire without terms refuses",
    );
    let mut propose_with_terms = grant.clone();
    propose_with_terms.authority_scope.verbs = verbs(&["propose"]);
    assert!(
        encode_federation_grant_body(&propose_with_terms).is_err(),
        "terms without inquire refuse",
    );
    let mut inquire_and_read = grant.clone();
    inquire_and_read.authority_scope.verbs = verbs(&[INQUIRE_VERB_CLASS, "read"]);
    assert!(
        encode_federation_grant_body(&inquire_and_read).is_err(),
        "inquire rides alone, never beside read",
    );
    let mut second_world = grant.clone();
    second_world.authority_scope.worlds = ScopeAxis::Some(BTreeSet::from([
        ScopeId(edge.terms.opened_world),
        ScopeId(EntityId::now()),
    ]));
    assert!(
        encode_federation_grant_body(&second_world).is_err(),
        "the opened WORLD is the grant's only world",
    );
    let mut elsewhere = grant.clone();
    elsewhere.inquiry_terms = Some(InquiryTerms {
        opened_world: EntityId::now(),
        ..edge.terms
    });
    assert!(
        encode_federation_grant_body(&elsewhere).is_err(),
        "the terms name the grant's world",
    );
    let mut member_role = grant.clone();
    member_role.role = FederationGrantRole::Member;
    assert!(
        encode_federation_grant_body(&member_role).is_err(),
        "only a Connect guest grant carries the terms",
    );

    for (key, value) in [
        ("tier_ceiling", Value::from("sensitive")),
        ("check_in_mode", Value::from("ask_when_unsure")),
        ("keep_allowed", Value::from("forever")),
        ("opened_world", Value::from("not-an-id")),
        ("check_in_mode", Value::from(1_u64)),
        ("band", Value::from("unstamped")),
    ] {
        assert!(
            decode_federation_grant_body(&with_terms_entry(&bytes, key, value.clone())).is_err(),
            "inquiry_terms with {key} = {value} refuses",
        );
    }
    for (key, token) in [
        ("check_in_mode", "manual"),
        ("check_in_mode", "full-access"),
        ("keep_allowed", "copy"),
    ] {
        let decoded =
            decode_federation_grant_body(&with_terms_entry(&bytes, key, Value::from(token)))
                .unwrap_or_else(|error| panic!("{key} = {token} decodes: {error:?}"));
        let terms = decoded.inquiry_terms.expect("terms");
        assert!(
            terms.check_in_mode.as_str() == token || terms.keep_allowed.as_str() == token,
            "{key} = {token} reads back",
        );
    }
}

#[test]
fn the_generic_connect_mint_refuses_the_inquire_class_and_mints_read_as_before() {
    let member = side(0x11);
    let world = member
        .vault
        .create_world(&member.proof, "Shared with a peer", T0)
        .expect("a named world");
    let inquire = connect_scope(world, &[INQUIRE_VERB_CLASS]);
    let refused = member
        .vault
        .mint_connect_grant(&member.proof, UNOPENED_COMPANY, inquire.clone(), None, None)
        .expect_err("the generic mint carries no terms");
    assert!(
        format!("{refused:?}").contains("inquiry edge"),
        "the refusal names the inquiry edge: {refused:?}",
    );
    assert!(
        FederationGrant::connect_guest(UNOPENED_COMPANY, EntityId::now(), inquire, None, None)
            .is_err(),
        "a Connect guest grant with inquire and no terms does not build",
    );

    let read = member
        .vault
        .mint_connect_grant(
            &member.proof,
            UNOPENED_PEER,
            connect_scope(world, &["propose", "read"]),
            None,
            None,
        )
        .expect("a read/propose Connect grant mints under the widened ceiling");
    assert_eq!(read.resolved_scope.verbs, verbs(&["propose", "read"]));
}

#[test]
fn a_statement_opens_lists_and_closes_and_its_link_stays_out_of_it() {
    let member = side(0x11);
    let vault = &member.vault;
    let edge = mint_edge(&member, UNOPENED_COMPANY);
    let chemo = source_claim(&member, "Chemo on Thursday");

    let out = vault
        .open_inquiry_scope_item(&member.proof, edge.grant, OUT_THURSDAY, Some(chemo))
        .expect("the member opens a statement drawn from a claim");
    let mornings = vault
        .open_inquiry_scope_item(&member.proof, edge.grant, "Prefers morning meetings.", None)
        .expect("the member opens a statement of their own");
    assert_eq!(out.statement, OUT_THURSDAY);
    assert_eq!(out.drawn_from, Some(chemo));
    assert_eq!(mornings.drawn_from, None);
    let items = vault
        .inquiry_scope_items(&member.proof, edge.grant)
        .expect("list the opened scope");
    assert_eq!(items.len(), 2, "{items:?}");
    assert!(
        items.contains(&out) && items.contains(&mornings),
        "{items:?}"
    );

    let body = vault
        .get_claim(&out.claim)
        .expect("read the statement")
        .expect("the statement is a claim");
    assert_eq!(body.world, Some(edge.terms.opened_world));
    assert_eq!(body.predicate, INQUIRY_STATEMENT_PREDICATE);
    assert_eq!(body.subject, ClaimSubject::Entity(member.owner));
    assert_eq!(body.source, Some(ClaimSource::UserStated));
    assert_eq!(body.lifecycle, ClaimLifecycleStatus::Active);
    assert_eq!(body.value.as_str(), Some(OUT_THURSDAY));
    let encoded = encode_claim_body(&body).expect("encode the statement");
    assert!(
        !holds(&encoded, chemo.as_bytes()) && !holds(&encoded, chemo.to_hex().as_bytes()),
        "the drawn-from link stays out of the statement",
    );

    assert!(
        vault
            .open_inquiry_scope_item(&member.proof, edge.grant, "Again.", Some(mornings.claim))
            .is_err(),
        "a statement is not drawn from the opened scope itself",
    );
    assert!(
        vault
            .open_inquiry_scope_item(&member.proof, edge.grant, "   ", None)
            .is_err(),
        "a blank statement refuses",
    );

    vault
        .close_inquiry_scope_item(&member.proof, edge.grant, out.claim)
        .expect("the member closes the statement");
    assert_eq!(
        vault
            .inquiry_scope_items(&member.proof, edge.grant)
            .expect("list the opened scope"),
        vec![mornings.clone()],
    );
    assert_eq!(
        vault
            .get_claim(&out.claim)
            .expect("read the statement")
            .expect("the closed statement stays a claim")
            .lifecycle,
        ClaimLifecycleStatus::Retracted,
    );
    vault
        .close_inquiry_scope_item(&member.proof, edge.grant, out.claim)
        .expect("closing a closed statement is a no-op");
    assert!(
        vault
            .close_inquiry_scope_item(&member.proof, edge.grant, chemo)
            .is_err(),
        "a claim outside the opened scope does not close here",
    );
}

#[test]
fn closing_a_statement_keeps_the_link_another_edge_drew_from_it() {
    let member = side(0x11);
    let vault = &member.vault;
    let edge = mint_edge(&member, UNOPENED_COMPANY);
    let other = vault
        .mint_inquiry_edge(
            &member.proof,
            &InquiryEdgeRequest::member_defaults(UNOPENED_PEER, "Globex"),
        )
        .expect("an edge to a second company");
    let out = vault
        .open_inquiry_scope_item(&member.proof, edge.grant, OUT_THURSDAY, None)
        .expect("open a statement to the first company");
    let again = vault
        .open_inquiry_scope_item(&member.proof, other.grant, OUT_THURSDAY, Some(out.claim))
        .expect("open the words to the second company, drawn from the first statement");
    assert_eq!(again.drawn_from, Some(out.claim));

    vault
        .close_inquiry_scope_item(&member.proof, edge.grant, out.claim)
        .expect("close the first company's statement");
    assert!(
        vault
            .inquiry_scope_items(&member.proof, edge.grant)
            .expect("list the first opened scope")
            .is_empty(),
        "the closed statement leaves the first opened scope",
    );
    assert_eq!(
        vault
            .inquiry_scope_items(&member.proof, other.grant)
            .expect("list the second opened scope"),
        vec![again],
        "the second company's statement keeps its link to the closed one",
    );
}

#[test]
fn an_erase_of_the_drawn_from_claim_drops_the_link() {
    let member = side(0x11);
    let vault = &member.vault;
    let edge = mint_edge(&member, UNOPENED_COMPANY);
    let chemo = source_claim(&member, "Chemo on Thursday");
    let out = vault
        .open_inquiry_scope_item(&member.proof, edge.grant, OUT_THURSDAY, Some(chemo))
        .expect("open a statement drawn from a claim");

    assert!(vault.delete_entity(&chemo).expect("delete the claim"));
    assert_eq!(
        vault
            .inquiry_scope_items(&member.proof, edge.grant)
            .expect("list the opened scope"),
        vec![InquiryScopeItem {
            drawn_from: None,
            ..out
        }],
        "the statement stays opened and its link goes with the claim",
    );
}

#[test]
fn revoking_the_edge_withdraws_the_grant_and_keeps_the_statements() {
    let member = side(0x11);
    let vault = &member.vault;
    let edge = mint_edge(&member, UNOPENED_COMPANY);
    let out = vault
        .open_inquiry_scope_item(&member.proof, edge.grant, OUT_THURSDAY, None)
        .expect("open a statement");
    let world = vault
        .create_world(&member.proof, "Shared with a peer", T0)
        .expect("a named world");
    let plain = vault
        .mint_connect_grant(
            &member.proof,
            UNOPENED_PEER,
            connect_scope(world, &["read"]),
            None,
            None,
        )
        .expect("a plain Connect grant");
    assert!(
        vault
            .revoke_inquiry_edge(&member.proof, &member.issuer, plain.grant)
            .is_err(),
        "a plain Connect grant is not an inquiry edge",
    );

    let outcome = vault
        .revoke_inquiry_edge(&member.proof, &member.issuer, edge.grant)
        .expect("the member revokes the edge");
    assert!(outcome.changed);
    assert_eq!(outcome.grant_ref, edge.grant);
    assert_eq!(vault.inquiry_edge(&edge.grant).expect("read"), None);
    assert_eq!(
        vault
            .get_claim(&out.claim)
            .expect("read the statement")
            .expect("the statement stays")
            .lifecycle,
        ClaimLifecycleStatus::Active,
    );
    let repeat = vault
        .revoke_inquiry_edge(&member.proof, &member.issuer, edge.grant)
        .expect("a repeat answers the first revoke");
    assert!(!repeat.changed);
}

#[test]
fn the_reciprocal_grant_and_the_edge_make_the_connect_pact_active_on_both_vaults() {
    let member = side(0x11);
    let company = side(0x22);
    assert_ne!(member.vault_id, company.vault_id);

    let edge = mint_edge(&member, company.vault_id);
    let reciprocal = company
        .vault
        .mint_inquiry_edge_reciprocal_grant(&company.proof, member.vault_id, MEMBER)
        .expect("the company Owner mints the reciprocal grant");
    assert_eq!(
        reciprocal.authority_scope,
        connect_scope(reciprocal.world, &["propose"]),
        "propose alone, one WORLD, no facet, one band, at most public",
    );

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
    let (company_pact, counter) = company
        .vault
        .accept_connect_as(&company.proof, &company.issuer, reciprocal.grant, &offer)
        .expect("the company Owner accepts");
    assert_eq!(company_pact.status, FederationPactStatus::Active);
    assert_eq!(company_pact.grant_ref, reciprocal.grant);
    assert_eq!(company_pact.peer_vault_id, member.vault_id);
    let (member_pact, _) = member
        .vault
        .accept_connect_as(&member.proof, &member.issuer, edge.grant, &counter)
        .expect("the member accepts the company's half");
    assert_eq!(member_pact.status, FederationPactStatus::Active);
    assert_eq!(member_pact.grant_ref, edge.grant);
    assert_eq!(member_pact.peer_vault_id, company.vault_id);

    let join = member
        .vault
        .mint_inquiry_edge(
            &member.proof,
            &InquiryEdgeRequest::member_defaults(company.vault_id, "Acme again"),
        )
        .expect_err("an edge does not join a live Connect with the company");
    assert!(
        format!("{join:?}").contains("disconnect that Connect first"),
        "the refusal says why and what the member can do: {join:?}",
    );

    assert!(
        !edge_grant(&edge).confers_at(T0),
        "the edge confers no read"
    );
    let company_grant = FederationGrant::connect_guest(
        member.vault_id,
        reciprocal.guest_actor,
        reciprocal.authority_scope.clone(),
        None,
        None,
    )
    .expect("the reciprocal grant's shape");
    assert!(company_grant.is_live_at(T0), "the reciprocal grant stands");
    assert!(
        !company_grant.confers_at(T0),
        "the reciprocal grant confers no read",
    );
}
