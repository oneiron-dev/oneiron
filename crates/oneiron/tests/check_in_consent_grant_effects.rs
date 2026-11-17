//! ROLES-CHECKIN P2.5, row 2k8a (ARCH-0082 #act-table "Widen another's
//! grant" and #owner-own-acts; Engine ruling P25-SHAPE Q1 = A, 14 Nov
//! 13:39): four Owner-proof doors that mint a standing consent grant take
//! the 2j apply shape.
//!
//! - `vault.consent.create_standing_grant`: the Owner's mint is never
//!   gated. It goes on their own proof, and its receipt records that
//!   decision. The Owner applies another asker's approved check-in for that
//!   exact grant: the mint's writer spends it, and the receipt names it and
//!   its asker. An approval for another grant stands no grant and stays
//!   unspent.
//! - `vault.consent.graduation.answer`: an auto answer mints the scope's
//!   standing grant, so it takes the same shape, and the grant's receipt
//!   records the decision. A decline widens nothing: it applies no
//!   check-in.
//! - `vault.consent.create_auto_weave_grant` and
//!   `vault.consent.create_nightly_link_grant` (ruling P25-2K8-SCOPE Q1 =
//!   A, 19:32): the same shape through the same writer. The nightly-link
//!   request names nothing, so its effect is one constant, and only an ask
//!   for that verb applies.
//!
//! On its base, 2k7c's head, this file does not build: none of the four
//! requests has a `check_in_ref`.
//!
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron
//! --all-features --test check_in_consent_grant_effects`.
#![cfg(oneiron_test_support)]
#![allow(clippy::unwrap_used, clippy::expect_used)]

#[path = "check_in/owner_apply_fixture.rs"]
mod owner_apply_fixture;

use oneiron::check_in::ActClass;
use oneiron::consent::lifecycle::{
    ActionBoundRequest, ActionEnvelopeRequest, AutoWeaveGrantRequest, AutoWeaveWriterClass,
    CreateStandingGrantRequest, StandingGrantBound, auto_weave_grant_effect_digest,
    create_standing_grant, create_standing_grant_effect_digest, mint_auto_weave_grant,
};
use oneiron::consent::{AuthenticatedOwner, ConsentRegistryQuery};
use oneiron::consent_graduation::api::{
    GraduationAnswer, GraduationAnswerRequest, GraduationScope, answer,
    graduation_answer_effect_digest,
};
use oneiron::consent_graduation::{DEFAULT_GRADUATION_STREAK_FLOOR, RampScope, RampState};
use oneiron::dreamer_consolidation::{
    NightlyLinkGrantRequest, mint_nightly_link_grant, nightly_link_grant_effect_digest,
};
use oneiron::identity_topology::ProposalOutcome;
use oneiron::{EntityId, Vault};
use owner_apply_fixture::{approved, owner_decision, rooted, spent};

const STANDING_VERB: &str = "vault.consent.create_standing_grant";
const GRADUATION_VERB: &str = "vault.consent.graduation.answer";
const AUTO_WEAVE_VERB: &str = "vault.consent.create_auto_weave_grant";
const NIGHTLY_LINK_VERB: &str = "vault.consent.create_nightly_link_grant";

/// The Owner's standing grant letting `actor` send email in `project` to
/// owen, as the wire carries it.
fn standing_request(actor: &str, project: &str) -> CreateStandingGrantRequest {
    CreateStandingGrantRequest {
        bound: StandingGrantBound::Action(ActionBoundRequest {
            actor: actor.to_owned(),
            class: "send_email".to_owned(),
            envelope: ActionEnvelopeRequest {
                project: project.to_owned(),
                audience: vec!["owen".to_owned()],
                budget: None,
            },
        }),
        check_in_ref: None,
    }
}

/// How many live consent grants the Owner's registry lists.
fn live_grants(vault: &Vault) -> usize {
    vault
        .consent_registry(ConsentRegistryQuery::new(1_000, false))
        .expect("the owner's consent registry")
        .rows
        .len()
}

/// Drives `scope` to a standing graduation offer: the streak floor's clean
/// rulings, each the Owner's own.
fn earn_an_offer(vault: &Vault, owner_proof: &AuthenticatedOwner, scope: &RampScope) {
    for _ in 0..DEFAULT_GRADUATION_STREAK_FLOOR {
        vault
            .record_proposal_outcome_for_ramp(
                owner_proof,
                scope,
                ProposalOutcome::ApprovedUntouched,
            )
            .expect("the Owner's clean ruling");
    }
    assert_eq!(
        vault.ramp_scope_state(scope).expect("the scope's state"),
        RampState::Offered,
        "the scope offers graduation"
    );
}

fn graduation_request(
    scope: &RampScope,
    answer: GraduationAnswer,
    check_in_ref: Option<EntityId>,
) -> GraduationAnswerRequest {
    GraduationAnswerRequest {
        scope: GraduationScope::from(scope.clone()),
        answer,
        check_in_ref: check_in_ref.map(|id| id.to_hex()),
    }
}

#[test]
fn the_owners_standing_grant_goes_on_their_own_proof_and_records_it() {
    let (_dir, vault, _owner, owner_proof) = rooted();
    let before = live_grants(&vault);
    let receipt = create_standing_grant(
        &vault,
        &owner_proof,
        standing_request("agent-a", "project-alpha"),
    )
    .expect("the Owner mints the standing grant");
    assert_eq!(live_grants(&vault), before + 1, "the grant stands");
    assert_eq!(
        receipt.check_in,
        Some(owner_decision(ActClass::GrantWiden, None, None)),
        "the Owner's mint records their own proof"
    );
}

#[test]
fn the_owner_applies_an_approved_ask_for_that_standing_grant_only() {
    let (_dir, vault, owner, owner_proof) = rooted();
    let asked = standing_request("agent-a", "project-alpha");
    let (check_in, asker) = approved(
        &vault,
        owner,
        &owner_proof,
        STANDING_VERB,
        ActClass::GrantWiden,
        &create_standing_grant_effect_digest(&asked).expect("the grant's digest"),
    );
    let before = live_grants(&vault);

    let other = create_standing_grant(
        &vault,
        &owner_proof,
        CreateStandingGrantRequest {
            check_in_ref: Some(check_in.to_hex()),
            ..standing_request("agent-a", "project-beta")
        },
    );
    assert!(
        other.is_err(),
        "the approval covers the grant it was asked for only; seen {other:?}"
    );
    assert_eq!(
        live_grants(&vault),
        before,
        "the refused mint stands no grant"
    );
    assert!(
        !spent(&vault, &check_in),
        "a refused call leaves it unspent"
    );

    // The same bound on the wire with its actor unnormalized: one effect.
    let receipt = create_standing_grant(
        &vault,
        &owner_proof,
        CreateStandingGrantRequest {
            check_in_ref: Some(check_in.to_hex()),
            ..standing_request(" agent-a ", "project-alpha")
        },
    )
    .expect("the Owner applies the approved ask");
    assert_eq!(
        live_grants(&vault),
        before + 1,
        "the asked-for grant stands"
    );
    assert!(spent(&vault, &check_in), "the mint spent the check-in");
    assert_eq!(
        receipt.check_in,
        Some(owner_decision(
            ActClass::GrantWiden,
            Some(check_in),
            Some(asker)
        )),
        "the receipt names the applied check-in and its asker"
    );
}

#[test]
fn the_owners_auto_answer_goes_on_their_own_proof_and_records_it() {
    let (_dir, vault, _owner, owner_proof) = rooted();
    let scope = RampScope::new("send_email", "client_followup", "agent-a").expect("scope");
    earn_an_offer(&vault, &owner_proof, &scope);

    let receipt = answer(
        &vault,
        &owner_proof,
        graduation_request(&scope, GraduationAnswer::Auto, None),
    )
    .expect("the Owner accepts the offer");
    let grant = receipt.grant.expect("the auto answer mints the grant");
    assert_eq!(
        grant.check_in,
        Some(owner_decision(ActClass::GrantWiden, None, None)),
        "the Owner's auto answer records their own proof"
    );
}

#[test]
fn the_owner_applies_an_approved_ask_for_that_auto_answer_only() {
    let (_dir, vault, owner, owner_proof) = rooted();
    let scope = RampScope::new("send_email", "client_followup", "agent-a").expect("scope");
    let other_scope = RampScope::new("send_email", "client_followup", "agent-b").expect("scope");
    earn_an_offer(&vault, &owner_proof, &scope);
    earn_an_offer(&vault, &owner_proof, &other_scope);
    let (check_in, asker) = approved(
        &vault,
        owner,
        &owner_proof,
        GRADUATION_VERB,
        ActClass::GrantWiden,
        &graduation_answer_effect_digest(&graduation_request(&scope, GraduationAnswer::Auto, None))
            .expect("the auto answer's digest"),
    );

    let declined = answer(
        &vault,
        &owner_proof,
        graduation_request(&scope, GraduationAnswer::NotNow, Some(check_in)),
    );
    assert!(
        declined.is_err(),
        "a decline widens nothing, so it applies no check-in; seen {declined:?}"
    );
    let other = answer(
        &vault,
        &owner_proof,
        graduation_request(&other_scope, GraduationAnswer::Auto, Some(check_in)),
    );
    assert!(
        other.is_err(),
        "the approval covers the scope it was asked for only; seen {other:?}"
    );
    assert_eq!(
        vault
            .ramp_scope_state(&other_scope)
            .expect("the other scope's state"),
        RampState::Offered,
        "the refused answer graduates nothing"
    );
    assert!(!spent(&vault, &check_in), "refused calls leave it unspent");

    let receipt = answer(
        &vault,
        &owner_proof,
        graduation_request(&scope, GraduationAnswer::Auto, Some(check_in)),
    )
    .expect("the Owner applies the approved ask");
    assert!(spent(&vault, &check_in), "the accept spent the check-in");
    assert_eq!(
        receipt
            .grant
            .expect("the auto answer mints the grant")
            .check_in,
        Some(owner_decision(
            ActClass::GrantWiden,
            Some(check_in),
            Some(asker)
        )),
        "the grant's receipt names the applied check-in and its asker"
    );
}

/// The Owner's auto-weave grant for agent `writer` in `project`.
fn auto_weave_request(writer: EntityId, project: EntityId) -> AutoWeaveGrantRequest {
    AutoWeaveGrantRequest {
        writer: writer.to_hex(),
        writer_class: AutoWeaveWriterClass::Agent,
        scope: "project".to_owned(),
        scope_id: project.to_hex(),
        check_in_ref: None,
    }
}

#[test]
fn the_owner_applies_an_approved_ask_for_that_auto_weave_grant_only() {
    let (_dir, vault, owner, owner_proof) = rooted();
    let project = EntityId::now();
    let (writer, other_writer) = (EntityId::now(), EntityId::now());
    let own = mint_auto_weave_grant(
        &vault,
        &owner_proof,
        auto_weave_request(other_writer, EntityId::now()),
    )
    .expect("the Owner mints an auto-weave grant");
    assert_eq!(
        own.check_in,
        Some(owner_decision(ActClass::GrantWiden, None, None)),
        "the Owner's own mint records their own proof"
    );

    let asked = auto_weave_request(writer, project);
    let (check_in, asker) = approved(
        &vault,
        owner,
        &owner_proof,
        AUTO_WEAVE_VERB,
        ActClass::GrantWiden,
        &auto_weave_grant_effect_digest(&asked).expect("the grant's digest"),
    );
    let before = live_grants(&vault);
    let other = mint_auto_weave_grant(
        &vault,
        &owner_proof,
        AutoWeaveGrantRequest {
            check_in_ref: Some(check_in.to_hex()),
            ..auto_weave_request(other_writer, project)
        },
    );
    assert!(
        other.is_err(),
        "the approval covers the writer it was asked for only; seen {other:?}"
    );
    assert_eq!(
        live_grants(&vault),
        before,
        "the refused mint stands no grant"
    );
    assert!(
        !spent(&vault, &check_in),
        "a refused call leaves it unspent"
    );

    let receipt = mint_auto_weave_grant(
        &vault,
        &owner_proof,
        AutoWeaveGrantRequest {
            check_in_ref: Some(check_in.to_hex()),
            ..asked
        },
    )
    .expect("the Owner applies the approved ask");
    assert_eq!(
        live_grants(&vault),
        before + 1,
        "the asked-for grant stands"
    );
    assert!(spent(&vault, &check_in), "the mint spent the check-in");
    assert_eq!(
        receipt.check_in,
        Some(owner_decision(
            ActClass::GrantWiden,
            Some(check_in),
            Some(asker)
        )),
        "the receipt names the applied check-in and its asker"
    );
}

#[test]
fn the_owner_applies_an_approved_ask_for_the_nightly_link_grant_only() {
    let (_dir, vault, owner, owner_proof) = rooted();
    // An ask for another verb over the same constant effect.
    let (standing_ask, _) = approved(
        &vault,
        owner,
        &owner_proof,
        STANDING_VERB,
        ActClass::GrantWiden,
        &nightly_link_grant_effect_digest(),
    );
    let before = live_grants(&vault);
    let other = mint_nightly_link_grant(
        &vault,
        &owner_proof,
        NightlyLinkGrantRequest {
            check_in_ref: Some(standing_ask.to_hex()),
        },
    );
    assert!(
        other.is_err(),
        "an ask for another verb does not apply; seen {other:?}"
    );
    assert_eq!(
        live_grants(&vault),
        before,
        "the refused mint stands no grant"
    );
    assert!(
        !spent(&vault, &standing_ask),
        "a refused call leaves it unspent"
    );

    let (check_in, asker) = approved(
        &vault,
        owner,
        &owner_proof,
        NIGHTLY_LINK_VERB,
        ActClass::GrantWiden,
        &nightly_link_grant_effect_digest(),
    );
    let receipt = mint_nightly_link_grant(
        &vault,
        &owner_proof,
        NightlyLinkGrantRequest {
            check_in_ref: Some(check_in.to_hex()),
        },
    )
    .expect("the Owner applies the approved ask");
    assert_eq!(
        live_grants(&vault),
        before + 1,
        "the Dreamer's grant stands"
    );
    assert!(spent(&vault, &check_in), "the mint spent the check-in");
    assert_eq!(
        receipt.check_in,
        Some(owner_decision(
            ActClass::GrantWiden,
            Some(check_in),
            Some(asker)
        )),
        "the receipt names the applied check-in and its asker"
    );

    let again = mint_nightly_link_grant(&vault, &owner_proof, NightlyLinkGrantRequest::default())
        .expect("the Owner's own mint");
    assert_eq!(
        again.check_in,
        Some(owner_decision(ActClass::GrantWiden, None, None)),
        "the Owner's own mint records their own proof"
    );
}
