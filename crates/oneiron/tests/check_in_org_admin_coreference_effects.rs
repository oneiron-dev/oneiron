//! ROLES-CHECKIN P2.5, row 2k8b (ARCH-0082 #act-table "Widen another's
//! grant" and #owner-own-acts; Engine rulings P25-SHAPE Q1 = A, 14 Nov
//! 13:39, and P25-2K8-SCOPE Q1 = A, 19:32): two Owner-proof doors take the
//! 2j apply shape, `vault.org_admin.configure` and
//! `vault.federation.coreference.share_consent`.
//!
//! - The Owner's act is never gated: it goes on their own proof, and the
//!   answer records that decision.
//! - The Owner applies another asker's approved check-in for that exact
//!   change: the act's writer spends it, and the answer names it and its
//!   asker. An approval for another change changes nothing and stays
//!   unspent.
//!
//! On its base, 2k8a's head, this file does not build: neither request has
//! a `check_in_ref`.
//!
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron
//! --all-features --test check_in_org_admin_coreference_effects`.
#![cfg(oneiron_test_support)]
#![allow(clippy::unwrap_used, clippy::expect_used)]

#[path = "check_in/owner_apply_fixture.rs"]
mod owner_apply_fixture;

use std::collections::BTreeSet;

use oneiron::check_in::ActClass;
use oneiron::consent::AuthenticatedOwner;
use oneiron::federation::{
    CoreferenceStatus, OrgAdminPolicy, OrgAdminPower, coreference_shared_for_pact,
};
use oneiron::registry::ENTITY_TYPE_PERSON;
use oneiron::verbs::{
    CoreferenceLinkRequest, CoreferenceShareConsentRequest, OrgAdminConfigureRequest,
    configure_org_admin_as_owner, coreference_share_consent_effect_digest,
    link_coreference_as_owner, org_admin_configure_effect_digest, share_coreference_as_owner,
};
use oneiron::{EntityId, TimeRange, Vault};
use owner_apply_fixture::{approved, owner_decision, rooted, spent};

/// The org admin policy naming `admin` the admin of `org`, with one power.
fn org_admin_request(org: EntityId, admin: EntityId) -> OrgAdminConfigureRequest {
    OrgAdminConfigureRequest {
        policy: OrgAdminPolicy::new(
            org,
            BTreeSet::from([admin]),
            BTreeSet::from([OrgAdminPower::AddMember]),
        )
        .expect("an org admin policy"),
        check_in_ref: None,
    }
}

#[test]
fn the_owner_applies_an_approved_ask_for_that_org_admin_configuration_only() {
    let (_dir, vault, owner, owner_proof) = rooted();
    let own = configure_org_admin_as_owner(
        &vault,
        &owner_proof,
        org_admin_request(EntityId::now(), EntityId::now()),
    )
    .expect("the Owner configures an org's admin");
    assert_eq!(
        own.check_in,
        Some(owner_decision(ActClass::GrantWiden, None, None)),
        "the Owner's own act records their own proof"
    );

    let (org, admin) = (EntityId::now(), EntityId::now());
    let asked = org_admin_request(org, admin);
    let (check_in, asker) = approved(
        &vault,
        owner,
        &owner_proof,
        "vault.org_admin.configure",
        ActClass::GrantWiden,
        &org_admin_configure_effect_digest(&asked).expect("the configuration's digest"),
    );
    let other = configure_org_admin_as_owner(
        &vault,
        &owner_proof,
        OrgAdminConfigureRequest {
            check_in_ref: Some(check_in.to_hex()),
            ..org_admin_request(org, EntityId::now())
        },
    );
    assert!(
        other.is_err(),
        "the approval covers the admin it was asked for only; seen {other:?}"
    );
    assert!(
        vault.org_admin_policy(org).is_err(),
        "the refused act configures nothing"
    );
    assert!(
        !spent(&vault, &check_in),
        "a refused call leaves it unspent"
    );

    let configured = configure_org_admin_as_owner(
        &vault,
        &owner_proof,
        OrgAdminConfigureRequest {
            check_in_ref: Some(check_in.to_hex()),
            ..asked
        },
    )
    .expect("the Owner applies the approved ask");
    assert!(
        vault.org_admin_policy(org).is_ok(),
        "the asked-for policy stands"
    );
    assert!(spent(&vault, &check_in), "the act spent the check-in");
    assert_eq!(
        configured.check_in,
        Some(owner_decision(
            ActClass::GrantWiden,
            Some(check_in),
            Some(asker)
        )),
        "the answer names the applied check-in and its asker"
    );
}

/// A live PERSON at `id`.
fn person(vault: &Vault, id: EntityId) {
    vault
        .put_entity(
            &id,
            ENTITY_TYPE_PERSON,
            TimeRange { start: 1, end: 1 },
            1,
            b"human",
        )
        .expect("a live person");
}

/// Declares the two coreference predicates normal in the stored default
/// manifest, at its own id (as `agent_interrupt_cut.rs` does for its
/// binding): the shipped manifest names `core.coreference.*` in no rule, so
/// the Owner's confirmed link and consent claims, which the coreference doors
/// write Approved with no owner-authored proof, would pend at the
/// criticality floor (FIX [COREFERENCE-OWNER-DOORS-PEND-AT-FLOOR]).
fn declare_coreference_normal(vault: &Vault, owner_proof: &AuthenticatedOwner) {
    use rmpv::Value;

    let id = oneiron_store::policy_record::default_policy_manifest_id()
        .expect("the default policy manifest id");
    let body = vault
        .get(&id)
        .expect("the default policy manifest reads")
        .expect("the default policy manifest is stored");
    let Value::Map(mut fields) =
        rmpv::decode::read_value(&mut body.as_slice()).expect("the manifest decodes")
    else {
        panic!("the default policy manifest is a map");
    };
    let Some((_, Value::Array(rules))) = fields
        .iter_mut()
        .find(|(key, _)| key.as_str() == Some("rules"))
    else {
        panic!("the default policy manifest has a rules array");
    };
    for predicate in ["core.coreference.status", "core.coreference.share_consent"] {
        rules.push(Value::Map(vec![
            (Value::from("prefix"), Value::from(predicate)),
            (Value::from("exact"), Value::Boolean(true)),
            (
                Value::from("axes"),
                Value::Map(vec![
                    (Value::from("criticality"), Value::from("normal")),
                    (Value::from("sensitivity"), Value::from("normal")),
                ]),
            ),
        ]));
    }
    let mut bytes = Vec::new();
    rmpv::encode::write_value(&mut bytes, &Value::Map(fields)).expect("the manifest encodes");
    vault
        .install_owner_policy_manifest(owner_proof, id, bytes, vault.now_recorded_at())
        .expect("the Owner declares the coreference predicates normal");
}

fn share_request(
    local: EntityId,
    other: EntityId,
    pact: &[u8; 32],
) -> CoreferenceShareConsentRequest {
    CoreferenceShareConsentRequest {
        local_person: local,
        other_person: other,
        pact: pact.iter().map(|byte| format!("{byte:02x}")).collect(),
        check_in_ref: None,
    }
}

#[test]
fn the_owner_applies_an_approved_ask_for_that_share_consent_only() {
    let (_dir, vault, owner, owner_proof) = rooted();
    declare_coreference_normal(&vault, &owner_proof);
    let (local, other) = (EntityId::now(), EntityId::now());
    person(&vault, local);
    person(&vault, other);
    link_coreference_as_owner(
        &vault,
        &owner_proof,
        CoreferenceLinkRequest {
            local_person: local,
            other_person: other,
            status: CoreferenceStatus::Confirmed,
        },
    )
    .expect("the Owner links the two people");
    let (own_pact, asked_pact, other_pact) = ([0x11; 32], [0x22; 32], [0x33; 32]);

    let own =
        share_coreference_as_owner(&vault, &owner_proof, share_request(local, other, &own_pact))
            .expect("the Owner consents to share the link into one pact");
    assert_eq!(
        own.check_in,
        Some(owner_decision(ActClass::GrantWiden, None, None)),
        "the Owner's own consent records their own proof"
    );

    let asked = share_request(local, other, &asked_pact);
    let (check_in, asker) = approved(
        &vault,
        owner,
        &owner_proof,
        "vault.federation.coreference.share_consent",
        ActClass::GrantWiden,
        &coreference_share_consent_effect_digest(&asked).expect("the consent's digest"),
    );
    let refused = share_coreference_as_owner(
        &vault,
        &owner_proof,
        CoreferenceShareConsentRequest {
            check_in_ref: Some(check_in.to_hex()),
            ..share_request(local, other, &other_pact)
        },
    );
    assert!(
        refused.is_err(),
        "the approval covers the pact it was asked for only; seen {refused:?}"
    );
    assert!(
        !coreference_shared_for_pact(&vault, local, other, &other_pact).expect("the pact read"),
        "the refused consent shares nothing"
    );
    assert!(
        !spent(&vault, &check_in),
        "a refused call leaves it unspent"
    );

    let receipt = share_coreference_as_owner(
        &vault,
        &owner_proof,
        CoreferenceShareConsentRequest {
            check_in_ref: Some(check_in.to_hex()),
            ..asked
        },
    )
    .expect("the Owner applies the approved ask");
    assert!(
        coreference_shared_for_pact(&vault, local, other, &asked_pact).expect("the pact read"),
        "the asked-for consent stands"
    );
    assert!(spent(&vault, &check_in), "the consent spent the check-in");
    assert_eq!(
        receipt.check_in,
        Some(owner_decision(
            ActClass::GrantWiden,
            Some(check_in),
            Some(asker)
        )),
        "the answer names the applied check-in and its asker"
    );
}
