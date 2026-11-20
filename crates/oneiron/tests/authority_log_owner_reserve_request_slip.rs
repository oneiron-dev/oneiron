//! An owner act whose proof came with a request's slip carries no owner key
//! proof (row OWNER-RESERVE-CROSS-INSTALL-COSIGN-REFUSALS, REVIEW-9955 P1).
//! Since #9904 the owner's own carried acts carry the owner key's proof this
//! install holds, which buys them room past another install's owner reserve
//! (`Vault::owner_act_proof_signer`). A proof the transport bound to the
//! slip its request arrived with (`Vault::bind_request_credential`) reads
//! that slip for its liveness alone, whatever its cut (a read-only token,
//! say), so no owner key's proof may vouch for the act it makes.
//!
//! Install A is rooted with the owner bound and holds the host root, which
//! proves the owner's acts (`owner_reserve/two_installs.rs`). The owner mints
//! a federation grant on A and sets its travel twice: with the owner's
//! proof, and with that proof bound to the owner's own slip as its request's
//! slip.
//!
//! Red at main 94477453 (every owner-authored write is proved): the
//! request-bound choice carries the host root's cosign. Green at the head: it
//! carries none; the control, the unbound proof's choice, carries one.
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron
//! --all-features --test authority_log_owner_reserve_request_slip`.

use std::collections::BTreeSet;

use oneiron::authority::{ActSurface, AuthorityLogEntry, AuthorityOp, VerifiedSlip};
use oneiron::consent::AuthenticatedOwner;
use oneiron::inquiry::InquiryEdgeRequest;
use oneiron::share_travel::{BornWithField, TravelChoice};
use oneiron::{EntityId, Vault};

#[path = "owner_reserve/two_installs.rs"]
mod two_installs;

use two_installs::{Rooted, hold_owner_key, rooted, stored_history};

/// A company vault no fixture opens: the inquiry edge mints before any pact.
const UNOPENED_COMPANY: oneiron::authority::AuthorityVaultId = [0xac; 32];

/// A fresh slip id from two entity ids.
fn slip_id() -> [u8; 32] {
    let mut id = [0_u8; 32];
    id[..16].copy_from_slice(EntityId::now().as_bytes());
    id[16..].copy_from_slice(EntityId::now().as_bytes());
    id
}

/// The owner's own verified human slip, cut from the host root with a fresh
/// id and verified on its binding, as a transport verifies the slip a
/// request arrives with.
fn owners_verified_slip(vault: &Vault, owner: EntityId) -> VerifiedSlip {
    let issuer = oneiron::test_support::test_host_issuer();
    let root = vault
        .ensure_host_root_slip(&issuer)
        .expect("FIXTURE: the host root slip");
    let mut claims = root.claims;
    claims.slip_id = slip_id();
    claims.holder_ref = owner.to_hex();
    claims.actor_class = Some("human".to_owned());
    let slip = vault
        .mint_capability_slip(&issuer, claims)
        .expect("FIXTURE: the owner's own slip");
    let challenge = b"authority-log-owner-reserve-request-slip";
    let binding = issuer
        .binding_proof(&slip, challenge)
        .expect("FIXTURE: the binding proof");
    vault
        .verify_capability_slip(&issuer.public_key(), &slip, challenge, &binding)
        .expect("FIXTURE: the slip verifies")
}

/// The owner sets a new federation grant's travel on A by `proof`; the
/// choice A carries for it.
fn travel_choice_by(rooted: &Rooted, proof: &AuthenticatedOwner) -> AuthorityLogEntry {
    let edge = rooted
        .vault
        .mint_inquiry_edge(
            &rooted.proof,
            &InquiryEdgeRequest::member_defaults(UNOPENED_COMPANY, "Acme"),
        )
        .expect("FIXTURE: the owner mints a federation grant on A");
    let choice = TravelChoice {
        born_with: BTreeSet::from([BornWithField::Why]),
    };
    let set = rooted
        .vault
        .set_federation_grant_travel_as(
            proof,
            ActSurface::ThisInstall,
            &edge.grant,
            Some(choice.clone()),
            None,
            rooted.vault.now_recorded_at(),
        )
        .expect("the owner sets the grant's travel on A");
    assert_eq!(set.map(|travel| travel.travel), Some(choice));
    let choices: Vec<AuthorityLogEntry> = stored_history(&rooted.vault)
        .iter()
        .map(|body| {
            oneiron::authority::decode_authority_log_entry_body(body).expect("a stored row")
        })
        .filter(
            |row| matches!(&row.op, AuthorityOp::GrantTravelSet(set) if set.grant == edge.grant),
        )
        .collect();
    let [carried] = choices.as_slice() else {
        panic!("A carried the owner's travel choice once: {choices:?}");
    };
    carried.clone()
}

#[test]
fn an_owner_act_whose_proof_came_with_a_request_slip_carries_no_owner_key_proof() {
    let rooted = rooted();
    hold_owner_key(&rooted);
    let proved = travel_choice_by(&rooted, &rooted.proof);
    assert_eq!(
        proved.cosigns.len(),
        1,
        "control: the owner's own proof makes A prove the choice with the key it holds"
    );
    let request_bound = rooted
        .vault
        .bind_request_credential(
            rooted.proof.clone(),
            owners_verified_slip(&rooted.vault, rooted.owner),
        )
        .expect("FIXTURE: the request's slip binds to the owner's proof");
    let carried = travel_choice_by(&rooted, &request_bound);
    assert!(
        carried.cosigns.is_empty(),
        "a choice whose proof came with a request's slip is carried unproven, though A holds an \
         owner key: {} cosigns",
        carried.cosigns.len()
    );
}
