//! AGENT-CREDENTIAL-VERB-ALLOWLIST: a slip's verb list rides its signed mint
//! as one optional key, a mint without one keeps its bytes, delegation keeps
//! the list or narrows it and never drops it, and a slip with a list is never
//! owner-grade.
//!
//! Run with: `cargo test --locked -p oneiron-authority --test slip_verb_allowlist`.

use std::collections::BTreeSet;

use ed25519_dalek::SigningKey;
use oneiron_authority::authority::{
    AuthorityOp, SLIP_KEY_VERB_ALLOWLIST, SlipClaims, SlipMintAction, decode_slip_mint,
    slip_mint_value,
};
use oneiron_authority::federation::{Scope, ScopeAxis};
use rmpv::Value;

fn claims(verb_allowlist: Option<&[&str]>) -> SlipClaims {
    SlipClaims {
        slip_id: [3; 32],
        vault_id: [4; 32],
        parent_id: None,
        holder_ref: "a1b2c3d4e5f60718293a4b5c6d7e8f90".to_owned(),
        binding_key: SigningKey::from_bytes(&[9; 32]).verifying_key().to_bytes(),
        scope: Scope {
            verbs: ScopeAxis::Some(["read".to_owned(), "write".to_owned()].into()),
            ..Scope::top()
        },
        issued_at: 10,
        expires_at: 100,
        ttl_secs: 60,
        single_use: false,
        records: BTreeSet::new(),
        channels: BTreeSet::new(),
        actor_class: Some("agent".to_owned()),
        org_ref: None,
        grant_ref: None,
        invitation_ref: None,
        share_ref: None,
        delegation: None,
        comm: None,
        trusted_contact: None,
        seat_claim: None,
        verb_allowlist: verb_allowlist
            .map(|verbs| verbs.iter().map(|verb| (*verb).to_owned()).collect()),
    }
}

fn mint(claims: SlipClaims) -> SlipMintAction {
    SlipMintAction {
        claims,
        renews: None,
        minting_member: None,
    }
}

fn entries(value: &Value) -> &[(Value, Value)] {
    value.as_map().expect("a slip mint is a map")
}

fn names_the_key(value: &Value) -> bool {
    entries(value)
        .iter()
        .any(|(key, _)| key.as_str() == Some(SLIP_KEY_VERB_ALLOWLIST))
}

#[test]
fn a_verb_list_rides_the_signed_mint_and_decodes_unchanged() {
    for list in [
        Some(&["vault.notes.create", "vault.notes.lifecycle"][..]),
        Some(&[][..]),
    ] {
        let action = mint(claims(list));
        let value = slip_mint_value(&action);
        assert!(names_the_key(&value), "{list:?}: the mint carries the key");
        let decoded = decode_slip_mint(entries(&value)).expect("the mint decodes");
        assert_eq!(decoded, AuthorityOp::SlipMint(action), "{list:?}");
    }
}

#[test]
fn a_mint_with_no_list_keeps_its_bytes_and_decodes_with_none() {
    let action = mint(claims(None));
    let value = slip_mint_value(&action);
    assert!(
        !names_the_key(&value),
        "a mint without a list carries no key, so every earlier mint's bytes stay as they were"
    );
    match decode_slip_mint(entries(&value)).expect("the mint decodes") {
        AuthorityOp::SlipMint(decoded) => assert_eq!(decoded.claims.verb_allowlist, None),
        other => panic!("not a slip mint: {other:?}"),
    }
}

#[test]
fn delegation_keeps_or_narrows_a_list_and_never_drops_it() {
    let parent = claims(Some(&["vault.notes.create", "vault.notes.lifecycle"]));
    let child = |list: Option<&[&str]>| SlipClaims {
        slip_id: [5; 32],
        parent_id: Some(parent.slip_id),
        ..claims(list)
    };
    assert!(child(Some(&["vault.notes.create", "vault.notes.lifecycle"])).narrows(&parent));
    assert!(child(Some(&["vault.notes.create"])).narrows(&parent));
    assert!(child(Some(&[])).narrows(&parent));
    assert!(
        !child(Some(&["vault.notes.create", "vault.batch"])).narrows(&parent),
        "a child never names a verb its parent's list leaves out"
    );
    assert!(
        !child(None).narrows(&parent),
        "a child never drops its parent's list"
    );
    let unlisted = claims(None);
    let under_unlisted = SlipClaims {
        slip_id: [5; 32],
        parent_id: Some(unlisted.slip_id),
        ..claims(Some(&["vault.notes.create"]))
    };
    assert!(
        under_unlisted.narrows(&unlisted),
        "a list narrows a parent with none"
    );
}

#[test]
fn a_list_names_only_nonempty_bounded_names_and_is_never_owner_grade() {
    claims(Some(&["vault.notes.create"]))
        .validate()
        .expect("a list of names validates");
    claims(Some(&[""]))
        .validate()
        .expect_err("an empty name is refused");
    let long = "v".repeat(oneiron_authority::authority::VERB_ALLOWLIST_NAME_MAX_BYTES + 1);
    claims(Some(&[long.as_str()]))
        .validate()
        .expect_err("an over-long name is refused");
    let owner_grade = |list: Option<&[&str]>| SlipClaims {
        scope: Scope::top(),
        ..claims(list)
    };
    assert!(owner_grade(None).is_full_vault_owner_grade());
    assert!(
        !owner_grade(Some(&[])).is_full_vault_owner_grade(),
        "a credential with a verb list is never the owner's full-vault instrument"
    );
}
