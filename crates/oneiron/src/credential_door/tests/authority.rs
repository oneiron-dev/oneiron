//! Credential authority, replay, consent, and federation-scope regression cases.
use super::*;
use crate::authority::{
    AuthorityOp, authority_log_entity_id_from_hash, decode_authority_log_entry_body,
    encode_authority_log_entry_body,
};

fn owner(vault: &Vault) -> crate::consent::AuthenticatedOwner {
    let id = EntityId::now();
    vault
        .put_entity(
            &id,
            crate::registry::ENTITY_TYPE_PERSON,
            crate::TimeRange { start: 1, end: 1 },
            1,
            b"owner",
        )
        .unwrap();
    vault
        .authenticate_owner(
            id,
            "principal:owner",
            true,
            crate::store::GateDecisionId::now(),
        )
        .unwrap()
}

#[test]
fn signed_handle_cannot_expand_the_immutable_class_or_scope() {
    let (_tmp, vault, door) = door_fixture();
    let root = signed_credential(&vault, "door.delegate", witnessed(&door).secs(), 600, false);
    let minted = door
        .mint_one_shot(&root, DOOR_SECRET, EFFECTOR, 120)
        .unwrap();
    let hash = minted.mint_hash().unwrap();
    let forged = door
        .credential_for_principal(&hash, "holder:tester")
        .unwrap()
        .with_verb_class("door.delegate");
    assert!(matches!(
        door.redeem_one_shot(forged),
        Err(CredentialDoorError::AuthorityRejected)
    ));
    assert!(
        vault
            .authority_fold()
            .unwrap()
            .live_door_slip(&hash)
            .is_some()
    );
    assert_eq!(
        door.redeem_one_shot(minted).unwrap().value.as_slice(),
        SECRET_VALUE
    );
}

#[test]
fn spent_mint_cannot_be_replayed_or_reconstructed_after_reopen() {
    let (tmp, vault, door) = door_fixture();
    let one_shot = one_shot_credential(&vault, witnessed(&door));
    let hash = one_shot.mint_hash().unwrap();
    let entry = vault
        .get_authority_log_entry(&authority_log_entity_id_from_hash(&hash).unwrap())
        .unwrap()
        .unwrap();
    let encoded = encode_authority_log_entry_body(&entry).unwrap();
    assert_eq!(decode_authority_log_entry_body(&encoded).unwrap(), entry);
    door.redeem_one_shot(one_shot).unwrap();
    drop(door);
    drop(vault);
    let reopened = Arc::new(Vault::open(tmp.path(), VaultConfig::default()).unwrap());
    reopened
        .put_authority_log_entry(&entry, crate::TimeRange { start: 1, end: 1 }, 1)
        .unwrap();
    let door = CredentialDoorService::new(Arc::clone(&reopened));
    assert!(matches!(
        door.credential_for_principal(&hash, "holder:tester"),
        Err(CredentialDoorError::AuthorityRejected)
    ));
    assert_eq!(lease_rows(&reopened), 1);
}

#[test]
fn parent_revocation_kills_a_child_without_editing_either_mint() {
    let (_tmp, vault, door) = door_fixture();
    let root = signed_credential(&vault, "door.delegate", witnessed(&door).secs(), 600, false);
    let child = door
        .mint_one_shot(&root, DOOR_SECRET, EFFECTOR, 120)
        .unwrap();
    let mut txn = vault.store.env.write_txn().unwrap();
    vault
        .append_local_door_op_in_txn(
            &mut txn,
            AuthorityOp::RevokeDoorSlip {
                mint_hash: root.mint_hash().unwrap(),
            },
        )
        .unwrap();
    txn.commit().unwrap();
    assert!(matches!(
        door.redeem_one_shot(child),
        Err(CredentialDoorError::AuthorityRejected)
    ));
    assert_eq!(lease_rows(&vault), 0);
}

#[test]
fn missing_verb_asks_then_owner_standing_grant_resolves_only_that_scope() {
    let (_tmp, vault, door) = door_fixture();
    let credential = signed_credential(&vault, "door.inject", witnessed(&door).secs(), 600, false);
    let ask = door
        .issue_lease_ticket(&credential, DOOR_SECRET, EFFECTOR, 30)
        .unwrap_err();
    let CredentialDoorError::Ask {
        reason: DoorDenyReason::VerbNotInSlip,
        effect,
    } = ask
    else {
        panic!("expected typed ASK");
    };
    let grant = vault
        .create_standing_grant(&owner(&vault), effect.action_requirement().unwrap().clone())
        .unwrap();
    assert_eq!(
        door.issue_lease_ticket(&credential, DOOR_SECRET, EFFECTOR, 30)
            .unwrap()
            .value
            .as_slice(),
        SECRET_VALUE
    );
    assert!(
        door.issue_lease_ticket(&credential, "another.secret", EFFECTOR, 30)
            .is_err()
    );
    assert_eq!(
        vault
            .authority_fold()
            .unwrap()
            .live_door_slip(&credential.mint_hash().unwrap())
            .unwrap()
            .scope
            .verb_class,
        "door.inject"
    );
    assert!(matches!(
        grant,
        crate::consent::ConsentReceipt::Approved { .. }
    ));
}

#[test]
fn approve_once_resolves_the_exact_missing_verb_and_is_spent() {
    let (_tmp, vault, door) = door_fixture();
    let credential = signed_credential(&vault, "door.inject", witnessed(&door).secs(), 600, false);
    let CredentialDoorError::Ask { effect, .. } = door
        .issue_lease_ticket(&credential, DOOR_SECRET, EFFECTOR, 30)
        .unwrap_err()
    else {
        panic!("ASK");
    };
    vault.approve_once(&owner(&vault), effect.digest()).unwrap();
    door.issue_lease_ticket(&credential, DOOR_SECRET, EFFECTOR, 30)
        .unwrap();
    assert!(
        door.issue_lease_ticket(&credential, DOOR_SECRET, EFFECTOR, 30)
            .is_err()
    );
    assert_eq!(lease_rows(&vault), 1);
}

#[test]
fn two_concurrent_redeemers_get_exactly_one_secret_lease() {
    let (_tmp, vault, door) = door_fixture();
    let one = one_shot_credential(&vault, witnessed(&door));
    let other = door
        .credential_for_principal(&one.mint_hash().unwrap(), "holder:tester")
        .unwrap();
    let outcomes = std::thread::scope(|scope| {
        let a = scope.spawn(|| door.redeem_one_shot(one));
        let b = scope.spawn(|| door.redeem_one_shot(other));
        [a.join().unwrap().is_ok(), b.join().unwrap().is_ok()]
    });
    assert_eq!(outcomes.into_iter().filter(|ok| *ok).count(), 1);
    assert_eq!(lease_rows(&vault), 1);
}

#[test]
fn unknown_class_is_not_an_ask_and_pact_meet_never_widens() {
    use crate::federation::{
        FederationDirectionScope, FederationScopeBands, FederationScopeFacets,
        FederationScopeWorlds,
    };
    let (_tmp, _vault, door) = door_fixture();
    let credential = push_credential(witnessed(&door)).with_verb_class("unregistered-class");
    assert_eq!(
        deny_reason(
            door.authenticate_receive_pack(Some(&credential), &repo(), loopback())
                .unwrap_err()
        ),
        DoorDenyReason::UnknownVerbClass
    );
    let wide = FederationDirectionScope {
        worlds: FederationScopeWorlds::All,
        facets: FederationScopeFacets::All,
        bands: FederationScopeBands::All,
    };
    let narrow = FederationDirectionScope {
        worlds: FederationScopeWorlds::Base,
        facets: FederationScopeFacets::Bottom,
        bands: FederationScopeBands::Bottom,
    };
    assert_eq!(wide.intersect(&narrow), narrow.intersect(&wide));
    assert!(wide.intersect(&narrow).is_narrowing_of(&wide));
    assert!(!wide.is_narrowing_of(&narrow));
}

#[test]
fn a_slip_bound_to_an_absent_pact_never_releases_the_secret() {
    use crate::federation::{
        FederationDirectionScope, FederationScopeBands, FederationScopeFacets,
        FederationScopeWorlds,
    };
    let (_tmp, vault, door) = door_fixture();
    let root = signed_credential(&vault, "door.inject", witnessed(&door).secs(), 600, false);
    let mut scope = vault
        .authority_fold()
        .unwrap()
        .live_door_slip(&root.mint_hash().unwrap())
        .unwrap()
        .scope
        .clone();
    scope.pact = Some((
        EntityId::now(),
        FederationDirectionScope {
            worlds: FederationScopeWorlds::All,
            facets: FederationScopeFacets::All,
            bands: FederationScopeBands::All,
        },
    ));
    let mut txn = vault.store.env.write_txn().unwrap();
    let hash = vault
        .append_local_door_op_in_txn(&mut txn, AuthorityOp::MintDoorSlip(scope.clone()))
        .unwrap();
    txn.commit().unwrap();
    let credential = DoorCredential::from_mint(&hash, &scope);
    let mut called = false;
    let mut apply = |_value: &[u8]| {
        called = true;
        Ok(())
    };
    assert!(matches!(
        door.inject_secret_at_door(&credential, DOOR_SECRET, EFFECTOR, &mut apply),
        Err(CredentialDoorError::AuthorityRejected)
    ));
    assert!(!called);
}
