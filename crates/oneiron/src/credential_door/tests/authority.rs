//! Credential capability replay, consent, and scope regression cases.
use super::*;

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
fn spent_mint_cannot_be_replayed_or_reconstructed_after_reopen() {
    let (tmp, vault, door) = door_fixture();
    let one_shot = one_shot_credential(&vault, witnessed(&door));
    let replay = replay_credential(&one_shot);
    let (id, _) = one_shot.capability_identity().unwrap();
    let fold = vault.authority_fold().unwrap();
    let hash = fold.slips.mints[&id].entry_hash;
    let entry = vault
        .get_authority_log_entry(
            &crate::authority::authority_log_entity_id_from_hash(&hash).unwrap(),
        )
        .unwrap()
        .unwrap();
    let encoded = crate::authority::encode_authority_log_entry_body(&entry).unwrap();
    assert_eq!(
        crate::authority::decode_authority_log_entry_body(&encoded).unwrap(),
        entry
    );
    door.redeem_one_shot(one_shot).unwrap();
    drop(door);
    drop(vault);
    let reopened = Arc::new(Vault::open(tmp.path(), VaultConfig::default()).unwrap());
    reopened
        .put_authority_log_entry(&entry, crate::TimeRange { start: 1, end: 1 }, 1)
        .unwrap();
    let door = CredentialDoorService::new(Arc::clone(&reopened));
    assert!(matches!(
        door.redeem_one_shot(replay),
        Err(CredentialDoorError::AuthorityRejected)
    ));
    assert!(!reopened.authority_fold().unwrap().slip_is_live(&id));
    assert_eq!(lease_rows(&reopened), 1);
}

#[test]
fn parent_revocation_kills_a_child_without_editing_either_mint() {
    let (_tmp, vault, door) = door_fixture();
    let parent = signed_credential(&vault, "door.delegate", witnessed(&door).secs(), 600, false);
    let super::super::door_credential::DoorGrant::Capability(verified) = &parent.grant else {
        panic!("capability");
    };
    let issuer = crate::authority::HostSlipIssuer::from_secret(b"door-test-root").unwrap();
    let mut claims = verified.claims().clone();
    claims.parent_id = Some(claims.slip_id);
    claims.slip_id = [33; 32];
    claims.scope = super::super::verb_class::preset("door.redeem").unwrap();
    claims.single_use = true;
    claims.expires_at = claims.issued_at + 120;
    claims.ttl_secs = 120;
    let child = vault.mint_capability_slip(&issuer, claims).unwrap();
    let proof = issuer.binding_proof(&child, b"child").unwrap();
    let credential = vault
        .verify_capability_slip(&issuer, &child, b"child", &proof)
        .unwrap()
        .door_credential();
    vault
        .revoke_capability_slip(&issuer, verified.claims().slip_id)
        .unwrap();
    assert!(matches!(
        door.redeem_one_shot(credential),
        Err(CredentialDoorError::AuthorityRejected)
    ));
    assert_eq!(lease_rows(&vault), 0);
}

#[test]
fn consent_cannot_widen_a_capability_preset() {
    let (_tmp, vault, door) = door_fixture();
    let credential = signed_credential(&vault, "door.inject", witnessed(&door).secs(), 600, false);
    let effect = credential
        .ask_effect("lease", DOOR_SECRET, EFFECTOR)
        .unwrap();
    let owner = owner(&vault);
    vault.approve_once(&owner, effect.digest()).unwrap();
    vault
        .create_standing_grant(&owner, effect.action_requirement().unwrap().clone())
        .unwrap();
    assert_eq!(
        deny_reason(
            door.issue_lease_ticket(&credential, DOOR_SECRET, EFFECTOR, 30)
                .unwrap_err()
        ),
        DoorDenyReason::VerbNotInSlip
    );
    assert_eq!(lease_rows(&vault), 0);
    let (id, _) = credential.capability_identity().unwrap();
    assert_eq!(
        vault.authority_fold().unwrap().slips.mints[&id]
            .action
            .claims
            .scope,
        super::super::verb_class::preset("door.inject").unwrap()
    );
}

#[test]
fn two_concurrent_redeemers_get_exactly_one_secret_lease() {
    let (_tmp, vault, door) = door_fixture();
    let one = one_shot_credential(&vault, witnessed(&door));
    let other = replay_credential(&one);
    let outcomes = std::thread::scope(|scope| {
        let a = scope.spawn(|| door.redeem_one_shot(one));
        let b = scope.spawn(|| door.redeem_one_shot(other));
        [a.join().unwrap().is_ok(), b.join().unwrap().is_ok()]
    });
    assert_eq!(outcomes.into_iter().filter(|ok| *ok).count(), 1);
    assert_eq!(lease_rows(&vault), 1);
}

#[test]
fn every_preset_meet_narrows_and_cannot_restore_verbs() {
    let names = [
        "door.none",
        "door.push",
        "door.inject",
        "door.lease",
        "door.redeem",
        "door.operate",
        "door.delegate",
    ];
    let (_tmp, vault, door) = door_fixture();
    let issuer = crate::authority::HostSlipIssuer::from_secret(b"door-test-root").unwrap();
    let root = vault.ensure_host_root_slip(&issuer).unwrap();
    for name in names {
        let preset = super::super::verb_class::preset(name).unwrap();
        assert!(preset.is_narrowing_of(&crate::federation::Scope::top()));
        for other in names {
            let other = super::super::verb_class::preset(other).unwrap();
            let mut slip = root.clone();
            slip.attenuate(crate::authority::SlipCaveat {
                scope: Some(preset.clone()),
                ..Default::default()
            })
            .unwrap();
            slip.attenuate(crate::authority::SlipCaveat {
                scope: Some(other.clone()),
                ..Default::default()
            })
            .unwrap();
            slip.attenuate(crate::authority::SlipCaveat {
                scope: Some(crate::federation::Scope::top()),
                ..Default::default()
            })
            .unwrap();
            let proof = issuer.binding_proof(&slip, b"presets").unwrap();
            let verified = vault
                .verify_capability_slip(&issuer, &slip, b"presets", &proof)
                .unwrap();
            assert_eq!(verified.scope(), &preset.meet(&other));
            assert!(verified.scope().is_narrowing_of(&preset));
            assert!(verified.scope().is_narrowing_of(&other));
        }
    }
    assert!(super::super::verb_class::preset("unregistered-class").is_none());
    assert_eq!(lease_rows(door.vault()), 0);
}

#[test]
fn a_slip_bound_to_an_absent_pact_never_releases_the_secret() {
    use crate::federation::{
        FederationDirectionScope, FederationScopeBands, FederationScopeFacets,
        FederationScopeWorlds,
    };
    let (_tmp, vault, door) = door_fixture();
    let issuer = crate::authority::HostSlipIssuer::from_secret(b"door-test-root").unwrap();
    let mut slip = vault.ensure_host_root_slip(&issuer).unwrap();
    slip.attenuate(crate::authority::SlipCaveat {
        pact: Some((
            EntityId::now(),
            FederationDirectionScope {
                worlds: FederationScopeWorlds::All,
                facets: FederationScopeFacets::All,
                bands: FederationScopeBands::All,
            },
        )),
        ..Default::default()
    })
    .unwrap();
    let proof = issuer.binding_proof(&slip, b"pact").unwrap();
    assert!(
        vault
            .verify_capability_slip(&issuer, &slip, b"pact", &proof)
            .is_err()
    );
    assert_eq!(lease_rows(door.vault()), 0);
}
