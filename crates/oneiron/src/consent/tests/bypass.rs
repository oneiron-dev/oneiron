//! DEC-0006 invariant 7 and `#bypass-grant` (REV-9 item 4): the catastrophe
//! floor is a versioned default policy row, and only the owner's scoped
//! bypass grant passes it.

use super::*;

/// This vault's own owner, authenticated; the only actor that may create a
/// bypass grant.
fn vault_owner(vault: &Vault) -> AuthenticatedOwner {
    let id = vault.ensure_embedded_owner_actor().expect("vault owner");
    vault
        .authenticate_owner(id, &id.to_hex(), true, GateDecisionId::now())
        .expect("authenticate the vault owner")
}

fn thread(vault: &Vault, seed: u8) -> EntityId {
    let id = entity(seed);
    vault
        .put_entity(
            &id,
            crate::registry::ENTITY_TYPE_CONVERSATION,
            at(1),
            1,
            b"thread",
        )
        .expect("seed thread");
    id
}

fn destruction(bound: &GrantBound, thread: Option<EntityId>) -> ComposedEffect {
    ComposedEffect::new(
        EffectFacts::new("vault.destroy")
            .expect("facts")
            .with_catastrophe(CatastropheClass::VaultWideDestruction),
    )
    .with_action_requirement(bound.clone())
    .expect("requirement")
    .in_place(EffectPlace {
        project: None,
        thread,
    })
}

fn decide(vault: &Vault, effect: &ComposedEffect) -> ConsentEvaluation {
    vault
        .evaluate_consent_for(effect, None)
        .expect("evaluate consent")
}

#[test]
fn the_floor_ships_as_a_versioned_default_policy_row() {
    let manifest = crate::gate::default_policy_manifest().expect("shipped manifest");
    let rmpv::Value::Map(entries) =
        rmpv::decode::read_value(&mut manifest.as_slice()).expect("manifest map")
    else {
        panic!("manifest is a map");
    };
    let (_, row) = entries
        .iter()
        .find(|(key, _)| key.as_str() == Some("catastrophe_floor"))
        .expect("the floor is a row in the shipped manifest");
    let floor = CatastropheFloor::decode_row(row).expect("the shipped row decodes");
    assert_eq!(floor, CatastropheFloor::pinned());
    assert_eq!(floor.version(), CATASTROPHE_FLOOR_VERSION);
    // The membership is pinned to the version: no row shrinks the floor.
    let shrunk = rmpv::Value::Map(vec![
        (rmpv::Value::from("version"), rmpv::Value::from(1)),
        (
            rmpv::Value::from("members"),
            rmpv::Value::Array(vec![rmpv::Value::from("key_recovery")]),
        ),
    ]);
    assert_eq!(CatastropheFloor::decode_row(&shrunk), None);
}

#[test]
fn an_owner_bypass_is_set_and_forget_inside_its_scope_and_receipted() {
    let (_dir, vault) = open_test_vault_with(embedding_test_config());
    let owner = vault_owner(&vault);
    let (inside, outside) = (thread(&vault, 0x61), thread(&vault, 0x62));
    let bound = action_bound("agent-a", "vault_wide_destruction", &["scope:all"]);

    // Off by default: the floor asks.
    assert_eq!(
        decide(&vault, &destruction(&bound, Some(inside))).decision,
        ConsentDecision::Ask
    );
    assert!(vault.active_bypass_grants().expect("state").is_empty());

    // One warning names what the grant allows and in which scope.
    let warning = vault
        .bypass_grant_warning(&owner, bound.clone(), BypassScope::Thread(inside))
        .expect("the warning");
    assert_eq!(warning.allows(), CatastropheClass::VaultWideDestruction);
    assert_eq!(warning.scope(), BypassScope::Thread(inside));
    let created = vault
        .create_bypass_grant(&owner, &warning)
        .expect("the owner creates the bypass");
    assert_eq!(created.reason_code(), CONSENT_REASON_BYPASS_CREATED);
    let grant_ref = created.grant_ref().expect("bypass row");
    let active = vault.active_bypass_grants().expect("state");
    assert_eq!(active.len(), 1, "the engine reports the bypass as active");
    assert_eq!(active[0].grant_ref, grant_ref);
    assert_eq!(active[0].scope, BypassScope::Thread(inside));

    // Set and forget: nothing inside the scope asks again, and every act
    // under it is receipted as bypassed.
    for _ in 0..2 {
        let evaluation = decide(&vault, &destruction(&bound, Some(inside)));
        assert_eq!(evaluation.decision, ConsentDecision::Auto);
        assert_eq!(evaluation.bypassed_by.as_deref(), Some(grant_ref.as_str()));
    }
    let bypassed = vault
        .store
        .gate_decisions_for_grant_ref(&grant_ref)
        .expect("receipts")
        .into_iter()
        .filter(|row| row.reason_codes == [CONSENT_REASON_BYPASSED])
        .count();
    assert_eq!(bypassed, 2);

    // Outside its scope everything asks as usual, and no bypass covers an
    // erase.
    for effect in [
        destruction(&bound, Some(outside)),
        destruction(&bound, None),
        destruction(&bound, Some(inside)).as_erase(),
    ] {
        let evaluation = decide(&vault, &effect);
        assert_eq!(evaluation.decision, ConsentDecision::Ask);
        assert_eq!(evaluation.bypassed_by, None);
    }

    // The bypass sits on the grant slate, and one revoke there ends it.
    let slate = vault
        .consent_registry(ConsentRegistryQuery::new(16, false))
        .expect("registry");
    let row = slate
        .rows
        .iter()
        .find(|row| row.grant_ref == grant_ref)
        .expect("the bypass is on the slate");
    assert_eq!(
        row.bypass.map(|extent| extent.scope),
        Some(BypassScope::Thread(inside))
    );
    vault
        .revoke_consent_grant(&owner, &row.revoke_action.grant_ref)
        .expect("revoke");
    assert!(vault.active_bypass_grants().expect("state").is_empty());
    assert_eq!(
        decide(&vault, &destruction(&bound, Some(inside))).decision,
        ConsentDecision::Ask
    );
}

#[test]
fn only_the_vault_owner_creates_a_bypass_and_never_for_the_whole_vault() {
    let (_dir, vault) = open_test_vault_with(embedding_test_config());
    let owner = vault_owner(&vault);
    let inside = thread(&vault, 0x63);
    let bound = action_bound("agent-a", "vault_wide_destruction", &["scope:all"]);

    // An agent cannot even authenticate as an owner, so it cannot
    // self-grant a bypass.
    let agent = entity(0x64);
    vault
        .put_entity(
            &agent,
            crate::registry::ENTITY_TYPE_MACHINE,
            at(1),
            1,
            b"agent",
        )
        .expect("seed agent");
    assert_eq!(
        vault
            .authenticate_owner(agent, &agent.to_hex(), true, GateDecisionId::now())
            .expect_err("an agent is no owner")
            .kind(),
        ErrorKind::ConsentOwnerNotAuthenticated
    );
    // A person who authenticated but does not own this vault is refused.
    let person = entity(0x65);
    vault
        .put_entity(&person, ENTITY_TYPE_PERSON, at(1), 1, b"person")
        .expect("seed person");
    let not_owner = vault
        .authenticate_owner(person, &person.to_hex(), true, GateDecisionId::now())
        .expect("authenticated person");
    assert_eq!(
        vault
            .bypass_grant_warning(&not_owner, bound.clone(), BypassScope::Thread(inside))
            .expect_err("only the owner")
            .kind(),
        ErrorKind::ConsentOwnerNotAuthenticated
    );
    // A warning made for the owner does not create a grant for anyone else.
    let warning = vault
        .bypass_grant_warning(&owner, bound.clone(), BypassScope::Thread(inside))
        .expect("the owner's warning");
    assert!(vault.create_bypass_grant(&not_owner, &warning).is_err());

    // Never the whole vault: the scope must name one project or one thread.
    let mut wide = vec![BypassScope::Project(person), BypassScope::Thread(person)];
    let txn = vault.store.env.read_txn().expect("read");
    if let Some(root) =
        crate::workspace_roster::root_project_in(&vault.store, &txn).expect("root project")
    {
        wide.push(BypassScope::Project(root));
    }
    drop(txn);
    for scope in wide {
        assert_eq!(
            vault
                .bypass_grant_warning(&owner, bound.clone(), scope)
                .expect_err("not one project or thread")
                .kind(),
            ErrorKind::InvalidConsentBound
        );
    }
    // A bypass covers a catastrophe-floor class, nothing else.
    assert_eq!(
        vault
            .bypass_grant_warning(
                &owner,
                action_bound("agent-a", "send", &["scope:all"]),
                BypassScope::Thread(inside),
            )
            .expect_err("not a floor class")
            .kind(),
        ErrorKind::InvalidConsentBound
    );
    assert!(vault.active_bypass_grants().expect("state").is_empty());
}
