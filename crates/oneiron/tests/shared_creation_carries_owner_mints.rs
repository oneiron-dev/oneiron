//! Sharing a personal vault carries the owner's mints to the shared scope (pass 28 R3f; Engine
//! ANSWER R3D-PRESHARE-OWNER-MINT-RESIDENCE = A, FIX [SHARED-CREATION-CARRIES-OWNER-MINTS]).
//! Every reader of an owner's mint reads its row at the vault's one residence: the own-device
//! residence on a personal vault, the shared vault's scope once shared. The creation door moves
//! each of his mint rows there in its own transaction, under the row's own id and on the same
//! counted mint: his agent Grant, his git push Grant, his `engine.controls` Grant and his Steward
//! mint to a base agent each go on standing after he shares. Before, the creation refused a vault
//! that held his agent Grant, and the other three rows stayed at the own-device residence, where
//! no reader of a shared vault reads them. A copy put back at the own-device residence after
//! sharing stands for nothing.
//!
//! Needs the doors:
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron
//! --all-features --test shared_creation_carries_owner_mints`.
#![cfg(oneiron_test_support)]

use std::collections::BTreeSet;

use oneiron::authority::ActSurface;
use oneiron::consent::AuthenticatedOwner;
use oneiron::federation::{
    EngineControlActor, EngineControlClass, FederationGrant, FederationGrantScope, Scope,
    ScopeAxis, decode_federation_grant_body, own_device_residence_scope,
};
use oneiron::registry::ENTITY_TYPE_PERSON;
use oneiron::temporal::TimeRange;
use oneiron::test_doors::grant_act::put_unkeyed_member_grant;
use oneiron::test_doors::grant_ending::standing_agent_grant_ids;
use oneiron::test_doors::grant_standing::{grant_line, standing_git_push_grant_ids};
use oneiron::test_doors::steward::{
    GrantMark, dreamer, grant_mark, open_owner_carrier_vault, owner, write_steward_holder_row,
};
use oneiron::verbs::{
    AgentGrantMintRequest, GitPushGrantMintInput, RepoAnchorBindInput, bind_repo_anchor_as,
    mint_agent_grant_as, mint_git_push_grant_as,
};
use oneiron::{EntityId, Vault};

const SHARED: u64 = 42;

/// A personal vault whose install carries the embedded owner's acts, and his proof.
struct Carrier {
    vault: Vault,
    owner: AuthenticatedOwner,
    _dir: tempfile::TempDir,
}

fn carrier() -> Carrier {
    let dir = tempfile::tempdir().expect("tempdir");
    let vault = open_owner_carrier_vault(dir.path()).expect("owner carrier vault");
    let owner = owner(&vault).expect("owner proof");
    Carrier {
        vault,
        owner,
        _dir: dir,
    }
}

/// The owner shares the vault, naming no other member.
fn share(carrier: &Carrier) {
    carrier
        .vault
        .initialize_shared_vault(&carrier.owner, SHARED, None, &[], 1)
        .expect("the owner shares a vault that holds his own mints");
}

/// The Grant row `id` as it is stored now.
fn row(vault: &Vault, id: EntityId) -> FederationGrant {
    let body = vault
        .get(&id)
        .expect("grant read")
        .expect("a live Grant row");
    decode_federation_grant_body(&body).expect("the Grant row decodes")
}

/// The fold's line of `id` holds a counted giving, and no counted act ended it.
fn assert_given_unended(vault: &Vault, id: EntityId, what: &str) {
    let line = grant_line(vault, id).expect("grant line read");
    assert!(
        matches!(line, Some((Some(_), false))),
        "{what} grant={id:?}; expected a counted giving no counted act ended; line={line:?}"
    );
}

/// The row `id`, which held `before` at the own-device residence, now holds the shared scope
/// and every other term unchanged, on the same unended counted giving.
fn assert_moved(vault: &Vault, id: EntityId, before: &FederationGrant, what: &str) {
    assert_eq!(
        before.scope,
        own_device_residence_scope(),
        "{what} grant={id:?}; expected a personal vault's mint row at the own-device residence"
    );
    let mut expected = before.clone();
    expected.scope = FederationGrantScope::vault(SHARED);
    assert_eq!(
        row(vault, id),
        expected,
        "{what} grant={id:?}; expected the same row at the shared scope, every other term unchanged"
    );
    assert_given_unended(vault, id, what);
}

#[test]
fn the_owners_agent_grant_stands_after_he_shares() {
    let carrier = carrier();
    let agent = carrier
        .vault
        .ensure_agent_principal("helper")
        .expect("a named agent principal");
    let mut scope = Scope::top();
    scope.verbs = ScopeAxis::Some(BTreeSet::from(["read".to_owned()]));
    let grant = mint_agent_grant_as(
        &carrier.vault,
        &carrier.owner,
        ActSurface::ThisInstall,
        AgentGrantMintRequest {
            agent,
            authority_scope: scope,
            expires_at: None,
            repo_bounds: None,
            verb_classes: BTreeSet::new(),
            wallet_ref: None,
            working_view_bounds: None,
        },
    )
    .expect("the owner mints the agent Grant")
    .grant
    .grant_ref;
    let before = row(&carrier.vault, grant);
    assert!(
        standing_agent_grant_ids(&carrier.vault)
            .expect("agent Grant list")
            .contains(&grant),
        "grant={grant:?}; expected the agent Grant to stand before sharing"
    );

    share(&carrier);

    assert_moved(&carrier.vault, grant, &before, "agent Grant");
    assert!(
        standing_agent_grant_ids(&carrier.vault)
            .expect("agent Grant list")
            .contains(&grant),
        "grant={grant:?}; expected the agent Grant to stand after sharing, under its own id"
    );

    // One residence: the old row put back at the own-device residence stands for nothing.
    put_unkeyed_member_grant(&carrier.vault, grant, &before).expect("the old row lands again");
    assert!(
        !standing_agent_grant_ids(&carrier.vault)
            .expect("agent Grant list")
            .contains(&grant),
        "grant={grant:?}; expected the row put back at the own-device residence to stand for \
         nothing on a shared vault"
    );
}

#[test]
fn the_owners_git_push_grant_stands_after_he_shares() {
    let carrier = carrier();
    carrier
        .vault
        .register_served_origin_as_owner(&carrier.owner, "demo", "main")
        .expect("register the served repo");
    let project = carrier.vault.root_project().expect("root project");
    let repo = bind_repo_anchor_as(
        &carrier.vault,
        &carrier.owner,
        RepoAnchorBindInput {
            repo: Some("demo".to_owned()),
            local_folder: None,
            project,
            anchor: None,
            editable: None,
        },
    )
    .expect("bind the repo's CODE anchor")
    .anchor;
    let holder = carrier
        .vault
        .ensure_agent_principal("pusher")
        .expect("a named agent principal");
    let grant = mint_git_push_grant_as(
        &carrier.vault,
        &carrier.owner,
        ActSurface::ThisInstall,
        GitPushGrantMintInput {
            member: holder,
            repos: BTreeSet::from([repo]),
            expires_at: None,
        },
    )
    .expect("the owner mints the holder's git push Grant")
    .grant
    .grant_ref;
    let before = row(&carrier.vault, grant);
    assert_eq!(
        standing_git_push_grant_ids(&carrier.vault).expect("git push Grant list"),
        vec![grant],
        "expected the git push Grant to stand before sharing"
    );

    share(&carrier);

    assert_moved(&carrier.vault, grant, &before, "git push Grant");
    assert_eq!(
        standing_git_push_grant_ids(&carrier.vault).expect("git push Grant list"),
        vec![grant],
        "expected the git push Grant to stand after sharing, under its own id"
    );
}

#[test]
fn the_owners_engine_controls_grant_stands_after_he_shares() {
    let carrier = carrier();
    let holder = EntityId::now();
    carrier
        .vault
        .put_entity(
            &holder,
            ENTITY_TYPE_PERSON,
            TimeRange { start: 1, end: 1 },
            1,
            b"human",
        )
        .expect("a live person");
    let class = EngineControlClass::WakeCadence;
    let grant = carrier
        .vault
        .grant_engine_controls(&carrier.owner, holder, &BTreeSet::from([class]))
        .expect("the owner's engine.controls Grant");
    let allowed = || {
        carrier
            .vault
            .engine_control_allowed(EngineControlActor::Holder(holder), class)
            .expect("engine control check")
    };
    assert!(
        allowed(),
        "expected the Grant to allow its class before sharing"
    );
    let before = row(&carrier.vault, grant);

    share(&carrier);

    assert_moved(&carrier.vault, grant, &before, "engine.controls Grant");
    assert!(
        allowed(),
        "grant={grant:?}; expected the engine.controls Grant to allow its class after sharing"
    );
}

#[test]
fn the_owners_steward_mint_stands_after_he_shares() {
    let carrier = carrier();
    let dreamer = dreamer(&carrier.vault).expect("the Dreamer");
    carrier
        .vault
        .provision_system_agent_grants()
        .expect("the engine's default Steward Grant");
    // A holder row that narrows the Dreamer's worlds, so the owner's grant back mints.
    write_steward_holder_row(&carrier.vault, dreamer, Some(&[EntityId::now()][..]), None)
        .expect("holder row");
    assert!(
        carrier
            .vault
            .grant_dreamer_weave(&carrier.owner, 1)
            .expect("the owner's grant back"),
        "expected the owner's grant back to mint a Steward Grant"
    );
    let mark = grant_mark(&carrier.vault, dreamer).expect("grant mark");
    let Some(GrantMark::Minted { grant, .. }) = mark.clone() else {
        panic!("expected the owner's Steward mint to stand; mark={mark:?}");
    };
    assert_given_unended(&carrier.vault, grant, "Steward mint before sharing");
    let before = row(&carrier.vault, grant);

    share(&carrier);

    assert_moved(&carrier.vault, grant, &before, "Steward mint");
    assert_eq!(
        grant_mark(&carrier.vault, dreamer).expect("grant mark"),
        mark,
        "grant={grant:?}; expected the Dreamer's reach to stand on the same row after sharing"
    );
}
