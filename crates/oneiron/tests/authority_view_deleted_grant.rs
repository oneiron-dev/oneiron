//! A deleted Grant must stop conferring on an already-cached authority view,
//! and the warm reads that judge it must not reload the authority history.
#![cfg(oneiron_test_support)]

use std::collections::BTreeSet;
use std::sync::Arc;

use oneiron::authority::{
    ActBy, ActSurface, AuthorityOp, EffectiveRead, HostSlipIssuer, MachineRole, ReadLocation,
    WorldPrivacy,
};
use oneiron::federation::{Scope, ScopeAxis, ScopeId};
use oneiron::policy_model::WorldPrivacyOutcome;
use oneiron::registry::ENTITY_TYPE_AUTHORITY_LOG;
use oneiron::store::GateDecisionId;
use oneiron::test_doors::authority_view_grant::{bind_agent, past_standing_history_loads};
use oneiron::verbs::{
    AgentDefinitionCreateRequest, AgentGrantMintRequest, create_agent_definition_as,
    mint_agent_grant_as,
};
use oneiron::{EntityId, Vault, VaultConfig};
use serde_json::json;

/// A vault whose agent tightened `world` under a Grant, read warm with the
/// tighten in effect, and then the Grant deleted by a plain delete: no
/// authority act, so the cached authority view stays at its generation.
fn warm_view_of_a_deleted_agent_grant() -> (tempfile::TempDir, Vault, EntityId) {
    let dir = tempfile::tempdir().expect("temporary vault directory");
    let vault = Vault::open(dir.path(), VaultConfig::device()).expect("fresh vault");
    let owner = vault.ensure_embedded_owner_actor().expect("embedded owner");
    let issuer =
        HostSlipIssuer::from_secret(b"authority-view-deleted-grant").expect("fixture host issuer");
    vault.ensure_host_root_slip(&issuer).expect("host root");
    vault.install_device_keystore(Arc::new(oneiron_keystore::MemoryKeystore::new()));
    vault
        .ensure_serving_install_profile(&issuer, MachineRole::Unanswered)
        .expect("live install profile to carry owner acts");
    let owner_proof = vault
        .authenticate_owner(owner, &owner.to_hex(), true, GateDecisionId::now())
        .expect("authenticated owner");
    let world = vault
        .create_world(&owner_proof, "Grant privacy world", vault.now_recorded_at())
        .expect("owner creates a world with default privacy");
    let agent = EntityId::now();
    create_agent_definition_as(
        &vault,
        &owner_proof,
        AgentDefinitionCreateRequest {
            agent_def_ref: agent,
            definition: serde_json::from_value(json!({
                "agent_id": "authority_view_deleted_grant_agent",
                "desc": "World privacy agent",
                "version": "1.0.0",
                "ceiling": "auto",
                "enabled": true,
            }))
            .expect("typed agent definition"),
        },
    )
    .expect("owner creates the agent");

    let mut scope = Scope::top();
    scope.worlds = ScopeAxis::Some(BTreeSet::from([ScopeId(world)]));
    scope.verbs = ScopeAxis::Some(BTreeSet::from([
        "read".to_owned(),
        "world_privacy_tighten".to_owned(),
    ]));
    let minted = mint_agent_grant_as(
        &vault,
        &owner_proof,
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
    .expect("owner mints the agent a world-privacy Grant");
    assert!(minted.grant.confers, "precondition: the Grant is live");
    let grant = minted.grant.grant_ref;

    // The fixture binder rebinds the host key, so owner setup precedes it.
    let writer = bind_agent(&vault, &issuer, agent).expect("active agent writer");
    let outcome = vault
        .agent_world_privacy(
            &writer,
            Vec::new(),
            world,
            WorldPrivacy {
                read: ReadLocation::MyMachines,
                ..WorldPrivacy::default()
            },
            None,
        )
        .expect("agent tightens the world under its Grant");
    assert!(
        matches!(outcome, WorldPrivacyOutcome::Applied(_)),
        "precondition: the agent's tighten applied, not a proposal or ask: {outcome:?}",
    );
    let edit = vault
        .entities_by_type(ENTITY_TYPE_AUTHORITY_LOG)
        .expect("authority entry ids")
        .into_iter()
        .find_map(|id| {
            let entry = vault
                .get_authority_log_entry(&id)
                .expect("read authority entry")
                .expect("listed authority entry exists");
            match entry.op {
                AuthorityOp::WorldPrivacy(edit) if edit.world == world => Some(edit),
                _ => None,
            }
        })
        .expect("the applied world-privacy act is stored");
    assert_eq!(
        edit.act.by,
        ActBy::Agent { agent, grant },
        "precondition: the agent's own act names this Grant",
    );

    assert_eq!(
        vault
            .world_privacy(world)
            .expect("warm world-privacy read")
            .read,
        EffectiveRead::MyMachines,
        "precondition: the warm authority view includes the agent's tighten",
    );
    let generation = vault
        .authority_log_head()
        .expect("warm authority generation");
    assert!(
        vault.delete_entity(&grant).expect("public Grant deletion"),
        "the live Grant was deleted",
    );
    assert_eq!(
        vault
            .authority_log_head()
            .expect("generation after deletion"),
        generation,
        "precondition: plain Grant deletion appends no authority act",
    );
    (dir, vault, world)
}

#[test]
fn deleting_an_agent_grant_invalidates_its_warm_authority_view() {
    let (_dir, vault, world) = warm_view_of_a_deleted_agent_grant();
    assert_eq!(
        vault
            .world_privacy(world)
            .expect("read after Grant deletion")
            .read,
        EffectiveRead::Everywhere,
        "a deleted Grant must hold back its agent's tighten even on a warm cache hit",
    );
}

#[test]
fn warm_reads_after_a_grant_deletion_load_the_authority_history_once() {
    let (_dir, vault, world) = warm_view_of_a_deleted_agent_grant();
    // The first read after the delete may be the one that loads it.
    let read = |what| vault.world_privacy(world).expect(what).read;
    assert_eq!(
        read("first read after Grant deletion"),
        EffectiveRead::Everywhere
    );
    let before = past_standing_history_loads();
    for _ in 0..10 {
        assert_eq!(
            read("warm read after Grant deletion"),
            EffectiveRead::Everywhere
        );
    }
    let loads = past_standing_history_loads() - before;
    assert!(
        loads <= 1,
        "ten warm reads of one authority generation loaded the stored authority history {loads} times",
    );
}
