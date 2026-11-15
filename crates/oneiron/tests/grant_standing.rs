//! A Grant row gives nothing by itself (Fable pass 28 R1): it stands only on the one counted
//! act that gives it, exactly as that act states it, while no counted act ended it. The
//! owner's agent Grant mint gives; his revoke ends. A copy of the row at another id, or the
//! row widened in place on the own-device lane, stands for nothing.
#![cfg(all(oneiron_test_support, feature = "sync"))]

use std::collections::BTreeSet;
use std::sync::Arc;

use oneiron::authority::{ActSurface, HostSlipIssuer, MachineRole};
use oneiron::consent::AuthenticatedOwner;
use oneiron::federation::{
    Scope, ScopeAxis, decode_federation_grant_body, encode_federation_grant_body,
};
use oneiron::registry::ENTITY_TYPE_FEDERATION_GRANT;
use oneiron::store::GateDecisionId;
use oneiron::sync::client::ImportTier;
use oneiron::sync::replay::{ReplicatedEntity, replay_entity};
use oneiron::test_doors::grant_standing::{grant_line, grant_row, standing_grant_act};
use oneiron::verbs::{
    AgentDefinitionCreateRequest, AgentGrantMintRequest, AgentGrantRevokeRequest,
    create_agent_definition_as, mint_agent_grant_as, revoke_agent_grant_as,
};
use oneiron::{EntityId, TimeRange, Vault, VaultConfig};
use serde_json::json;

/// A vault whose owner minted his agent a read Grant: the vault, his proof, the Grant's id
/// and the mint's act, as 64 lower-case hex.
struct Minted {
    _dir: tempfile::TempDir,
    vault: Vault,
    owner: AuthenticatedOwner,
    grant: EntityId,
    act: String,
}

fn minted_read_grant() -> Minted {
    let dir = tempfile::tempdir().expect("temporary vault directory");
    let vault = Vault::open(dir.path(), VaultConfig::device()).expect("fresh vault");
    let owner_actor = vault.ensure_embedded_owner_actor().expect("embedded owner");
    let issuer = HostSlipIssuer::from_secret(b"grant-standing-r1").expect("fixture host issuer");
    vault.ensure_host_root_slip(&issuer).expect("host root");
    vault.install_device_keystore(Arc::new(oneiron_keystore::MemoryKeystore::new()));
    vault
        .ensure_serving_install_profile(&issuer, MachineRole::Unanswered)
        .expect("live install profile to carry owner acts");
    let owner = vault
        .authenticate_owner(
            owner_actor,
            &owner_actor.to_hex(),
            true,
            GateDecisionId::now(),
        )
        .expect("authenticated owner");
    let agent = EntityId::now();
    create_agent_definition_as(
        &vault,
        &owner,
        AgentDefinitionCreateRequest {
            agent_def_ref: agent,
            definition: serde_json::from_value(json!({
                "agent_id": "grant_standing_agent",
                "desc": "Grant standing agent",
                "version": "1.0.0",
                "ceiling": "auto",
                "enabled": true,
            }))
            .expect("typed agent definition"),
        },
    )
    .expect("owner creates the agent");
    let mut scope = Scope::top();
    scope.verbs = ScopeAxis::Some(BTreeSet::from(["read".to_owned()]));
    let minted = mint_agent_grant_as(
        &vault,
        &owner,
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
    .expect("owner mints the agent a read Grant");
    assert!(minted.grant.confers, "precondition: the Grant is live");
    Minted {
        _dir: dir,
        grant: minted.grant.grant_ref,
        act: minted.act_ref,
        vault,
        owner,
    }
}

fn hex(bytes: [u8; 32]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// Puts `body` at `id` as another of the owner's devices would send it: own-device replay,
/// which judges no standing.
fn put_from_own_device(vault: &Vault, id: EntityId, body: &[u8]) {
    let now = vault.now_recorded_at();
    replay_entity(
        vault,
        ReplicatedEntity {
            id,
            entity_type: ENTITY_TYPE_FEDERATION_GRANT,
            occurred: TimeRange {
                start: now,
                end: now,
            },
            learned_at: now,
            row_version: 0,
            body,
        },
        ImportTier::OwnDevice,
    )
    .expect("own-device replay lands the row");
}

#[test]
fn an_owner_mint_gives_its_grant_and_the_row_stands_on_it() {
    let minted = minted_read_grant();
    let now = minted.vault.now_recorded_at();
    let line = grant_line(&minted.vault, minted.grant)
        .expect("grant line")
        .expect("the counted mint names the Grant");
    assert_eq!(
        (line.0.map(hex), line.1),
        (Some(minted.act.clone()), false),
        "the line gives the Grant by the owner's mint and nothing ended it",
    );
    let standing = standing_grant_act(&minted.vault, minted.grant, now).expect("standing read");
    assert_eq!(
        standing.map(hex),
        Some(minted.act),
        "the minted row stands on the owner's mint",
    );
}

#[test]
fn a_copy_of_a_grant_row_at_another_id_stands_for_nothing() {
    let minted = minted_read_grant();
    let body = grant_row(&minted.vault, minted.grant)
        .expect("grant row read")
        .expect("the minted row is live");
    let copy = EntityId::now();
    put_from_own_device(&minted.vault, copy, &body);
    assert_eq!(
        grant_row(&minted.vault, copy).expect("copy read"),
        Some(body),
        "precondition: the copied row is live at its new id",
    );
    let now = minted.vault.now_recorded_at();
    assert_eq!(
        grant_line(&minted.vault, copy).expect("grant line"),
        None,
        "no counted act names the copy",
    );
    assert_eq!(
        standing_grant_act(&minted.vault, copy, now).expect("standing read"),
        None,
        "a row no counted act gives stands for nothing",
    );
}

#[test]
fn a_grant_row_widened_in_place_stands_for_nothing() {
    let minted = minted_read_grant();
    let body = grant_row(&minted.vault, minted.grant)
        .expect("grant row read")
        .expect("the minted row is live");
    let mut widened = decode_federation_grant_body(&body).expect("minted row decodes");
    widened.authority_scope.verbs =
        ScopeAxis::Some(BTreeSet::from(["read".to_owned(), "write".to_owned()]));
    let widened = encode_federation_grant_body(&widened).expect("widened row encodes");
    put_from_own_device(&minted.vault, minted.grant, &widened);
    assert_eq!(
        grant_row(&minted.vault, minted.grant).expect("row read"),
        Some(widened),
        "precondition: the widened row replaced the minted one",
    );
    let now = minted.vault.now_recorded_at();
    assert_eq!(
        grant_line(&minted.vault, minted.grant)
            .expect("grant line")
            .map(|(act, ended)| (act.map(hex), ended)),
        Some((Some(minted.act), false)),
        "the line still gives the Grant on the owner's mint, as he stated it",
    );
    assert_eq!(
        standing_grant_act(&minted.vault, minted.grant, now).expect("standing read"),
        None,
        "a row whose terms are not its act's stands for nothing",
    );
}

#[test]
fn the_owner_revoke_ends_the_grant() {
    let minted = minted_read_grant();
    let revoked = revoke_agent_grant_as(
        &minted.vault,
        &minted.owner,
        ActSurface::ThisInstall,
        AgentGrantRevokeRequest {
            grant_ref: minted.grant,
            seen: None,
        },
    )
    .expect("owner revokes the Grant");
    assert!(revoked.changed, "precondition: the revoke landed an act");
    let now = minted.vault.now_recorded_at();
    assert_eq!(
        grant_line(&minted.vault, minted.grant)
            .expect("grant line")
            .map(|(_, ended)| ended),
        Some(true),
        "the owner's counted revoke ends the Grant's line",
    );
    assert_eq!(
        standing_grant_act(&minted.vault, minted.grant, now).expect("standing read"),
        None,
        "an ended Grant stands for nothing",
    );
}
