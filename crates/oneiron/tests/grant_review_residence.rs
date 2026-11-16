//! F5 (R3b, review #8852 P1-1): an owner's agent Grant row rewritten only in its
//! residence scope to another vault's `Vault` stands for nothing.
//!
//! Expected: red at 7530df714585 (and 9c2869976776), where the mint match takes
//! the residence from the row, so the rewritten row still lists and confers;
//! green at 1a55fe798df8 (and 62a0b0981c43), where the reader holds the row to
//! this vault's residence.
//!
//! Run: `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron
//! --all-features --test grant_review_residence`.
#![cfg(all(oneiron_test_support, feature = "sync"))]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::collections::BTreeSet;
use std::sync::Arc;

use oneiron::authority::{ActSurface, HostSlipIssuer, MachineRole};
use oneiron::consent::{
    AuthenticatedOwner, ConsentGrantStatus, ConsentRegistryQuery, ConsentRegistryRow,
};
use oneiron::federation::{
    FederationGrantScope, Scope, ScopeAxis, decode_federation_grant_body,
    encode_federation_grant_body, own_device_residence_scope,
};
use oneiron::registry::ENTITY_TYPE_FEDERATION_GRANT;
use oneiron::store::GateDecisionId;
use oneiron::sync::client::ImportTier;
use oneiron::sync::replay::{ReplicatedEntity, replay_entity};
use oneiron::test_doors::grant_standing::{grant_line, grant_row};
use oneiron::verbs::{
    AgentDefinitionCreateRequest, AgentGrantMintRequest, create_agent_definition_as,
    mint_agent_grant_as,
};
use oneiron::{EntityId, TimeRange, Vault, VaultConfig};
use serde_json::json;

/// A vault whose owner minted his agent an `ai.text` Grant.
struct Minted {
    _dir: tempfile::TempDir,
    vault: Vault,
    owner: AuthenticatedOwner,
    agent: EntityId,
    grant: EntityId,
    act: String,
    confers: bool,
}

/// The owner mints his agent a Grant naming `read` and `ai.text`.
fn minted_ai_grant() -> Minted {
    let mut scope = Scope::top();
    scope.verbs = ScopeAxis::Some(BTreeSet::from(["read".to_owned(), "ai.text".to_owned()]));
    let dir = tempfile::tempdir().expect("temporary vault directory");
    let vault = Vault::open(dir.path(), VaultConfig::device()).expect("fresh vault");
    let owner_actor = vault.ensure_embedded_owner_actor().expect("embedded owner");
    let issuer =
        HostSlipIssuer::from_secret(b"grant-review-residence").expect("fixture host issuer");
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
                "agent_id": "grant_review_residence_agent",
                "desc": "Residence review agent",
                "version": "1.0.0",
                "ceiling": "auto",
                "enabled": true,
            }))
            .expect("typed agent definition"),
        },
    )
    .expect("owner creates the agent");
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
    .expect("owner mints the agent a Grant");
    Minted {
        _dir: dir,
        agent,
        grant: minted.grant.grant_ref,
        act: minted.act_ref,
        confers: minted.grant.confers,
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

/// The consent registry rows for `grant`, newest first.
fn registry_for(vault: &Vault, grant: EntityId, include_revoked: bool) -> Vec<ConsentRegistryRow> {
    let want = grant.to_hex();
    vault
        .consent_registry(ConsentRegistryQuery::new(1_000, include_revoked))
        .expect("the owner's consent registry")
        .rows
        .into_iter()
        .filter(|row| row.grant_ref == want)
        .collect()
}

#[test]
fn an_agent_grant_rewritten_to_another_residence_stands_for_nothing() {
    let minted = minted_ai_grant();
    assert!(minted.confers, "precondition: the minted Grant confers");
    assert_eq!(
        minted
            .vault
            .agent_ai_operations(minted.agent)
            .expect("ai operations"),
        BTreeSet::from(["text".to_owned()]),
        "precondition: the minted Grant names ai.text",
    );
    let before = registry_for(&minted.vault, minted.grant, false);
    assert!(
        before.len() == 1 && before[0].status == ConsentGrantStatus::Active,
        "precondition: the registry lists the minted Grant as active; \
         seen rows={before:?}",
    );
    let body = grant_row(&minted.vault, minted.grant)
        .expect("grant row read")
        .expect("the minted row is live");
    let decoded = decode_federation_grant_body(&body).expect("minted row decodes");
    assert_eq!(
        decoded.scope,
        own_device_residence_scope(),
        "precondition: a personal vault's agent Grant holds its residence",
    );
    let mut rewritten = decoded;
    rewritten.scope = FederationGrantScope::vault(8);
    assert_ne!(
        rewritten.scope,
        own_device_residence_scope(),
        "precondition: the rewritten scope is another vault's residence",
    );
    let widened = encode_federation_grant_body(&rewritten).expect("rewritten row encodes");
    put_from_own_device(&minted.vault, minted.grant, &widened);
    assert_eq!(
        grant_row(&minted.vault, minted.grant).expect("row read"),
        Some(widened),
        "precondition: the rewritten row replaced the minted one",
    );
    assert_eq!(
        grant_line(&minted.vault, minted.grant)
            .expect("grant line")
            .map(|(act, ended)| (act.map(hex), ended)),
        Some((Some(minted.act), false)),
        "the line still gives the Grant on the owner's mint, as he stated it",
    );
    let operations = minted
        .vault
        .agent_ai_operations(minted.agent)
        .expect("ai operations");
    assert!(
        operations.is_empty(),
        "grant={:?}; expected a row over another residence to name no ai operation; \
         seen operations={operations:?}",
        minted.grant,
    );
    let standing = registry_for(&minted.vault, minted.grant, false);
    assert!(
        standing.is_empty(),
        "grant={:?}; expected the standing registry to list no Grant over another \
         residence; seen rows={standing:?}",
        minted.grant,
    );
    let reviewed = registry_for(&minted.vault, minted.grant, true);
    assert!(
        reviewed.len() == 1
            && reviewed[0].status == ConsentGrantStatus::Revoked
            && reviewed[0]
                .agent_grant
                .as_ref()
                .is_some_and(|grant| !grant.confers),
        "grant={:?}; expected the review to show the rewritten row once, revoked and \
         conferring nothing; seen rows={reviewed:?}",
        minted.grant,
    );
}
