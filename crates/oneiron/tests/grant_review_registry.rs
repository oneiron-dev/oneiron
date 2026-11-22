//! F4 (R2a, review #8846 P1-2): a live Grant row whose Grant a counted act withdrew
//! shows as revoked, not active, in `vault.consent.registry`.
//!
//! Expected: red at 71b1f3e800ed (R2a before the fix), where the live registry path
//! judges expiry (and the local marker) alone, so a lapsed row still shows active;
//! green at deefa8635921, where it reads the counted withdrawal too, and above
//! it, where the registry reads standing from the Grant's line (R3b).
//!
//! Run: `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron
//! --all-features --test grant_review_registry`.
#![cfg(all(oneiron_test_support, feature = "sync"))]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::collections::BTreeSet;
use std::sync::Arc;

use oneiron::authority::{ActSurface, HostSlipIssuer, MachineRole};
use oneiron::consent::{
    AuthenticatedOwner, ConsentGrantStatus, ConsentRegistryQuery, ConsentRegistryRow,
};
use oneiron::federation::{Scope, ScopeAxis};
use oneiron::store::GateDecisionId;
use oneiron::test_doors::grant_act::end_agent_grant_by_rule;
use oneiron::test_doors::grant_standing::{grant_line, grant_row, standing_grant_act};
use oneiron::verbs::{
    AgentDefinitionCreateRequest, AgentGrantMintRequest, create_agent_definition_as,
    mint_agent_grant_as,
};
use oneiron::{EntityId, Vault, VaultConfig};
use serde_json::json;

/// A vault whose owner minted his agent a Grant.
struct Minted {
    _dir: tempfile::TempDir,
    vault: Vault,
    owner: AuthenticatedOwner,
    grant: EntityId,
    act: String,
    confers: bool,
}

/// The owner mints his agent a read Grant.
fn minted_read_grant() -> Minted {
    let mut scope = Scope::top();
    scope.verbs = ScopeAxis::Some(BTreeSet::from(["read".to_owned()]));
    let minted = minted_grant(scope, BTreeSet::new());
    assert!(minted.confers, "precondition: the Grant is live");
    minted
}

/// The owner mints his agent a Grant of `scope` and `verb_classes`.
fn minted_grant(scope: Scope, verb_classes: BTreeSet<String>) -> Minted {
    let dir = tempfile::tempdir().expect("temporary vault directory");
    let vault = Vault::open(dir.path(), VaultConfig::device()).expect("fresh vault");
    let owner_actor = vault.ensure_embedded_owner_actor().expect("embedded owner");
    let issuer = HostSlipIssuer::from_secret(b"grant-review-registry").expect("fixture issuer");
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
                "agent_id": "grant_review_registry_agent",
                "desc": "Registry review agent",
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
            verb_classes,
            wallet_ref: None,
            working_view_bounds: None,
        },
    )
    .expect("owner mints the agent a Grant");
    Minted {
        _dir: dir,
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

/// The consent registry rows for `grant`.
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
fn a_lapsed_agent_grant_shows_revoked_in_the_registry() {
    let minted = minted_read_grant();
    let before = registry_for(&minted.vault, minted.grant, false);
    assert!(
        before.len() == 1 && before[0].status == ConsentGrantStatus::Active,
        "precondition: the registry lists the minted Grant as active; \
         seen rows={before:?}",
    );
    end_agent_grant_by_rule(&minted.vault, minted.grant).expect("the lapse's end lands");
    assert!(
        grant_row(&minted.vault, minted.grant)
            .expect("grant row read")
            .is_some(),
        "precondition: the lapsed row is still live",
    );
    let now = minted.vault.now_recorded_at();
    assert_eq!(
        grant_line(&minted.vault, minted.grant)
            .expect("grant line")
            .map(|(act, ended)| (act.map(hex), ended)),
        Some((Some(minted.act.clone()), true)),
        "precondition: the lapse's counted end ends the Grant's line",
    );
    assert_eq!(
        standing_grant_act(&minted.vault, minted.grant, now).expect("standing read"),
        None,
        "precondition: a lapsed Grant stands for nothing",
    );
    let standing = registry_for(&minted.vault, minted.grant, false);
    assert!(
        standing.is_empty(),
        "grant={:?}; expected the standing registry to list no lapsed Grant; \
         seen rows={standing:?}",
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
        "grant={:?}; expected the review to show the lapsed row once, revoked and \
         conferring nothing; seen rows={reviewed:?}",
        minted.grant,
    );
}
