//! The owner's agent Grant that names an act an agent's Grant may carry also
//! lists `read` (Engine ANSWER AGENT-GRANTABLE-ACT-GRANT-NEEDS-READ-VERB = A,
//! 20 Nov 20:32). The act judge asks the Grant to confer, which needs `read`,
//! so a Grant that names only the act's verb would look live and never carry
//! its act. The mint refuses it and says so; the same Grant with `read`
//! mints as before, and so does a Grant that names no act's verb.
#![cfg(oneiron_test_support)]

use std::collections::BTreeSet;
use std::sync::Arc;

use oneiron::authority::{ActSurface, MachineRole};
use oneiron::consent::AuthenticatedOwner;
use oneiron::federation::{Scope, ScopeAxis};
use oneiron::test_doors::label_writers::embedded_owner;
use oneiron::verbs::{AgentGrantMintRequest, mint_agent_grant_as};
use oneiron::{EntityId, Vault, VaultConfig};

/// The verb an agent's Grant lists to name each act it may carry: a
/// topology seal, a world privacy tighten, a free-time policy set, a model
/// binding proposal, a runner continue and a hook transcript import.
const ACT_VERBS: [&str; 6] = [
    "topology_seal",
    "world_privacy_tighten",
    "free_time_policy_set",
    "vault.models.bindings.propose",
    "vault.runners.continue",
    "vault.imports.hook_transcript",
];

/// The mint's refusal of an act Grant without `read`, in the Engine's words.
const NO_READ_REFUSAL: &str = "an act Grant also lists read";

struct Fixture {
    vault: Vault,
    _dir: tempfile::TempDir,
    owner_proof: AuthenticatedOwner,
    agent: EntityId,
}

fn fixture() -> Fixture {
    let dir = tempfile::tempdir().expect("temporary vault directory");
    let vault = Vault::open(dir.path(), VaultConfig::device()).expect("fresh vault");
    vault.install_device_keystore(Arc::new(oneiron_keystore::MemoryKeystore::default()));
    let issuer = oneiron::test_support::provision_engine_machines(&vault);
    // The owner's agent Grant act is carried by this install's live machine
    // profile, as a serving start or `init` enrols it (FIX 4648).
    vault
        .ensure_serving_install_profile(&issuer, MachineRole::Unanswered)
        .expect("this install's live machine profile");
    let (_, owner_proof) = embedded_owner(&vault).expect("authenticated embedded owner");
    let agent = vault
        .ensure_agent_principal("act-grant-lists-read-agent")
        .expect("a named agent");
    Fixture {
        vault,
        _dir: dir,
        owner_proof,
        agent,
    }
}

/// The owner's Grant mint for the fixture's agent, listing exactly `verbs`.
fn mint(fixture: &Fixture, verbs: &[&str]) -> oneiron::memory::MemoryResult<()> {
    let mut authority_scope = Scope::top();
    authority_scope.verbs = ScopeAxis::Some(verbs.iter().map(|verb| (*verb).to_owned()).collect());
    mint_agent_grant_as(
        &fixture.vault,
        &fixture.owner_proof,
        ActSurface::ThisInstall,
        AgentGrantMintRequest {
            agent: fixture.agent,
            authority_scope,
            expires_at: None,
            repo_bounds: None,
            verb_classes: BTreeSet::new(),
            wallet_ref: None,
            working_view_bounds: None,
        },
    )
    .map(|_| ())
}

#[test]
fn an_act_grant_without_read_is_refused_at_the_mint() {
    let fixture = fixture();
    for verb in ACT_VERBS {
        let refused = mint(&fixture, &[verb])
            .expect_err("the owner's Grant naming only an act's verb is refused");
        assert!(
            refused.message.contains(NO_READ_REFUSAL),
            "verbs=[{verb}]: the refusal says the Grant also lists read: {refused}"
        );
        let refused = mint(&fixture, &["propose", verb]).expect_err(
            "the owner's Grant naming an act's verb beside another verb, no read, is refused",
        );
        assert!(
            refused.message.contains(NO_READ_REFUSAL),
            "verbs=[propose, {verb}]: the refusal says the Grant also lists read: {refused}"
        );
        mint(&fixture, &["read", verb]).unwrap_or_else(|error| {
            panic!("verbs=[read, {verb}]: the owner mints an act Grant that lists read: {error}")
        });
    }
}

#[test]
fn a_grant_naming_no_act_verb_mints_without_read() {
    let fixture = fixture();
    mint(&fixture, &["propose"])
        .expect("the owner mints a Grant that names no act's verb, with no read, as before");
}
