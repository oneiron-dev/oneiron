//! ROLES-CHECKIN P2.5, row 2k7c (ARCH-0082 #act-table "Widen another's
//! grant" and #owner-own-acts; Engine ruling P25-SHAPE Q1 = A, 14 Nov
//! 13:39): `vault.engine.controls.grant` and `vault.repo.git_push.mint`,
//! Owner-proof doors, take the 2j apply shape.
//!
//! - The Owner's grant and mint are never gated: each goes on their own
//!   proof, and the answer records that decision.
//! - The Owner applies another asker's approved check-in for that exact
//!   grant or mint on their own proof: the act's writer spends it, and the
//!   answer names it and its asker. An approval for another grant or mint
//!   changes nothing and stays unspent.
//!
//! On 2k7b's head this file does not build: the doors' inputs have no
//! `check_in_ref`, and their answers no `check_in`.
//!
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron
//! --all-features --test check_in_engine_controls_git_push_effects`.
#![cfg(oneiron_test_support)]
#![allow(clippy::unwrap_used, clippy::expect_used)]

#[path = "check_in/owner_apply_fixture.rs"]
mod owner_apply_fixture;

use std::collections::BTreeSet;

use oneiron::authority::ActSurface;
use oneiron::check_in::ActClass;
use oneiron::consent::{AuthenticatedOwner, ConsentRegistryQuery};
use oneiron::federation::{EngineControlClass, GitPushRepo};
use oneiron::memory::MemoryResult;
use oneiron::memory::origin_doors::OriginRegisterRequest;
use oneiron::registry::ENTITY_TYPE_PERSON;
use oneiron::temporal::TimeRange;
use oneiron::test_doors::steward::steward_grant_rows;
use oneiron::verbs::{
    EngineControlsGrantRequest, EngineControlsGranted, GitPushGrantMintInput,
    GitPushGrantMintOutput, RepoAnchorBindInput, bind_repo_anchor_as,
    engine_controls_grant_effect_digest, git_push_grant_mint_effect_digest,
    grant_engine_controls_as, mint_git_push_grant_as,
};
use oneiron::{EdgeActorClass, EntityId, Vault};
use owner_apply_fixture::{approved, owner_decision, rooted, spent};

const ENGINE_GRANT_VERB: &str = "vault.engine.controls.grant";
const GIT_PUSH_MINT_VERB: &str = "vault.repo.git_push.mint";
const GIT_PUSH_REVOKE_VERB: &str = "vault.repo.git_push.revoke";

/// A live person who never joined the vault: the holder of each grant.
fn holder(vault: &Vault) -> EntityId {
    let holder = EntityId::now();
    vault
        .put_entity(
            &holder,
            ENTITY_TYPE_PERSON,
            TimeRange { start: 1, end: 1 },
            1,
            b"human",
        )
        .expect("a live person");
    holder
}

fn engine_request(agent: EntityId, classes: &[EngineControlClass]) -> EngineControlsGrantRequest {
    EngineControlsGrantRequest {
        agent,
        classes: classes.iter().copied().collect(),
        check_in_ref: None,
    }
}

fn grant_engine(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    request: EngineControlsGrantRequest,
    check_in_ref: Option<EntityId>,
) -> MemoryResult<EngineControlsGranted> {
    grant_engine_controls_as(
        vault,
        owner,
        EngineControlsGrantRequest {
            check_in_ref: check_in_ref.map(|id| id.to_hex()),
            ..request
        },
    )
}

/// How many Steward grants name `agent`, from the stored rows.
fn engine_grants_naming(vault: &Vault, agent: EntityId) -> usize {
    steward_grant_rows(vault, agent)
        .expect("the stored Steward grant rows")
        .len()
}

/// A served repo the Owner registers and binds as a CODE anchor of the
/// vault's root PROJECT.
fn served_repo(vault: &Vault, owner: EntityId, owner_proof: &AuthenticatedOwner) -> GitPushRepo {
    vault
        .memory(owner, EdgeActorClass::Human)
        .origin_register_as(
            owner_proof,
            OriginRegisterRequest {
                repo: "demo".to_owned(),
                default_branch: "main".to_owned(),
            },
        )
        .expect("the owner registers a served repo");
    let project = vault.root_project().expect("the vault's root PROJECT");
    bind_repo_anchor_as(
        vault,
        owner_proof,
        RepoAnchorBindInput {
            repo: Some("demo".to_owned()),
            local_folder: None,
            project,
            anchor: None,
            editable: None,
        },
    )
    .expect("the owner binds the served repo")
    .anchor
}

fn git_push_request(
    member: EntityId,
    repo: GitPushRepo,
    expires_at: Option<u64>,
) -> GitPushGrantMintInput {
    GitPushGrantMintInput {
        member,
        repos: BTreeSet::from([repo]),
        expires_at,
        check_in_ref: None,
    }
}

fn mint_git_push(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    request: GitPushGrantMintInput,
    check_in_ref: Option<EntityId>,
) -> MemoryResult<GitPushGrantMintOutput> {
    mint_git_push_grant_as(
        vault,
        owner,
        ActSurface::ThisInstall,
        GitPushGrantMintInput {
            check_in_ref: check_in_ref.map(|id| id.to_hex()),
            ..request
        },
    )
}

/// How many git_push grants the Owner's consent registry lists, each with
/// its own one-tap revoke.
fn git_push_grants(vault: &Vault) -> usize {
    vault
        .consent_registry(ConsentRegistryQuery::new(1_000, false))
        .expect("the owner's consent registry")
        .rows
        .iter()
        .filter(|row| row.revoke_action.command == GIT_PUSH_REVOKE_VERB)
        .count()
}

#[test]
fn the_owners_engine_controls_grant_records_their_own_proof() {
    let (_dir, vault, _owner, owner_proof) = rooted();
    let holder = holder(&vault);

    let granted = grant_engine(
        &vault,
        &owner_proof,
        engine_request(holder, &[EngineControlClass::WakeCadence]),
        None,
    )
    .expect("the Owner's own grant goes");
    assert_eq!(
        granted.check_in,
        Some(owner_decision(ActClass::GrantWiden, None, None)),
        "the answer records the Owner's own proof"
    );
    assert_eq!(engine_grants_naming(&vault, holder), 1);
}

#[test]
fn the_owner_applies_an_approved_engine_controls_grant_for_its_exact_classes_only() {
    let (_dir, vault, owner, owner_proof) = rooted();
    let holder = holder(&vault);
    let asked = engine_request(holder, &[EngineControlClass::WorkBudget]);
    let digest = engine_controls_grant_effect_digest(&asked).expect("the grant's digest");
    let (ask, asker) = approved(
        &vault,
        owner,
        &owner_proof,
        ENGINE_GRANT_VERB,
        ActClass::GrantWiden,
        &digest,
    );

    // An approval for one class never carries a wider grant.
    let wider = engine_request(
        holder,
        &[
            EngineControlClass::WorkBudget,
            EngineControlClass::WakeCadence,
        ],
    );
    assert!(
        grant_engine(&vault, &owner_proof, wider, Some(ask)).is_err(),
        "the approval covers its own classes only"
    );
    assert_eq!(engine_grants_naming(&vault, holder), 0, "no grant stands");
    assert!(!spent(&vault, &ask), "the ask stays unspent");

    let granted = grant_engine(&vault, &owner_proof, asked, Some(ask))
        .expect("the Owner applies the approved grant");
    assert_eq!(
        granted.check_in,
        Some(owner_decision(ActClass::GrantWiden, Some(ask), Some(asker))),
        "the answer names the applied ask and its asker"
    );
    assert_eq!(engine_grants_naming(&vault, holder), 1);
    assert!(spent(&vault, &ask), "the grant spent the ask");
}

#[test]
fn the_owners_git_push_mint_records_their_own_proof() {
    let (_dir, vault, owner, owner_proof) = rooted();
    let repo = served_repo(&vault, owner, &owner_proof);
    let holder = holder(&vault);

    let minted = mint_git_push(
        &vault,
        &owner_proof,
        git_push_request(holder, repo, None),
        None,
    )
    .expect("the Owner's own mint goes");
    assert_eq!(
        minted.check_in,
        Some(owner_decision(ActClass::GrantWiden, None, None)),
        "the answer records the Owner's own proof"
    );
    assert_eq!(minted.grant.member, holder);
    assert_eq!(git_push_grants(&vault), 1);
}

#[test]
fn the_owner_applies_an_approved_git_push_mint_for_its_exact_bounds_only() {
    let (_dir, vault, owner, owner_proof) = rooted();
    let repo = served_repo(&vault, owner, &owner_proof);
    let holder = holder(&vault);
    // An expiry a day past this run's clock.
    let expires_at = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("the clock is past the epoch")
        .as_secs()
        + 86_400;
    let asked = git_push_request(holder, repo, Some(expires_at));
    let digest = git_push_grant_mint_effect_digest(&asked).expect("the mint's digest");
    let (ask, asker) = approved(
        &vault,
        owner,
        &owner_proof,
        GIT_PUSH_MINT_VERB,
        ActClass::GrantWiden,
        &digest,
    );

    // An approval for a grant that expires never carries one that stands
    // until revoked.
    let standing = git_push_request(holder, repo, None);
    assert!(
        mint_git_push(&vault, &owner_proof, standing, Some(ask)).is_err(),
        "the approval covers its own expiry only"
    );
    assert_eq!(git_push_grants(&vault), 0, "no grant stands");
    assert!(!spent(&vault, &ask), "the ask stays unspent");

    let minted = mint_git_push(&vault, &owner_proof, asked, Some(ask))
        .expect("the Owner applies the approved mint");
    assert_eq!(
        minted.check_in,
        Some(owner_decision(ActClass::GrantWiden, Some(ask), Some(asker))),
        "the answer names the applied ask and its asker"
    );
    assert_eq!(minted.grant.expires_at, Some(expires_at));
    assert_eq!(git_push_grants(&vault), 1);
    assert!(spent(&vault, &ask), "the mint spent the ask");
}
