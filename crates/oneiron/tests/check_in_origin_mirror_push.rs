//! ROLES-CHECKIN P2.5, row 2k9b (ARCH-0082 #act-table "Outbound send (C)"
//! and #owner-own-acts; Engine ruling P25-SHAPE Q1 = A, 14 Nov 13:39):
//! `vault.code.origin.mirror.push` checks in, in the 2j apply shape.
//!
//! - The Owner's own push goes on their own proof and answers an `own_proof`
//!   decision (`outbound_send`); the run the mirror target keeps carries no
//!   decision, so the target row names no asker.
//! - With `check_in_ref` the Owner applies an asker's approved check-in for
//!   this repository's push on their own proof: the digest binds the served
//!   repository name, the ask is spent in a writer of its own before anything
//!   leaves, and the answer names the check-in and its asker as requester.
//! - A refusal before the spend (an `ask_me` mirror, a check-in that does not
//!   apply) leaves the ask unspent and records no run.
//!
//! The mirror points at an https URL nothing answers, so each attempted push
//! comes back as a FAILED run (`failure: Some`), which still answers the
//! decision. The ask is opened here through the check-in test doors on a chain
//! whose Owner rung is the vault owner, as in `check_in_erase_effects`.
//!
//! On the base (d65cd04ddf51) this file does not build: the push request has
//! no `check_in_ref`, its answer no `check_in`, and the push effect digest
//! does not exist.
//!
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron
//! --all-features --test check_in_origin_mirror_push`.
#![cfg(oneiron_test_support)]
#![allow(clippy::unwrap_used, clippy::expect_used)]

#[path = "check_in/owner_apply_fixture.rs"]
mod owner_apply_fixture;

use std::path::Path;

use oneiron::check_in::{
    ActClass, CheckInMode, CheckInScope, HolderKind, OpenPendingCheckIn, Rung, RungHolder,
    RungMembers, WaitReason, origin_mirror_push_effect_digest,
};
use oneiron::consent::AuthenticatedOwner;
use oneiron::git_wire::{GitOid, GitRefName, GitWire};
use oneiron::memory::MEMORY_CODE_INVALID_STATE;
use oneiron::memory::MemoryResult;
use oneiron::memory::origin_doors::{
    OriginMirrorPushRequest, OriginMirrorSetRequest, OriginMirrorStrategyRequest,
    OriginRegisterRequest, OriginRepoRequest,
};
use oneiron::origin::lfs::lfs_repo_id;
use oneiron::origin::mirror::{ORIGIN_MIRROR_PUSH_EFFECTOR, OriginMirrorRun};
use oneiron::origin::mirror_strategy::OriginMirrorSyncStrategy;
use oneiron::origin::publication::{OriginPublicationRequest, OriginPublicationStatus};
use oneiron::origin::smart_http::origin_repo_dir;
use oneiron::secret_custody::{
    CustodyClass, CustodyTier, OwnerSecretRegistration, RequestedBinding,
};
use oneiron::test_doors::check_in::{FixedChain, open};
use oneiron::{EdgeActorClass, EntityId, RepoRef, TimeRange, Vault};
use owner_apply_fixture::{approved, owner_decision, rooted, spent};

const MIRROR_PUSH: &str = "vault.code.origin.mirror.push";
const REPO: &str = "notes";
const OTHER_REPO: &str = "yuki";
const MIRROR_URL: &str = "https://127.0.0.1:9/owen/notes.git";
const SECRET_NAME: &str = "owen-mirror-token";

fn git(cwd: &Path, args: &[&str]) -> String {
    let output = std::process::Command::new("git")
        .current_dir(cwd)
        .env("GIT_TERMINAL_PROMPT", "0")
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_AUTHOR_NAME", "Owen")
        .env("GIT_AUTHOR_EMAIL", "owen@example.invalid")
        .env("GIT_COMMITTER_NAME", "Owen")
        .env("GIT_COMMITTER_EMAIL", "owen@example.invalid")
        .args(args)
        .output()
        .expect("run git");
    assert!(
        output.status.success(),
        "git {args:?} failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8_lossy(&output.stdout).trim().to_owned()
}

/// Publishes `refs/heads/main` at one commit, as a landed push would: the
/// objects go into the served bare repository, its raw ref is deleted (a raw
/// ref is not publication authority; the journal is), then the advance is
/// published through the protocol.
fn publish_main(vault: &Vault, repo: &str) {
    let source = tempfile::tempdir().expect("source tempdir");
    git(source.path(), &["init", "--initial-branch=main"]);
    std::fs::write(source.path().join("notes.md"), "owen's notes\n").expect("write file");
    git(source.path(), &["add", "--", "notes.md"]);
    git(source.path(), &["commit", "-m", "initial"]);
    let commit = git(source.path(), &["rev-parse", "--verify", "HEAD"]);
    let bare = origin_repo_dir(vault, repo).expect("served repo dir");
    let bare_str = bare.to_str().expect("utf-8 repo path").to_owned();
    git(
        source.path(),
        &["push", &bare_str, "refs/heads/main:refs/heads/main"],
    );
    git(&bare, &["update-ref", "-d", "refs/heads/main"]);
    let wire = GitWire::new(vault).expect("git wire");
    let repo_ref = RepoRef::parse(&format!("local:{bare_str}#{commit}")).expect("repo ref");
    let handle = wire.open_repo(repo_ref, &bare).expect("open repo");
    let repo_id = lfs_repo_id(&handle.identity().as_hex()).expect("repo id");
    let request = OriginPublicationRequest {
        repo_id,
        repo: handle,
        ref_name: GitRefName::parse_full("refs/heads/main").expect("ref name"),
        expected_old_oid: None,
        new_oid: GitOid::parse_hex(commit.as_str()).expect("commit oid"),
        required_objects: Vec::new(),
        required_lfs_oids: Vec::new(),
        provenance_claim_id: EntityId::now(),
        actor_id: EntityId::now(),
        occurred: TimeRange { start: 1, end: 1 },
        learned_at: 1,
    };
    vault
        .put_origin_publication_intent(&request)
        .expect("publication intent");
    let receipt = vault.publish_origin_ref(&wire, request).expect("publish");
    assert_eq!(
        receipt.record.status,
        OriginPublicationStatus::Published,
        "the fixture publishes main"
    );
}

/// A rooted vault serving `notes` with one published ref, its mirror at an
/// https URL nothing answers, on `strategy` (set through the strategy door).
fn setup(
    strategy: OriginMirrorSyncStrategy,
) -> (tempfile::TempDir, Vault, EntityId, AuthenticatedOwner) {
    let (dir, vault, owner, proof) = rooted();
    let memory = vault.memory(owner, EdgeActorClass::Human);
    memory
        .origin_register_as(
            &proof,
            OriginRegisterRequest {
                repo: REPO.to_owned(),
                default_branch: "main".to_owned(),
            },
        )
        .expect("register notes");
    vault
        .register_secret_as_owner(
            &proof,
            &OwnerSecretRegistration {
                name: SECRET_NAME,
                class: CustodyClass::CustodyPortable,
                device_only: true,
                rung: CustodyTier::T0Doored,
                bindings: vec![RequestedBinding {
                    effector: ORIGIN_MIRROR_PUSH_EFFECTOR.to_owned(),
                    tier_ceiling: None,
                    scopes: vec!["read".to_owned()],
                }],
                manifest: None,
                value: b"owen-mirror-token-value",
            },
            vault.now_recorded_at(),
        )
        .expect("the mirror token in custody");
    memory
        .origin_mirror_set_as(
            &proof,
            OriginMirrorSetRequest {
                repo: REPO.to_owned(),
                url: MIRROR_URL.to_owned(),
                secret_ref: SECRET_NAME.to_owned(),
                user: None,
                every_secs: 60,
                sync_strategy: None,
                visibility: None,
            },
        )
        .expect("mirror set");
    memory
        .origin_mirror_strategy_as(
            &proof,
            OriginMirrorStrategyRequest {
                repo: REPO.to_owned(),
                sync_strategy: strategy,
            },
        )
        .expect("mirror strategy");
    publish_main(&vault, REPO);
    (dir, vault, owner, proof)
}

/// The run the mirror target keeps, read through the get door.
fn kept_run(vault: &Vault, owner: EntityId, proof: &AuthenticatedOwner) -> Option<OriginMirrorRun> {
    vault
        .memory(owner, EdgeActorClass::Human)
        .origin_mirror_get_as(
            proof,
            OriginRepoRequest {
                repo: REPO.to_owned(),
            },
        )
        .expect("read the mirror")
        .mirror
        .expect("a mirror is set")
        .last
}

/// The Owner's push of `notes`, applying `check_in` when given.
fn push(
    vault: &Vault,
    owner: EntityId,
    proof: &AuthenticatedOwner,
    check_in: Option<EntityId>,
) -> MemoryResult<OriginMirrorRun> {
    vault
        .memory(owner, EdgeActorClass::Human)
        .origin_mirror_push_as(
            proof,
            OriginMirrorPushRequest {
                repo: REPO.to_owned(),
                check_in_ref: check_in.map(|id| id.to_hex()),
            },
        )
}

/// An agent's ask for the push, opened and left unanswered.
fn unanswered(vault: &Vault, owner: EntityId) -> EntityId {
    let asker = EntityId::now();
    let chain = FixedChain::default().with(
        Rung::Owner,
        RungMembers::Holders(vec![RungHolder {
            principal: owner,
            kind: HolderKind::Person,
        }]),
    );
    open(
        vault,
        OpenPendingCheckIn {
            asker,
            grant_ref: "grant:deputy".to_owned(),
            verb: MIRROR_PUSH.to_owned(),
            act: ActClass::OutboundSend,
            scope: CheckInScope::default(),
            effect_digest: origin_mirror_push_effect_digest(REPO),
            mode: CheckInMode::AlwaysAsk,
            reason: WaitReason::AlwaysAsk,
            asker_wait_secs: None,
            until: None,
            undo_plan: None,
            delay_window: None,
        },
        &chain,
    )
    .expect("the agent asks")
    .id
}

/// An Owner's own push answers their own proof, and the target keeps the run
/// without it.
#[test]
fn an_owners_own_push_answers_own_proof() {
    let (_dir, vault, owner, proof) = setup(OriginMirrorSyncStrategy::Schedule);
    assert!(
        kept_run(&vault, owner, &proof).is_none(),
        "no run before the push"
    );
    let run = push(&vault, owner, &proof, None).expect("the owner pushes on their own proof");
    assert!(
        run.failure.is_some(),
        "the push leaves the machine nowhere: {run:?}"
    );
    assert_eq!(
        run.check_in,
        Some(owner_decision(ActClass::OutboundSend, None, None)),
        "the Owner's own push answers their own proof"
    );
    let kept = kept_run(&vault, owner, &proof).expect("the target keeps the run");
    assert_eq!(
        kept,
        OriginMirrorRun {
            check_in: None,
            ..run
        },
        "the kept run carries no decision"
    );
}

/// An Owner applies an asker's approved ask for the push, spending it.
#[test]
fn an_owner_applies_an_askers_approved_ask() {
    let (_dir, vault, owner, proof) = setup(OriginMirrorSyncStrategy::Schedule);
    let digest = origin_mirror_push_effect_digest(REPO);
    let (asked, asker) = approved(
        &vault,
        owner,
        &proof,
        MIRROR_PUSH,
        ActClass::OutboundSend,
        &digest,
    );
    assert!(!spent(&vault, &asked), "the ask is unspent before the push");
    let run =
        push(&vault, owner, &proof, Some(asked)).expect("the owner applies the approved push");
    assert!(
        run.failure.is_some(),
        "the push leaves the machine nowhere: {run:?}"
    );
    assert_eq!(
        run.check_in,
        Some(owner_decision(
            ActClass::OutboundSend,
            Some(asked),
            Some(asker)
        )),
        "the answer names the check-in it applied and its asker"
    );
    assert!(spent(&vault, &asked), "the push spent the check-in");
    let kept = kept_run(&vault, owner, &proof).expect("the target keeps the run");
    assert_eq!(
        kept,
        OriginMirrorRun {
            check_in: None,
            ..run
        },
        "the kept run carries no decision"
    );
}

/// An ask that does not apply is refused and left unspent, recording no run.
#[test]
fn an_ask_that_does_not_apply_is_refused_and_left_unspent() {
    // (i) An ask opened but not answered.
    {
        let (_dir, vault, owner, proof) = setup(OriginMirrorSyncStrategy::Schedule);
        assert!(
            kept_run(&vault, owner, &proof).is_none(),
            "no run before the push"
        );
        let asked = unanswered(&vault, owner);
        let err =
            push(&vault, owner, &proof, Some(asked)).expect_err("an unanswered ask pushes nothing");
        assert!(
            err.message.contains("check_in"),
            "the refusal names the check-in: {err:?}"
        );
        assert!(!spent(&vault, &asked), "a refused apply spends nothing");
        assert!(
            kept_run(&vault, owner, &proof).is_none(),
            "a refused push records no run"
        );
    }
    // (ii) An approved ask over another repository's digest.
    {
        let (_dir, vault, owner, proof) = setup(OriginMirrorSyncStrategy::Schedule);
        let digest = origin_mirror_push_effect_digest(OTHER_REPO);
        let (asked, _) = approved(
            &vault,
            owner,
            &proof,
            MIRROR_PUSH,
            ActClass::OutboundSend,
            &digest,
        );
        let err = push(&vault, owner, &proof, Some(asked))
            .expect_err("another repository's ask pushes nothing");
        assert!(
            err.message.contains("check_in"),
            "the refusal names the check-in: {err:?}"
        );
        assert!(!spent(&vault, &asked), "a refused apply spends nothing");
        assert!(
            kept_run(&vault, owner, &proof).is_none(),
            "a refused push records no run"
        );
    }
}

/// An `ask_me` mirror refuses before the check-in, leaving the ask unspent.
#[test]
fn an_ask_me_mirror_refuses_before_the_check_in() {
    let (_dir, vault, owner, proof) = setup(OriginMirrorSyncStrategy::AskMe);
    let digest = origin_mirror_push_effect_digest(REPO);
    let (asked, _) = approved(
        &vault,
        owner,
        &proof,
        MIRROR_PUSH,
        ActClass::OutboundSend,
        &digest,
    );
    let err = push(&vault, owner, &proof, Some(asked))
        .expect_err("an ask_me mirror pushes nothing whole");
    assert_eq!(err.code, MEMORY_CODE_INVALID_STATE, "{err:?}");
    assert!(
        err.message.contains("publish_request_required"),
        "the refusal names publish_request_required: {err:?}"
    );
    assert!(
        !spent(&vault, &asked),
        "a refusal before the spend leaves the ask unspent"
    );
    assert!(
        kept_run(&vault, owner, &proof).is_none(),
        "a refused push records no run"
    );
}
