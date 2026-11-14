//! ROLES-CHECKIN P2.5, row 2k8d (ARCH-0082 #act-table "Widen another's
//! grant" and #owner-own-acts; Engine rulings P25-SHAPE Q1 = A, 14 Nov
//! 13:39, and P25-2K8-SCOPE Q1 = A, 19:32): two Owner-proof hub doors take
//! the 2j apply shape, `vault.skill_hubs.publishers.admit` and
//! `vault.skills.import`.
//!
//! - The Owner's act is never gated: it goes on their own proof, and the
//!   answer records that decision.
//! - The Owner applies another asker's approved check-in for that exact
//!   act: the act's writer spends it, and the answer names it and its
//!   asker. An approval for another act changes nothing and stays unspent.
//! - An import that applies a check-in names its exact bytes: its source is
//!   pinned to a commit or a content hash. A tag is refused before any
//!   fetch, and the check-in stays unspent.
//! - The import admits its publisher in a writer of its own, before the
//!   import's: a check-in for another import is refused before that, so it
//!   admits no one (2k8d review, fixed in 2k8d2).
//!
//! On its base, 2k8c's head, this file does not build: neither door has a
//! request with a `check_in_ref`.
//!
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron
//! --all-features --test check_in_hub_import_effects`.
#![cfg(oneiron_test_support)]
#![allow(clippy::unwrap_used, clippy::expect_used)]
#![allow(
    clippy::disallowed_methods,
    reason = "a test process starts its own subprocesses; the rule covers the server's crates"
)]

#[path = "check_in/hub_fixture.rs"]
mod hub_fixture;
#[path = "check_in/owner_apply_fixture.rs"]
mod owner_apply_fixture;

use hub_fixture::{configured_hub, publisher_grant_ref, skill_md};
use oneiron::EntityId;
use oneiron::check_in::ActClass;
use oneiron::skill_hub::{HubPin, HubRef, HubSyncPolicy, SkillHubKind};
use oneiron::verbs::{
    HubSkillImportRequest, SkillPublisherAdmitRequest, hub_skill_import_as_owner,
    hub_skill_import_effect_digest, skill_publisher_admit_as_owner,
    skill_publisher_admit_effect_digest,
};
use owner_apply_fixture::{approved, owner_decision, rooted, spent};

fn admit_request(
    hub: EntityId,
    identity: &str,
    check_in_ref: Option<EntityId>,
) -> SkillPublisherAdmitRequest {
    SkillPublisherAdmitRequest {
        hub,
        identity: identity.to_owned(),
        check_in_ref: check_in_ref.map(|id| id.to_hex()),
    }
}

#[test]
fn the_owner_applies_an_approved_ask_for_that_publisher_admission_only() {
    let (_dir, vault, owner, owner_proof) = rooted();
    let hub = configured_hub(
        &vault,
        &owner_proof,
        SkillHubKind::HttpIndex,
        "https://hub.example.invalid/index.json",
        HubSyncPolicy::ContentHashFrozen,
    );

    let own = skill_publisher_admit_as_owner(
        &vault,
        &owner_proof,
        &admit_request(hub, "publisher:own", None),
    )
    .expect("the Owner admits a publisher");
    assert_eq!(
        own.check_in,
        Some(owner_decision(ActClass::GrantWiden, None, None)),
        "the Owner's own admission records their own proof"
    );

    let asked = admit_request(hub, "publisher:asked", None);
    let (check_in, asker) = approved(
        &vault,
        owner,
        &owner_proof,
        "vault.skill_hubs.publishers.admit",
        ActClass::GrantWiden,
        &skill_publisher_admit_effect_digest(&asked).expect("the admission's digest"),
    );
    let refused = skill_publisher_admit_as_owner(
        &vault,
        &owner_proof,
        &admit_request(hub, "publisher:other", Some(check_in)),
    );
    assert!(
        refused.is_err(),
        "the approval covers the publisher it was asked for only; seen {refused:?}"
    );
    assert!(
        !spent(&vault, &check_in),
        "a refused call leaves it unspent"
    );
    assert!(
        vault
            .consent_grant(&publisher_grant_ref("publisher:other", hub))
            .expect("read the Grant")
            .is_none(),
        "the refused call admitted no one"
    );

    let admitted = skill_publisher_admit_as_owner(
        &vault,
        &owner_proof,
        &admit_request(hub, "publisher:asked", Some(check_in)),
    )
    .expect("the Owner applies the approved ask");
    assert_eq!(
        admitted.grant_ref,
        publisher_grant_ref("publisher:asked", hub),
        "the admission stands the Grant the ask named"
    );
    assert!(spent(&vault, &check_in), "the admission spent the check-in");
    assert_eq!(
        admitted.check_in,
        Some(owner_decision(
            ActClass::GrantWiden,
            Some(check_in),
            Some(asker)
        )),
        "the answer names the applied check-in and its asker"
    );
}

/// Runs git in `root` with no user or system configuration.
fn git(root: &std::path::Path, args: &[&str]) -> String {
    let output = std::process::Command::new("git")
        .current_dir(root)
        .env_clear()
        .env("PATH", "/usr/bin:/bin:/usr/local/bin:/opt/homebrew/bin")
        .env("HOME", root)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .args([
            "-c",
            "core.hooksPath=/dev/null",
            "-c",
            "init.templateDir=",
            "-c",
            "user.name=Fixture",
            "-c",
            "user.email=fixture@example.invalid",
        ])
        .args(args)
        .output()
        .expect("local git fixture");
    assert!(output.status.success(), "local git fixture command failed");
    String::from_utf8(output.stdout)
        .expect("git UTF-8")
        .trim()
        .to_owned()
}

fn import_request(
    hub: EntityId,
    folder: &str,
    pin: HubPin,
    publisher: &str,
    check_in_ref: Option<EntityId>,
) -> HubSkillImportRequest {
    HubSkillImportRequest {
        hub_ref: HubRef::new(hub, folder, pin).expect("a hub ref"),
        publisher: publisher.to_owned(),
        check_in_ref: check_in_ref.map(|id| id.to_hex()),
    }
}

#[test]
fn the_owner_applies_an_approved_ask_for_that_pinned_skill_import_only() {
    let (_dir, vault, owner, owner_proof) = rooted();
    let repo = tempfile::tempdir().expect("a repository directory");
    git(repo.path(), &["init", "--quiet"]);
    for name in ["own", "asked"] {
        let folder = repo.path().join("skills").join(name);
        std::fs::create_dir_all(&folder).expect("the skill folder");
        std::fs::write(
            folder.join("SKILL.md"),
            skill_md(&format!("fixture.{name}")),
        )
        .expect("the skill");
    }
    git(repo.path(), &["add", "."]);
    git(repo.path(), &["commit", "-qm", "skills"]);
    let commit = git(repo.path(), &["rev-parse", "HEAD"]);
    let hub = configured_hub(
        &vault,
        &owner_proof,
        SkillHubKind::LocalDir,
        repo.path().to_str().expect("a UTF-8 path"),
        HubSyncPolicy::PinnedCommit,
    );

    let own = hub_skill_import_as_owner(
        &vault,
        &owner_proof,
        &import_request(
            hub,
            "skills/own",
            HubPin::Commit(commit.clone()),
            "publisher:own",
            None,
        ),
    )
    .expect("the Owner imports a skill");
    assert_eq!(
        own.check_in,
        Some(owner_decision(ActClass::GrantWiden, None, None)),
        "the Owner's own import records their own proof"
    );

    let asked = import_request(
        hub,
        "skills/asked",
        HubPin::Commit(commit.clone()),
        "publisher:asked",
        None,
    );
    let (check_in, asker) = approved(
        &vault,
        owner,
        &owner_proof,
        "vault.skills.import",
        ActClass::GrantWiden,
        &hub_skill_import_effect_digest(&asked).expect("the import's digest"),
    );
    let tagged = hub_skill_import_as_owner(
        &vault,
        &owner_proof,
        &import_request(
            hub,
            "skills/asked",
            HubPin::Tag("v1".to_owned()),
            "publisher:asked",
            Some(check_in),
        ),
    )
    .expect_err("a tag names no exact bytes");
    assert!(
        format!("{tagged:?}").contains("commit or content_hash pin"),
        "refused for its pin, before any fetch; seen {tagged:?}"
    );
    assert!(
        !spent(&vault, &check_in),
        "a refused call leaves it unspent"
    );
    let other = hub_skill_import_as_owner(
        &vault,
        &owner_proof,
        &import_request(
            hub,
            "skills/asked",
            HubPin::Commit(commit.clone()),
            "publisher:other",
            Some(check_in),
        ),
    );
    assert!(
        other.is_err(),
        "the approval covers the publisher it was asked for only; seen {other:?}"
    );
    assert!(
        !spent(&vault, &check_in),
        "a refused call leaves it unspent"
    );
    assert!(
        vault
            .consent_grant(&publisher_grant_ref("publisher:other", hub))
            .expect("read the Grant")
            .is_none(),
        "the refused import admitted no publisher"
    );

    let imported = hub_skill_import_as_owner(
        &vault,
        &owner_proof,
        &import_request(
            hub,
            "skills/asked",
            HubPin::Commit(commit),
            "publisher:asked",
            Some(check_in),
        ),
    )
    .expect("the Owner applies the approved ask");
    assert_ne!(imported.entity, own.entity, "the asked-for skill landed");
    assert!(spent(&vault, &check_in), "the import spent the check-in");
    assert_eq!(
        imported.check_in,
        Some(owner_decision(
            ActClass::GrantWiden,
            Some(check_in),
            Some(asker)
        )),
        "the answer names the applied check-in and its asker"
    );
}
