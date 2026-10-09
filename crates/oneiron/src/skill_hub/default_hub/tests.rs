use super::*;
use crate::{error::ErrorKind, skill::SkillLifecycle};

#[test]
fn agent_authored_v1_library_skill_imports_through_hub_one_at_pinned_ref() -> Result<()> {
    // A chat-authored v1 library body, beyond the four embedded bootstraps.
    // A real local Git repository keeps the test fully offline.
    let repository = tempfile::tempdir()?;
    let path = repository.path().join("skills/review-evidence");
    std::fs::create_dir_all(&path)?;
    std::fs::write(
        path.join("SKILL.md"),
        "---\nname: review-evidence\ndescription: Review a person's claim against cited evidence\nversion: 1.0.0\nlicense: Apache-2.0\nmetadata:\n  author: vault-agent\n  terms: authored in chat\n---\n# Review evidence\nCheck the cited evidence before writing a verdict.\n",
    )?;
    let git = |args: &[&str]| {
        let output = std::process::Command::new("git")
            .current_dir(repository.path())
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .args([
                "-c",
                "user.name=Fixture",
                "-c",
                "user.email=fixture@example.invalid",
            ])
            .args(args)
            .output()
            .expect("local git");
        assert!(
            output.status.success(),
            "git {:?}: {}",
            args,
            String::from_utf8_lossy(&output.stderr)
        );
        String::from_utf8(output.stdout)
            .expect("git stdout")
            .trim()
            .to_owned()
    };
    git(&["init", "--quiet"]);
    git(&["add", "."]);
    git(&["commit", "-qm", "v1 library skill"]);
    let commit = git(&["rev-parse", "HEAD"]);
    let dir = tempfile::tempdir()?;
    let vault = Vault::open(dir.path(), crate::VaultConfig::default())?;
    let hub_id = default_skill_hub_id()?;
    assert_eq!(
        vault.skill_hub_record(&hub_id)?.sync_policy,
        HubSyncPolicy::PinnedCommit
    );
    let owner_id = EntityId::now();
    vault.put_entity(
        &owner_id,
        crate::registry::ENTITY_TYPE_PERSON,
        TimeRange { start: 1, end: 1 },
        1,
        b"owner",
    )?;
    let owner = vault.authenticate_owner(
        owner_id,
        "principal:library",
        true,
        crate::store::GateDecisionId::now(),
    )?;
    vault.configure_skill_hub(
        &owner,
        &hub_id,
        &SkillHubRecord::new(
            SkillHubKind::Git,
            repository.path().to_str().expect("utf8"),
            SkillHubTrustTier::Verified,
            HubSyncPolicy::PinnedCommit,
        )?,
        TimeRange { start: 1, end: 1 },
        1,
    )?;
    let adapter = GitEndpointSkillHubAdapter::new(
        hub_id,
        repository.path().to_str().expect("utf8"),
        &commit,
    )?;
    let reference = HubRef::new(
        hub_id,
        "skills/review-evidence",
        HubPin::Commit(commit.clone()),
    )?;
    let package = crate::skill_hub::SkillHubAdapter::fetch_package(&adapter, &reference)?;
    let hash = package.content_hash()?;
    let at = TimeRange { start: 2, end: 2 };
    let id = vault.import_default_hub_skill_at_commit("skills/review-evidence", &commit, at, 2)?;
    assert_eq!(
        vault.get_skill_record(&id)?.expect("imported").content_hash,
        Some(hash)
    );
    assert_eq!(
        vault
            .get_skill_record(&id)?
            .expect("imported")
            .lifecycle_status,
        SkillLifecycle::Candidate
    );
    assert!(!vault.skill_scan_verdicts_for_content_hash(hash)?.is_empty());
    assert_eq!(
        vault.import_default_hub_skill_at_commit("skills/review-evidence", &commit, at, 2)?,
        id
    );
    assert_eq!(vault.skill_hub_provenance_count(&id)?, 1);
    assert_eq!(
        vault.sync_skill_from_hub(
            &id,
            &reference,
            &package,
            HubSyncPolicy::PinnedCommit,
            at,
            2
        )?,
        super::super::HubSyncDisposition::RefusedByPolicy
    );
    let wrong = HubRef::new(
        hub_id,
        "skills/review-evidence",
        HubPin::Commit("a".repeat(40)),
    )?;
    assert_eq!(
        crate::skill_hub::SkillHubAdapter::fetch_package(&adapter, &wrong)
            .expect_err("wrong pin")
            .kind(),
        ErrorKind::InvalidSkillBody
    );
    assert_eq!(
        vault.restore_default_hub_skill_at_commit(
            &owner,
            "skills/review-evidence",
            &commit,
            at,
            2
        )?,
        id,
    );
    assert!(vault.delete_entity(&id)?);
    let restored = vault.restore_default_hub_skill_at_commit(
        &owner,
        "skills/review-evidence",
        &commit,
        TimeRange { start: 3, end: 3 },
        3,
    )?;
    assert_ne!(restored, id);
    assert_eq!(
        vault.get_skill_record(&restored)?.unwrap().content_hash,
        Some(hash)
    );
    assert_eq!(
        vault.get_skill_record(&restored)?.unwrap().lifecycle_status,
        SkillLifecycle::Candidate
    );
    assert_eq!(
        vault
            .hub_import_receipt(&restored, &reference)?
            .unwrap()
            .content_hash,
        hash.to_hex()
    );
    // Even an idempotent restore is an owner-only verb; a stale owner proof
    // cannot use the no-op branch to inspect a default's live holder.
    assert!(vault.delete_entity(&owner.actor())?);
    assert!(
        vault
            .restore_default_hub_skill_at_commit(&owner, "skills/review-evidence", &commit, at, 4,)
            .is_err()
    );
    Ok(())
}
