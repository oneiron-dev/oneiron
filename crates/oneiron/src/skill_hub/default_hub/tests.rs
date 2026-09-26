use super::*;
use crate::{error::ErrorKind, skill::SkillLifecycle};

#[test]
fn first_open_seeds_offline_and_reopen_preserves_owner_configuration() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let id = default_skill_hub_id()?;
    let vault = Vault::open(dir.path(), crate::VaultConfig::default())?;
    assert_eq!(
        vault.entities_by_type(crate::registry::ENTITY_TYPE_SKILL_HUB)?,
        vec![id]
    );
    let row = vault.skill_hub_record(&id)?;
    assert_eq!(row.kind, SkillHubKind::Git);
    assert_eq!(row.endpoint, HUB_ENDPOINT);
    assert_eq!(row.trust_tier, SkillHubTrustTier::Verified);
    assert_eq!(row.sync_policy, HubSyncPolicy::PinnedCommit);
    assert_eq!(default_skill_hub_commit().len(), 40);
    let before = vault.get_raw(&id)?;
    drop(vault);
    let vault = Vault::open_existing(dir.path(), crate::VaultConfig::default())?;
    assert_eq!(vault.get_raw(&id)?, before);
    // A configured hub is owner data; open does not reconfigure it.
    let changed = SkillHubRecord::new(
        SkillHubKind::Git,
        "https://example.org/hub.git",
        SkillHubTrustTier::Community,
        HubSyncPolicy::PinnedCommit,
    )?;
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
        "principal:hub-one",
        true,
        crate::store::GateDecisionId::now(),
    )?;
    vault.configure_skill_hub(&owner, &id, &changed, TimeRange { start: 1, end: 1 }, 1)?;
    drop(vault);
    let vault = Vault::open(dir.path(), crate::VaultConfig::default())?;
    assert_eq!(vault.skill_hub_record(&id)?, changed);
    Ok(())
}

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
    Ok(())
}
