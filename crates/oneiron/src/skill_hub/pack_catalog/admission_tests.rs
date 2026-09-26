//! Caller-visible pack admission, re-consent, runtime and transaction laws.
use super::*;
use crate::{
    Vault, VaultConfig,
    consent::AuthenticatedOwner,
    entity_id::EntityId,
    error::Result,
    skill_hub::{
        ForeignSkillPublisher, HubAskSurface, HubFile, HubPin, HubRef, HubSyncPolicy, SkillHubKind,
        SkillHubRecord, SkillHubTrustTier,
    },
    temporal::TimeRange,
};
fn source(connector: bool) -> Result<PackSource> {
    let kind = if connector {
        "kind: connector\nadapter: built-in:email"
    } else {
        "kind: capability"
    };
    PackSource::from_files(vec![
        HubFile::new("PACK.md", format!("---\nname: alice.tools\ndescription: fixture\nversion: 1\n{kind}\npredicates: [\"alice.tools.topic\"]\nkinds: [\"alice.tools.item\"]\ngrants: [\"mail.read\"]\nwakes: [\"mail.arrived\"]\n---\nExact pack source\n").into_bytes()),
        HubFile::new("knowledge/kinds/alice.tools.item.json", br#"{"type":"object","description":"inert shape descriptor"}"#.to_vec()),
        HubFile::new("skills/format/SKILL.md", b"---\nname: alice.format\ndescription: format\nversion: 1\n---\nKeep facts exact.\n".to_vec()),
    ])
}
struct Qualification {
    runtime: bool,
    passed: bool,
}
impl PackQualifier for Qualification {
    fn qualify(&self, source: &PackSource) -> Result<PackQualification> {
        Ok(PackQualification {
            suite: "fixture-suite".into(),
            report_hash: "12".repeat(32),
            passed: self.passed,
            advisory_accepted: true,
            advisory: "Fixture only; not native connector qualification".into(),
            runtime: if self.runtime {
                source
                    .manifest
                    .adapter
                    .clone()
                    .map(|adapter| PackRuntimeRecipe {
                        adapter,
                        runtime_id: "fixture-native-recipe".into(),
                        runtime_hash: "23".repeat(32),
                    })
            } else {
                None
            },
        })
    }
}
fn fixture(
    tier: SkillHubTrustTier,
    source: &PackSource,
) -> Result<(
    tempfile::TempDir,
    Vault,
    AuthenticatedOwner,
    HubRef,
    ForeignSkillPublisher,
)> {
    let mut config = VaultConfig::device();
    config.dimensions = 4;
    config.map_size = 16 * 1024 * 1024;
    let (dir, vault) = crate::test_util::open_test_vault_with(config);
    let owner = EntityId::now();
    let at = TimeRange { start: 1, end: 1 };
    vault.put_entity(&owner, crate::registry::ENTITY_TYPE_PERSON, at, 1, b"owner")?;
    let owner = vault.authenticate_owner(
        owner,
        "principal:pack-owner",
        true,
        crate::store::GateDecisionId::now(),
    )?;
    let hub = EntityId::now();
    let record = SkillHubRecord::new(
        SkillHubKind::HttpIndex,
        "https://example.invalid/packs.json",
        tier,
        HubSyncPolicy::ContentHashFrozen,
    )?;
    vault.configure_skill_hub(&owner, &hub, &record, at, 1)?;
    let publisher = vault.admit_skill_publisher(&owner, "publisher:pack-author", hub)?;
    let reference = HubRef::new(
        hub,
        "pack",
        HubPin::ContentHash(source.content_hash().to_hex()),
    )?;
    Ok((dir, vault, owner, reference, publisher))
}
#[test]
fn all_tiers_require_consent_and_bundled_skills_remain_candidates() -> Result<()> {
    for (tier, surface) in [
        (SkillHubTrustTier::Verified, HubAskSurface::OneTap),
        (
            SkillHubTrustTier::Community,
            HubAskSurface::SummarizedReview,
        ),
        (SkillHubTrustTier::Untrusted, HubAskSurface::FullReview),
    ] {
        let source = source(false)?;
        let (dir, vault, owner, reference, publisher) = fixture(tier, &source)?;
        let id = vault.stage_pack_source(&source, TimeRange { start: 3, end: 3 }, 3)?;
        let ask = vault.prepare_pack_install(
            id,
            &reference,
            &publisher,
            &Qualification {
                runtime: false,
                passed: true,
            },
        )?;
        assert_eq!(ask.surface(), surface);
        assert_eq!(
            vault.install_pack(&ask)?,
            PackInstallDisposition::PendingConsent
        );
        assert!(vault.pack_kind_registration("alice.tools.item")?.is_none());
        vault.approve_pack_install(&ask, &owner)?;
        let PackInstallDisposition::Installed(receipt) = vault.install_pack(&ask)? else {
            panic!("consented");
        };
        assert_eq!(receipt.content_hash, source.content_hash().to_hex());
        assert_eq!(receipt.requested_grants, ["mail.read"]);
        assert_eq!(receipt.wake_subscriptions, ["mail.arrived"]);
        assert_eq!(
            vault.pack_for_predicate("alice.tools.topic")?,
            Some((*receipt).clone())
        );
        assert_eq!(
            vault
                .pack_kind_registration("alice.tools.item")?
                .unwrap()
                .handle,
            Some(128)
        );
        let skill = EntityId::from_hex(&receipt.candidate_skills[0])?;
        assert_eq!(
            vault.get_skill_record(&skill)?.unwrap().lifecycle_status,
            crate::skill::SkillLifecycle::Candidate
        );
        assert!(vault.install_pack(&ask).is_err()); // prior-install binding changed; consent cannot replay.
        drop(vault);
        let mut config = VaultConfig::device();
        config.dimensions = 4;
        config.map_size = 16 * 1024 * 1024;
        let reopened = Vault::open(dir.path(), config)?;
        assert_eq!(reopened.installed_pack("alice.tools")?, Some(*receipt));
    }
    Ok(())
}
#[test]
fn connector_requires_qualified_runtime_and_changed_hub_requires_reconsent() -> Result<()> {
    let source = source(true)?;
    let (_dir, vault, owner, reference, publisher) = fixture(SkillHubTrustTier::Verified, &source)?;
    let id = vault.stage_pack_source(&source, TimeRange { start: 3, end: 3 }, 3)?;
    assert!(
        vault
            .prepare_pack_install(
                id,
                &reference,
                &publisher,
                &Qualification {
                    runtime: false,
                    passed: true
                }
            )
            .is_err()
    );
    assert!(
        vault
            .prepare_pack_install(
                id,
                &reference,
                &publisher,
                &Qualification {
                    runtime: true,
                    passed: false
                }
            )
            .is_err()
    );
    let ask = vault.prepare_pack_install(
        id,
        &reference,
        &publisher,
        &Qualification {
            runtime: true,
            passed: true,
        },
    )?;
    vault.approve_pack_install(&ask, &owner)?;
    let revised = SkillHubRecord::new(
        SkillHubKind::HttpIndex,
        "https://example.invalid/revised.json",
        SkillHubTrustTier::Untrusted,
        HubSyncPolicy::ContentHashFrozen,
    )?;
    vault.configure_skill_hub(
        &owner,
        &reference.hub_id,
        &revised,
        TimeRange { start: 2, end: 2 },
        2,
    )?;
    assert!(vault.install_pack(&ask).is_err());
    assert!(vault.installed_pack("alice.tools")?.is_none());
    let fresh = vault.prepare_pack_install(
        id,
        &reference,
        &publisher,
        &Qualification {
            runtime: true,
            passed: true,
        },
    )?;
    assert_eq!(fresh.surface(), HubAskSurface::FullReview);
    assert_eq!(
        vault.install_pack(&fresh)?,
        PackInstallDisposition::PendingConsent
    );
    vault.approve_pack_install(&fresh, &owner)?;
    assert!(matches!(
        vault.install_pack(&fresh)?,
        PackInstallDisposition::Installed(_)
    ));
    Ok(())
}
#[test]
fn invalid_bundled_skill_rolls_back_map_catalog_and_consent_spend() -> Result<()> {
    let mut files = source(false)?.files().to_vec();
    files
        .iter_mut()
        .find(|f| f.path == "skills/format/SKILL.md")
        .unwrap()
        .content = b"missing required folder manifest".to_vec();
    let source = PackSource::from_files(files)?;
    let (_dir, vault, owner, reference, publisher) =
        fixture(SkillHubTrustTier::Community, &source)?;
    let id = vault.stage_pack_source(&source, TimeRange { start: 3, end: 3 }, 3)?;
    let ask = vault.prepare_pack_install(
        id,
        &reference,
        &publisher,
        &Qualification {
            runtime: false,
            passed: true,
        },
    )?;
    vault.approve_pack_install(&ask, &owner)?;
    assert!(vault.install_pack(&ask).is_err());
    assert!(vault.installed_pack("alice.tools")?.is_none());
    assert!(vault.pack_byte_map_snapshot()?.is_none());
    assert!(vault.pack_for_predicate("alice.tools.topic")?.is_none());
    // The source remains intact; the failed attempted install publishes no half-state.
    assert_eq!(vault.get_pack_source(&id)?, Some(source));
    Ok(())
}

struct Replay;
impl crate::skill_optimize::HeldOutReplayScorer for Replay {
    fn score(&self, case: &crate::skill_optimize::HeldOutReplayCase<'_>) -> Result<f32> {
        Ok(if case.instructions.contains("Keep facts exact.") {
            0.9
        } else {
            0.2
        })
    }
}

fn installed_active_lens() -> Result<(
    tempfile::TempDir,
    Vault,
    crate::lens::LensMount,
    EntityId,
    crate::lens::LensMount,
)> {
    installed_active_lens_for(None, "format")
}

fn installed_active_lens_for(
    reference_text: Option<&str>,
    folder: &str,
) -> Result<(
    tempfile::TempDir,
    Vault,
    crate::lens::LensMount,
    EntityId,
    crate::lens::LensMount,
)> {
    use crate::lens::LensMount;
    use crate::skill::SkillLifecycle;
    let mut files = source(false)?.files().to_vec();
    files.push(HubFile::new(
        "skills/z-extra/SKILL.md",
        b"---\nname: alice.extra\ndescription: extra\nversion: 1\n---\nAnother skill.\n".to_vec(),
    ));
    files
        .iter_mut()
        .find(|file| file.path == "skills/format/SKILL.md")
        .unwrap()
        .path = format!("skills/{folder}/SKILL.md");
    let source = PackSource::from_files(files)?;
    let (dir, vault, owner, mut reference, publisher) =
        fixture(SkillHubTrustTier::Verified, &source)?;
    if let Some(text) = reference_text {
        reference = HubRef::new(
            reference.hub_id,
            text,
            HubPin::ContentHash(source.content_hash().to_hex()),
        )?;
    }
    let source_id = vault.stage_pack_source(&source, TimeRange { start: 3, end: 3 }, 3)?;
    let ask = vault.prepare_pack_install(
        source_id,
        &reference,
        &publisher,
        &Qualification {
            runtime: false,
            passed: true,
        },
    )?;
    let absent = LensMount::Pack {
        pack_name: "alice.tools".into(),
        skill_id: EntityId::now(),
    };
    assert_eq!(
        vault.mounted_lenses(std::slice::from_ref(&absent))?,
        vec![LensMount::Vault, LensMount::Admin]
    );
    assert_eq!(vault.render_mounted_lens(&absent, || Ok(1))?, None);
    vault.approve_pack_install(&ask, &owner)?;
    let PackInstallDisposition::Installed(receipt) = vault.install_pack(&ask)? else {
        panic!("consented install");
    };
    assert_eq!(receipt.candidate_skills.len(), 2);
    let skill_id = EntityId::from_hex(&receipt.candidate_skills[0])?;
    let skill_hash = vault
        .get_skill_record(&skill_id)?
        .unwrap()
        .content_hash
        .unwrap();
    let skill_source = super::bundled_skills::pack_skill_hub_ref(&reference, folder, skill_hash)?;
    let lens = LensMount::Pack {
        pack_name: receipt.pack_name,
        skill_id,
    };
    assert_eq!(vault.render_mounted_lens(&lens, || Ok(1))?, None); // Candidate cannot mount.

    let baseline = EntityId::now();
    let mut base = super::super::folder::package_from_files(vec![HubFile::new(
        "SKILL.md",
        b"---\nname: fixture.base\ndescription: baseline\nversion: 1\n---\nBaseline.\n".to_vec(),
    )])?
    .record;
    base.source = crate::claim::ClaimSource::UserStated;
    base.content_hash = None;
    base.approval_status = crate::claim::ClaimApprovalStatus::Approved;
    vault.put_skill_record(&baseline, &base, TimeRange { start: 4, end: 4 }, 4)?;
    base.lifecycle_status = SkillLifecycle::Active;
    vault.update_skill_record(&baseline, &base, TimeRange { start: 5, end: 5 }, 5)?;
    crate::skill_hub::test_support::reserve(&vault, &baseline, &base.skill_id);
    let activation =
        vault.prepare_marketplace_activation(skill_id, &skill_source, &publisher, baseline)?;
    vault.approve_marketplace_activation(&activation, &owner)?;
    let crate::skill_hub::HubAdmissionDisposition::Ruled(result) = vault.admit_marketplace_skill(
        &activation,
        &Replay,
        TimeRange { start: 20, end: 20 },
        21,
    )?
    else {
        panic!("consented activation");
    };
    assert!(result.accepted);
    let healthy = install_healthy_pack(&vault, &owner, &reference, &publisher, baseline)?;
    Ok((dir, vault, lens, source_id, healthy))
}

fn install_healthy_pack(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    reference: &HubRef,
    publisher: &ForeignSkillPublisher,
    baseline: EntityId,
) -> Result<crate::lens::LensMount> {
    let source = PackSource::from_files(vec![
        HubFile::new("PACK.md", b"---\nname: alice.other\ndescription: fixture\nversion: 1\nkind: capability\n---\nOther pack.\n".to_vec()),
        HubFile::new("skills/healthy/SKILL.md", b"---\nname: alice.healthy\ndescription: healthy\nversion: 1\n---\nKeep facts exact.\n".to_vec()),
    ])?;
    let other_ref = HubRef::new(
        reference.hub_id,
        "other-pack",
        HubPin::ContentHash(source.content_hash().to_hex()),
    )?;
    let id = vault.stage_pack_source(&source, TimeRange { start: 6, end: 6 }, 6)?;
    let ask = vault.prepare_pack_install(
        id,
        &other_ref,
        publisher,
        &Qualification {
            runtime: false,
            passed: true,
        },
    )?;
    vault.approve_pack_install(&ask, owner)?;
    let PackInstallDisposition::Installed(receipt) = vault.install_pack(&ask)? else {
        panic!("consented second install");
    };
    let skill_id = EntityId::from_hex(&receipt.candidate_skills[0])?;
    let hash = vault
        .get_skill_record(&skill_id)?
        .unwrap()
        .content_hash
        .unwrap();
    let skill_source = super::bundled_skills::pack_skill_hub_ref(&other_ref, "healthy", hash)?;
    let activation =
        vault.prepare_marketplace_activation(skill_id, &skill_source, publisher, baseline)?;
    vault.approve_marketplace_activation(&activation, owner)?;
    let crate::skill_hub::HubAdmissionDisposition::Ruled(result) = vault.admit_marketplace_skill(
        &activation,
        &Replay,
        TimeRange { start: 22, end: 22 },
        23,
    )?
    else {
        panic!("consented second activation");
    };
    assert!(result.accepted);
    Ok(crate::lens::LensMount::Pack {
        pack_name: receipt.pack_name,
        skill_id,
    })
}

#[test]
fn pack_lens_mounts_only_while_its_installed_skill_loads_as_canon() -> Result<()> {
    use crate::lens::LensMount;
    use crate::skill::SkillLifecycle;
    for state in [
        Some(SkillLifecycle::Stale),
        Some(SkillLifecycle::Quarantined),
        None,
    ] {
        let (_dir, vault, lens, _, _healthy) = installed_active_lens()?;
        let LensMount::Pack { skill_id, .. } = &lens else {
            panic!("pack binding");
        };
        let core = vec![LensMount::Vault, LensMount::Admin];
        let wrong_pack = LensMount::Pack {
            pack_name: "alice.other".into(),
            skill_id: *skill_id,
        };
        assert_eq!(
            vault.mounted_lenses(&[lens.clone(), wrong_pack])?,
            vec![LensMount::Vault, LensMount::Admin, lens.clone()]
        );
        assert_eq!(vault.render_mounted_lens(&lens, || Ok(7))?, Some(7));
        if let Some(state) = state {
            let mut skill = vault.get_skill_record(skill_id)?.unwrap();
            skill.lifecycle_status = state;
            if state == SkillLifecycle::Quarantined {
                skill.approval_status = crate::claim::ClaimApprovalStatus::Approved;
            }
            vault.update_skill_record(skill_id, &skill, TimeRange { start: 30, end: 30 }, 31)?;
        } else {
            assert!(vault.delete_entity(skill_id)?);
        }
        assert_eq!(vault.mounted_lenses(std::slice::from_ref(&lens))?, core);
        assert_eq!(
            vault.render_mounted_lens(&lens, || panic!("hidden renderer ran"))?,
            None::<()>
        );
        // A removed host binding cannot leave an orphaned mount either.
        assert_eq!(vault.mounted_lenses(&[])?, core);
        assert_eq!(
            vault.render_mounted_lens(&LensMount::Admin, || Ok(9))?,
            Some(9)
        );
    }
    Ok(())
}

#[test]
fn deleted_pack_source_or_soft_erased_skill_hides_only_affected_lens() -> Result<()> {
    use crate::lens::LensMount;
    for remove_source in [false, true] {
        let (_dir, vault, lens, source_id, healthy) = installed_active_lens()?;
        let LensMount::Pack { skill_id, .. } = &lens else {
            panic!("pack binding");
        };
        let bindings = [lens.clone(), healthy.clone()];
        assert_eq!(
            vault.mounted_lenses(&bindings)?,
            vec![
                LensMount::Vault,
                LensMount::Admin,
                lens.clone(),
                healthy.clone()
            ]
        );
        if remove_source {
            assert!(vault.delete_entity(&source_id)?);
        } else {
            vault.delete_entity_with_reason(skill_id, crate::DeleteReason::UserDelete)?;
        }
        assert_eq!(
            vault.mounted_lenses(&bindings)?,
            vec![LensMount::Vault, LensMount::Admin, healthy.clone()]
        );
        assert_eq!(
            vault.render_mounted_lens(&lens, || panic!("removed renderer ran"))?,
            None::<()>
        );
        assert_eq!(vault.render_mounted_lens(&healthy, || Ok(7))?, Some(7));
    }
    Ok(())
}

#[test]
fn longest_valid_pack_ref_and_long_skill_folder_install_and_activate() -> Result<()> {
    for (reference, folder) in [
        ("r".repeat(4096), "format".to_owned()),
        ("pack".to_owned(), "f".repeat(900)),
    ] {
        let (_dir, vault, lens, _source_id, healthy) =
            installed_active_lens_for(Some(&reference), &folder)?;
        assert_eq!(
            vault.mounted_lenses(&[lens.clone(), healthy])?.get(2),
            Some(&lens)
        );
        assert_eq!(vault.render_mounted_lens(&lens, || Ok(1))?, Some(1));
    }
    Ok(())
}
