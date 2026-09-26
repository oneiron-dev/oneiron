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

#[test]
fn agent_source_cannot_be_installed_as_a_runtime_pack() -> Result<()> {
    let source = PackSource::from_files(super::tests::agent_files()?)?;
    let (_dir, vault, _owner, reference, publisher) =
        fixture(SkillHubTrustTier::Verified, &source)?;
    let id = vault.stage_pack_source(&source, TimeRange { start: 3, end: 3 }, 3)?;
    let err = vault
        .prepare_pack_install(
            id,
            &reference,
            &publisher,
            &Qualification {
                runtime: false,
                passed: true,
            },
        )
        .expect_err("agent sources are not runtime installations");
    assert!(format!("{err:?}").contains("agent packs are inert sources"));
    Ok(())
}
