//! Census cases for what the activation gate decides about a skill, and for
//! the script code an installed pack's name runs.
use super::Case;
use crate::claim::{ClaimApprovalStatus, ClaimSource, ClaimSubject};
use crate::code_sandbox::SANDBOX_JS_COMPONENT_NAME;
use crate::edge::EdgeKind;
use crate::recovery::checkpoint::RestoreReason;
use crate::registry::ENTITY_TYPE_PERSON;
use crate::skill::{SkillContentHash, SkillLifecycle, SkillRecord, canonical_skill_tree_hash};
use crate::skill_hub::pack_catalog::{
    PackFitPolicy, PackFitVerdict, PackInstallDisposition, PackInstallStatus, PackPermissions,
    PackQualification, PackRuntimeRecipe, PackSource, PackSourceAdapter,
};
use crate::skill_hub::{
    ForeignSkillPublisher, HubFile, HubPackage, HubPin, HubRef, HubSyncPolicy, ScanCompleteness,
    ScanRiskLevel, ScanVerdict, SkillGovernance, SkillHubAdapter, SkillHubKind, SkillHubRecord,
    SkillHubTrustTier, SkillScanReceipt,
};
use crate::store::GateDecisionId;
use crate::test_util::entity;
use crate::{EntityId, Error, Result, TimeRange, Vault, VaultConfig};

fn open_vault() -> (tempfile::TempDir, Vault) {
    let mut config = VaultConfig::device();
    config.map_size = 16 * 1024 * 1024;
    config.dimensions = 4;
    config.embedding_model = None;
    crate::test_util::open_test_vault_with(config)
}

/// One scanner's verdict at `risk` on the bytes `skill` carries.
fn scan(
    vault: &Vault,
    skill: &EntityId,
    bytes: SkillContentHash,
    provider: &str,
    risk: ScanRiskLevel,
) -> Result<EntityId> {
    let receipt = SkillScanReceipt::new(
        provider,
        10,
        ScanVerdict::Unknown,
        risk,
        ScanCompleteness::Complete,
        SkillGovernance::Recommended,
    )?;
    vault.ingest_skill_scan_verdict(skill, bytes, &receipt, TimeRange { start: 10, end: 10 }, 10)
}

/// The gate reads a skill's verdicts through the `claim_of` edges of its
/// bytes' content anchor. A verdict above the dial whose edge reaches the
/// anchor since the backup, its body unchanged, is one a restore would take
/// off it; a verdict below the dial changes nothing.
pub(super) fn skill_activations() -> Result<Case> {
    let (dir, vault) = open_vault();
    let skill = entity(0xC1);
    let bytes = canonical_skill_tree_hash([("SKILL.md", b"# fixture skill\n".as_slice())])?;
    let mut record = SkillRecord::new(
        "fixture.skill",
        "fixture description",
        "1.0.0",
        ClaimApprovalStatus::Auto,
        SkillLifecycle::Candidate,
        ClaimSource::UserStated,
        1.0,
        false,
        true,
        Vec::new(),
        rmpv::Value::Map(vec![(
            rmpv::Value::from("source"),
            rmpv::Value::from("fixture"),
        )]),
    );
    record.content_hash = Some(bytes);
    vault.put_skill_record(&skill, &record, TimeRange { start: 5, end: 5 }, 5)?;
    let flagged = scan(
        &vault,
        &skill,
        bytes,
        "fixture.scanner",
        ScanRiskLevel::High,
    )?;
    let Some(ClaimSubject::Entity(anchor)) = vault.get_claim(&flagged)?.map(|claim| claim.subject)
    else {
        return Err(Error::EntityNotFound);
    };
    vault.delete_edge(&flagged, EdgeKind::ClaimOf, &anchor)?;
    Case::after_backup(
        "skill activations",
        (dir, vault),
        move |vault| scan(vault, &skill, bytes, "fixture.linter", ScanRiskLevel::Low).map(drop),
        move |vault| vault.put_edge(&flagged, EdgeKind::ClaimOf, &anchor, 1.0),
    )
}

/// The name both pack sources install under.
const PACK: &str = "fixture.echo";
/// The configured hub's index, which the fixture adapter stands in for.
const HUB_INDEX: &str = "https://example.invalid/packs.json";

/// A capability pack under `PACK` whose adapter is the echo script.
fn script_source() -> Result<PackSource> {
    PackSource::from_files(vec![
        HubFile::new(
            "PACK.md",
            b"---\nname: fixture.echo\ndescription: echo fixture\nversion: 1\nkind: capability\nadapter: script:scripts/adapter.js\ngrants: [\"email\"]\nwakes: [\"email.arrived\"]\n---\n".to_vec(),
        ),
        HubFile::new(
            "scripts/adapter.js",
            include_bytes!("../../../../../tests/fixtures/echo_pack/scripts/adapter.js").to_vec(),
        ),
        HubFile::new(
            "scripts/input.json",
            include_bytes!("../../../../../tests/fixtures/echo_pack/scripts/input.json").to_vec(),
        ),
    ])
}

/// A later version under `PACK` that carries data only: no adapter, no
/// script.
fn data_source() -> Result<PackSource> {
    PackSource::from_files(vec![HubFile::new(
        "PACK.md",
        b"---\nname: fixture.echo\ndescription: echo fixture\nversion: 2\nkind: capability\n---\nEcho data only.\n".to_vec(),
    )])
}

/// A vault as a host opens one, its seeded pack-install policy in force, with
/// an owner who configured one verified hub and admitted a publisher on it.
fn pack_vault() -> Result<(tempfile::TempDir, Vault, ForeignSkillPublisher, EntityId)> {
    let mut config = VaultConfig::device();
    config.map_size = 64 * 1024 * 1024;
    config.dimensions = 4;
    config.embedding_model = None;
    let dir = tempfile::tempdir()?;
    let vault = Vault::open(dir.path(), config)?;
    let at = TimeRange { start: 1, end: 1 };
    let (owner, hub) = (entity(0xC5), entity(0xC6));
    vault.put_entity(&owner, ENTITY_TYPE_PERSON, at, 1, b"owner")?;
    let owner =
        vault.authenticate_owner(owner, "principal:pack-owner", true, GateDecisionId::now())?;
    let record = SkillHubRecord::new(
        SkillHubKind::HttpIndex,
        HUB_INDEX,
        SkillHubTrustTier::Verified,
        HubSyncPolicy::ContentHashFrozen,
    )?;
    vault.configure_skill_hub(&owner, &hub, &record, at, 1)?;
    let publisher = vault.admit_skill_publisher(&owner, "publisher:pack-author", hub)?;
    Ok((dir, vault, publisher, hub))
}

/// The hub's adapter serving one held source.
struct HeldSource {
    hub: EntityId,
    source: PackSource,
}

impl SkillHubAdapter for HeldSource {
    fn hub_id(&self) -> EntityId {
        self.hub
    }
    fn kind(&self) -> SkillHubKind {
        SkillHubKind::HttpIndex
    }
    fn endpoint(&self) -> Option<&str> {
        Some(HUB_INDEX)
    }
    fn fetch_package(&self, _: &HubRef) -> Result<HubPackage> {
        Err(Error::EntityNotFound)
    }
}

impl PackSourceAdapter for HeldSource {
    fn fetch_pack_source(&self, _: &HubRef) -> Result<PackSource> {
        Ok(self.source.clone())
    }
}

/// Fetches `source` from `hub` through the publisher, pinned to its bytes.
fn fetch(
    vault: &Vault,
    hub: EntityId,
    publisher: &ForeignSkillPublisher,
    source: PackSource,
) -> Result<(EntityId, HubRef)> {
    let pin = HubPin::ContentHash(source.content_hash().to_hex());
    let reference = HubRef::new(hub, "pack", pin)?;
    let adapter = HeldSource { hub, source };
    let at = TimeRange { start: 3, end: 3 };
    vault.fetch_pack_from_adapter(&adapter, &reference, publisher, at, 3)
}

/// The host's fit ladder: every source fits and may run code once qualified.
/// A script qualifies on the code-mode interpreter, its suite reporting
/// `report`; a rule hit keeps a source a candidate.
struct Fit {
    report: &'static str,
    rules_hit: bool,
}

impl PackFitPolicy for Fit {
    fn evaluate(&self, _: &PackSource, _: &PackPermissions) -> Result<PackFitVerdict> {
        Ok(PackFitVerdict {
            fits: true,
            rules_hit: self.rules_hit,
            code_auto_install: true,
        })
    }

    fn qualify_script(&self, source: &PackSource) -> Result<Option<PackQualification>> {
        Ok(Some(PackQualification {
            suite: "fixture".to_owned(),
            report_hash: self.report.repeat(32),
            passed: true,
            advisory_accepted: true,
            advisory: "fixture".to_owned(),
            runtime: source
                .manifest()
                .adapter
                .clone()
                .map(|adapter| PackRuntimeRecipe {
                    adapter,
                    runtime_id: SANDBOX_JS_COMPONENT_NAME.to_owned(),
                    runtime_hash: "23".repeat(32),
                }),
        }))
    }
}

/// The fit a source installs `Active` under.
const QUALIFIED: Fit = Fit {
    report: "12",
    rules_hit: false,
};

/// Installs the fetched source `id` under `fit`, as the owner's tap on its
/// ask does; it must land with `status`.
fn install(
    vault: &Vault,
    publisher: &ForeignSkillPublisher,
    (id, pinned): &(EntityId, HubRef),
    fit: &Fit,
    status: PackInstallStatus,
) -> Result<()> {
    let ask = vault.prepare_pack_install(*id, pinned, publisher, fit)?;
    match vault.install_pack(&ask)? {
        PackInstallDisposition::Installed(receipt) | PackInstallDisposition::Candidate(receipt)
            if receipt.status == status =>
        {
            Ok(())
        }
        other => Err(Error::InvalidConfig(format!("the pack landed {other:?}"))),
    }
}

/// A script run selects the name's script by its `Active` install receipt.
/// The script requalified since the backup on the same runtime, and a
/// data-only source the rules hold a candidate, leave the name running it;
/// the data-only source installed under the name since runs no script, which
/// a restore would run again.
pub(super) fn installed_script_packs() -> Result<Case> {
    let (dir, vault, publisher, hub) = pack_vault()?;
    let script = fetch(&vault, hub, &publisher, script_source()?)?;
    let data = fetch(&vault, hub, &publisher, data_source()?)?;
    install(
        &vault,
        &publisher,
        &script,
        &QUALIFIED,
        PackInstallStatus::Active,
    )?;
    let (routine_publisher, routine_data) = (publisher.clone(), data.clone());
    Case::after_backup(
        "installed script packs",
        (dir, vault),
        move |vault| {
            let requalified = Fit {
                report: "34",
                rules_hit: false,
            };
            install(
                vault,
                &routine_publisher,
                &script,
                &requalified,
                PackInstallStatus::Active,
            )?;
            let held = Fit {
                report: "12",
                rules_hit: true,
            };
            install(
                vault,
                &routine_publisher,
                &routine_data,
                &held,
                PackInstallStatus::Candidate,
            )
        },
        move |vault| {
            install(
                vault,
                &publisher,
                &data,
                &QUALIFIED,
                PackInstallStatus::Active,
            )
        },
    )
}

/// ASTRA-9A-2-R4 R4-5: a data-only source installed under a script pack's
/// name since the backup leaves the name running no script, with both
/// sources still held. A plain restore takes the name back to the script,
/// which passes a run's preflight again without qualifying again; a restore
/// beside the vault refuses that. A script installed only since the backup
/// leaves with a restore, which goes ahead.
#[test]
fn a_restore_never_reselects_a_script_pack_replaced_since() -> Result<()> {
    let (_dir, vault, publisher, hub) = pack_vault()?;
    let script = fetch(&vault, hub, &publisher, script_source()?)?;
    let data = fetch(&vault, hub, &publisher, data_source()?)?;
    let backups = tempfile::tempdir()?;
    let restore = |image: &std::path::Path, destination: &std::path::Path| {
        Vault::restore_checkpoint_keeping_authority(
            image,
            destination,
            vault.config.clone(),
            &vault,
            1_000,
        )
        .map(|(restored, _)| restored)
    };

    let unscripted = backups.path().join("unscripted");
    vault.snapshot_checkpoint(&unscripted, 100)?;
    install(
        &vault,
        &publisher,
        &script,
        &QUALIFIED,
        PackInstallStatus::Active,
    )?;
    let restored = restore(&unscripted, &backups.path().join("dropped"))?;
    assert!(restored.installed_pack(PACK)?.is_none());
    drop(restored);

    let scripted = backups.path().join("scripted");
    vault.snapshot_checkpoint(&scripted, 200)?;
    install(
        &vault,
        &publisher,
        &data,
        &QUALIFIED,
        PackInstallStatus::Active,
    )?;
    assert!(vault.installed_script_pack(PACK).is_err());
    assert!(vault.get_pack_source(&script.0)?.is_some());
    let (historical, _) = Vault::restore_checkpoint(
        &scripted,
        &backups.path().join("historical"),
        vault.config.clone(),
        RestoreReason::Restore,
        1_000,
    )?;
    let (selected, _, _) = historical.installed_script_pack(PACK)?;
    assert_eq!(selected.entity_id()?, script.0);
    drop(historical);
    let destination = backups.path().join("beside");
    let error = restore(&scripted, &destination)
        .err()
        .expect("the restore must be refused");
    assert!(
        error.to_string().contains("installed script packs"),
        "{error}"
    );
    assert!(!destination.exists());
    Ok(())
}
