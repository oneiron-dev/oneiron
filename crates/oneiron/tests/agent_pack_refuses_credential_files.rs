//! An agent pack keeps clean skill files byte-exact and refuses any skill file holding a credential.
//!
//! Run: `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron --all-features --test agent_pack_refuses_credential_files`.

// GAP: No existing integration test models export_agent_pack or SkillDependency construction.
// Both calls below use their existing public definitions; no test-only door is needed.

use base64::Engine as _;
use oneiron::agent_def::{AgentCeiling, AgentDefinition, AgentScope};
use oneiron::batch::export::ExportSourceContent;
use oneiron::claim::{ClaimApprovalStatus, ClaimLifecycleStatus, ClaimSource};
use oneiron::policy_model::SecretScanMode;
use oneiron::share_travel::AgentPackExportRequest;
use oneiron::skill::{SkillLifecycle, SkillRecord};
use oneiron::skill_hub::{HubFile, HubPackage, HubPin, HubRef, SkillCapabilitySurface};
use oneiron::store::GateDecisionId;
use oneiron::{EdgeActorClass, EntityId, TimeRange, Vault, VaultConfig};
use rmpv::Value;

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

struct Fixture {
    vault: Vault,
    owner: EntityId,
    agent: EntityId,
    package: HubPackage,
    _dir: tempfile::TempDir,
}

fn fixture(extra_file: Option<HubFile>) -> TestResult<Fixture> {
    let dir = tempfile::tempdir()?;
    let vault = Vault::open(dir.path(), VaultConfig::default())?;
    let owner = vault.ensure_embedded_owner_actor()?;
    let authenticated_owner =
        vault.authenticate_owner(owner, "owen@example.com", true, GateDecisionId::now())?;
    // Disable ingestion masking before the package lands, not merely before export.
    vault.set_secret_scan_mode(&authenticated_owner, SecretScanMode::Off, 10)?;

    let record = SkillRecord::new(
        "yuki",
        "Count input lines",
        "1.0.0",
        ClaimApprovalStatus::Approved,
        SkillLifecycle::Candidate,
        ClaimSource::Imported,
        0.5,
        false,
        true,
        vec![],
        Value::Map(vec![(Value::from("fixture"), Value::from("yuki"))]),
    );
    let mut files = vec![
        HubFile::new(
            "SKILL.md",
            b"---\nname: yuki\ndescription: Count input lines\nversion: 1.0.0\n---\nCount input lines.\n"
                .to_vec(),
        ),
        HubFile::new("scripts/count.py", b"print(3)\n".to_vec()),
        HubFile::new("references/readme.md", b"Exact reference bytes.\n".to_vec()),
    ];
    if let Some(file) = extra_file {
        files.push(file);
    }
    let mut package = HubPackage::new(record, files, SkillCapabilitySurface::default());
    package.record.content_hash = Some(package.content_hash()?);
    let skill = vault.import_skill_from_hub(
        &HubRef::new(EntityId::now(), "yuki", HubPin::None)?,
        &package,
        TimeRange {
            start: 100,
            end: 120,
        },
        130,
    )?;

    // The public owner archive reads the stored package without export nulling.
    // Check every file, including the credential fixture, before exercising the pack.
    let archive = vault.export_whole_vault(true)?;
    assert!(archive.manifest().secrets_included);
    let document = vault.read_whole_vault_archive(archive.bytes())?;
    let tree = document
        .skills
        .iter()
        .find(|bundle| bundle.entity.id == skill.to_hex())
        .expect("stored skill bundle")
        .source_tree
        .as_ref()
        .expect("stored skill source tree");
    assert_eq!(tree.files.len(), package.files.len());
    assert_eq!(tree.content_hash, Some(package.content_hash()?.to_hex()));
    for want in &package.files {
        let stored = tree
            .files
            .iter()
            .find(|file| file.path == want.path)
            .expect("stored package file");
        assert_eq!(
            stored.content,
            ExportSourceContent::Text(String::from_utf8(want.content.clone())?),
            "scan-off storage keeps {} byte-exact",
            want.path
        );
    }

    let agent = EntityId::now();
    vault.put_agent_definition(
        &agent,
        &AgentDefinition::new(
            "owen",
            "Count input lines",
            "1.0.0",
            None,
            vec![oneiron::skill::SkillDependency::new(
                package.record.skill_id.clone(),
            )],
            Vec::new(),
            Vec::new(),
            None,
            AgentScope::All,
            AgentCeiling::Proposed,
            None,
            ClaimApprovalStatus::Approved,
            ClaimLifecycleStatus::Active,
            ClaimSource::UserStated,
            1.0,
            false,
            true,
            Value::Map(vec![(Value::from("fixture"), Value::from("owen"))]),
            None,
            true,
            None,
        ),
        TimeRange {
            start: 140,
            end: 140,
        },
        140,
    )?;
    Ok(Fixture {
        vault,
        owner,
        agent,
        package,
        _dir: dir,
    })
}

fn assert_clean_pack_exports_exactly() -> TestResult {
    let fixture = fixture(None)?;
    let pack = fixture
        .vault
        .memory(fixture.owner, EdgeActorClass::Human)
        .export_agent_pack(&AgentPackExportRequest {
            agent_ref: fixture.agent.to_hex(),
            travel: None,
        })?;
    let prefix = format!("skills/{}/", fixture.package.content_hash()?.to_hex());
    assert_eq!(
        pack.files
            .iter()
            .filter(|file| file.path.starts_with(&prefix))
            .count(),
        fixture.package.files.len(),
        "the clean pack carries every skill file, with no extra skill file"
    );
    for want in &fixture.package.files {
        let path = format!("{prefix}{}", want.path);
        let carried = pack
            .files
            .iter()
            .find(|file| file.path == path)
            .expect("clean skill file in pack");
        let bytes = base64::engine::general_purpose::STANDARD.decode(&carried.content_base64)?;
        assert_eq!(
            bytes, want.content,
            "the pack keeps {} byte-exact",
            want.path
        );
    }
    Ok(())
}

#[test]
fn pack_with_clean_skill_files_exports_them_exactly() -> TestResult {
    assert_clean_pack_exports_exactly()
}

#[test]
fn pack_refuses_a_skill_file_with_an_assignment_credential() -> TestResult {
    assert_clean_pack_exports_exactly()?;
    let fixture = fixture(Some(HubFile::new(
        "scripts/private.py",
        b"api_key = 'residual-file-credential'\n".to_vec(),
    )))?;
    let result = fixture
        .vault
        .memory(fixture.owner, EdgeActorClass::Human)
        .export_agent_pack(&AgentPackExportRequest {
            agent_ref: fixture.agent.to_hex(),
            travel: None,
        });
    assert!(
        result.is_err(),
        "an agent pack must refuse a skill file holding an assignment credential"
    );
    let error = result
        .expect_err("credential-bearing skill file is refused")
        .to_string();
    assert!(error.contains("scripts/private.py"), "{error}");
    assert!(
        !error.contains("residual-file-credential"),
        "the refusal must not disclose the credential"
    );
    Ok(())
}

#[test]
fn pack_refuses_a_skill_file_with_a_signature_member() -> TestResult {
    assert_clean_pack_exports_exactly()?;
    let fixture = fixture(Some(HubFile::new(
        "signature.json",
        br#"{"signature":"residual-signature"}"#.to_vec(),
    )))?;
    let result = fixture
        .vault
        .memory(fixture.owner, EdgeActorClass::Human)
        .export_agent_pack(&AgentPackExportRequest {
            agent_ref: fixture.agent.to_hex(),
            travel: None,
        });
    assert!(
        result.is_err(),
        "an agent pack must refuse a skill file holding a signature member"
    );
    let error = result
        .expect_err("credential-bearing skill file is refused")
        .to_string();
    assert!(error.contains("signature.json"), "{error}");
    assert!(
        !error.contains("residual-signature"),
        "the refusal must not disclose the credential"
    );
    Ok(())
}
