//! Census case for what the publication and build-cache doors admit of a
//! retained output by its taint.
use super::Case;
use crate::artifact_hosting::ArtifactPointerChannel;
use crate::blob_artifact::{BlobArtifactBody, BlobVersionProvenance};
use crate::build_cache::{
    ActionKey, ActionResult, ArtifactVersionRef, BuildAction, BuildCache, BuildCacheError,
    BuildInputRoot, BuildPlatform, DeclaredOutputPath, FrozenBuildCommand,
};
use crate::code_artifact::{CODE_ARTIFACT_SUMMARY_HASH_LEN, CodeArtifactBody, CodeArtifactClass};
use crate::codebase::{CodebaseFileEntry, CodebaseForkHash, CodebaseSnapshot, RepoRef};
use crate::edge::EdgeActorClass;
use crate::error::SecretError;
use crate::recovery::checkpoint::RestoreReason;
use crate::registry::ENTITY_TYPE_PERSON;
use crate::secret_custody::{
    CustodyClass, SECRET_CUSTODY_SCHEMA_VERSION, SecretCustodyFloor, SecretCustodyRecord,
    SecretCustodyStatus,
};
use crate::secret_lease::SecretTaintRef;
use crate::test_util::entity;
use crate::write_envelope::WriteActor;
use crate::{EntityId, Error, Result, TimeRange, Vault, VaultConfig};
use std::collections::BTreeMap;

fn open_vault() -> (tempfile::TempDir, Vault) {
    let mut config = VaultConfig::device();
    config.map_size = 16 * 1024 * 1024;
    config.dimensions = 4;
    config.embedding_model = None;
    crate::test_util::open_test_vault_with(config)
}

const AT: TimeRange = TimeRange { start: 10, end: 10 };

/// The secret every taint here names.
const SECRET: &str = "build-token";

/// The project a site's snapshot is published under.
const SITE: &str = "site";

const COMMIT: &str = "9d561405a81ffbf29d1369cd848e0ef9fca4f277";

fn invalid(error: impl std::fmt::Debug) -> Error {
    Error::InvalidConfig(format!("{error:?}"))
}

/// Registers the secret and revokes it, both before any backup: the custody a
/// restore compares stays as it was, and a taint naming it reads stale.
fn revoked_secret(vault: &Vault) -> Result<()> {
    vault.register_secret(SecretCustodyRecord {
        schema_version: SECRET_CUSTODY_SCHEMA_VERSION,
        name: SECRET.to_owned(),
        class: CustodyClass::CustodyPortable,
        device_only: false,
        value_bytes: b"census taint value".to_vec(),
        status: SecretCustodyStatus::Active,
        registered_at: 1,
        rotated_at: None,
        rotation_generation: 0,
        bindings: Vec::new(),
        manifest_ref: "secrets.toml".to_owned(),
        declared_paths: vec![".secrets/api.key".to_owned()],
        policy_floor_snapshot: SecretCustodyFloor::default(),
    })?;
    vault.revoke_secret(SECRET, 2).map(drop)
}

/// A taint naming the revoked secret at the generation it died at.
fn stale_taint() -> [SecretTaintRef; 1] {
    [SecretTaintRef {
        secret_ref: SECRET.to_owned(),
        generation: 0,
    }]
}

fn site_repo() -> Result<RepoRef> {
    RepoRef::parse(&format!("github:oneiron-dev/oneiron#{COMMIT}"))
}

/// The code artifact `id`, of the class a site is published from, with
/// `summary` as its summary prompt.
fn put_site_body(vault: &Vault, id: EntityId, summary: &str) -> Result<()> {
    let body = CodeArtifactBody::new(
        summary,
        [0xA5; CODE_ARTIFACT_SUMMARY_HASH_LEN],
        site_repo()?.canonical(),
    )
    .with_class(CodeArtifactClass::Artifact);
    vault.put_code_artifact(&id, &body, AT, 10)
}

/// A publishable site at `id`, its artifact and a one-file snapshot put
/// through the store doors. Returns the snapshot's fork.
fn publishable_site(vault: &Vault, id: EntityId) -> Result<CodebaseForkHash> {
    put_site_body(vault, id, "Summarize the artifact snapshot.")?;
    let snapshot = CodebaseSnapshot::new(
        SITE,
        site_repo()?,
        Some(COMMIT.to_owned()),
        vec![CodebaseFileEntry::new(
            "index.html",
            *blake3::hash(b"").as_bytes(),
            0,
        )],
    )?;
    vault.put_codebase_snapshot(&id, &snapshot, &|_| Some(Vec::new()))?;
    Ok(snapshot.fork_hash)
}

/// Whether `vault` refuses to publish the site at `fork` for its stale taint.
fn publish_refused_stale(vault: &Vault, fork: &CodebaseForkHash) -> bool {
    matches!(
        vault.publish_artifact_pointer(SITE, ArtifactPointerChannel::Preview, fork),
        Err(Error::Secret(SecretError::TaintedArtifactStale { .. }))
    )
}

/// Uploads `bytes` as the next version of `artifact`, returning its number.
fn upload(vault: &Vault, uploader: EntityId, artifact: EntityId, bytes: &[u8]) -> Result<u64> {
    let version = vault.append_blob_artifact_version(
        &artifact,
        bytes,
        &BlobVersionProvenance::UserUpload,
        WriteActor::new(uploader, EdgeActorClass::Human),
        AT,
        11,
    )?;
    Ok(version.version)
}

/// A build output `artifact` that `uploader` uploads, and the cached result
/// of the action that built it to `path`. Returns the action's key.
fn cached_build(
    vault: &Vault,
    uploader: EntityId,
    artifact: EntityId,
    path: &str,
) -> Result<ActionKey> {
    vault.put_blob_artifact(
        &artifact,
        &BlobArtifactBody::new("build.bin", "application/octet-stream"),
        AT,
        10,
    )?;
    let version = upload(vault, uploader, artifact, path.as_bytes())?;
    let path = DeclaredOutputPath::parse(path).map_err(invalid)?;
    let action = BuildAction::new(
        FrozenBuildCommand::new(vec!["cc".to_owned(), "main.c".to_owned()], [("A", "1")])
            .map_err(invalid)?,
        BuildInputRoot {
            repo_ref: RepoRef::parse(&format!("local:/source#{}", "a".repeat(40)))?,
            fork_hash: [1; 32],
            extra_inputs: Vec::new(),
        },
        BuildPlatform::new([("os", "linux")]).map_err(invalid)?,
        vec![path.clone()],
    )
    .map_err(invalid)?;
    let result = ActionResult {
        exit_code: 0,
        outputs: BTreeMap::from([(
            path,
            ArtifactVersionRef::new(artifact, version).map_err(invalid)?,
        )]),
        stdout_ref: None,
        stderr_ref: None,
        produced_at: 42,
        producer_ref: "executor:first".to_owned(),
    };
    BuildCache::new(vault)
        .put(&action, result)
        .map_err(invalid)?;
    action.action_key().map_err(invalid)
}

/// A stale taint holds a site's publication. One attached since the backup,
/// through the attachment door, to a site the backup holds unchanged is one a
/// restore would drop, publishing the site again; a new summary of the site
/// is content.
pub(super) fn artifact_taint_admissions() -> Result<Case> {
    let (dir, vault) = open_vault();
    revoked_secret(&vault)?;
    let site = entity(0xC1);
    let fork = publishable_site(&vault, site)?;
    Case::after_backup(
        "artifact taint admissions",
        (dir, vault),
        move |vault| put_site_body(vault, site, "Summarize the published site."),
        move |vault| {
            vault.mark_artifact_tainted(&site, &stale_taint())?;
            if publish_refused_stale(vault, &fork) {
                Ok(())
            } else {
                Err(Error::InvalidConfig(
                    "a stale-tainted site published".to_owned(),
                ))
            }
        },
    )
}

/// Astra R4-8. A taint attached since the backup, through the attachment
/// door, to a site and to a cached build output the backup holds unchanged
/// refuses the site's publication and the cached result's hit. An unguarded
/// restore drops it and admits both again, so the guarded restore is
/// refused. A later version of the output, and an output deleted since the
/// backup with its version and cached result in the backup, are content:
/// before the taint, the guarded restore goes ahead.
#[test]
fn a_restore_does_not_lift_a_taint_attached_since_the_backup() -> Result<()> {
    let (_dir, vault) = open_vault();
    revoked_secret(&vault)?;
    let site = entity(0xC1);
    let fork = publishable_site(&vault, site)?;
    let uploader = entity(0xC2);
    vault.put_entity(&uploader, ENTITY_TYPE_PERSON, AT, 10, b"uploader")?;
    let (output, deleted) = (entity(0xC3), entity(0xC4));
    let built = cached_build(&vault, uploader, output, "out/a")?;
    cached_build(&vault, uploader, deleted, "out/b")?;
    let backups = tempfile::tempdir()?;
    let image = backups.path().join("backup");
    vault.snapshot_checkpoint(&image, 100)?;
    let restore = |name: &str| {
        Vault::restore_checkpoint_keeping_authority(
            &image,
            &backups.path().join(name),
            vault.config.clone(),
            &vault,
            1_000,
        )
        .map(drop)
    };

    upload(&vault, uploader, output, b"output v2")?;
    assert!(vault.delete_entity(&deleted)?);
    if let Err(error) = restore("content") {
        panic!(
            "{error}{}",
            super::unread(&vault, &image, &backups.path().join("unread"))
        );
    }

    vault.mark_artifact_tainted(&site, &stale_taint())?;
    vault.mark_artifact_tainted(&output, &stale_taint())?;
    assert!(publish_refused_stale(&vault, &fork));
    assert!(matches!(
        BuildCache::new(&vault).get(&built),
        Err(BuildCacheError::TaintedResult { .. })
    ));

    let (unguarded, _) = Vault::restore_checkpoint(
        &image,
        &backups.path().join("unguarded"),
        vault.config.clone(),
        RestoreReason::Restore,
        1_000,
    )?;
    unguarded.publish_artifact_pointer(SITE, ArtifactPointerChannel::Preview, &fork)?;
    assert!(
        BuildCache::new(&unguarded)
            .get(&built)
            .map_err(invalid)?
            .is_some()
    );

    let refused = restore("tainted").expect_err("a restore that lifts the taint is refused");
    assert!(
        refused.to_string().contains("artifact taint admissions"),
        "{refused}"
    );
    Ok(())
}
