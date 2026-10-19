//! The repo secret manifest, read from a repository the vault serves as
//! origin (ARCH-0069 S2; ARCH-0068 RC4 and its secrets split).
//!
//! A repository declares its secrets in one file at [`SECRET_MANIFEST_PATH`]:
//! names, classes, bindings and the repo-relative paths that hold values. The
//! file is read at a ref the vault PUBLISHED. The publication journal, never a
//! raw ref, says which commit that is, as it does for every ref the origin
//! advertises. Declared paths are relative to the repository root, so the one
//! file reads the same in the origin, in each checkout and in each mirror
//! clone, which is where snapshot exclusion matches them.

use std::path::Path;

use crate::Vault;
use crate::codebase::RepoRef;
use crate::entity_id::EntityId;
use crate::error::{Error, Result, SecretError};
use crate::git_wire::{GitOid, GitRefName, GitWire, GitWireRepo};
use crate::origin::lfs::lfs_repo_id;
use crate::origin::publication::OriginPublicationStatus;
use crate::origin::smart_http::{
    ORIGIN_REPO_DIR_SUFFIX, ORIGIN_SERVING_ROOT_NAME, origin_repo_dir, validate_repo_name,
};
use crate::secret_manifest::{SecretManifest, parse_secret_manifest};

/// Where a repository declares its secrets, relative to its root.
///
/// The name says what the file is: it declares and never holds a value. A
/// root `secrets.toml` is where several frameworks keep values, and common
/// ignore templates leave it out of commits; a manifest must be committed.
pub const SECRET_MANIFEST_PATH: &str = ".oneiron/secret-manifest.toml";

/// The largest manifest read: names and paths, far below this.
const MANIFEST_LIMIT: usize = 256 * 1024;

/// A manifest read from one published commit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OriginSecretManifest {
    /// `<repo>:<ref>@<commit>:<path>`, kept on each record registered from it.
    pub manifest_ref: String,
    /// The parsed declaration.
    pub manifest: SecretManifest,
    /// The file's text at that commit: the snapshot a register hands a
    /// holder that is not this install (CALLS CUSTODY_MANIFEST_RECHECK).
    pub text: String,
}

impl Vault {
    /// Reads the secret manifest of the served repository `repo_name` at the
    /// commit the vault published for `ref_name`.
    ///
    /// # Errors
    /// The origin's own errors for a repository name that is malformed or
    /// serves nothing; [`SecretError::SecretManifestNotFound`] when the ref is
    /// not published or its commit has no manifest file; the parser's error
    /// for a manifest that does not parse.
    pub fn origin_secret_manifest(
        &self,
        repo_name: &str,
        ref_name: &str,
    ) -> Result<OriginSecretManifest> {
        let repo_dir = origin_repo_dir(self, repo_name)?;
        let ref_name = GitRefName::parse_full(ref_name)?;
        // A branch names a commit, and git refuses any other object there. A
        // tag may name a tag object, which pins no repository and holds no
        // tree to read.
        if !ref_name.as_str().starts_with("refs/heads/") {
            return Err(Error::Secret(SecretError::InvalidSecretCustodyBody(
                "a secret manifest is read from a branch, refs/heads/...",
            )));
        }
        let source_ref = format!("{repo_name}:{}", ref_name.as_str());
        let not_found = || {
            Error::Secret(SecretError::SecretManifestNotFound {
                source_ref: source_ref.clone(),
            })
        };
        let wire = GitWire::new(self)?;
        let (repo_id, repo) = self
            .published_origin_repo(&wire, &repo_dir)?
            .ok_or_else(not_found)?;
        let commit = self
            .published_origin_refs(&wire, repo_id, &repo)?
            .into_iter()
            .find_map(|(name, oid)| (name == ref_name).then_some(oid))
            .ok_or_else(not_found)?;
        let bytes = manifest_bytes(&wire, &repo, &commit)?.ok_or_else(not_found)?;
        let text = String::from_utf8(bytes).map_err(|_| {
            Error::Secret(SecretError::InvalidSecretCustodyBody(
                "secret manifest must be UTF-8",
            ))
        })?;
        Ok(OriginSecretManifest {
            manifest_ref: format!("{source_ref}@{}:{SECRET_MANIFEST_PATH}", commit.as_str()),
            manifest: parse_secret_manifest(&text)?,
            text,
        })
    }
}

impl Vault {
    /// The served repository at `repo_dir` opened through a commit it
    /// published, with its id: where its published refs are read. `None`
    /// when no commit it published opens.
    fn published_origin_repo(
        &self,
        wire: &GitWire<'_>,
        repo_dir: &Path,
    ) -> Result<Option<(EntityId, GitWireRepo)>> {
        let repo_id = lfs_repo_id(&wire.repository_identity(repo_dir)?.as_hex())?;
        let path = repo_dir
            .to_str()
            .ok_or(Error::InvariantViolation("origin repo path must be UTF-8"))?;
        // A pin only proves which object store the handle names, and only a
        // commit can: any commit this repository published will do, and a
        // visible slot names one without reading the publication history.
        // Which object the ref names NOW is the projection's answer, as for
        // an advertisement, and only a commit there holds a manifest.
        for id in self.origin_visible_ref_rows(&repo_id)? {
            let Some(record) = self.origin_publication(id)? else {
                continue;
            };
            if record.status != OriginPublicationStatus::Published {
                continue;
            }
            let repo_ref = RepoRef::parse(&format!("local:{path}#{}", record.new_oid.as_str()))?;
            if let Ok(handle) = wire.open_repo(repo_ref, repo_dir) {
                return Ok(Some((repo_id, handle)));
            }
        }
        Ok(None)
    }

    /// Every secret manifest the vault publishes now: the manifest file that
    /// parses at the commit this vault publishes for each branch of each
    /// repository it serves, ordered by `manifest_ref` (CALLS
    /// CUSTODY_MANIFEST_UNSTATED_MULTI). The publication journal is the
    /// approval: a ref counts only while the vault advertises it, as for
    /// [`Vault::origin_secret_manifest`]. No count is capped. An empty list
    /// says none is published.
    ///
    /// # Errors
    /// The manifests could not be read, which never says that none is
    /// published: the origin's, git's and the store's own errors.
    pub(crate) fn published_origin_secret_manifests(&self) -> Result<Vec<OriginSecretManifest>> {
        let mut found = self.current_origin_secret_manifests(usize::MAX)?;
        found.sort_by(|left, right| left.manifest_ref.cmp(&right.manifest_ref));
        Ok(found)
    }

    /// Up to `limit` manifests that parse at the commits this vault
    /// publishes now for the branches of the repositories it serves, by
    /// repository name, then as the projection lists the refs.
    fn current_origin_secret_manifests(&self, limit: usize) -> Result<Vec<OriginSecretManifest>> {
        // Looked up, never created: a vault that serves nothing has none.
        let root = self.store.env.path().join(ORIGIN_SERVING_ROOT_NAME);
        if !root.is_dir() {
            return Ok(Vec::new());
        }
        let mut names = Vec::new();
        for entry in std::fs::read_dir(&root)? {
            let entry = entry?;
            if let Some(name) = entry
                .file_name()
                .to_str()
                .and_then(|name| name.strip_suffix(ORIGIN_REPO_DIR_SUFFIX))
                && validate_repo_name(name).is_ok()
                && entry.file_type()?.is_dir()
            {
                names.push(name.to_owned());
            }
        }
        names.sort();
        let wire = GitWire::new(self)?;
        let mut found = Vec::new();
        for repo_name in names {
            let repo_dir = origin_repo_dir(self, &repo_name)?;
            let Some((repo_id, repo)) = self.published_origin_repo(&wire, &repo_dir)? else {
                continue;
            };
            for (ref_name, commit) in self.published_origin_refs(&wire, repo_id, &repo)? {
                if !ref_name.as_str().starts_with("refs/heads/") {
                    continue;
                }
                let Some(text) = manifest_bytes(&wire, &repo, &commit)?
                    .and_then(|bytes| String::from_utf8(bytes).ok())
                else {
                    continue;
                };
                let Ok(manifest) = parse_secret_manifest(&text) else {
                    continue;
                };
                found.push(OriginSecretManifest {
                    manifest_ref: format!(
                        "{repo_name}:{}@{}:{SECRET_MANIFEST_PATH}",
                        ref_name.as_str(),
                        commit.as_str()
                    ),
                    manifest,
                    text,
                });
                if found.len() >= limit {
                    return Ok(found);
                }
            }
        }
        Ok(found)
    }

    /// Reads the manifest a record's `manifest_ref`,
    /// `<repo>:<ref>@<commit>:<path>`, names, as this vault publishes it now:
    /// the snapshot a recorder attaches to a register the owner's surface
    /// sealed (CALLS CUSTODY_MANIFEST_RECHECK).
    ///
    /// # Errors
    /// [`SecretError::SecretManifestNotFound`] naming `manifest_ref` when it
    /// is malformed, its ref is not published here, the ref now names another
    /// commit, or that commit holds no manifest; the origin's and the
    /// parser's own errors otherwise.
    pub(crate) fn origin_secret_manifest_at(
        &self,
        manifest_ref: &str,
    ) -> Result<OriginSecretManifest> {
        let unknown = || {
            Error::Secret(SecretError::SecretManifestNotFound {
                source_ref: manifest_ref.to_owned(),
            })
        };
        let (source, _) = manifest_ref.rsplit_once('@').ok_or_else(unknown)?;
        let (repo, git_ref) = source.split_once(':').ok_or_else(unknown)?;
        let manifest = match self.origin_secret_manifest(repo, git_ref) {
            Ok(manifest) => manifest,
            Err(Error::Secret(SecretError::SecretManifestNotFound { .. })) => return Err(unknown()),
            Err(error) => return Err(error),
        };
        if manifest.manifest_ref != manifest_ref {
            return Err(unknown());
        }
        Ok(manifest)
    }
}

/// The manifest file's bytes in `commit`'s tree, or `None` when it has none
/// or `commit` names no commit. Only a regular file counts: a symlink or a
/// submodule at the path declares nothing.
fn manifest_bytes(
    wire: &GitWire<'_>,
    repo: &GitWireRepo,
    commit: &GitOid,
) -> Result<Option<Vec<u8>>> {
    // Only a commit holds a manifest. A ref published at a tag or a blob
    // declares nothing, whatever its bytes look like, and is never read.
    if wire
        .object_info(repo, std::slice::from_ref(commit))?
        .get(commit)
        .map(String::as_str)
        != Some("commit")
    {
        return Ok(None);
    }
    // `ls-tree` on a commit lists its root tree; the commit's own body is
    // never read. Each step asks git for the one component it wants: a
    // published tree may be too wide to list in full within the process's
    // output bound.
    let mut oid = commit.clone();
    let mut components = SECRET_MANIFEST_PATH.split('/').peekable();
    while let Some(component) = components.next() {
        let last = components.peek().is_none();
        let wanted = |mode: u32| {
            if last {
                matches!(mode, 0o100644 | 0o100755)
            } else {
                mode == 0o040000
            }
        };
        let Some(entry) = wire
            .read_tree_entry(repo, &oid, component)?
            .filter(|entry| wanted(entry.mode))
        else {
            return Ok(None);
        };
        oid = entry.oid;
    }
    // Sized before it is read: past the process's output bound the read
    // fails as a whole, and that is no answer to give the owner.
    match wire.object_size(repo, &oid)? {
        None => Ok(None),
        Some(size) if size > MANIFEST_LIMIT as u64 => Err(Error::Secret(
            SecretError::InvalidSecretCustodyBody("secret manifest is larger than 256 KiB"),
        )),
        Some(_) => Ok(Some(wire.read_object(repo, &oid)?)),
    }
}
