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

use crate::Vault;
use crate::codebase::RepoRef;
use crate::error::{Error, Result, SecretError};
use crate::git_wire::{GitOid, GitRefName, GitWire, GitWireRepo};
use crate::origin::lfs::lfs_repo_id;
use crate::origin::publication::OriginPublicationStatus;
use crate::origin::smart_http::origin_repo_dir;
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
        let repo_id = lfs_repo_id(&wire.repository_identity(&repo_dir)?.as_hex())?;
        let path = repo_dir
            .to_str()
            .ok_or(Error::InvariantViolation("origin repo path must be UTF-8"))?;
        // A pin only proves which object store the handle names, and only a
        // commit can: any commit this repository published will do. Which
        // object the ref names NOW is the projection's answer below, as for an
        // advertisement. A ref published at a tag object pins nothing and
        // holds no manifest.
        let mut repo = None;
        for id in self.origin_publication_ids(Some(repo_id))? {
            let Some(record) = self.origin_publication(id)? else {
                continue;
            };
            if record.status != OriginPublicationStatus::Published {
                continue;
            }
            let repo_ref = RepoRef::parse(&format!("local:{path}#{}", record.new_oid.as_str()))?;
            if let Ok(handle) = wire.open_repo(repo_ref, &repo_dir) {
                repo = Some(handle);
                break;
            }
        }
        let repo = repo.ok_or_else(not_found)?;
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
        })
    }
}

/// The manifest file's bytes in `commit`'s tree, or `None` when it has none.
/// Only a regular file counts: a symlink or a submodule at the path declares
/// nothing.
fn manifest_bytes(
    wire: &GitWire<'_>,
    repo: &GitWireRepo,
    commit: &GitOid,
) -> Result<Option<Vec<u8>>> {
    let object = wire.read_object(repo, commit)?;
    // Anything but a commit holds no manifest.
    let Some(tree) = object
        .split(|byte| *byte == b'\n')
        .next()
        .and_then(|line| line.strip_prefix(b"tree "))
        .and_then(|hex| std::str::from_utf8(hex).ok())
    else {
        return Ok(None);
    };
    let mut oid = GitOid::parse_hex(tree)?;
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
            .read_tree(repo, &oid)?
            .into_iter()
            .find(|entry| entry.name == component.as_bytes() && wanted(entry.mode))
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
