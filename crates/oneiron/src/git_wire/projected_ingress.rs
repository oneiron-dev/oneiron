//! A masked copy's private ingress (FIX 7608 slice 2b-ii-B2, ASK S): the
//! writable bare store a projection-bound push is received into, seeded
//! from the copy it was given.
//!
//! The ingress borrows the copy store's objects through its alternates and
//! starts with the copy's root refs at their copy tips, so a stock client
//! that fetched the copy pushes onto exactly what it was shown. It is
//! distinct from the canonical store and from the copy store: nothing
//! received here reaches either, and the canonical store's coordinator,
//! refs, Grant, lease and host epoch stay the push's authority. A ref the
//! seed already holds is left as a push moved it.

use std::path::{Path, PathBuf};

use super::failure::{classify_failure, invalid};
use super::import_fetch::init_private_bare_store;
use super::repo::repo_identity_for;
use super::{
    GitOid, GitRefExpectation, GitRefName, GitRefPublication, GitWire, GitWireOperation,
    GitWireRepo, GitWireResult,
};
use crate::codebase::RepoRef;

/// The bare store's directory inside an ingress's own directory.
const PROJECTION_INGRESS_REPO: &str = "repo.git";

impl GitWire<'_> {
    /// The private ingress at `root/repo.git`, made when absent: a bare
    /// store whose alternates name `copy_store`'s objects, holding each of
    /// `refs` (a root ref and its copy tip) where it holds nothing yet.
    ///
    /// # Errors
    /// A store that cannot be made, or a seed ref its publication refused.
    pub(crate) fn projection_ingress(
        &self,
        root: &Path,
        copy_store: &GitWireRepo,
        refs: &[(GitRefName, GitOid)],
        now: u64,
    ) -> GitWireResult<GitWireRepo> {
        std::fs::create_dir_all(root)?;
        let root = root.canonicalize()?;
        let repo_root = root.join(PROJECTION_INGRESS_REPO);
        if !repo_root.join("objects").exists() {
            let output =
                init_private_bare_store(&self.process_env, &root, PROJECTION_INGRESS_REPO)?;
            if !output.success {
                return Err(classify_failure(&output).error(GitWireOperation::ImportScratchInit));
            }
        }
        let repo_root = repo_root.canonicalize()?;
        let objects = copy_store.common_dir().join("objects");
        let objects = objects
            .to_str()
            .ok_or_else(|| invalid("a masked copy's object directory must be UTF-8"))?;
        std::fs::write(
            repo_root.join("objects").join("info").join("alternates"),
            format!("{objects}\n"),
        )?;
        let ingress = self.bind_projection_ingress(&repo_root)?;
        let names: Vec<GitRefName> = refs.iter().map(|(name, _)| name.clone()).collect();
        let held = self.read_refs(&ingress, &names)?;
        let seeds: Vec<GitRefPublication> = refs
            .iter()
            .filter(|(name, _)| {
                held.iter()
                    .all(|seen| seen.name != *name || seen.oid.is_none())
            })
            .map(|(name, copy)| {
                GitRefPublication::update(name.clone(), GitRefExpectation::Absent, copy.clone())
            })
            .collect();
        if !seeds.is_empty() {
            self.publish_projection_refs(&ingress, seeds, now)?;
        }
        Ok(ingress)
    }

    /// The private ingress at `root/repo.git`, or `None` when there is none.
    ///
    /// # Errors
    /// A store that is not its own common directory.
    pub(crate) fn existing_projection_ingress(
        &self,
        root: &Path,
    ) -> GitWireResult<Option<GitWireRepo>> {
        let candidate = root.join(PROJECTION_INGRESS_REPO);
        if !candidate.join("objects").exists() {
            return Ok(None);
        }
        self.bind_projection_ingress(&candidate.canonicalize()?)
            .map(Some)
    }

    /// The object-store identity of the ingress at `root/repo.git`, read
    /// from its path alone: an ingress is its own common directory.
    ///
    /// # Errors
    /// A path that does not resolve.
    pub(crate) fn projection_ingress_identity(root: &Path) -> GitWireResult<String> {
        let common_dir = root.join(PROJECTION_INGRESS_REPO).canonicalize()?;
        Ok(repo_identity_for(&common_dir).as_hex())
    }

    fn bind_projection_ingress(&self, repo_root: &Path) -> GitWireResult<GitWireRepo> {
        let common_dir = self.canonical_common_dir(repo_root)?;
        if common_dir != repo_root {
            return Err(invalid(
                "a masked copy's ingress must be its own common directory",
            ));
        }
        Ok(GitWireRepo {
            repo_ref: RepoRef::LocalFolder {
                path: repo_root.to_string_lossy().into_owned(),
                commit: String::new(),
            },
            repo_root: PathBuf::from(repo_root),
            identity: repo_identity_for(&common_dir),
            common_dir,
        })
    }
}
