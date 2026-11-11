//! The repository identity code symbols and code documents are keyed by
//! (FIX 12761).
//!
//! A symbol id and a code document's genesis id hash the repository they
//! belong to. That input is the repository's standing portable id (FIX
//! 6870) when one stands for its location, so moving or renaming the
//! repository keeps every symbol and document id while the moved location
//! binds the same portable repository. With no standing portable id, or two
//! for one location, it is the location itself: `local:<path>` or
//! `github:<owner>/<repo>`, as before. The revision a `RepoRef` pins is
//! never part of it.
//!
//! The identity is resolved once per extraction or document session and
//! then carried: a symbol manifest stores the identity its ids were derived
//! under, and a document session keeps the key it opened with. Readers
//! re-derive from what was stored, never from a fresh resolution. There is
//! no backfill and no old-identity reader: a repository whose standing
//! changes starts a new namespace at its next extraction.

use crate::Vault;
use crate::codebase::RepoRef;
use crate::error::Result;
use crate::origin::RepoPortableId;

/// The spelling prefix of a portable identity.
const PORTABLE_PREFIX: &str = "portable:";
/// The spelling prefix of a local folder location identity.
const LOCAL_PREFIX: &str = "local:";
/// The spelling prefix of a GitHub location identity.
const GITHUB_PREFIX: &str = "github:";

/// One repository's identity, by its canonical spelling (module docs).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct RepoIdentity(String);

impl RepoIdentity {
    /// The identity of the location `repo` names, its revision left out:
    /// what a repository with no standing portable id is keyed by.
    #[must_use]
    pub fn from_location(repo: &RepoRef) -> Self {
        Self(match repo {
            RepoRef::LocalFolder { path, .. } | RepoRef::LocalCapture { path } => {
                format!("{LOCAL_PREFIX}{path}")
            }
            RepoRef::GitHubAtCommit { owner, repo, .. } => {
                format!("{GITHUB_PREFIX}{owner}/{repo}")
            }
        })
    }

    /// The identity of the portable repository `portable`.
    #[must_use]
    pub fn from_portable(portable: &RepoPortableId) -> Self {
        Self(format!("{PORTABLE_PREFIX}{}", portable.to_hex()))
    }

    /// The identity a stored key spells, or `None` for anything but one of
    /// the three spellings. It resolves nothing: an alias or a stale
    /// portable id is read as it was stored.
    #[must_use]
    pub fn from_key(key: &str) -> Option<Self> {
        let well_formed = if let Some(hex) = key.strip_prefix(PORTABLE_PREFIX) {
            RepoPortableId::from_hex(hex).is_some()
        } else if let Some(path) = key.strip_prefix(LOCAL_PREFIX) {
            !path.is_empty()
        } else if let Some(name) = key.strip_prefix(GITHUB_PREFIX) {
            name.split_once('/')
                .is_some_and(|(owner, repo)| !owner.is_empty() && !repo.is_empty())
        } else {
            false
        };
        well_formed.then(|| Self(key.to_owned()))
    }

    /// The identity's canonical spelling: the key its ids hash.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// The identity of the repository at `repo` in `txn`: its standing
/// portable id, else its location (module docs). It reads only.
///
/// # Errors
/// A store failure.
pub(crate) fn resolve_repo_identity_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    repo: &RepoRef,
) -> Result<RepoIdentity> {
    Ok(
        match crate::origin::standing_portable_id_for_location_in_txn(vault, txn, repo)? {
            Some(portable) => RepoIdentity::from_portable(&portable),
            None => RepoIdentity::from_location(repo),
        },
    )
}

impl Vault {
    /// The identity code symbols and code documents of the repository at
    /// `repo` are keyed by now (FIX 12761): its standing portable id, else
    /// its location.
    ///
    /// # Errors
    /// A store failure.
    pub fn resolve_repo_identity(&self, repo: &RepoRef) -> Result<RepoIdentity> {
        let txn = self.store.env.read_txn()?;
        resolve_repo_identity_in_txn(self, &txn, repo)
    }
}
