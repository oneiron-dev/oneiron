//! An attached folder of notes while `serve` runs (OF-554, FIX 1364): attach,
//! rescan and detach over the engine functions the `import folder` command
//! calls, and every attached folder with its ledger's counts. Nothing is ever
//! written to the folder.

use std::path::Path;

use oneiron::Vault;
use oneiron::consent::AuthenticatedOwner;
use oneiron::note::{FolderFileState, FolderSource};
use serde::Serialize;

use super::{OwnerError, OwnerResult};
use crate::files_intake::{Rescanned, canonical_folder, rescanned};

/// A folder just attached, with its first rescan, as `import folder attach`
/// shows it.
#[derive(Serialize)]
pub(crate) struct AttachedFolder {
    pub(crate) source: FolderSource,
    pub(crate) rescan: Rescanned,
}

/// One attached folder, with its ledger's counts, as `import folder list`
/// shows it.
#[derive(Serialize)]
pub(crate) struct ListedFolder {
    #[serde(flatten)]
    pub(crate) source: FolderSource,
    pub(crate) files: usize,
    pub(crate) retracted: usize,
    pub(crate) proposed: usize,
}

/// A detached folder: no rescan reads it again, and its notes stay.
#[derive(Serialize)]
pub(crate) struct DetachedFolder {
    pub(crate) folder: String,
    pub(crate) detached: bool,
}

/// An engine refusal of the request's own shape as the owner's 400: a blank
/// folder, a bad pattern, an unknown kind, or a folder attached already.
fn invalid(error: oneiron::Error) -> OwnerError {
    match error.kind() {
        oneiron::ErrorKind::InvalidNoteBody => OwnerError::Invalid(error.to_string()),
        _ => OwnerError::Engine(Box::new(error)),
    }
}

/// Attaches `path` and lands its notes: the owner's one act, as `import
/// folder attach` does it.
pub(crate) fn attach(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    path: &str,
    include: Vec<String>,
    kind: &str,
) -> OwnerResult<AttachedFolder> {
    let folder = canonical_folder(Path::new(path))
        .map_err(|error| OwnerError::Invalid(error.to_string()))?;
    let source = vault.attach_folder_source(owner, &folder, include, kind).map_err(invalid)?;
    let rescan = rescanned(vault, owner, &source);
    Ok(AttachedFolder { source, rescan })
}

/// Rescans one attached folder now, or every attached folder, as `import
/// folder rescan` does.
pub(crate) fn rescan(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    path: Option<&str>,
) -> OwnerResult<Vec<Rescanned>> {
    let sources = match path {
        Some(path) => {
            let folder = canonical_folder(Path::new(path))
                .map_err(|error| OwnerError::Invalid(error.to_string()))?;
            let source = vault
                .folder_source(&folder)?
                .ok_or_else(|| OwnerError::NotFound("folder", folder))?;
            vec![source]
        }
        None => vault.folder_sources()?,
    };
    Ok(sources
        .iter()
        .map(|source| rescanned(vault, owner, source))
        .collect::<Vec<_>>())
}

/// Detaches `path`: no rescan reads it again, and its notes stay. A folder
/// that is gone is detached by the name it was attached by.
pub(crate) fn detach(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    path: &str,
) -> OwnerResult<DetachedFolder> {
    let folder = canonical_folder(Path::new(path)).unwrap_or_else(|_| path.to_owned());
    if !vault.detach_folder_source(owner, &folder)? {
        return Err(OwnerError::NotFound("folder", folder));
    }
    Ok(DetachedFolder {
        folder,
        detached: true,
    })
}

/// Every attached folder, with its ledger's counts.
pub(crate) fn list(vault: &Vault) -> OwnerResult<Vec<ListedFolder>> {
    vault
        .folder_sources()?
        .into_iter()
        .map(|source| {
            let files = vault.folder_source_files(&source.folder)?;
            let count = |wanted: fn(&FolderFileState) -> bool| {
                files.iter().filter(|file| wanted(&file.state)).count()
            };
            Ok(ListedFolder {
                retracted: count(|state| *state == FolderFileState::Retracted),
                proposed: count(|state| matches!(state, FolderFileState::Proposed { .. })),
                files: files.len(),
                source,
            })
        })
        .collect::<OwnerResult<Vec<_>>>()
}
