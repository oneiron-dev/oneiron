//! The Files world and its sources: one world per install, born the first
//! time the owner attaches a folder to it, and each attached folder's
//! identity in it.

use serde::{Deserialize, Serialize};

use crate::authority::{ActSurface, ModelOrder, ReadLocation, SealedCopies, WorldPrivacy};
use crate::consent::AuthenticatedOwner;
use crate::entity_id::derived_domains;
use crate::error::{Error, Result};
use crate::registry::ENTITY_TYPE_WORLD;
use crate::{EntityId, TimeRange, Vault};

use super::super::folder_source::FolderSource;

/// The name a Files world's WORLD row carries, before the first eight hex
/// of its install's machine id: `Files 1a2b3c4d`.
pub const FILES_WORLD_NAME: &str = "Files";

/// The note kind a Files source's file lands as when its frontmatter names
/// none, as a folder attached as notes defaults.
pub const FILES_DEFAULT_KIND: &str = "observation";

/// The exclusions a Files source keeps when its owner names none: matched
/// against each entry's name and its path under the folder, before the
/// entry is opened or read. Hidden entries, version control, dependency and
/// build folders, and credential stores and key files. The owner's own list,
/// even an empty one, replaces it.
pub const DEFAULT_FILES_EXCLUDE: &[&str] = &[
    ".*",
    ".git",
    ".hg",
    ".svn",
    "node_modules",
    "bower_components",
    "vendor",
    ".venv",
    "venv",
    "__pycache__",
    "target",
    "build",
    "dist",
    ".next",
    ".gradle",
    "Pods",
    "DerivedData",
    ".env",
    ".env.*",
    ".ssh",
    ".gnupg",
    ".aws",
    ".netrc",
    ".npmrc",
    ".pypirc",
    "*.pem",
    "*.key",
    "*.p12",
    "*.pfx",
    "*.keychain",
    "*.keychain-db",
    "*.kdbx",
    "id_rsa*",
    "id_dsa*",
    "id_ecdsa*",
    "id_ed25519*",
];

/// What a Files source's notes derive their ids from, before the source's
/// id: never a host path, which a UTF-8 canonical folder always is.
const FILES_NAMESPACE: &str = "oneiron-files/";

/// How many counters a Files world's id derivation tries for one outside
/// the foreign-world range: each is one in sixteen, so the first nearly
/// always is.
const FILES_WORLD_COUNTER_BOUND: u64 = 64;

/// This install's Files world: the WORLD every Files source of this install
/// lands in, and the machine it stays on.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct FilesWorld {
    pub world: EntityId,
    /// The install whose files the world holds: its one reader by default.
    pub machine: EntityId,
}

/// Where a Files source's files live (FIX 6942): the source's identity, the
/// world its notes are born in, the install it reads on, and what it never
/// reads.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FilesPlacement {
    /// The source's id: derived from its install, its world and its folder,
    /// so attaching the folder again finds the notes it landed.
    pub source: EntityId,
    pub world: EntityId,
    pub machine: EntityId,
    /// Patterns over each entry's name and its `/`-separated path under the
    /// folder (`*` within a name, `**` across folders, `?` one character):
    /// what the host never opens.
    pub exclude: Vec<String>,
}

/// One file of a Files source, as a later search, action or peer names it:
/// the source (its install and world with it) and the path under the
/// folder. The ledger's hashes are its revision.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct FileHandle {
    pub source: EntityId,
    pub path: String,
}

/// The namespace a Files source's notes derive their ids from.
pub(in crate::note) fn namespace(source: EntityId) -> String {
    format!("{FILES_NAMESPACE}{}", source.to_hex())
}

/// The Files world of the install `machine`: the first id derived from it
/// outside the foreign-world range.
fn files_world_id(machine: EntityId) -> Result<EntityId> {
    for counter in 0..FILES_WORLD_COUNTER_BOUND {
        let id = EntityId::derive(
            derived_domains::FILES_WORLD,
            &[machine.as_bytes(), &counter.to_le_bytes()],
        )?;
        if !crate::entity_id::is_foreign_world_id_range(id) {
            return Ok(id);
        }
    }
    Err(Error::InvariantViolation(
        "no derived Files world id within the counter bound",
    ))
}

/// The settings a Files world is born with: read on its own install only,
/// no sealed copy anywhere, and the vault's model order. The owner can
/// change them as any world's.
fn files_world_privacy(machine: EntityId) -> WorldPrivacy {
    WorldPrivacy {
        read: ReadLocation::OneMachine(machine),
        sealed: SealedCopies::Off,
        models: ModelOrder::Inherit,
    }
}

impl Vault {
    /// This install's Files world, once the owner opted in; none before, or
    /// on an install that is not a machine yet.
    ///
    /// # Errors
    /// A storage error.
    pub fn files_world(&self) -> Result<Option<FilesWorld>> {
        let txn = self.store.env.read_txn()?;
        let Some(machine) = crate::identity::read_machine_id_in_txn(self, &txn)? else {
            return Ok(None);
        };
        let world = files_world_id(machine)?;
        Ok(
            (self.get_entity_type_in_txn(&txn, &world)? == Some(ENTITY_TYPE_WORLD))
                .then_some(FilesWorld { world, machine }),
        )
    }

    /// The owner's opt-in: this install's Files world, born on the first
    /// call. Its WORLD row lands first, then the owner's privacy door sets
    /// it to read on this install only with no sealed copies, before any
    /// file is born in it. A world whose settings nobody set yet (one an
    /// earlier call left half made) takes them now; one whose settings the
    /// owner chose keeps his.
    ///
    /// # Errors
    /// An install that is not a machine yet, an owner proof that no longer
    /// holds, the privacy door's refusal (this install not live and marked
    /// yours), or a storage error.
    pub fn open_files_world(
        &self,
        owner: &AuthenticatedOwner,
        surface: ActSurface,
    ) -> Result<FilesWorld> {
        #[derive(Serialize)]
        struct WorldBody<'a> {
            name: &'a str,
        }
        let machine = {
            let txn = self.store.env.read_txn()?;
            crate::identity::read_machine_id_in_txn(self, &txn)?
        }
        .ok_or_else(|| {
            super::super::document::invalid(
                "this install is not a machine yet; `oneiron device enrol` enrols it",
            )
        })?;
        let world = files_world_id(machine)?;
        let name = format!("{FILES_WORLD_NAME} {}", &machine.to_hex()[..8]);
        self.with_write_txn(|txn| {
            owner.revalidate_as_vault_owner_in_txn(self, txn)?;
            match self.get_entity_type_in_txn(txn, &world)? {
                Some(ENTITY_TYPE_WORLD) => Ok(()),
                Some(_) => Err(Error::InvalidClaimBody(
                    "this install's Files world id is taken by another entity",
                )),
                None => {
                    let at = crate::ports::recorded_at_in_txn(&self.store, txn)?;
                    let body = rmp_serde::to_vec_named(&WorldBody { name: &name })
                        .map_err(|_| Error::InvariantViolation("world encoding failed"))?;
                    self.batch_in()
                        .put(
                            &world,
                            ENTITY_TYPE_WORLD,
                            TimeRange { start: at, end: at },
                            at,
                            &body,
                        )
                        .apply(txn)?;
                    Ok(())
                }
            }
        })?;
        if self.world_privacy_revision(world)?.0 == [0; 32] {
            let _receipt = self.set_world_privacy_as(
                owner,
                surface,
                world,
                files_world_privacy(machine),
                None,
            )?;
        }
        Ok(FilesWorld { world, machine })
    }

    /// Attaches `folder` to this install's Files world, opting in on the
    /// first one: the owner's standing act, as for a folder attached as
    /// notes. `exclude` replaces [`DEFAULT_FILES_EXCLUDE`] when given;
    /// `kind` defaults to [`FILES_DEFAULT_KIND`].
    ///
    /// # Errors
    /// As [`Self::open_files_world`] and [`Self::attach_folder_source`].
    pub fn attach_files_source(
        &self,
        owner: &AuthenticatedOwner,
        surface: ActSurface,
        folder: &str,
        include: Vec<String>,
        exclude: Option<Vec<String>>,
        kind: Option<&str>,
    ) -> Result<(FilesWorld, FolderSource)> {
        let files = self.open_files_world(owner, surface)?;
        let placement = FilesPlacement {
            source: EntityId::derive(
                derived_domains::FILES_SOURCE,
                &[
                    files.machine.as_bytes(),
                    files.world.as_bytes(),
                    folder.as_bytes(),
                ],
            )?,
            world: files.world,
            machine: files.machine,
            exclude: exclude.unwrap_or_else(|| {
                DEFAULT_FILES_EXCLUDE
                    .iter()
                    .map(|pattern| (*pattern).to_owned())
                    .collect()
            }),
        };
        let source = self.attach_source(
            owner,
            folder,
            include,
            kind.unwrap_or(FILES_DEFAULT_KIND),
            Some(placement),
        )?;
        Ok((files, source))
    }

    /// Every folder attached to a Files world.
    ///
    /// # Errors
    /// A storage error.
    pub fn files_sources(&self) -> Result<Vec<FolderSource>> {
        Ok(self
            .folder_sources()?
            .into_iter()
            .filter(|source| source.files.is_some())
            .collect())
    }

    /// The Files source `source` names, if it is attached.
    ///
    /// # Errors
    /// A storage error.
    pub fn files_source(&self, source: EntityId) -> Result<Option<FolderSource>> {
        Ok(self.folder_sources()?.into_iter().find(|attached| {
            attached
                .files
                .as_ref()
                .is_some_and(|files| files.source == source)
        }))
    }
}
