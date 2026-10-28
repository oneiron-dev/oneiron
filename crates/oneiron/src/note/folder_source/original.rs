//! The kept original of each imported folder file (FIX 7779): the exact
//! bytes the host opened, as one version of the file's own blob artifact.
//! The file's note holds its text; the original holds the file itself, a
//! PDF's bytes included. Bytes equal to the artifact's head keep no second
//! version, so each file version is kept once. The folder's import MACHINE
//! writes it, as it writes the file's note, and its made_by names the import
//! that read it. An attached folder's ledger rows name the version their
//! file was read at.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use super::super::import::NOTES_IMPORT_SOURCE;
use super::{FILES, file_key};
use crate::blob_artifact::{BlobArtifactBody, BlobVersionProvenance, encode_blob_artifact_body};
use crate::provenance::made_by::{MadeBy, MadeByClass, MadeByProcess};
use crate::consent::AuthenticatedOwner;
use crate::edge::EdgeActorClass;
use crate::error::Result;
use crate::registry::ENTITY_TYPE_BLOB_ARTIFACT;
use crate::temporal::TimeRange;
use crate::write_envelope::WriteActor;
use crate::{EntityId, Vault};

/// The part that sets a file's original apart from its note, whose id
/// derives in the same domain from the folder and the path alone.
const ORIGINAL_ID_PART: &[u8] = b"original";

/// One folder file's bytes as the host opened them, and their media type.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OriginalBytes {
    pub media_type: String,
    pub bytes: Vec<u8>,
}

impl OriginalBytes {
    /// The bytes' blake3 hash, lower hex: what a kept original names.
    #[must_use]
    pub fn content_hash(&self) -> String {
        blake3::hash(&self.bytes).to_hex().to_string()
    }
}

/// A kept original: the version of its file's blob artifact that holds the
/// bytes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FileOriginal {
    /// The file's blob artifact, one per file across its versions.
    pub artifact: EntityId,
    /// The version that holds these bytes.
    pub version: u64,
    /// The bytes' blake3 hash, lower hex.
    pub content_hash: String,
}

impl Vault {
    /// The blob artifact that keeps the originals of the file at `path`
    /// under `folder` (an attached folder's namespace, or a one-shot
    /// import's folder).
    ///
    /// # Errors
    /// Only if id derivation fails.
    pub fn folder_file_original_id(folder: &str, path: &str) -> Result<EntityId> {
        EntityId::derive(
            crate::entity_id::derived_domains::IMPORTED_NOTE,
            &[folder.as_bytes(), path.as_bytes(), ORIGINAL_ID_PART],
        )
    }

    /// Keeps `original` as the original of the file at `path` under
    /// `folder`, for `owner`, in one write: the file's artifact is registered
    /// the first time, and bytes equal to its head add no version. The
    /// folder's import MACHINE writes it, and its made_by names the import
    /// as the process that read the bytes.
    ///
    /// # Errors
    /// An owner that no longer revalidates, or the blob door's refusal.
    pub fn keep_folder_file_original(
        &self,
        owner: &AuthenticatedOwner,
        folder: &str,
        path: &str,
        original: &OriginalBytes,
    ) -> Result<FileOriginal> {
        self.with_write_txn(|txn| {
            owner.revalidate_in_txn(self, txn)?;
            let importer = Self::imported_note_author(folder)?;
            let artifact = Self::folder_file_original_id(folder, path)?;
            let at = crate::ports::recorded_at_in_txn(&self.store, txn)?;
            let occurred = TimeRange { start: at, end: at };
            if self.get_blob_artifact_in_txn(txn, &artifact)?.is_none() {
                let name = path.rsplit('/').next().unwrap_or(path);
                let body = BlobArtifactBody::new(name, original.media_type.clone());
                self.batch_in()
                    .put(
                        &artifact,
                        ENTITY_TYPE_BLOB_ARTIFACT,
                        occurred,
                        at,
                        &encode_blob_artifact_body(&body)?,
                    )
                    .apply(txn)?;
            }
            let made_by = MadeBy {
                inputs: Vec::new(),
                process: MadeByProcess {
                    actor: importer,
                    class: MadeByClass::Stated,
                    identity: NOTES_IMPORT_SOURCE.to_owned(),
                    version: env!("CARGO_PKG_VERSION").to_owned(),
                    params_hash: original.content_hash(),
                },
                at,
                trigger: None,
            };
            let version = self.append_blob_artifact_version_made_by_in_txn(
                txn,
                &artifact,
                None,
                &original.bytes,
                &BlobVersionProvenance::UserUpload,
                &made_by,
                WriteActor::new(importer, EdgeActorClass::System),
                occurred,
                at,
            )?;
            Ok(FileOriginal {
                artifact,
                version: version.version,
                content_hash: original.content_hash(),
            })
        })
    }

    /// Names each file's kept original on the ledger rows of the attached
    /// `folder`, by path, a continuation part's path included; `None` says
    /// the file's last read kept none. A path the ledger holds no row for is
    /// passed over, and a row already naming the same original is left as
    /// it is.
    ///
    /// # Errors
    /// An owner that no longer revalidates, or a storage error.
    pub fn link_folder_file_originals(
        &self,
        owner: &AuthenticatedOwner,
        folder: &str,
        originals: &HashMap<String, Option<FileOriginal>>,
    ) -> Result<()> {
        if originals.is_empty() {
            return Ok(());
        }
        self.with_write_txn(|txn| {
            owner.revalidate_in_txn(self, txn)?;
            for (path, original) in originals {
                let key = file_key(folder, path);
                let Some(mut row) = FILES.get(&self.store, txn, &key)? else {
                    continue;
                };
                if row.original == *original {
                    continue;
                }
                row.original.clone_from(original);
                FILES.put(&self.store, txn, &key, &row)?;
            }
            Ok(())
        })
    }
}
