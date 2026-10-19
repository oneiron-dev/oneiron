//! The body files a checkpoint carries beside its rows (OF-597, FIX 3677,
//! FIX 5348).
//!
//! The snapshot gathers every file its canonical rows name: a result body's
//! raw-output row, a file-plane ASSET's row, and every body descriptor that
//! holds a file, a legal hold's superseded ASSET file and an incomplete
//! body's retained part included. Each is carried once, whatever its size.
//!
//! A sealed vault's file is carried as it rests, its envelope's ciphertext,
//! each frame checked as the artifact reads it; the image names it by the
//! body's BLAKE3 and length and its instance, and the artifact's manifest by
//! its stored length and BLAKE3. Its key row travels with the canonical rows,
//! wrapped: the image holds no key and no sidecar. A restore opens the key
//! rows with the checkpoint's key before any file lands, and checks every
//! frame and its binding before the rows commit: a sealed vault takes the
//! envelope as it is, a plain one the body decrypted, and keeps no key row.
//! A plain body landing in a sealed vault is sealed under a new key, whose
//! row joins the image's.

use std::collections::{BTreeMap, BTreeSet};
use std::io::Read;

use heed::RoTxn;
use serde::{Deserialize, Serialize};

use super::artifact::{ArtifactBody, SealedBodies};
use super::{CheckpointImage, codec_error};
use crate::store::{BODY_KEYS, BodyDir, BodyKeyRow, KeyScope, SealedStream, Store};
use crate::{Error, Result, Vault};

/// One body file an image carries: the body's BLAKE3 and length, and a
/// sealed vault's file's envelope.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ImageBody {
    pub(super) digest: [u8; 32],
    pub(super) len: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) sealed: Option<SealedFile>,
}

/// A carried envelope: its instance, and its length as it rests.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct SealedFile {
    pub(super) instance: [u8; 16],
    pub(super) stored_len: u64,
}

/// Whether the bodies an image names are the streams its artifact's
/// manifest carries, in order: a plain body's own BLAKE3 and length, an
/// envelope's length as it rests.
pub(super) fn matches_artifact(image: &[ImageBody], streams: &[([u8; 32], u64)]) -> bool {
    image.len() == streams.len()
        && image
            .iter()
            .zip(streams)
            .all(|(body, (digest, len))| match &body.sealed {
                None => body.digest == *digest && body.len == *len,
                Some(sealed) => sealed.stored_len == *len,
            })
}

/// The key row a raw `vault_meta` row is, by its digest.
fn key_row_of(key: &[u8], value: &[u8]) -> Result<Option<([u8; 32], BodyKeyRow)>> {
    let Some(digest) = key.strip_prefix(BODY_KEYS.decl().prefix) else {
        return Ok(None);
    };
    let digest: [u8; 32] = digest
        .try_into()
        .map_err(|_| Error::CorruptedIndex("body file key row key"))?;
    Ok(Some((digest, BODY_KEYS.decode_value(value)?)))
}

/// What a snapshot's rows name of the body files beside them, gathered as
/// its transaction reads them.
#[derive(Default)]
pub(super) struct BodyCensus {
    bodies: BTreeSet<([u8; 32], u64)>,
    keys: BTreeMap<[u8; 32], BodyKeyRow>,
}

impl BodyCensus {
    /// Notes what the canonical row `key` of `database`, holding `value`,
    /// names: a result body's file, a file-plane ASSET's, a descriptor's
    /// file, or a sealed file's key row.
    ///
    /// # Errors
    ///
    /// A row that does not decode, and storage errors.
    pub(super) fn note(
        &mut self,
        store: &Store,
        txn: &RoTxn<'_>,
        database: &str,
        key: &[u8],
        value: &[u8],
    ) -> Result<()> {
        match database {
            "vault_meta" => {
                if let Some(body) = crate::code_run::code_run_body_file_of_row(key, value) {
                    self.bodies.insert(body);
                }
                if let Some(body) = crate::provenance::body::file_body_of_row(key, value)? {
                    self.bodies.insert(body);
                }
                if let Some((digest, row)) = key_row_of(key, value)? {
                    self.keys.insert(digest, row);
                }
            }
            "entities" => {
                if let Some(body) = crate::store::asset_body_file_of_row(store, txn, key, value)? {
                    self.bodies.insert(body);
                }
            }
            _ => {}
        }
        Ok(())
    }

    /// The files to carry, each once: a sealed one with its envelope's facts,
    /// read from the file, which the snapshot's pin keeps. `store`'s
    /// `bodies/` is opened only when there is one.
    ///
    /// # Errors
    ///
    /// [`Error::CorruptedIndex`] for a named file that is missing or does
    /// not check; filesystem errors.
    pub(super) fn finish(self, store: &Store) -> Result<CarriedFiles> {
        let dir = if self.bodies.is_empty() {
            None
        } else {
            Some(store.body_dir()?)
        };
        let mut bodies = Vec::with_capacity(self.bodies.len());
        for (digest, len) in self.bodies {
            let sealed = match (self.keys.get(&digest), &dir) {
                (Some(row), Some(dir)) => Some(SealedFile {
                    instance: row.instance,
                    stored_len: open_stored(dir, &digest, len, Some(row))?.stored_len()?,
                }),
                _ => None,
            };
            bodies.push(ImageBody {
                digest,
                len,
                sealed,
            });
        }
        Ok(CarriedFiles {
            bodies,
            keys: self.keys,
            dir,
        })
    }
}

/// The body `digest` of `len` bytes in `dir`, as `row` names it.
fn open_stored(
    dir: &BodyDir,
    digest: &[u8; 32],
    len: u64,
    row: Option<&BodyKeyRow>,
) -> Result<crate::store::BodyFile> {
    dir.open_reader(digest, len, row)?
        .ok_or(Error::CorruptedIndex("code-run result body file missing"))
}

/// The files a snapshot carries, ready for its artifact.
pub(super) struct CarriedFiles {
    bodies: Vec<ImageBody>,
    keys: BTreeMap<[u8; 32], BodyKeyRow>,
    dir: Option<BodyDir>,
}

impl CarriedFiles {
    /// What the image names.
    pub(super) fn image_bodies(&self) -> Vec<ImageBody> {
        self.bodies.clone()
    }

    /// What each stream the artifact carries must be: a plain body's own
    /// bytes, or an envelope of its stored length, whose frames its stream
    /// checks as it is read.
    pub(super) fn streams(&self) -> Vec<ArtifactBody> {
        self.bodies
            .iter()
            .map(|body| match &body.sealed {
                None => ArtifactBody {
                    len: body.len,
                    digest: Some(body.digest),
                },
                Some(sealed) => ArtifactBody {
                    len: sealed.stored_len,
                    digest: None,
                },
            })
            .collect()
    }

    /// The `index`th file as it rests, from its start.
    ///
    /// # Errors
    ///
    /// As [`BodyCensus::finish`].
    pub(super) fn open(&self, index: usize) -> Result<Box<dyn Read + Send>> {
        let (Some(body), Some(dir)) = (self.bodies.get(index), &self.dir) else {
            return Err(codec_error());
        };
        let row = body
            .sealed
            .as_ref()
            .map(|_| self.keys.get(&body.digest).ok_or_else(codec_error))
            .transpose()?;
        Ok(open_stored(dir, &body.digest, body.len, row)?.into_stored())
    }
}

/// Brings the image's body files into `vault`'s `bodies/`, each read back
/// through its sealed chunks and checked, before any row naming them lands.
/// A result body comes back with its line index, an ASSET's raw. The image's
/// key rows follow the vault: a plain vault keeps none, a sealed one gains
/// the row of each plain body it seals.
///
/// # Errors
///
/// [`Error::CorruptedIndex`] for an envelope with no key row of its own or
/// a frame that does not check; a key that does not open with the
/// checkpoint's key; filesystem errors.
pub(super) fn restore(
    vault: &Vault,
    image: &mut CheckpointImage,
    mut bodies: SealedBodies<'_>,
) -> Result<()> {
    let target = vault.store.body_dir()?;
    let seal = bodies.checkpoint_key().body_seal();
    let rows = image
        .databases
        .get_mut("vault_meta")
        .ok_or_else(codec_error)?;
    let results = rows
        .iter()
        .filter_map(|(key, value)| crate::code_run::code_run_body_file_of_row(key, value))
        .map(|(digest, _)| digest)
        .collect::<BTreeSet<_>>();
    let mut keys = BTreeMap::new();
    for (key, value) in rows.iter() {
        if let Some((digest, row)) = key_row_of(key, value)? {
            keys.insert(digest, row);
        }
    }
    let mut sealed_here = Vec::new();
    for (index, body) in image.bodies.iter().enumerate() {
        let lines = results.contains(&body.digest);
        let source = bodies.body(index);
        let Some(carried) = &body.sealed else {
            let mut source = source;
            if target.sealed.is_some() {
                let staged = target.import_sealing(&body.digest, body.len, &mut source, lines)?;
                sealed_here.push((
                    BODY_KEYS.key_bytes(&body.digest),
                    BODY_KEYS.encode_value(staged.row())?,
                ));
            } else if lines {
                target.import(&body.digest, body.len, &mut source)?;
            } else {
                target.import_asset_body(&body.digest, body.len, &mut source)?;
            }
            continue;
        };
        let row = keys
            .get(&body.digest)
            .filter(|row| row.instance == carried.instance && row.len == body.len)
            .ok_or_else(codec_error)?;
        let key = row.open_under(&body.digest, &seal, KeyScope::Vault)?;
        if target.sealed.is_some() {
            target.import_sealed(&body.digest, body.len, source, key, lines)?;
        } else {
            let mut plain = SealedStream::plaintext(source, key, body.digest, body.len);
            if lines {
                target.import(&body.digest, body.len, &mut plain)?;
            } else {
                target.import_asset_body(&body.digest, body.len, &mut plain)?;
            }
        }
    }
    if target.sealed.is_none() {
        rows.retain(|(key, _)| !key.starts_with(BODY_KEYS.decl().prefix));
    } else if !sealed_here.is_empty() {
        rows.retain(|(key, _)| !sealed_here.iter().any(|(added, _)| added == key));
        rows.extend(sealed_here);
        rows.sort();
    }
    Ok(())
}
