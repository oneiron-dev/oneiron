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
//! body's BLAKE3 and length and, beside them, its instance and stored length,
//! and the artifact's manifest by its stored length and BLAKE3. A plain
//! vault's image is as it was. Its key row travels with the canonical rows,
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
use super::write_budget::{RestoreRoom, landing_len};
use super::{CheckpointImage, codec_error};
use crate::store::{BODY_KEYS, BodyDir, BodyKeyRow, KeyScope, SealedStream, Store};
use crate::{Error, Result, Vault};

/// A carried envelope: its instance, and its length as it rests. The image
/// names it by its place among the bodies, whose BLAKE3 and length are the
/// body's own; a plain vault's image names none, so its format is as before.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct SealedFile {
    pub(super) instance: [u8; 16],
    pub(super) stored_len: u64,
}

/// Whether the bodies an image names, `sealed` of them envelopes, are the
/// streams its artifact's manifest carries, in order: a plain body's own
/// BLAKE3 and length, an envelope's length as it rests.
pub(super) fn matches_artifact(
    bodies: &[([u8; 32], u64)],
    sealed: &BTreeMap<u64, SealedFile>,
    streams: &[([u8; 32], u64)],
) -> bool {
    bodies.len() == streams.len()
        && sealed.keys().all(|index| *index < bodies.len() as u64)
        && bodies
            .iter()
            .zip(streams)
            .enumerate()
            .all(
                |(index, (body, stream))| match sealed.get(&(index as u64)) {
                    None => body == stream,
                    Some(file) => file.stored_len == stream.1,
                },
            )
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
        let bodies: Vec<_> = self.bodies.into_iter().collect();
        let mut sealed = BTreeMap::new();
        for (index, (digest, len)) in bodies.iter().enumerate() {
            // A key row whose file is not there names no envelope.
            if let (Some(row), Some(dir)) = (self.keys.get(digest), &dir)
                && dir.holds_pair(digest, Some(row))?
            {
                let file = SealedFile {
                    instance: row.instance,
                    stored_len: open_stored(dir, digest, *len, Some(row))?.stored_len()?,
                };
                sealed.insert(index as u64, file);
            }
        }
        Ok(CarriedFiles {
            bodies,
            sealed,
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
    bodies: Vec<([u8; 32], u64)>,
    sealed: BTreeMap<u64, SealedFile>,
    keys: BTreeMap<[u8; 32], BodyKeyRow>,
    dir: Option<BodyDir>,
}

impl CarriedFiles {
    /// What the image names: each body's BLAKE3 and length, and the
    /// envelopes among them.
    pub(super) fn image_bodies(&self) -> (Vec<([u8; 32], u64)>, BTreeMap<u64, SealedFile>) {
        (self.bodies.clone(), self.sealed.clone())
    }

    /// What each stream the artifact carries must be: a plain body's own
    /// bytes, or an envelope of its stored length, whose frames its stream
    /// checks as it is read.
    pub(super) fn streams(&self) -> Vec<ArtifactBody> {
        self.bodies
            .iter()
            .enumerate()
            .map(
                |(index, (digest, len))| match self.sealed.get(&(index as u64)) {
                    None => ArtifactBody {
                        len: *len,
                        digest: Some(*digest),
                    },
                    Some(file) => ArtifactBody {
                        len: file.stored_len,
                        digest: None,
                    },
                },
            )
            .collect()
    }

    /// The `index`th file as it rests, from its start.
    ///
    /// # Errors
    ///
    /// As [`BodyCensus::finish`].
    pub(super) fn open(&self, index: usize) -> Result<Box<dyn Read + Send>> {
        let (Some((digest, len)), Some(dir)) = (self.bodies.get(index), &self.dir) else {
            return Err(codec_error());
        };
        let row = self
            .sealed
            .get(&(index as u64))
            .map(|_| self.keys.get(digest).ok_or_else(codec_error))
            .transpose()?;
        Ok(open_stored(dir, digest, *len, row)?.into_stored())
    }
}

/// Brings the image's body files into `vault`'s `bodies/`, each read back
/// through its sealed chunks and checked, before any row naming them lands.
/// A result body comes back with its line index, an ASSET's raw. The image's
/// key rows follow the vault: a plain vault keeps none, a sealed one gains
/// the row of each plain body it seals. Each body claims what is left of the
/// copy's room on `room` before it lands (FIX 5479).
///
/// # Errors
///
/// [`Error::CorruptedIndex`] for an envelope with no key row of its own or
/// a frame that does not check; a key that does not open with the
/// checkpoint's key; a claim the disk's floor refuses; filesystem errors.
pub(super) fn restore(
    vault: &Vault,
    image: &mut CheckpointImage,
    mut bodies: SealedBodies<'_>,
    room: &mut RestoreRoom<'_>,
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
    for (index, (digest, len)) in image.bodies.iter().enumerate() {
        room.landing_body(landing_len(*len, image.sealed_bodies.get(&(index as u64))))?;
        let lines = results.contains(digest);
        let source = bodies.body(index);
        let Some(carried) = image.sealed_bodies.get(&(index as u64)) else {
            let mut source = source;
            if target.sealed.is_some() {
                let staged = target.import_sealing(digest, *len, &mut source, lines)?;
                sealed_here.push((
                    BODY_KEYS.key_bytes(digest),
                    BODY_KEYS.encode_value(staged.row())?,
                ));
            } else if lines {
                target.import(digest, *len, &mut source)?;
            } else {
                target.import_asset_body(digest, *len, &mut source)?;
            }
            continue;
        };
        let row = keys
            .get(digest)
            .filter(|row| row.instance == carried.instance && row.len == *len)
            .ok_or_else(codec_error)?;
        let key = row.open_under(digest, &seal, KeyScope::Vault)?;
        if target.sealed.is_some() {
            target.import_sealed(digest, *len, source, key, lines)?;
        } else {
            let mut plain = SealedStream::plaintext(source, key, *digest, *len);
            if lines {
                target.import(digest, *len, &mut plain)?;
            } else {
                target.import_asset_body(digest, *len, &mut plain)?;
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
