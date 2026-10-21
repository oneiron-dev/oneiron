//! The bodies a checkpoint carries beside its rows (OF-597, FIX 3677, FIX
//! 5348; KS-2A, FIX 5683 part A).
//!
//! The snapshot gathers every body its canonical rows name: a result body's
//! file, a file-plane ASSET's, each descriptor's file (a legal hold's
//! superseded ASSET file and an incomplete body's retained part included),
//! and every inline body, an ASSET entity's row body and an inline result's.
//! Each is one instance whose key typed custody holds, and each travels
//! sealed under that key alone, in the body envelope's format: a sealed
//! vault's file as it rests, a plain vault's file and every inline body
//! sealed as the artifact reads it, with no plaintext temp file. An inline
//! body's row travels without its bytes. The image names each by its
//! instance and its envelope's length, whatever its size; it holds no key
//! and no wrap of one, so only current custody opens a body: an erase that
//! retired an instance reaches every kept copy.
//!
//! A restore requires every instance its rows name through the shared
//! custody plan before anything is made (a missing one refuses as
//! `body_key_custody_unavailable`), takes a retired one's rows out as its
//! erase took them, and lands the rest, every frame checked against its
//! instance and body before the rows commit: a sealed vault takes each
//! envelope as it is, a plain one the body opened, and an inline body goes
//! back into its row.

use std::collections::{BTreeMap, BTreeSet};
use std::io::{Cursor, Read};
use std::sync::Arc;

use heed::RoTxn;
use serde::{Deserialize, Serialize};

use super::artifact::{ArtifactBody, SealedBodies};
use super::response_rows::{self, Noted, ResponseCensus};
use super::write_budget::{RestoreRoom, landing_len};
use super::{CheckpointImage, codec_error};
use crate::batch::{ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader};
use crate::store::{
    BODY_KEYS, BodyDir, BodyKeyRow, CustodyBinding, CustodyPlan, FileKey, INLINE_ASSETS,
    SealedStream, SealingStream, Store, body_instances_in_rows, body_key_in,
    prune_retired_bodies_in_rows, require_body_instances,
};
use crate::{EntityId, Error, Result, Vault};

/// A carried file: its instance, and the length of the envelope it travels
/// in. The image names it by its place among the bodies, whose BLAKE3 and
/// length are the body's own.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct SealedFile {
    pub(super) instance: [u8; 16],
    pub(super) stored_len: u64,
}

/// A carried inline body: the row it rests in, by database and key, the
/// bytes of that row before the body (its header, its tag), its instance,
/// the body's BLAKE3 and length, and the length of its envelope.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct CarriedInline {
    pub(super) database: String,
    pub(super) key: Vec<u8>,
    pub(super) keep: u32,
    pub(super) instance: [u8; 16],
    pub(super) digest: [u8; 32],
    pub(super) len: u64,
    pub(super) stored_len: u64,
    /// A row-held response's (KS-2B1): its row travels as its family's
    /// stub, whose first `keep` bytes the body follows under a live
    /// instance, and of which a retired instance's row keeps this many, its
    /// erased disposition. `None` for an inline body, whose row travels as
    /// its first `keep` bytes alone.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) retired: Option<u32>,
    /// The length a queue row's carried bytes land at once a restore
    /// unleases them (FIX 7115), counted at capture from the original row, so
    /// a restore can count what it lands before it opens anything. `None`:
    /// the row lands at `keep` plus `len` bytes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) landed_len: Option<u64>,
    /// A restore over a live vault keeps this response's row as the live
    /// vault holds it, with the live vault's binding (a media job, a Live
    /// family; KS-2B2): its stream is passed over, never required or
    /// landed. Never in an image.
    #[serde(skip)]
    pub(super) superseded: bool,
}

/// Whether the bodies `image` names are the streams its artifact's manifest
/// carries, in order: each file's envelope, then each inline body's.
pub(super) fn matches_artifact(image: &CheckpointImage, streams: &[([u8; 32], u64)]) -> bool {
    let files = image.bodies.len();
    streams.len() == files + image.inline_bodies.len()
        && image.sealed_bodies.len() == files
        && streams
            .iter()
            .enumerate()
            .all(|(index, (_, len))| match index.checked_sub(files) {
                None => image
                    .sealed_bodies
                    .get(&(index as u64))
                    .is_some_and(|file| file.stored_len == *len),
                Some(inline) => image
                    .inline_bodies
                    .get(inline)
                    .is_some_and(|carried| carried.stored_len == *len),
            })
}

/// The instance row a raw `vault_meta` row is, by its digest.
fn key_row_of(key: &[u8], value: &[u8]) -> Result<Option<([u8; 32], BodyKeyRow)>> {
    let Some(digest) = key.strip_prefix(BODY_KEYS.decl().prefix) else {
        return Ok(None);
    };
    let digest: [u8; 32] = digest
        .try_into()
        .map_err(|_| Error::CorruptedIndex("body file key row key"))?;
    Ok(Some((digest, BODY_KEYS.decode_value(value)?)))
}

/// A body a checkpoint must carry that has no instance bound yet: the
/// binding pass mints one for it before the snapshot (KS-2A).
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) enum Unbound {
    /// An ASSET entity's row body.
    Asset(EntityId),
    /// An inline result's body, `len` bytes long.
    Result([u8; 32], u64),
    /// A plain vault's body file, `len` bytes long.
    File([u8; 32], u64),
    /// A row-held response with no instance bound to its bytes, by its
    /// carrier (KS-2B1).
    Response(Vec<u8>),
}

/// What a snapshot's rows name of the bodies beside and inside them,
/// gathered as its transaction reads them.
#[derive(Default)]
pub(super) struct BodyCensus {
    bodies: BTreeSet<([u8; 32], u64)>,
    keys: BTreeMap<[u8; 32], BodyKeyRow>,
    inline: Vec<(CarriedInline, Vec<u8>)>,
    /// Inline bodies with no instance bound yet.
    unbound: Vec<Unbound>,
    /// The row-held responses the rows hold, and the bindings read
    /// (KS-2B1).
    responses: ResponseCensus,
}

impl BodyCensus {
    /// Notes what the canonical row `key` of `database`, holding `value`,
    /// names: a result body's file, a file-plane ASSET's, a descriptor's
    /// file, an instance row, or an inline body. An inline body's row comes
    /// back without its bytes, which travel sealed under its instance.
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
    ) -> Result<Option<Vec<u8>>> {
        match self.responses.note(store, txn, database, key, value)? {
            Noted::Not => {}
            Noted::Unbound => return Ok(None),
            Noted::Bound {
                carriage,
                instance,
                digest,
            } => {
                let (carried, body, stub) =
                    response_rows::carry(database, key, value, (carriage, instance, digest))?;
                self.inline.push((carried, body));
                return Ok(Some(stub));
            }
        }
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
                if let Some((digest, body)) =
                    crate::code_run::code_run_inline_body_of_row(key, value)
                {
                    let Some(row) = BODY_KEYS.get(store, txn, &digest)?.filter(|row| row.inline)
                    else {
                        self.unbound
                            .push(Unbound::Result(digest, body.len() as u64));
                        return Ok(None);
                    };
                    return self.carry(database, key, value, 1, row.instance, body);
                }
            }
            "entities" => {
                if let Some(body) = crate::store::asset_body_file_of_row(store, txn, key, value)? {
                    self.bodies.insert(body);
                } else if inline_asset(value) {
                    let id = EntityId::from_bytes(
                        key.try_into()
                            .map_err(|_| Error::CorruptedIndex("entity key"))?,
                    )?;
                    let Some(instance) = INLINE_ASSETS.get(store, txn, &id)? else {
                        self.unbound.push(Unbound::Asset(id));
                        return Ok(None);
                    };
                    let body = &value[ENTITY_METADATA_HEADER_LEN..];
                    return self.carry(
                        database,
                        key,
                        value,
                        ENTITY_METADATA_HEADER_LEN,
                        instance,
                        body,
                    );
                }
            }
            _ => {}
        }
        Ok(None)
    }

    /// Carries `body`, the bytes of the row `key` after its first `keep`,
    /// sealed under `instance`: the row comes back without it.
    fn carry(
        &mut self,
        database: &str,
        key: &[u8],
        value: &[u8],
        keep: usize,
        instance: [u8; 16],
        body: &[u8],
    ) -> Result<Option<Vec<u8>>> {
        self.inline.push((
            CarriedInline {
                database: database.to_owned(),
                key: key.to_vec(),
                keep: u32::try_from(keep).map_err(|_| codec_error())?,
                instance,
                digest: *blake3::hash(body).as_bytes(),
                len: body.len() as u64,
                stored_len: 0,
                retired: None,
                landed_len: None,
                superseded: false,
            },
            body.to_vec(),
        ));
        Ok(Some(value[..keep].to_vec()))
    }

    /// Every body the rows name that has no instance bound yet: an inline
    /// one, and a plain vault's file with no file instance row. A sealed
    /// vault's file always has its instance, minted with it.
    ///
    /// # Errors
    ///
    /// [`Error::CorruptedIndex`] for a sealed vault's file with no instance
    /// row.
    pub(super) fn unbound(&self, store: &Store) -> Result<Vec<Unbound>> {
        let mut unbound = self.unbound.clone();
        unbound.extend(
            self.responses
                .unbound()
                .iter()
                .cloned()
                .map(Unbound::Response),
        );
        let sealed = store.dir_seal(crate::store::KeyScope::Vault).is_some();
        for (digest, len) in &self.bodies {
            if self.keys.get(digest).is_none_or(|row| row.inline) {
                if sealed {
                    return Err(Error::CorruptedIndex("body file with no instance row"));
                }
                unbound.push(Unbound::File(*digest, *len));
            }
        }
        Ok(unbound)
    }

    /// The full key of each response binding whose row holds no response
    /// now (KS-2B1): the image leaves it out, the binding pass drops it.
    pub(super) fn stale(&self) -> BTreeSet<Vec<u8>> {
        self.responses.stale()
    }

    /// The bodies to carry, each once, with its envelope's facts; `None`
    /// when a body the rows name has no instance bound yet, so the snapshot
    /// is taken again after the next binding pass. `store`'s `bodies/` is
    /// opened only when there is one.
    ///
    /// # Errors
    ///
    /// [`Error::CorruptedIndex`] for a named file that is missing or does
    /// not check; custody, sealing and filesystem errors.
    pub(super) fn finish(self, store: &Store) -> Result<Option<CarriedFiles>> {
        if !self.unbound(store)?.is_empty() {
            return Ok(None);
        }
        let carries = !self.bodies.is_empty() || !self.inline.is_empty();
        let custody = match store.body_custody() {
            Some(custody) => Some(custody),
            None if carries => return Err(crate::store::custody_unavailable(1)),
            None => None,
        };
        let dir = if self.bodies.is_empty() {
            None
        } else {
            Some(store.body_dir()?)
        };
        let bodies: Vec<_> = self.bodies.into_iter().collect();
        let mut sealed = BTreeMap::new();
        for (index, (digest, len)) in bodies.iter().enumerate() {
            let (Some(row), Some(dir), Some(custody)) = (
                self.keys.get(digest).filter(|row| !row.inline),
                &dir,
                &custody,
            ) else {
                return Err(codec_error());
            };
            let stored_len = if dir.sealed.is_some() {
                open_stored(dir, digest, *len, Some(row))?.stored_len()?
            } else {
                let key = body_key_in(custody, &row.instance)?;
                SealingStream::new(std::io::empty(), key, *len, None)?.sealed_len()?
            };
            sealed.insert(
                index as u64,
                SealedFile {
                    instance: row.instance,
                    stored_len,
                },
            );
        }
        let mut inline = self.inline;
        for (carried, _) in &mut inline {
            let custody = custody.as_ref().ok_or_else(codec_error)?;
            let key = body_key_in(custody, &carried.instance)?;
            carried.stored_len =
                SealingStream::new(std::io::empty(), key, carried.len, None)?.sealed_len()?;
        }
        Ok(Some(CarriedFiles {
            bodies,
            sealed,
            keys: self.keys,
            inline,
            dir,
            custody,
        }))
    }
}

/// Whether an `entities` row is an ASSET whose body rests in it.
pub(super) fn inline_asset(value: &[u8]) -> bool {
    EntityMetadataHeader::parse(value)
        .is_some_and(|header| header.entity_type == crate::registry::ENTITY_TYPE_ASSET)
        && value.len() > ENTITY_METADATA_HEADER_LEN
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

/// The bodies a snapshot carries, ready for its artifact.
pub(super) struct CarriedFiles {
    bodies: Vec<([u8; 32], u64)>,
    sealed: BTreeMap<u64, SealedFile>,
    keys: BTreeMap<[u8; 32], BodyKeyRow>,
    inline: Vec<(CarriedInline, Vec<u8>)>,
    dir: Option<BodyDir>,
    custody: Option<CustodyBinding>,
}

impl CarriedFiles {
    /// What the image names: each file's BLAKE3 and length, each one's
    /// instance and envelope, and each inline body.
    pub(super) fn image_bodies(
        &self,
    ) -> (
        Vec<([u8; 32], u64)>,
        BTreeMap<u64, SealedFile>,
        Vec<CarriedInline>,
    ) {
        (
            self.bodies.clone(),
            self.sealed.clone(),
            self.inline
                .iter()
                .map(|(carried, _)| carried.clone())
                .collect(),
        )
    }

    /// What each stream the artifact carries must be: an envelope of its
    /// length, whose frames its stream checks as it is read.
    pub(super) fn streams(&self) -> Vec<ArtifactBody> {
        self.sealed
            .values()
            .map(|file| file.stored_len)
            .chain(self.inline.iter().map(|(carried, _)| carried.stored_len))
            .map(|len| ArtifactBody { len, digest: None })
            .collect()
    }

    /// The `index`th stream, sealed under its instance's key, from its
    /// start.
    ///
    /// # Errors
    ///
    /// As [`BodyCensus::finish`].
    pub(super) fn open(&self, index: usize) -> Result<Box<dyn Read + Send>> {
        let custody = self.custody.as_ref().ok_or_else(codec_error)?;
        let Some(inline) = index.checked_sub(self.bodies.len()) else {
            let ((digest, len), dir) = self
                .bodies
                .get(index)
                .zip(self.dir.as_ref())
                .ok_or_else(codec_error)?;
            let row = self.keys.get(digest).ok_or_else(codec_error)?;
            let file = open_stored(dir, digest, *len, Some(row))?;
            if dir.sealed.is_some() {
                return Ok(file.into_stored());
            }
            let key = body_key_in(custody, &row.instance)?;
            return Ok(Box::new(SealingStream::new(
                file.into_stored(),
                key,
                *len,
                Some(*digest),
            )?));
        };
        let (carried, body) = self.inline.get(inline).ok_or_else(codec_error)?;
        let key = body_key_in(custody, &carried.instance)?;
        Ok(Box::new(SealingStream::new(
            Cursor::new(body.clone()),
            key,
            carried.len,
            Some(carried.digest),
        )?))
    }
}

/// Requires every body instance the image's rows name through `plan`, the
/// custody plan its claim keys share, before anything is made: a missing
/// one refuses as `body_key_custody_unavailable`, and a retired one's rows
/// go as its erase took them. Each carried stream must be an instance the
/// rows name. The retired instances, whose streams the restore passes over.
///
/// # Errors
///
/// `body_key_custody_unavailable`, a stream no row names, and custody
/// errors.
pub(super) fn require(
    image: &mut CheckpointImage,
    plan: &mut CustodyPlan,
) -> Result<BTreeSet<[u8; 16]>> {
    let rows = image
        .databases
        .get_mut("vault_meta")
        .ok_or_else(codec_error)?;
    let named = body_instances_in_rows(rows)?;
    // A superseded response's binding is the live vault's now (KS-2B2).
    let carried = image
        .sealed_bodies
        .values()
        .map(|file| file.instance)
        .chain(
            image
                .inline_bodies
                .iter()
                .filter(|carried| !carried.superseded)
                .map(|carried| carried.instance),
        );
    for instance in carried {
        if !named.contains(&instance) {
            return Err(codec_error());
        }
    }
    let retired = require_body_instances(&named, plan)?;
    let pruned = prune_retired_bodies_in_rows(rows, &retired)?;
    // A retired response's row keeps its erased disposition (KS-2B1).
    response_rows::retire_carried(image, &retired)?;
    // So does a step claim whose response's artifact version rests in a
    // retired body; its pins release once the rows land (FIX 6225).
    crate::llm::retire_erased_step_responses_in_rows(
        &mut image.databases,
        &pruned.assets,
        &pruned.digests,
    )?;
    Ok(retired)
}

/// Reads past the `index`th stream without opening it: its outer frames
/// are still checked against the manifest as they pass.
fn pass_over(bodies: &mut SealedBodies<'_>, index: usize) -> Result<()> {
    std::io::copy(&mut bodies.body(index), &mut std::io::sink())?;
    Ok(())
}

/// Brings the image's bodies into `vault`: each file into its `bodies/`,
/// read back through its frames and checked, before any row naming it
/// lands; each inline body back into its row. Keys come from `custody`, the
/// custody the rows bind. A retired instance's stream is passed over; its
/// rows went at [`require`]. A result body comes back with its line index,
/// an ASSET's file raw. Each file claims what is left of the copy's room on
/// `room` before it lands (FIX 5479).
///
/// # Errors
///
/// [`Error::CorruptedIndex`] for a frame that does not check or a row the
/// image does not hold; custody errors; a claim the disk's floor refuses;
/// filesystem errors.
pub(super) fn restore(
    vault: &Vault,
    image: &mut CheckpointImage,
    mut bodies: SealedBodies<'_>,
    room: &mut RestoreRoom<'_>,
    (custody, retired): (Option<&CustodyBinding>, &BTreeSet<[u8; 16]>),
) -> Result<()> {
    let files = image.bodies.len();
    if files + image.inline_bodies.len() == 0 {
        return Ok(());
    }
    let custody = custody.ok_or_else(|| crate::store::custody_unavailable(1))?;
    let target = vault.store.body_dir()?;
    let results = image.databases["vault_meta"]
        .iter()
        .filter_map(|(key, value)| crate::code_run::code_run_body_file_of_row(key, value))
        .map(|(digest, _)| digest)
        .collect::<BTreeSet<_>>();
    for (index, (digest, len)) in image.bodies.iter().enumerate() {
        let carried = image
            .sealed_bodies
            .get(&(index as u64))
            .ok_or_else(codec_error)?;
        if retired.contains(&carried.instance) {
            pass_over(&mut bodies, index)?;
            continue;
        }
        room.landing_body(landing_len(*len, Some(carried)))?;
        let key = body_key_in(custody, &carried.instance)?;
        land_file(
            &target,
            &mut bodies,
            index,
            (digest, *len),
            key,
            results.contains(digest),
        )?;
    }
    for (inline, carried) in image.inline_bodies.iter().enumerate() {
        if carried.superseded || retired.contains(&carried.instance) {
            pass_over(&mut bodies, files + inline)?;
            continue;
        }
        let key = body_key_in(custody, &carried.instance)?;
        let mut body = Vec::with_capacity(usize::try_from(carried.len).map_err(|_| codec_error())?);
        SealedStream::plaintext(
            bodies.body(files + inline),
            key,
            carried.digest,
            carried.len,
        )
        .read_to_end(&mut body)?;
        let rows = image
            .databases
            .get_mut(&carried.database)
            .ok_or_else(codec_error)?;
        let value = response_rows::row_mut(rows, &carried.key)?;
        let keep = carried.keep as usize;
        // An inline body's row is its first bytes alone; a response's is its
        // stub, whose first bytes the exact body follows (KS-2B1).
        if value.len() < keep || (carried.retired.is_none() && value.len() != keep) {
            return Err(codec_error());
        }
        value.truncate(keep);
        value.extend_from_slice(&body);
    }
    Ok(())
}

/// Lands the `index`th file, the body `digest` of `len` bytes sealed under
/// `key`: a sealed vault takes the envelope as it is, a plain one the body
/// opened, a result with its line index.
fn land_file(
    target: &BodyDir,
    bodies: &mut SealedBodies<'_>,
    index: usize,
    (digest, len): (&[u8; 32], u64),
    key: Arc<FileKey>,
    lines: bool,
) -> Result<()> {
    let source = bodies.body(index);
    if target.sealed.is_some() {
        return target.import_sealed(digest, len, source, key, lines);
    }
    let mut plain = SealedStream::plaintext(source, key, *digest, len);
    if lines {
        target.import(digest, len, &mut plain)
    } else {
        target.import_asset_body(digest, len, &mut plain)
    }
}
