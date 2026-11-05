//! Files stored with keys in them (OF-560; ARCH-0069 #mask-on-write, owner
//! ruling G04 binary = C2). An ASSET is named by its bytes, so the write door
//! keeps a file's bytes as they are. It lifts each key it finds into its own
//! custody record and records here where the key sits and which record holds
//! it, and the file's band. Custody never holds a copy of the file.
//!
//! A serving door reads that record by the bytes' hash: the owner reads the
//! stored bytes; every other reader a copy with each key's span overwritten
//! by filler of the same length. The stored bytes never change, and a copy
//! the write door's scan still reads as secret is refused, never served
//! (FIX 2480): the door that accepted the file reads its copy.
//!
//! A key inside a container's member (a ZIP entry, a gzip payload, a PDF
//! stream or an object's text strings) is marked at its span in the decoded
//! member (OF-067 C). Its copy is rebuilt: the member decoded, its keys
//! overwritten, the container encoded around it again
//! (`batch::secret_scan::container`); in a text member a key reads as its
//! custody handle, `[secret sc12]` (FIX 7944). A container the write door
//! kept no keys in is still read whole before a masked reader gets it, the
//! bytes no reader shows included (FIX 2470). One whose only key sits in
//! those bytes is served its copy rebuilt without them, as a marked file's
//! copy is, once the scan reads that copy clean (FIX 11553, 12268); one that
//! holds a key no mark places elsewhere is refused. A sealed one, which no
//! reader here reads whole (encrypted, malformed, past the byte floor), is
//! stored as it is (owner ruling C2): the owner and a granted agent read its
//! bytes (`reveal::file`), and a masked reader gets
//! [`SecretError::SealedFileWithheld`], never the raw bytes. A file a masked
//! reader cannot be served is [`SecretError::MaskedCopyWithheld`] with the
//! scan's reason (FIX 2475).

use heed::{RoTxn, RwTxn};

use crate::entity_id::EntityId;
use crate::error::{Error, Result, SecretError};
use crate::file_secret_marks::{
    KeyPlaces, KeySpan, MemberStep, PlaceHandles, SecretSight, masked_copy_withheld,
};
use crate::ports::ShortIdStoreRead;
use crate::registry::ENTITY_TYPE_ASSET;
use crate::side_table::{self, Named, SideTable, SideTableDbs};
use crate::store::Store;
use oneiron_authority::federation::Sensitivity;

/// The band a file with keys in it carries.
pub(crate) const MASKED_FILE_BAND: Sensitivity = Sensitivity::Restricted;

/// One row per file the write door kept with keys in it. Key: the blake3 hash
/// of the stored bytes, which every door that serves them holds.
const MASKED_FILE: SideTable<[u8; 32], MaskedFile, Named> =
    SideTable::new(&side_table::SECRET_MASK_SPANS);

/// Where the keys sit in one stored file. It holds no value.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub(crate) struct MaskedFile {
    pub(crate) band: Sensitivity,
    /// In the stored bytes, in byte order; none overlaps the next.
    pub(crate) keys: Vec<KeySpan>,
    pub(crate) masked_at: u64,
    /// The keys inside the file's members, one entry per member, in the
    /// order the walk meets them. A row written before members were read
    /// has none.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub(crate) members: Vec<MemberKeys>,
}

/// The keys in one member of a stored container: its path from the stored
/// bytes down, and each key's span in the member's decoded bytes, in byte
/// order. The path names no member by its name, which may hold a key.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub(crate) struct MemberKeys {
    pub(crate) path: Vec<MemberStep>,
    pub(crate) keys: Vec<KeySpan>,
}

impl MaskedFile {
    /// Each place this row marks keys at.
    pub(crate) fn places(&self) -> KeyPlaces {
        let spans = |keys: &[KeySpan]| -> Vec<(u64, u64)> {
            keys.iter().map(|key| (key.start, key.end)).collect()
        };
        let mut places = Vec::with_capacity(self.members.len() + 1);
        if !self.keys.is_empty() {
            places.push((Vec::new(), spans(&self.keys)));
        }
        places.extend(
            self.members
                .iter()
                .map(|member| (member.path.clone(), spans(&member.keys))),
        );
        places
    }

    /// Each place's handle texts, in [`Self::places`]' order (FIX 7944): a
    /// key's custody record's handle, `[secret sc12]`.
    fn place_handles(&self, store: &Store, txn: &RoTxn<'_>) -> Result<PlaceHandles> {
        let texts = |keys: &[KeySpan]| -> Result<Vec<Option<String>>> {
            keys.iter()
                .map(|key| {
                    Ok(store
                        .port_short_id_reference(txn, &key.custody)?
                        .map(|(handle, _)| super::known_value_index::handle_text(&handle)))
                })
                .collect()
        };
        let mut handles = Vec::with_capacity(self.members.len() + 1);
        if !self.keys.is_empty() {
            handles.push(texts(&self.keys)?);
        }
        for member in &self.members {
            handles.push(texts(&member.keys)?);
        }
        Ok(handles)
    }

    /// Adds `key` at `path` (the stored bytes' own place for an empty path)
    /// unless a key there overlaps it, each place's keys kept in byte order
    /// (FIX 2781): the marks already held stay as they are. `true` when it
    /// was added.
    pub(crate) fn unite(&mut self, path: &[MemberStep], key: KeySpan) -> bool {
        let keys = if path.is_empty() {
            &mut self.keys
        } else if let Some(at) = self.members.iter().position(|member| member.path == path) {
            &mut self.members[at].keys
        } else {
            self.members.push(MemberKeys {
                path: path.to_vec(),
                keys: Vec::new(),
            });
            let last = self.members.len() - 1;
            &mut self.members[last].keys
        };
        if keys
            .iter()
            .any(|held| held.start < key.end && key.start < held.end)
        {
            return false;
        }
        let at = keys.partition_point(|held| held.start < key.start);
        keys.insert(at, key);
        true
    }
}

pub(crate) fn masked_file_in_txn(
    store: &impl SideTableDbs,
    txn: &RoTxn<'_>,
    hash: &[u8; 32],
) -> Result<Option<MaskedFile>> {
    MASKED_FILE.get(store, txn, hash)
}

pub(crate) fn put_masked_file_in_txn(
    store: &impl SideTableDbs,
    txn: &mut RwTxn<'_>,
    hash: &[u8; 32],
    file: &MaskedFile,
) -> Result<()> {
    MASKED_FILE.put(store, txn, hash, file)
}

/// Drops `custody`'s key from the mark of the file `hash` names, in its
/// stored bytes and in each member, and the mark with its last key: the
/// owner ruled it no secret.
pub(crate) fn drop_masked_key_in_txn(
    store: &impl SideTableDbs,
    txn: &mut RwTxn<'_>,
    hash: &[u8; 32],
    custody: &EntityId,
) -> Result<()> {
    let Some(mut file) = masked_file_in_txn(store, txn, hash)? else {
        return Ok(());
    };
    file.keys.retain(|key| key.custody != *custody);
    for member in &mut file.members {
        member.keys.retain(|key| key.custody != *custody);
    }
    file.members.retain(|member| !member.keys.is_empty());
    if file.keys.is_empty() && file.members.is_empty() {
        MASKED_FILE.delete(store, txn, hash)?;
        return Ok(());
    }
    MASKED_FILE.put(store, txn, hash, &file)
}

/// `bytes`, read from the store, as `sight` reads them. A file the write
/// door kept no keys in is served as it is, once a container's members and
/// the bytes no reader shows read clean to the write door; a container whose
/// only key sits in those bytes, at any depth, is served its copy rebuilt
/// through the whole tree without them, once that copy reads clean (FIX
/// 11553, 12268, 12279). A masked
/// copy is read by the write door's rules before it is served (FIX 2480); a
/// file this reader cannot be served masked is
/// [`SecretError::MaskedCopyWithheld`] (FIX 2475).
///
/// `digest` is the BLAKE3 of `bytes` when the caller holds one it computed
/// from, or checked against, these exact bytes: the mark is read by it and
/// the bytes are not hashed again (speed). `None` hashes them here. The
/// walks over an unmarked container and a marked file's rebuild take it
/// for the root file's entry (FIX 12270).
pub(crate) fn sighted_bytes_in_txn(
    store: &Store,
    txn: &RoTxn<'_>,
    bytes: Vec<u8>,
    digest: Option<&[u8; 32]>,
    sight: SecretSight,
) -> Result<Vec<u8>> {
    use crate::batch::secret_scan;
    if sight != SecretSight::Masked {
        return Ok(bytes);
    }
    let hash = match digest {
        Some(digest) => {
            debug_assert!(
                blake3::hash(&bytes).as_bytes() == digest,
                "a caller's digest names other bytes"
            );
            *digest
        }
        None => *blake3::hash(&bytes).as_bytes(),
    };
    let Some(file) = masked_file_in_txn(store, txn, &hash)? else {
        // Bytes that lead as no container are none to the walk, so none is
        // sealed and none holds a member: they are served as they are, read
        // once (speed).
        if !secret_scan::is_container(&bytes) {
            return Ok(bytes);
        }
        // A sealed file goes to the owner and a granted agent only: no mark
        // covers what it holds.
        if secret_scan::is_sealed(&bytes, digest) {
            return Err(Error::Secret(SecretError::SealedFileWithheld));
        }
        // A container stored with the scan off, or one no mark covers, may
        // hold keys in its members or in bytes no reader shows (FIX 2470):
        // it is read whole before it is served.
        let Some(reason) = secret_scan::write_tree_hit(&bytes, digest) else {
            return Ok(bytes);
        };
        // A key in what a reader shows is refused either way: the rebuild
        // keeps those bytes and the rescan refuses its copy, so it is
        // refused here, before the rebuild pays for the same answer (FIX
        // 12280). Only the refusal's timing changes; a key no live member
        // holds reads no hit here and takes the rebuild below unchanged.
        if secret_scan::live_content_hit(&bytes, digest).is_some() {
            return Err(masked_copy_withheld(reason));
        }
        // A key only in the bytes no reader shows is gone from the copy
        // rebuilt through the whole tree, which leaves them out at every
        // level as a marked file's copy does: that copy is served once the
        // write door's scan reads it clean (FIX 11553, 12268, 12279).
        let Some(copy) = secret_scan::tree_rebuilt_copy(&bytes, digest) else {
            return Err(masked_copy_withheld(reason));
        };
        if let Some(reason) = secret_scan::write_tree_hit(&copy, None) {
            return Err(masked_copy_withheld(reason));
        }
        return Ok(copy);
    };
    let handles = file.place_handles(store, txn)?;
    let copy = secret_scan::served_masked_copy(&bytes, &file.places(), &handles, digest)?;
    if let Some(reason) = secret_scan::write_tree_hit(&copy, None) {
        return Err(masked_copy_withheld(reason));
    }
    Ok(copy)
}

/// Whether the stored body of record `id` is a file with keys in it. A door
/// that hands whole stored records to a contact leaves it out: a contact
/// reads a key's handle only. A body kept in its file is named by the file's
/// digest, never by its manifest's (FIX 5507).
pub(crate) fn holds_masked_keys_in_txn(
    store: &crate::store::Store,
    txn: &RoTxn<'_>,
    id: &EntityId,
    entity_type: u8,
    body: &[u8],
) -> Result<bool> {
    if entity_type != ENTITY_TYPE_ASSET {
        return Ok(false);
    }
    let hash = match crate::store::asset_file_in_txn(store, txn, id, body)? {
        Some(manifest) => manifest.facts.blake3,
        None => *blake3::hash(body).as_bytes(),
    };
    Ok(masked_file_in_txn(store, txn, &hash)?.is_some())
}
