//! The kept-generation inventory beside a checkpoint artifact (KS7-5): the
//! compartments its payload is sealed under, for the host that keeps the
//! copy. Each line names an owner's incarnation and its leaf's generation;
//! the holder ref is the artifact's checkpoint id. A host's prune reads the
//! inventory of every copy it keeps
//! ([`Vault::retire_unkept_checkpoint_payloads`]), and a retention
//! retirement of a leaf waits while a kept copy names it.
//!
//! It sits beside its artifact as `.<snapshot id hex>.payload-inventory`,
//! named by the snapshot id the artifact's head carries, which outlives the
//! rename a host lands the artifact by. It is sealed under the artifact's
//! own key on the manifest's stream, past the manifest root's index: a root
//! envelope names the pieces' count, length and BLAKE3, and each piece, at
//! most the artifact's chunk length, follows in a frame of its own. It
//! opens only for its artifact, and a piece dropped, added or moved does
//! not open. One that is missing or does not open keeps every leaf.
//!
//! ```text
//! "OKPI" ‖ u8 1 ‖ (u32be len ‖ E0 envelope)*
//! ```

use std::fs::File;
use std::path::{Path, PathBuf};

use oneiron_crypto::backup::MANIFEST_STREAM;
use oneiron_vault_contract::backup_handoff::write_private_file;
use serde::{Deserialize, Serialize};

use super::sink::Sealer;
use super::{ArtifactKind, CHUNK_LEN, CheckpointKey, Prelude, codec};
use crate::recovery::checkpoint::payload::PayloadSection;
use crate::store::checkpoint_payload::kept::KeptGenerations;
use crate::store::checkpoint_payload::{CHECKPOINT_PAYLOADS_ENABLED, PayloadItem, Subtype};
use crate::world_keys::{CarriedVaultKey, refused};
use crate::{Result, Vault};

const MAGIC: &[u8; 4] = b"OKPI";
const VERSION: u8 = 1;
const SUFFIX: &str = ".payload-inventory";

/// The manifest stream's index the inventory's root seals at: the
/// manifest's own root takes 0, and the pieces follow this one.
const ROOT_INDEX: u32 = 1;

/// What the root envelope names of the pieces after it.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Root {
    pieces: u32,
    len: u64,
    digest: [u8; 32],
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Inventory {
    /// The artifact's checkpoint id: the kept copy that holds every line.
    checkpoint: [u8; 32],
    kept: Vec<KeptLine>,
}

/// One compartment: its owner's item (subtype, owner, incarnation) and its
/// leaf's generation.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct KeptLine {
    subtype: u8,
    owner: [u8; 32],
    incarnation: [u8; 16],
    generation: u64,
}

/// The directory and name of the inventory beside `artifact`, whose
/// snapshot id is `snapshot`.
fn place(artifact: &Path, snapshot: &[u8; 32]) -> (PathBuf, String) {
    let dir = artifact
        .parent()
        .filter(|dir| !dir.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let name = format!(".{}{SUFFIX}", blake3::Hash::from(*snapshot).to_hex());
    (dir.to_path_buf(), name)
}

/// The manifest stream's index of the `at`th piece.
fn piece_index(at: usize) -> Result<u32> {
    u32::try_from(at)
        .ok()
        .and_then(|at| at.checked_add(ROOT_INDEX + 1))
        .ok_or_else(codec)
}

fn put_frame(out: &mut Vec<u8>, envelope: &[u8]) -> Result<()> {
    let len = u32::try_from(envelope.len()).map_err(|_| codec())?;
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(envelope);
    Ok(())
}

fn next_frame<'a>(rest: &mut &'a [u8]) -> Result<&'a [u8]> {
    let (len, tail) = rest.split_first_chunk::<4>().ok_or_else(codec)?;
    let len = usize::try_from(u32::from_be_bytes(*len)).map_err(|_| codec())?;
    let (frame, tail) = tail.split_at_checked(len).ok_or_else(codec)?;
    *rest = tail;
    Ok(frame)
}

/// Writes the inventory of `section`, the payload of the `kind` artifact
/// about to be written at `artifact` for `snapshot` under `key` and the
/// vault key `carried` names, whose checkpoint id is `checkpoint`. Written,
/// synced and renamed into place before the artifact is; returns where.
///
/// # Errors
///
/// Sealing, encoding and filesystem faults.
pub(in crate::recovery::checkpoint) fn write_payload_inventory(
    artifact: &Path,
    key: &CheckpointKey,
    kind: ArtifactKind,
    carried: &CarriedVaultKey,
    snapshot: [u8; 32],
    checkpoint: [u8; 32],
    section: &PayloadSection,
) -> Result<PathBuf> {
    let sealer = Sealer {
        key,
        purpose: kind.purpose(),
        commitment: *carried.commitment(),
        snapshot,
    };
    let kept = section
        .required()?
        .into_iter()
        .map(|(item, generation)| KeptLine {
            subtype: item.subtype().tag(),
            owner: *item.owner(),
            incarnation: *item.incarnation(),
            generation,
        })
        .collect();
    let plain = rmp_serde::to_vec_named(&Inventory { checkpoint, kept }).map_err(|_| codec())?;
    let pieces: Vec<&[u8]> = plain.chunks(CHUNK_LEN).collect();
    let root = Root {
        pieces: u32::try_from(pieces.len()).map_err(|_| codec())?,
        len: plain.len() as u64,
        digest: *blake3::hash(&plain).as_bytes(),
    };
    let root = rmp_serde::to_vec_named(&root).map_err(|_| codec())?;
    let mut out = MAGIC.to_vec();
    out.push(VERSION);
    put_frame(&mut out, &sealer.seal(MANIFEST_STREAM, ROOT_INDEX, &root)?)?;
    for (at, piece) in pieces.into_iter().enumerate() {
        put_frame(
            &mut out,
            &sealer.seal(MANIFEST_STREAM, piece_index(at)?, piece)?,
        )?;
    }
    let (dir, name) = place(artifact, &snapshot);
    Ok(write_private_file(&dir, &name, &out)?)
}

/// The inventory beside the artifact at `artifact`, opened with `key`.
fn read_inventory(artifact: &Path, key: &CheckpointKey) -> Result<Inventory> {
    let prelude = Prelude::read(&mut File::open(artifact)?)?;
    if prelude.vault_id != key.vault_id {
        return Err(refused("the checkpoint is another vault's"));
    }
    let sealer = Sealer {
        key,
        purpose: prelude.kind.purpose(),
        commitment: *prelude.carried()?.commitment(),
        snapshot: prelude.snapshot,
    };
    let (dir, name) = place(artifact, &prelude.snapshot);
    let bytes = std::fs::read(dir.join(name))?;
    let mut rest = bytes
        .strip_prefix(MAGIC.as_slice())
        .and_then(<[u8]>::split_first)
        .filter(|(version, _)| **version == VERSION)
        .map(|(_, rest)| rest)
        .ok_or_else(codec)?;
    let root = sealer.open(MANIFEST_STREAM, ROOT_INDEX, next_frame(&mut rest)?)?;
    let root: Root = rmp_serde::from_slice(&root).map_err(|_| codec())?;
    let mut plain = Vec::new();
    for at in 0..root.pieces as usize {
        let piece = sealer.open(MANIFEST_STREAM, piece_index(at)?, next_frame(&mut rest)?)?;
        plain.extend_from_slice(&piece);
    }
    if !rest.is_empty()
        || plain.len() as u64 != root.len
        || *blake3::hash(&plain).as_bytes() != root.digest
    {
        return Err(codec());
    }
    rmp_serde::from_slice(&plain).map_err(|_| codec())
}

/// Records every line of the inventory beside `artifact` in `kept`.
fn hold_inventory(artifact: &Path, key: &CheckpointKey, kept: &mut KeptGenerations) -> Result<()> {
    let inventory = read_inventory(artifact, key)?;
    for line in inventory.kept {
        let subtype = Subtype::from_tag(line.subtype).ok_or_else(codec)?;
        let item = PayloadItem::new(subtype, line.owner, line.incarnation)?;
        kept.hold(item, line.generation, inventory.checkpoint);
    }
    Ok(())
}

impl Vault {
    /// Where the kept-generation inventory of the checkpoint artifact at
    /// `artifact` sits (KS7-5), by the snapshot id its head carries: what a
    /// host removes once the artifact is gone. `None` when the head does
    /// not read.
    #[must_use]
    pub fn checkpoint_payload_inventory(artifact: &Path) -> Option<PathBuf> {
        let prelude = Prelude::read(&mut File::open(artifact).ok()?).ok()?;
        let (dir, name) = place(artifact, &prelude.snapshot);
        Some(dir.join(name))
    }

    /// Carries out every staged checkpoint payload leaf retirement no kept
    /// copy still needs (KS7-5): `kept` names every artifact of this vault
    /// the host keeps, each read through the inventory beside it. One whose
    /// inventory is missing or does not open keeps every leaf, so a
    /// retention retirement waits; an erase's retires as before, and no user
    /// act waits on either. Whether any retirement was owed.
    ///
    /// # Errors
    ///
    /// Custody faults, and an intent the checkpoint payload client refuses
    /// by name: the next pass retries.
    pub fn retire_unkept_checkpoint_payloads(&self, kept: &[PathBuf]) -> Result<bool> {
        if !CHECKPOINT_PAYLOADS_ENABLED {
            return Ok(false);
        }
        let mut generations = KeptGenerations::default();
        match self.checkpoint_key() {
            Ok(key) => {
                for artifact in kept {
                    if let Err(error) = hold_inventory(artifact, &key, &mut generations) {
                        tracing::warn!(
                            kind = ?error.kind(),
                            "a kept checkpoint's payload inventory did not read; payload leaf \
                             retention waits"
                        );
                        generations.unread();
                    }
                }
            }
            Err(error) => {
                tracing::warn!(
                    kind = ?error.kind(),
                    "the checkpoint key did not unlock; payload leaf retention waits"
                );
                generations.unread();
            }
        }
        self.store.finish_checkpoint_payload_retention(&generations)
    }
}
