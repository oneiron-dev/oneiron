//! A checkpoint image and its structural read (moved out of the checkpoint
//! module whole).

use std::collections::BTreeMap;
use std::path::Path;

use serde::{Deserialize, Serialize};

use super::{
    CanonicalRows, CheckpointKey, StorageTier, artifact, carried_bodies, codec_error, storage_tier,
};
use crate::Result;
use crate::store::DB_MANIFEST;

/// The image format: 3 carries every body sealed under its instance's key
/// and inline bodies out of their rows (KS-2A).
pub(super) const IMAGE_VERSION: u16 = 3;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct CheckpointImage {
    pub(super) version: u16,
    pub(super) created_at: u64,
    pub(super) databases: BTreeMap<String, CanonicalRows>,
    /// Each body file the rows name: its BLAKE3 and length.
    pub(super) bodies: Vec<([u8; 32], u64)>,
    /// Each one's instance and the length of the envelope it travels in, by
    /// its place in `bodies`: every body is carried sealed under its
    /// instance's key alone (FIX 5348, KS-2A).
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub(super) sealed_bodies: BTreeMap<u64, carried_bodies::SealedFile>,
    /// Each inline body the rows hold, carried sealed under its instance's
    /// key after the files; its row here keeps only what precedes the body
    /// (KS-2A).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub(super) inline_bodies: Vec<carried_bodies::CarriedInline>,
    /// The checkpoint sequence its artifact's verified commitment signs, set
    /// as the artifact opens (OF-570 (e)); never in an image.
    #[serde(skip)]
    pub(super) checkpoint_sequence: Option<u64>,
}

impl CheckpointImage {
    /// A direct restore may land on any install, so the image's machine
    /// identity, and the root it pins, stay with the install that minted it:
    /// the restored vault joins as a new machine and opens unpinned. So does a copy served beside a live vault,
    /// whose authority it keeps; only a restore that takes that vault's
    /// place carries its identity (`restore_class`).
    pub(super) fn drop_machine_identity(&mut self) {
        if let Some(rows) = self.databases.get_mut("sync_state") {
            rows.retain(|(key, _)| !crate::identity::is_machine_identity_row(key));
        }
    }
}

/// Opens one sealed artifact with `key` and structurally checks its image;
/// returns the image, its checkpoint id and the bodies it carries.
pub(super) fn read_image<'k>(
    path: &Path,
    key: &'k CheckpointKey,
) -> Result<(CheckpointImage, String, artifact::SealedBodies<'k>)> {
    read_image_required(path, key).map(|(image, id, bodies, _)| (image, id, bodies))
}

/// [`read_image`], with what the image needs of its custody (KS-4).
pub(super) fn read_image_required<'k>(
    path: &Path,
    key: &'k CheckpointKey,
) -> Result<(
    CheckpointImage,
    String,
    artifact::SealedBodies<'k>,
    Option<crate::store::CustodyRequirement>,
)> {
    decode_image(artifact::open_artifact(path, key)?)
}

/// The image's structural read once its artifact opened: its checkpoint id,
/// the bodies it carries and what it needs of its custody.
pub(super) fn decode_image(
    opened: artifact::OpenedArtifact<'_>,
) -> Result<(
    CheckpointImage,
    String,
    artifact::SealedBodies<'_>,
    Option<crate::store::CustodyRequirement>,
)> {
    let mut image: CheckpointImage =
        rmp_serde::from_slice(&opened.image).map_err(|_| codec_error())?;
    image.checkpoint_sequence = Some(opened.sequence);
    if image.version != IMAGE_VERSION
        || image.created_at != opened.created_at
        || !carried_bodies::matches_artifact(&image, &opened.bodies.list())
        || image.databases.len() != DB_MANIFEST.len()
        || DB_MANIFEST
            .iter()
            .any(|e| !image.databases.contains_key(e.name))
    {
        return Err(codec_error());
    }
    for (name, rows) in &image.databases {
        if rows.windows(2).any(|w| w[0].0 >= w[1].0)
            || rows
                .iter()
                .any(|(k, _)| storage_tier(name, k) != StorageTier::Canonical)
        {
            return Err(codec_error());
        }
    }
    if image.databases["entities"].iter().any(|(_, value)| {
        crate::batch::EntityMetadataHeader::parse(value)
            .is_some_and(|h| h.entity_type == crate::registry::ENTITY_TYPE_DIAGNOSTIC)
    }) {
        return Err(codec_error());
    }
    // A pad row rides an image by reference (KS-5): never at rest with its
    // pad beside it.
    if image.databases["entities"]
        .iter()
        .any(|(_, value)| !crate::world_keys::image_pad_form_ok(value))
    {
        return Err(codec_error());
    }
    let id = blake3::Hash::from(opened.image_id).to_hex().to_string();
    Ok((image, id, opened.bodies, opened.custody))
}
