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

/// The image format: 4 adds exact-row source custody-key observations.
/// Every body remains sealed under its instance's key, with inline bodies
/// out of their rows (KS-2A).
pub(super) const IMAGE_VERSION: u16 = 4;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct CheckpointImage {
    pub(super) version: u16,
    pub(super) created_at: u64,
    pub(super) databases: BTreeMap<String, CanonicalRows>,
    /// Source key unavailability observed under this snapshot's custody
    /// guard, bound to exact credential row bytes. Missing evidence says
    /// nothing about source readability. Never restore or erase authority.
    pub(super) credential_keys_unavailable:
        Vec<super::credential_custody::UnavailableCredentialKey>,
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
    /// A hosted vault's host-order legal holds, sealed to its host's
    /// recipient (FIX 6598): host-private, never a canonical row and never
    /// the owner's to open (`host_holds`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) host_holds: Option<super::host_holds::HostHoldsMember>,
    /// The snapshot id its artifact's verified commitment signs, set as the
    /// artifact opens; never in an image.
    #[serde(skip)]
    pub(super) snapshot: Option<[u8; 32]>,
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

/// One authenticated artifact's image and streams, owned through its restore.
/// Only the verified artifact decoder constructs this value. Consuming its
/// parts gives up that ownership; raw images cannot enter `restore_image`.
pub(super) struct AuthenticatedCheckpoint<'k> {
    image: CheckpointImage,
    id: String,
    bodies: artifact::SealedBodies<'k>,
    required: Option<crate::store::CustodyRequirement>,
}

impl<'k> AuthenticatedCheckpoint<'k> {
    pub(super) fn image(&self) -> &CheckpointImage {
        &self.image
    }

    pub(super) fn required(&self) -> Option<&crate::store::CustodyRequirement> {
        self.required.as_ref()
    }

    pub(super) fn drop_machine_identity(&mut self) {
        self.image.drop_machine_identity();
    }

    pub(super) fn carry_host_holds(&mut self, live: &crate::store::LiveCustody) -> Result<()> {
        super::host_holds::carry(&mut self.image.databases, live.host_holds())
    }

    pub(super) fn carry_current_authority(
        &mut self,
        current: &crate::Vault,
    ) -> Result<(Vec<super::HomeTableNote>, crate::store::PadObjectsCapture)> {
        super::authority_plane::carry_current_authority(&mut self.image.databases, current)
    }

    pub(super) fn supersede_live_responses(&mut self, current: &crate::Vault) -> Result<()> {
        super::response_rows::supersede_live(&mut self.image, current)
    }

    pub(super) fn carry_current_host_holds(&mut self, current: &crate::Vault) -> Result<()> {
        super::host_holds::carry_current(&mut self.image.databases, current)
    }

    pub(super) fn artifact_host_holds(
        &mut self,
        key: &CheckpointKey,
    ) -> Option<super::HostOrderHolds> {
        super::host_holds::artifact_host_holds(&mut self.image, key)
    }

    pub(super) fn route_custody(
        &mut self,
        destination: &Path,
        key: &CheckpointKey,
        source: Option<&crate::store::CustodySourceAt<'_>>,
    ) -> std::result::Result<crate::store::CustodyRoute, super::Rejected> {
        crate::store::route_custody(
            self.image
                .databases
                .get_mut("vault_meta")
                .ok_or_else(codec_error)?,
            self.required.as_ref(),
            destination,
            key.custody_wrap(),
            source,
        )
    }

    pub(super) fn into_identity_and_requirement(
        self,
    ) -> (String, Option<crate::store::CustodyRequirement>) {
        (self.id, self.required)
    }

    pub(super) fn into_host_holds_member(self) -> Option<super::host_holds::HostHoldsMember> {
        self.image.host_holds
    }

    pub(super) fn into_landing_parts(
        self,
    ) -> (
        CheckpointImage,
        String,
        artifact::SealedBodies<'k>,
        Option<crate::store::CustodyRequirement>,
    ) {
        (self.image, self.id, self.bodies, self.required)
    }
}

/// Opens and structurally checks one authenticated artifact, retaining ownership
/// of the image and all streams until restore or read-only consumption.
pub(super) fn read_image<'k>(
    path: &Path,
    key: &'k CheckpointKey,
) -> Result<AuthenticatedCheckpoint<'k>> {
    read_image_required(path, key)
}

/// [`read_image`], retaining the image's custody requirement (KS-4).
pub(super) fn read_image_required<'k>(
    path: &Path,
    key: &'k CheckpointKey,
) -> Result<AuthenticatedCheckpoint<'k>> {
    decode_image(artifact::open_artifact(path, key)?)
}

/// The closed artifact's structural read. No raw image or caller-supplied
/// body collection can construct its authenticated restore continuation.
pub(super) fn decode_image<'k>(
    opened: artifact::OpenedArtifact<'k>,
) -> Result<AuthenticatedCheckpoint<'k>> {
    let mut image: CheckpointImage =
        rmp_serde::from_slice(opened.image()).map_err(|_| codec_error())?;
    image.checkpoint_sequence = Some(opened.sequence());
    image.snapshot = Some(opened.snapshot());
    if image.version != IMAGE_VERSION
        || image.created_at != opened.created_at()
        || !carried_bodies::matches_artifact(&image, &opened.bodies().list())
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
    let id = blake3::Hash::from(opened.image_id()).to_hex().to_string();
    let (bodies, custody) = opened.into_bodies_and_custody();
    Ok(AuthenticatedCheckpoint {
        image,
        id,
        bodies,
        required: custody,
    })
}
