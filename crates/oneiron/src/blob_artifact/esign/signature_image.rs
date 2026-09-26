//! Capability-bound, decoded and re-encoded signature images.
use super::{
    capability::{EsignCapability, binding},
    ledger::state_in,
    model::*,
};
use crate::side_table::{self, Raw, SideTable};
use crate::{EntityId, Result, TimeRange, Vault};
use std::io::Cursor;

/// Signature image ownership marker. Key: id16 (document) + string (recipient) + string (image
/// hex) — recipient and image are concatenated with no separator between them, so the shape is
/// exact-match or (document, recipient)-prefix only; the tail is never split back apart.
pub(super) const BINDINGS: SideTable<(EntityId, Vec<u8>), (), Raw> =
    SideTable::new(&side_table::ESIGN_SIGNATURE_IMAGE_BINDING);
/// Signature image byte budget. Key: id16 (document).
const IMAGE_BYTES_BUDGET: SideTable<EntityId, u64, Raw> =
    SideTable::new(&side_table::ESIGN_IMAGE_BYTES_BUDGET);

pub(super) fn image_binding_key(
    document: EntityId,
    recipient: &str,
    image: &str,
) -> (EntityId, Vec<u8>) {
    (document, [recipient.as_bytes(), image.as_bytes()].concat())
}

/// The (document, recipient) leading bytes of every [`BINDINGS`] key that recipient owns.
fn image_binding_prefix(document: EntityId, recipient: &str) -> Vec<u8> {
    [document.as_bytes().as_slice(), recipient.as_bytes()].concat()
}
impl Vault {
    pub fn upload_esign_signature_image(
        &self,
        token: &EsignCapability,
        bytes: &[u8],
    ) -> Result<String> {
        let now = crate::unix_seconds_now();
        // Authenticate and account before any attacker-controlled image decode.
        self.with_write_txn(|txn| {
            let cap = binding(self, txn, token)?;
            if cap.revoked_at.is_some() || now >= cap.hard_expires_at {
                return Err(invalid("invalid capability"));
            }
            super::rate::admit(self, txn, &cap.document, &cap.recipient, now)
        })?;
        if bytes.is_empty() || bytes.len() > 2 * 1024 * 1024 {
            return Err(invalid("signature image size"));
        }
        let format = image::guess_format(bytes).map_err(|_| invalid("signature image format"))?;
        if !matches!(format, image::ImageFormat::Png | image::ImageFormat::Jpeg) {
            return Err(invalid("signature image format"));
        }
        let mut reader = image::ImageReader::with_format(Cursor::new(bytes), format);
        let mut limits = image::Limits::default();
        limits.max_image_width = Some(2048);
        limits.max_image_height = Some(2048);
        limits.max_alloc = Some(32 * 1024 * 1024);
        reader.limits(limits);
        let decoded = reader
            .decode()
            .map_err(|_| invalid("signature image decode"))?;
        if !decoded.to_rgba8().pixels().any(|p| p.0[3] != 0) {
            return Err(invalid("signature image has no visible pixels"));
        }
        let mut canonical = Cursor::new(Vec::new());
        decoded
            .write_to(&mut canonical, image::ImageFormat::Png)
            .map_err(|_| invalid("signature image encode"))?;
        let canonical = canonical.into_inner();
        if canonical.len() > 2 * 1024 * 1024 {
            return Err(invalid("signature image output size"));
        }
        let now = crate::unix_seconds_now();
        self.with_write_txn(|txn| {
            let cap = binding(self, txn, token)?;
            let id = EntityId::from_hex(&cap.document)?;
            let state = state_in(self, txn, id)?;
            let recipient = state
                .recipients
                .get(&cap.recipient)
                .ok_or_else(|| invalid("invalid capability"))?;
            if cap.revoked_at.is_some()
                || now >= cap.hard_expires_at
                || now >= recipient.expires_at
                || state.status != DocumentStatus::Pending
                || state.rejection.is_some()
                || recipient.signing != SigningStatus::Ready
            {
                return Err(invalid("invalid capability or turn"));
            }
            let mut hash = blake3::Hasher::new();
            hash.update(b"esign.signature_image.v1");
            hash.update(id.as_bytes());
            hash.update(cap.recipient.as_bytes());
            hash.update(&canonical);
            let image = EntityId::from_bytes(
                hash.finalize().as_bytes()[..16]
                    .try_into()
                    .map_err(|_| invalid("image id"))?,
            )?;
            let key = image_binding_key(id, &cap.recipient, &image.to_hex());
            if BINDINGS.contains(&self.store, txn, &key)? {
                return Ok(image.to_hex());
            }
            let prior = IMAGE_BYTES_BUDGET.get(&self.store, txn, &id)?.unwrap_or(0);
            let total = prior
                .checked_add(canonical.len() as u64)
                .ok_or_else(|| invalid("image budget overflow"))?;
            if total > 64 * 1024 * 1024 {
                return Err(invalid("document signature image budget"));
            }
            IMAGE_BYTES_BUDGET.put(&self.store, txn, &id, &total)?;
            let prefix = image_binding_prefix(id, &cap.recipient);
            if BINDINGS
                .iter_from(&self.store, txn, &prefix)?
                .take(16)
                .collect::<Result<Vec<_>>>()?
                .len()
                >= 16
            {
                return Err(invalid("recipient signature image limit"));
            }
            let body = crate::blob_artifact::encode_blob_artifact_body(
                &crate::blob_artifact::BlobArtifactBody::new("signature.png", "image/png"),
            )?;
            self.batch_in()
                .put_internal(
                    &image,
                    crate::registry::ENTITY_TYPE_BLOB_ARTIFACT,
                    TimeRange {
                        start: now,
                        end: now,
                    },
                    now,
                    &body,
                )
                .apply(txn)?;
            // A bearer authorizes document input, not an owner-level Auto assertion.
            let artifact_actor = super::artifact_actor::actor(self, txn, now)?;
            self.append_blob_artifact_version_in_txn(
                txn,
                &image,
                &canonical,
                &crate::blob_artifact::BlobVersionProvenance::CapabilityUpload,
                artifact_actor,
                TimeRange {
                    start: now,
                    end: now,
                },
                now,
            )?;
            BINDINGS.put(
                &self.store,
                txn,
                &image_binding_key(id, &cap.recipient, &image.to_hex()),
                &(),
            )?;
            Ok(image.to_hex())
        })
    }
}

impl Vault {
    /// Read only a canonical raster uploaded by this capability's recipient.
    pub fn esign_signature_image_for_capability(
        &self,
        token: &EsignCapability,
        image_ref: &str,
    ) -> Result<Vec<u8>> {
        reference(image_ref)?;
        let now = crate::unix_seconds_now();
        self.with_write_txn(|txn| {
            let cap = binding(self, txn, token)?;
            super::rate::admit(self, txn, &cap.document, &cap.recipient, now)
        })?;
        let txn = self.store.env.read_txn()?;
        let cap = binding(self, &txn, token)?;
        let id = EntityId::from_hex(&cap.document)?;
        let state = state_in(self, &txn, id)?;
        let recipient = state
            .recipients
            .get(&cap.recipient)
            .ok_or_else(|| invalid("invalid capability"))?;
        if cap.revoked_at.is_some()
            || now >= cap.hard_expires_at
            || now >= recipient.expires_at
            || state.status != DocumentStatus::Pending
            || recipient.signing != SigningStatus::Ready
            || !BINDINGS.contains(
                &self.store,
                &txn,
                &image_binding_key(id, &cap.recipient, image_ref),
            )?
        {
            return Err(invalid("signature image is unavailable"));
        }
        self.read_blob_artifact_version_in_txn(&txn, &EntityId::from_hex(image_ref)?, 1)?
            .ok_or_else(|| invalid("signature image is unavailable"))
    }
}
