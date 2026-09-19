//! Capability-bound, decoded and re-encoded signature images.
use super::{
    capability::{EsignCapability, binding},
    ledger::state_in,
    model::*,
};
use crate::{EntityId, Result, TimeRange, Vault};
use std::io::Cursor;
pub(super) fn image_binding_key(document: EntityId, recipient: &str, image: &str) -> Vec<u8> {
    [
        b"esign.signature_image.v1/".as_slice(),
        document.as_bytes(),
        recipient.as_bytes(),
        image.as_bytes(),
    ]
    .concat()
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
            if self.store.vault_meta.get(txn, &key)?.is_some() {
                return Ok(image.to_hex());
            }
            let budget_key = [b"esign.image_bytes.v1/".as_slice(), id.as_bytes()].concat();
            let prior = self
                .store
                .vault_meta
                .get(txn, &budget_key)?
                .map(|v| {
                    <[u8; 8]>::try_from(v.as_ref())
                        .map(u64::from_be_bytes)
                        .map_err(|_| invalid("image budget encoding"))
                })
                .transpose()?
                .unwrap_or(0);
            let total = prior
                .checked_add(canonical.len() as u64)
                .ok_or_else(|| invalid("image budget overflow"))?;
            if total > 64 * 1024 * 1024 {
                return Err(invalid("document signature image budget"));
            }
            self.store
                .vault_meta
                .put(txn, &budget_key, &total.to_be_bytes())?;
            let prefix = image_binding_key(id, &cap.recipient, "");
            if self
                .store
                .vault_meta
                .prefix_iter(txn, &prefix)?
                .take(16)
                .collect::<std::result::Result<Vec<_>, _>>()?
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
            self.store.vault_meta.put(
                txn,
                &image_binding_key(id, &cap.recipient, &image.to_hex()),
                &[],
            )?;
            Ok(image.to_hex())
        })
    }
}
