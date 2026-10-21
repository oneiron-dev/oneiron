//! Capability-bound, decoded and re-encoded signature images.
use super::{
    capability::{EsignCapability, binding},
    ledger::state_in,
    model::*,
    rate::{LimitCrossing, keep_limit_crossings},
};
use crate::limit_ask::EngineLimit;
use crate::side_table::{self, Raw, SideTable};
use crate::{EntityId, Result, TimeRange, Vault};
use std::io::{BufRead, Cursor, Read, Seek, SeekFrom};

/// The widest and the tallest a signature image decodes: past either axis its
/// decode is refused before a raster is allocated.
const DECODE_MAX_AXIS: u32 = 2048;

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
    /// One signature upload past this row: its bound, this vault's `[limits]`
    /// override or the row's default, and what it measured. Only the
    /// envelope's sender is asked about it, so the owner-wide limit ask is not
    /// raised as well.
    fn signature_crossing(&self, row: EngineLimit, measured: u64) -> Option<LimitCrossing> {
        let bound = self.limit_watch().bound(row);
        (measured > bound).then_some((row, bound, measured))
    }

    /// Stores and binds one recipient's signature image, re-encoded as PNG.
    /// Its size and count rows (`[limits] esign_signature_*`) never refuse
    /// it: past one, the image is stored and bound, and the crossing is kept
    /// for the host's health check to ask the envelope's sender whether
    /// everything is okay (FIX 3807, Engine ruling 10-19). Only its
    /// capability and turn, its format and visible pixels, and the decoder's
    /// bounds can refuse it.
    pub fn upload_esign_signature_image(
        &self,
        token: &EsignCapability,
        bytes: &[u8],
    ) -> Result<String> {
        let now = self.now_recorded_at();
        // Authenticate before attacker-controlled image decode. Count the
        // attempt separately so an observation failure never denies signing.
        let (document, recipient) = self.with_write_txn_grouped(|txn| {
            let cap = binding(self, txn, token)?;
            if cap.revoked_at.is_some() || now >= cap.hard_expires_at {
                return Err(invalid("invalid capability"));
            }
            Ok((cap.document, cap.recipient))
        })?;
        let _ = self.with_write_txn_grouped(|txn| {
            super::rate::observe(self, txn, &document, &recipient, now)
        });
        if bytes.is_empty() {
            return Err(invalid("signature image size"));
        }
        let mut crossings = Vec::new();
        crossings.extend(
            self.signature_crossing(EngineLimit::EsignSignatureInputBytes, bytes.len() as u64),
        );
        let format = image::guess_format(bytes).map_err(|_| invalid("signature image format"))?;
        if !matches!(format, image::ImageFormat::Png | image::ImageFormat::Jpeg) {
            return Err(invalid("signature image format"));
        }
        let decoded = self.decode_signature_image(bytes, format)?;
        if !decoded.to_rgba8().pixels().any(|p| p.0[3] != 0) {
            return Err(invalid("signature image has no visible pixels"));
        }
        let mut canonical = Cursor::new(Vec::new());
        decoded
            .write_to(&mut canonical, image::ImageFormat::Png)
            .map_err(|_| invalid("signature image encode"))?;
        let canonical = canonical.into_inner();
        crossings.extend(
            self.signature_crossing(EngineLimit::EsignSignaturePngBytes, canonical.len() as u64),
        );
        let now = self.now_recorded_at();
        self.with_write_txn_grouped(|txn| {
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
                keep_limit_crossings(self, txn, &cap.document, &cap.recipient, &crossings, now)?;
                return Ok(image.to_hex());
            }
            let prior = IMAGE_BYTES_BUDGET.get(&self.store, txn, &id)?.unwrap_or(0);
            let total = prior.saturating_add(canonical.len() as u64);
            crossings
                .extend(self.signature_crossing(EngineLimit::EsignSignatureDocumentBytes, total));
            IMAGE_BYTES_BUDGET.put(&self.store, txn, &id, &total)?;
            // Every image the recipient holds, this one included, is counted:
            // a row that cannot be read fails the upload, never goes uncounted.
            let images = BINDINGS
                .iter_from(&self.store, txn, &image_binding_prefix(id, &cap.recipient))?
                .try_fold(1u64, |held, row| row.map(|_| held.saturating_add(1)))?;
            crossings.extend(
                self.signature_crossing(EngineLimit::EsignSignatureRecipientImages, images),
            );
            keep_limit_crossings(self, txn, &cap.document, &cap.recipient, &crossings, now)?;
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
            if let Some(project) = state.document.project {
                crate::federation::record_scope::stamp_blob_project(
                    &self.store,
                    txn,
                    image,
                    project,
                )?;
            }
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
    /// Decodes an uploaded signature image under the decoder's alloc bound,
    /// the `[limits] signature_decode_bytes` row (OF-520). The raster its
    /// header declares is measured against the row first: past it, the row
    /// asks whether everything is okay and the image is decoded whole, the
    /// bound lifted by that raster (ask and serve).
    fn decode_signature_image(
        &self,
        bytes: &[u8],
        format: image::ImageFormat,
    ) -> Result<image::DynamicImage> {
        let row = EngineLimit::SignatureDecodeBytes;
        let bound = self.limit_watch().bound(row);
        let reader = |max_alloc: u64| {
            let mut reader = image::ImageReader::with_format(Cursor::new(bytes), format);
            let mut limits = image::Limits::default();
            limits.max_image_width = Some(DECODE_MAX_AXIS);
            limits.max_image_height = Some(DECODE_MAX_AXIS);
            limits.max_alloc = Some(max_alloc);
            reader.limits(limits);
            reader
        };
        let raster = reader(bound)
            .into_decoder()
            .map(|decoder| image::ImageDecoder::total_bytes(&decoder))
            .map_err(|_| invalid("signature image decode"))?;
        let max_alloc = match self.measure_limit(row, raster) {
            Some(_) => bound.saturating_add(raster),
            None => bound,
        };
        reader(max_alloc)
            .decode()
            .map_err(|_| invalid("signature image decode"))
    }

    /// Read only a canonical raster uploaded by this capability's recipient.
    pub fn esign_signature_image_for_capability(
        &self,
        token: &EsignCapability,
        image_ref: &str,
    ) -> Result<Vec<u8>> {
        reference(image_ref)?;
        let now = self.now_recorded_at();
        let _ = self.with_write_txn_grouped(|txn| {
            let cap = binding(self, txn, token)?;
            super::rate::observe(self, txn, &cap.document, &cap.recipient, now)
        });
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

/// Bytes of one decoded pixel at most: four 8-bit channels.
const PIXEL_BYTES: u64 = 4;

/// Bytes of one decoded pixel at most in a 16-bit PNG: four 16-bit channels.
const WIDE_PIXEL_BYTES: u64 = 8;

/// Bytes the JPEG decoder works in for each pixel beside its raster: a
/// progressive image's coefficients, two bytes for each of up to four
/// components.
const JPEG_SCRATCH_PIXEL_BYTES: u64 = 8;

/// Bytes of a canonical PNG past its stored rows: its signature, header and
/// end chunks, the zlib header and checksum, and each data chunk's framing.
const PNG_FRAMING_BYTES: u64 = 4096;

/// What uploading one signature image holds in memory at its peak, planned
/// from its header alone before its body is read into memory
/// ([`plan_signature_image`], FIX 7649), so the host can admit that much of
/// the machine's memory first. An upper bound, never a refusal size: the
/// upload's own checks judge the image as they always have.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SignatureImagePlan {
    /// Pixels the decode can hold: its width by its height, each axis at
    /// most [`DECODE_MAX_AXIS`], past which the decode is refused unallocated.
    pixels: u64,
    /// Rows of those pixels: each takes one filter byte in the PNG.
    rows: u64,
    /// Bytes of one decoded pixel at most.
    pixel_bytes: u64,
    /// Bytes per pixel the decoder works in beside its raster.
    scratch_pixel_bytes: u64,
    /// Whether the decoder copies the encoded image whole before it decodes
    /// it, as the JPEG decoder does.
    copies_input: bool,
}

impl SignatureImagePlan {
    /// No raster: an upload that is no PNG or JPEG is refused before any
    /// decode.
    const UNDECODED: Self = Self {
        pixels: 0,
        rows: 0,
        pixel_bytes: 0,
        scratch_pixel_bytes: 0,
        copies_input: false,
    };

    /// A decode of `width` by `height` pixels of `pixel_bytes` each, by the
    /// JPEG decoder when `jpeg`.
    fn decoded(width: u32, height: u32, pixel_bytes: u64, jpeg: bool) -> Self {
        let width = u64::from(width.min(DECODE_MAX_AXIS));
        let height = u64::from(height.min(DECODE_MAX_AXIS));
        Self {
            pixels: width * height,
            rows: height,
            pixel_bytes,
            scratch_pixel_bytes: if jpeg { JPEG_SCRATCH_PIXEL_BYTES } else { 0 },
            copies_input: jpeg,
        }
    }

    /// The most any decode can hold, for a PNG or JPEG whose header cannot
    /// be read: both axes at their bound, the widest pixel, and the JPEG
    /// decoder's copy and scratch.
    fn ceiling() -> Self {
        Self::decoded(DECODE_MAX_AXIS, DECODE_MAX_AXIS, WIDE_PIXEL_BYTES, true)
    }

    /// Bytes uploading this image of `input` encoded bytes holds at its
    /// peak, all summed though some are dropped before others are made: the
    /// encoded body read whole; the decoder's own copy of it, for a JPEG; the
    /// decoded raster and the decoder's scratch; the raster's RGBA copy, which
    /// the visible-pixel check makes; and the canonical PNG's encoding, which
    /// is a 16-bit raster's big-endian copy, then the zlib stream and the file
    /// written, each a buffer that may grow to twice the rows' stored size.
    /// `None` past `u64`.
    #[must_use]
    pub fn peak_bytes(&self, input: u64) -> Option<u64> {
        let copy = if self.copies_input { input } else { 0 };
        let read = input.checked_add(copy)?;
        if self.pixels == 0 {
            return Some(read);
        }
        let raster = self.pixels.checked_mul(self.pixel_bytes)?;
        let scratch = self.pixels.checked_mul(self.scratch_pixel_bytes)?;
        let rgba = self.pixels.checked_mul(PIXEL_BYTES)?;
        let reordered = if self.pixel_bytes > PIXEL_BYTES {
            raster
        } else {
            0
        };
        // Each row after its filter byte, stored past deflate's worst case:
        // 5 bytes in a block of at least 16 KiB, well under one in 1,024.
        let filtered = raster.checked_add(self.rows)?;
        let stored = filtered
            .checked_add(filtered / 1024)?
            .checked_add(PNG_FRAMING_BYTES)?;
        let encoding = reordered.checked_add(stored.checked_mul(4)?)?;
        read.checked_add(raster)?
            .checked_add(scratch)?
            .checked_add(rgba)?
            .checked_add(encoding)
    }
}

/// Plans uploading the signature image `spool` holds, reading no more of it
/// than its format and its frame header, then rewinds it (FIX 7649). A PNG
/// or JPEG whose header cannot be read is planned at the most any decode can
/// hold; an upload that is neither plans no raster, since the upload refuses
/// it before decoding.
///
/// # Errors
/// Reading or rewinding `spool` failed.
pub fn plan_signature_image(spool: &mut (impl BufRead + Seek)) -> Result<SignatureImagePlan> {
    spool.seek(SeekFrom::Start(0))?;
    let mut start = Vec::with_capacity(16);
    spool.by_ref().take(16).read_to_end(&mut start)?;
    let plan = match image::guess_format(&start) {
        Ok(image::ImageFormat::Png) => png_plan(spool)?,
        Ok(image::ImageFormat::Jpeg) => jpeg_plan(spool)?,
        _ => SignatureImagePlan::UNDECODED,
    };
    spool.seek(SeekFrom::Start(0))?;
    Ok(plan)
}

/// A PNG's plan from its header chunk, which the format puts first: its
/// width, its height and its bit depth.
fn png_plan(spool: &mut (impl BufRead + Seek)) -> Result<SignatureImagePlan> {
    spool.seek(SeekFrom::Start(0))?;
    // The signature, then IHDR's length and type, width, height and depth.
    let mut header = [0u8; 25];
    if !read_whole(spool, &mut header)? || header[12..16] != *b"IHDR" {
        return Ok(SignatureImagePlan::ceiling());
    }
    let width = u32::from_be_bytes([header[16], header[17], header[18], header[19]]);
    let height = u32::from_be_bytes([header[20], header[21], header[22], header[23]]);
    let pixel_bytes = if header[24] == 16 {
        WIDE_PIXEL_BYTES
    } else {
        PIXEL_BYTES
    };
    Ok(SignatureImagePlan::decoded(
        width,
        height,
        pixel_bytes,
        false,
    ))
}

/// A JPEG's plan from its frame header, found by stepping over the segments
/// before it by their lengths, their bodies unread. One that ends, scans or
/// names no size before a frame header is planned at the ceiling.
fn jpeg_plan(spool: &mut (impl BufRead + Seek)) -> Result<SignatureImagePlan> {
    // Past the start-of-image marker.
    spool.seek(SeekFrom::Start(2))?;
    let mut byte = [0u8; 1];
    loop {
        if !read_whole(spool, &mut byte)? || byte[0] != 0xFF {
            return Ok(SignatureImagePlan::ceiling());
        }
        // A marker may follow any number of fill bytes.
        let mut marker = 0xFF;
        while marker == 0xFF {
            if !read_whole(spool, &mut byte)? {
                return Ok(SignatureImagePlan::ceiling());
            }
            marker = byte[0];
        }
        match marker {
            // Markers with no segment after them.
            0x01 | 0xD0..=0xD7 => {}
            // Every frame header but DHT (C4), JPG (C8) and DAC (CC): its
            // length, precision, height, width.
            0xC0..=0xC3 | 0xC5..=0xC7 | 0xC9..=0xCB | 0xCD..=0xCF => {
                let mut frame = [0u8; 7];
                if !read_whole(spool, &mut frame)? {
                    return Ok(SignatureImagePlan::ceiling());
                }
                let height = u32::from(u16::from_be_bytes([frame[3], frame[4]]));
                let width = u32::from(u16::from_be_bytes([frame[5], frame[6]]));
                // A height of 0 is named later, past the first scan.
                if width == 0 || height == 0 {
                    return Ok(SignatureImagePlan::ceiling());
                }
                return Ok(SignatureImagePlan::decoded(
                    width,
                    height,
                    PIXEL_BYTES,
                    true,
                ));
            }
            // A second image's start, the image's end or its first scan.
            0xD8..=0xDA => return Ok(SignatureImagePlan::ceiling()),
            _ => {
                let mut length = [0u8; 2];
                if !read_whole(spool, &mut length)? {
                    return Ok(SignatureImagePlan::ceiling());
                }
                let Some(body) = u16::from_be_bytes(length).checked_sub(2) else {
                    return Ok(SignatureImagePlan::ceiling());
                };
                spool.seek_relative(i64::from(body))?;
            }
        }
    }
}

/// Fills `buf` from `spool`: `false` when the spool ends first.
fn read_whole(spool: &mut impl Read, buf: &mut [u8]) -> Result<bool> {
    match spool.read_exact(buf) {
        Ok(()) => Ok(true),
        Err(error) if error.kind() == std::io::ErrorKind::UnexpectedEof => Ok(false),
        Err(error) => Err(error.into()),
    }
}
