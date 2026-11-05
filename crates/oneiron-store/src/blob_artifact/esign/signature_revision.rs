//! The ordinary signature revision, written on the engine's side of the seal
//! (ARCH-0075 `#organ-host-design-seal-binding`). The engine appends the
//! invisible signature field and widget, the signature dictionary with its
//! zero `/Contents` hole, the page `/Annots` and AcroForm links, the xref and
//! the trailer, and patches the ByteRange. The seal organ builds only the CMS
//! that fills the hole, so it never chooses a PDF object of the revision the
//! key signs. One revision is written for each contents capacity. The layout
//! is the native seal writer's, so its verifier reads it as its own. The
//! objects it re-emits keep every value and type: a real is written as the
//! shortest decimal that reads back as the same real, never rounded.

use lopdf::{
    DecodeAdmission, DecodeAdmissionError, Dictionary, Document, LoadOptions, Object, ObjectId,
    StringFormat,
};
use oneiron_docedit::resource::{Hold, ResourceRefusal, wide};
use sha2::{Digest, Sha256};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use crate::blob_artifact::esign::sealer::EsignSignatureRevision;
use oneiron_contracts::limit_ask::EngineLimit;

/// The contents ladder: the DER bytes each revision's hole holds.
pub const SEAL_CONTENTS_LADDER: [usize; 3] = [64 * 1024, 128 * 1024, 256 * 1024];
pub const BYTERANGE_DIGITS: usize = 20;
/// A classic xref entry carries a ten-digit offset. No signature revision may
/// address bytes past this format bound, however large the organ's CMS claim is.
pub const MAX_CLASSIC_XREF_OFFSET: u64 = 9_999_999_999;
/// The row bounding what one stream of the prepared PDF decodes to while
/// the host reads it here: the host's per-stream codec bound (Rule 5, FIX
/// 6287), past which the revisions are refused with this row named. The
/// seal organ decodes each stream whole under its own memory grant. Below
/// the bound a stream's decoded size is measured against the
/// `seal_prepared_stream_bytes` row and read whole.
pub const STREAM_CODEC_ROW: EngineLimit = EngineLimit::EsignSealStreamCodecBytes;

/// The largest uncompressed cross-reference stream's bytes, within `codec`.
/// The load never decodes these, so the admission never sees them, while the
/// old re-decode counted their length. A length read, never a decode.
/// Over-codec streams count as nothing, as the re-decode's `.ok()` did.
pub fn uncompressed_xref_bytes(doc: &Document, codec: usize) -> u64 {
    doc.objects
        .values()
        .filter_map(|object| object.as_stream().ok())
        .filter_map(|stream| {
            let kind = stream
                .dict
                .get(b"Type")
                .ok()
                .and_then(|kind| kind.as_name().ok());
            match kind {
                Some(b"XRef") if !stream.is_compressed() && stream.content.len() <= codec => {
                    Some(stream.content.len() as u64)
                }
                _ => None,
            }
        })
        .max()
        .unwrap_or(0)
}

pub fn reference(object: &Object) -> Option<ObjectId> {
    match object {
        Object::Reference(id) => Some(*id),
        _ => None,
    }
}

/// The revision read's admission on the host's machine memory (6274): one
/// hold, NOT a ledger. It admits every table, copy, and decode before it is
/// allocated and records each finished decode's length. Admissions are never
/// released on this base (lopdf admits only), so growth holds old+new
/// together: correct, only more conservative. A process with no registered
/// host reserves nothing, as before (measuring port).
pub struct BaseAdmission {
    pub state: Mutex<BaseAdmissionState>,
    pub max_decoded: AtomicU64,
}

struct BaseAdmissionState {
    hold: Hold,
    /// Stays 0: this base's trait has no `release` to credit it (§4).
    spare: u64,
}

impl BaseAdmission {
    pub fn new(hold: Hold) -> Self {
        Self {
            state: Mutex::new(BaseAdmissionState { hold, spare: 0 }),
            max_decoded: AtomicU64::new(0),
        }
    }

    pub fn max_decoded(&self) -> u64 {
        self.max_decoded.load(Ordering::Relaxed)
    }
}

impl DecodeAdmission for BaseAdmission {
    fn admit(&self, bytes: usize) -> std::result::Result<(), DecodeAdmissionError> {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        let bytes = wide(bytes);
        let credit = state.spare.min(bytes);
        state.spare -= credit;
        let rest = bytes - credit;
        if rest == 0 {
            return Ok(());
        }
        state.hold.take(rest).map_err(|refusal| match refusal {
            ResourceRefusal::MemoryFloor { needed, available } => {
                DecodeAdmissionError::MemoryFloor { needed, available }
            }
            ResourceRefusal::Deadline => DecodeAdmissionError::Deadline,
        })
    }

    fn decoded(&self, bytes: usize) {
        self.max_decoded.fetch_max(wide(bytes), Ordering::Relaxed);
    }
}

/// The field name the seal derives from its operation.
pub fn field_name(operation_id: &str) -> String {
    let digest = Sha256::digest(operation_id.as_bytes());
    let mut name = String::from("Seal-");
    for byte in &digest[..6] {
        name.push_str(&format!("{byte:02X}"));
    }
    name
}

/// `D:YYYYMMDDHHmmSSZ`.
pub fn pdf_date(unix_ms: u64) -> String {
    let secs = i64::try_from(unix_ms / 1000).unwrap_or(i64::MAX);
    let at = chrono::DateTime::from_timestamp(secs, 0).unwrap_or_default();
    format!("D:{}Z", at.format("%Y%m%d%H%M%S"))
}

/// A literal string as the same literal string: `(`, `)` and `\` escaped,
/// and every byte outside printable ASCII as a three-digit octal escape, so
/// no raw end of line is read back as another.
pub fn write_literal_bytes(bytes: &[u8], out: &mut Vec<u8>) {
    out.push(b'(');
    for &byte in bytes {
        match byte {
            b'(' | b')' | b'\\' => out.extend_from_slice(&[b'\\', byte]),
            b' '..=b'~' => out.push(byte),
            _ => out.extend_from_slice(format!("\\{byte:03o}").as_bytes()),
        }
    }
    out.push(b')');
}

pub fn write_name(name: &[u8], out: &mut Vec<u8>) {
    out.push(b'/');
    for &byte in name {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.' | b'+' | b'*') {
            out.push(byte);
        } else {
            out.extend_from_slice(format!("#{byte:02X}").as_bytes());
        }
    }
}

pub fn write_hex_string(bytes: &[u8], out: &mut Vec<u8>) {
    out.push(b'<');
    for byte in bytes {
        out.extend_from_slice(format!("{byte:02X}").as_bytes());
    }
    out.push(b'>');
}

pub fn write_literal_string(text: &str, out: &mut Vec<u8>) {
    out.push(b'(');
    for &byte in text.as_bytes() {
        if matches!(byte, b'(' | b')' | b'\\') {
            out.push(b'\\');
        }
        out.push(byte);
    }
    out.push(b')');
}
