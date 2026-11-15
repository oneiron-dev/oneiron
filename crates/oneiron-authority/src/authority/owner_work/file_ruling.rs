//! A sealed-file ruling's carry (Engine RULING PLAN-SEALED-FILE-RULING-CARRY,
//! 14 Nov 16:48): the owner ruled that a file the write door sealed whole
//! holds no secret, and every install of his vault keeps those bytes as
//! written, not only the one he answered on.
//!
//! The ruling is keyed by the file's bytes, not by its record, so it holds
//! for the same bytes in every record. The request carries no value, and
//! never the file's plain BLAKE3, which would let anyone who reads the main
//! log test a guess of a small, structured file: it names one digest, keyed
//! BLAKE3 under the vault's ruled-screen key (which every install derives
//! from the vault data key) over a file domain tag and the file's BLAKE3.
//! Its act is the owner's alone ([`OwnerActKind::SealedFileRuling`]): it
//! targets the file's ASSET record, where he answered, and its `seen` is
//! zero ([`FILE_RULING_SEEN`]), so a ruling always lands. Its carrier
//! executes it and appends its enacted result as it records it, as a custody
//! revoke's carrier does, so nothing is left pending; every install's owner
//! work drain keeps the digest from the fold.

use rmpv::Value;

use crate::error::Result;

use super::*;

const FILE_RULING_WORK_KEYS: [&str; 2] = [OP_KEY_KIND, "digest"];

/// A sealed-file ruling's `seen`: zero, as the ruling follows no revision.
pub const FILE_RULING_SEEN: [u8; 32] = [0; 32];

/// The file a ruling holds no secret, named by its keyed digest alone.
/// Value-free.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize, serde::Deserialize,
)]
pub struct FileRulingWork {
    /// Keyed BLAKE3, under the vault's ruled-screen key, over the file
    /// domain tag and the file's BLAKE3. Never zero.
    pub digest: [u8; 32],
}

/// A sealed-file ruling is executed by the install that carries it, under
/// the owner's own act with a zero `seen` (the owner-only check is the
/// request's), and names a digest.
pub(super) fn validate_file_ruling(
    request: &OwnerWorkRequest,
    work: &FileRulingWork,
) -> Result<()> {
    if request.executor != request.carrier
        || request.act.seen != FILE_RULING_SEEN
        || work.digest == [0; 32]
    {
        return Err(invalid_authority());
    }
    Ok(())
}

/// Canonical field order: kind, then digest.
pub(super) fn file_ruling_work_value(work: &FileRulingWork) -> Value {
    Value::Map(vec![
        (
            Value::from(OP_KEY_KIND),
            Value::from(OwnerWorkKind::FileRuling.as_str()),
        ),
        (Value::from("digest"), binary_value(work.digest)),
    ])
}

/// Strict keys; the shape is the request's ([`validate_file_ruling`]).
pub(super) fn decode_file_ruling_work(work: &[(Value, Value)]) -> Result<OwnerWorkBody> {
    validate_keys(work, &FILE_RULING_WORK_KEYS)?;
    Ok(OwnerWorkBody::FileRuling(FileRulingWork {
        digest: decode_hash(required(work, "digest")?)?,
    }))
}
