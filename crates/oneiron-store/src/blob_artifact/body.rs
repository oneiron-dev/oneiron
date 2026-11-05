//! Blob artifact body: pinned body keys, body type, MessagePack codec, and validators.

use rmpv::Value;

use oneiron_base::error::Error;
use oneiron_base::error::Result;

use oneiron_base::error::ArtifactError;

/// The REQUIRED artifact-body keys. A body missing any of them fails closed
/// — an artifact is complete on write.
pub const BLOB_ARTIFACT_BODY_KEYS: [&str; 2] = ["name", "media_type"];

/// The OPTIONAL artifact-body keys (SECRET-04, ONE-1922).
///
/// Pinned exactly like the required set — a key outside the UNION of the two
/// still rejects, and duplicates within either still reject — but ABSENCE is
/// meaningful rather than fatal: an artifact with no `secret_taint.refs`
/// consumed no secret and reads `Clean`. That is what keeps every body
/// written before this key existed decodable, and it is why the key could
/// not simply join [`BLOB_ARTIFACT_BODY_KEYS`], whose whole contract is that
/// each of its members is mandatory.
///
/// Encode emits the key only when the list is non-empty, so an untainted
/// body is BYTE-IDENTICAL to what it was before SECRET-04.
///
/// There is deliberately no `secret_taint.state` key beside it: taint STATE
/// is derived at read time (ARCH-0069 S7, amended 2026-08-05), and a stored
/// state is exactly the thing that amendment removed.
pub const BLOB_ARTIFACT_OPTIONAL_BODY_KEYS: [&str; 1] = ["secret_taint.refs"];

pub const BLOB_ARTIFACT_NAME_MAX_BYTES: usize = 512;

pub const BLOB_ARTIFACT_MEDIA_TYPE_MAX_BYTES: usize = 256;

pub const KEY_NAME: &str = BLOB_ARTIFACT_BODY_KEYS[0];

pub const KEY_MEDIA_TYPE: &str = BLOB_ARTIFACT_BODY_KEYS[1];

pub const KEY_SECRET_TAINT_REFS: &str = BLOB_ARTIFACT_OPTIONAL_BODY_KEYS[0];

/// Every key the pinned-key law admits: required followed by optional.
/// Decode resolves each body key against THIS union, so an unknown key is
/// still a reject and a duplicate of either kind is still a reject.
pub const BLOB_ARTIFACT_KNOWN_BODY_KEYS: [&str; 3] =
    [KEY_NAME, KEY_MEDIA_TYPE, KEY_SECRET_TAINT_REFS];

pub fn validate_text_field(text: &str, max_bytes: usize, context: &'static str) -> Result<()> {
    if text.is_empty() || text.len() > max_bytes {
        return Err(Error::Artifact(ArtifactError::InvalidBlobArtifactBody(
            context,
        )));
    }
    Ok(())
}
