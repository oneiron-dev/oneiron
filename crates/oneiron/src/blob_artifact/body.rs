//! Blob artifact body: pinned body keys, body type, MessagePack codec, and validators.

use rmpv::Value;

use crate::error::{Error, Result};
use crate::secret_lease::SecretTaintRef;
use crate::secret_rotation::{taint_refs_from_value, taint_refs_to_value, validate_taint_refs};

use super::store_keys::{encode_value, read_value};
use crate::error::ArtifactError;

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

const KEY_NAME: &str = BLOB_ARTIFACT_BODY_KEYS[0];

const KEY_MEDIA_TYPE: &str = BLOB_ARTIFACT_BODY_KEYS[1];

const KEY_SECRET_TAINT_REFS: &str = BLOB_ARTIFACT_OPTIONAL_BODY_KEYS[0];

/// Every key the pinned-key law admits: required followed by optional.
/// Decode resolves each body key against THIS union, so an unknown key is
/// still a reject and a duplicate of either kind is still a reject.
const BLOB_ARTIFACT_KNOWN_BODY_KEYS: [&str; 3] = [KEY_NAME, KEY_MEDIA_TYPE, KEY_SECRET_TAINT_REFS];

/// Artifact-level metadata. Stable across versions; content bytes never live
/// here (OF-320 reference-not-content law) — they are content-addressed
/// ASSET entities resolved through the version records.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct BlobArtifactBody {
    pub name: String,
    pub media_type: String,
    /// SECRET-04 (ONE-1922): the secrets whose values were consumed
    /// producing this artifact, each pinned to the custody generation the
    /// value was read at.
    ///
    /// REFS, not state. A consumer derives `Clean | TaintedLive |
    /// TaintedStale` by comparing these generations against the records'
    /// current ones ([`crate::Vault::artifact_taint_state`]); nothing here
    /// is ever flipped when a secret rotates. Empty is the overwhelmingly
    /// common case and costs nothing on the wire.
    pub secret_taint_refs: Vec<SecretTaintRef>,
}

impl BlobArtifactBody {
    /// An UNTAINTED artifact body — the shape every existing caller wants
    /// and the reason this constructor did not grow an argument.
    #[must_use]
    pub fn new(name: impl Into<String>, media_type: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            media_type: media_type.into(),
            secret_taint_refs: Vec::new(),
        }
    }

    /// Attaches the taint refs of the action that produced this artifact.
    ///
    /// The attach is the artifact PUT itself: the refs live in the body, so
    /// they land in the same transaction as the artifact they mark and
    /// cannot drift apart from it.
    #[must_use]
    pub fn with_secret_taint_refs(mut self, refs: Vec<SecretTaintRef>) -> Self {
        self.secret_taint_refs = refs;
        self
    }
}

pub fn encode_blob_artifact_body(body: &BlobArtifactBody) -> Result<Vec<u8>> {
    validate_blob_artifact_body(body)?;
    let mut entries = vec![
        (Value::from(KEY_NAME), Value::from(body.name.as_str())),
        (
            Value::from(KEY_MEDIA_TYPE),
            Value::from(body.media_type.as_str()),
        ),
    ];
    // Emitted ONLY when non-empty: an untainted body keeps the exact bytes
    // it had before this key existed.
    if !body.secret_taint_refs.is_empty() {
        entries.push((
            Value::from(KEY_SECRET_TAINT_REFS),
            taint_refs_to_value(&body.secret_taint_refs),
        ));
    }
    encode_value(
        &Value::Map(entries),
        "BLOB artifact body MessagePack encode failed",
    )
}

pub fn decode_blob_artifact_body(bytes: &[u8]) -> Result<BlobArtifactBody> {
    let value = read_value(bytes, "body")?;
    decode_blob_artifact_body_value(&value)
}

pub(crate) fn validate_blob_artifact_body_bytes(bytes: &[u8]) -> Result<()> {
    decode_blob_artifact_body(bytes).map(|_| ())
}

fn decode_blob_artifact_body_value(value: &Value) -> Result<BlobArtifactBody> {
    let Value::Map(entries) = value else {
        return Err(Error::Artifact(ArtifactError::InvalidBlobArtifactBody(
            "body must be a MessagePack map",
        )));
    };

    let mut name: Option<String> = None;
    let mut media_type: Option<String> = None;
    let mut secret_taint_refs: Vec<SecretTaintRef> = Vec::new();
    let mut seen = [false; BLOB_ARTIFACT_KNOWN_BODY_KEYS.len()];

    for (key, value) in entries {
        let Some(key) = key.as_str() else {
            return Err(Error::Artifact(ArtifactError::InvalidBlobArtifactBody(
                "body keys must be strings",
            )));
        };
        let Some(index) = BLOB_ARTIFACT_KNOWN_BODY_KEYS
            .iter()
            .position(|known| *known == key)
        else {
            return Err(Error::Artifact(ArtifactError::InvalidBlobArtifactBody(
                "body key is not in the pinned BLOB_ARTIFACT_BODY_KEYS / BLOB_ARTIFACT_OPTIONAL_BODY_KEYS set",
            )));
        };
        if seen[index] {
            return Err(Error::Artifact(ArtifactError::InvalidBlobArtifactBody(
                "duplicate body key",
            )));
        }
        seen[index] = true;

        match BLOB_ARTIFACT_KNOWN_BODY_KEYS[index] {
            KEY_NAME => {
                let text = value.as_str().ok_or(Error::Artifact(
                    ArtifactError::InvalidBlobArtifactBody("name must be a UTF-8 string"),
                ))?;
                name = Some(text.to_owned());
            }
            KEY_MEDIA_TYPE => {
                let text = value.as_str().ok_or(Error::Artifact(
                    ArtifactError::InvalidBlobArtifactBody("media_type must be a UTF-8 string"),
                ))?;
                media_type = Some(text.to_owned());
            }
            KEY_SECRET_TAINT_REFS => {
                secret_taint_refs =
                    taint_refs_from_value(value).ok_or(Error::Artifact(ArtifactError::InvalidBlobArtifactBody(
                        "secret_taint.refs must be an array of {secret_ref, generation} maps with bounded, non-duplicated names",
                    )))?;
            }
            _ => unreachable!("index resolved from BLOB_ARTIFACT_KNOWN_BODY_KEYS"),
        }
    }

    let body = BlobArtifactBody {
        name: name.ok_or(Error::Artifact(ArtifactError::InvalidBlobArtifactBody(
            "missing required body key name",
        )))?,
        media_type: media_type.ok_or(Error::Artifact(ArtifactError::InvalidBlobArtifactBody(
            "missing required body key media_type",
        )))?,
        // OPTIONAL by contract: an absent key is an artifact that consumed
        // no secret, which reads Clean.
        secret_taint_refs,
    };
    validate_blob_artifact_body(&body)?;
    Ok(body)
}

fn validate_blob_artifact_body(body: &BlobArtifactBody) -> Result<()> {
    validate_text_field(
        &body.name,
        BLOB_ARTIFACT_NAME_MAX_BYTES,
        "name must be non-empty and at most 512 bytes",
    )?;
    validate_text_field(
        &body.media_type,
        BLOB_ARTIFACT_MEDIA_TYPE_MAX_BYTES,
        "media_type must be non-empty and at most 256 bytes",
    )?;
    validate_taint_refs(&body.secret_taint_refs).map_err(|_| {
        Error::Artifact(ArtifactError::InvalidBlobArtifactBody(
            "secret_taint.refs entries must carry bounded, non-empty, non-duplicated secret names",
        ))
    })?;
    Ok(())
}

pub(super) fn validate_text_field(
    text: &str,
    max_bytes: usize,
    context: &'static str,
) -> Result<()> {
    if text.is_empty() || text.len() > max_bytes {
        return Err(Error::Artifact(ArtifactError::InvalidBlobArtifactBody(
            context,
        )));
    }
    Ok(())
}
