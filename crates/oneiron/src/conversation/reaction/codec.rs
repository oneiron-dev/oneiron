//! Pinned REACTION body codec and transport types.

use crate::entity_id::EntityId;
use crate::error::{Error, RecordError, Result};
use rmpv::Value;
use serde::{Deserialize, Serialize};

/// Pinned REACTION body ABI keys.
pub const REACTION_BODY_KEYS: [&str; 6] = ["v", "msg", "by", "glyph", "at", "ext"];

/// Pinned REACTION body schema version.
pub const REACTION_BODY_VERSION: u64 = 1;

/// Glyph bound: non-empty, at most 64 Unicode scalar values.
pub const REACTION_GLYPH_MAX_SCALARS: usize = 64;

/// Mirrored external-id bounds (provider correlation, preserved verbatim).
pub const REACTION_EXTERNAL_CONNECTOR_MAX_BYTES: usize = 64;
pub const REACTION_EXTERNAL_ID_MAX_BYTES: usize = 256;

/// Grouped-pills batch bounds (SOW T8).
pub const GROUPED_PILLS_MAX_MESSAGES: usize = 50;
pub const GROUPED_PILLS_MAX_REACTIONS: usize = 120;

/// Derived inbox sidecar prefix in `vault_meta` (rebuildable, never primary).
pub const REACTION_INBOX_KEY_PREFIX: &[u8] = b"reaction_inbox:v1:";

const KEY_V: &str = REACTION_BODY_KEYS[0];
const KEY_MSG: &str = REACTION_BODY_KEYS[1];
const KEY_BY: &str = REACTION_BODY_KEYS[2];
const KEY_GLYPH: &str = REACTION_BODY_KEYS[3];
const KEY_AT: &str = REACTION_BODY_KEYS[4];
const KEY_EXT: &str = REACTION_BODY_KEYS[5];

const EXT_KEY_CONNECTOR: &str = "connector";
const EXT_KEY_ID: &str = "id";

/// Mirrored provenance: which connector row this reaction mirrors.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReactionExternalId {
    pub connector: String,
    pub id: String,
}

/// A decoded REACTION body.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReactionBody {
    pub msg: EntityId,
    pub by: EntityId,
    pub glyph: String,
    pub at: u64,
    pub ext: Option<ReactionExternalId>,
}

/// Toggle outcome.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReactionState {
    Put,
    Revoked,
}

/// One live reaction row, newest-first where ordered.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LiveReaction {
    pub id: EntityId,
    pub body: ReactionBody,
    pub recorded_at: u64,
}

/// One grouped pill per glyph on a message.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReactionPill {
    pub glyph: String,
    pub count: usize,
    /// Reactors in first-put order (recorded_at, then id).
    pub by: Vec<String>,
    /// Whether `viewer` reacted with this glyph.
    pub mine: bool,
}

/// Grouped pills for one message.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReactionGrouping {
    pub message: String,
    pub pills: Vec<ReactionPill>,
}

/// One agent signal row.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReactionSignal {
    pub kind: ReactionSignalKind,
    pub reaction: String,
    pub message: String,
    pub by: String,
    pub glyph: String,
    pub at: u64,
    pub recorded_at: u64,
}

/// Signal kind: the record IS the event.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReactionSignalKind {
    #[serde(rename = "reaction.put")]
    Put,
    #[serde(rename = "reaction.revoked")]
    Revoked,
}

impl ReactionSignalKind {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Put => "reaction.put",
            Self::Revoked => "reaction.revoked",
        }
    }
}

/// Validates a reaction glyph: non-empty, at most 64 Unicode scalar values.
pub fn validate_reaction_glyph(glyph: &str) -> Result<()> {
    let scalars = glyph.chars().count();
    if glyph.is_empty() || scalars > REACTION_GLYPH_MAX_SCALARS {
        return Err(Error::Record(RecordError::InvalidReactionBody(
            "glyph must be a non-empty Unicode string of at most 64 scalars",
        )));
    }
    Ok(())
}

fn validate_external_id(ext: &ReactionExternalId) -> Result<()> {
    if ext.connector.trim().is_empty()
        || ext.connector.len() > REACTION_EXTERNAL_CONNECTOR_MAX_BYTES
        || ext.id.trim().is_empty()
        || ext.id.len() > REACTION_EXTERNAL_ID_MAX_BYTES
    {
        return Err(Error::Record(RecordError::InvalidReactionBody(
            "ext.connector/ext.id must be non-blank within length bounds",
        )));
    }
    Ok(())
}

/// Encodes a REACTION body to the pinned canonical MessagePack map.
pub fn encode_reaction_body(body: &ReactionBody) -> Result<Vec<u8>> {
    validate_reaction_glyph(&body.glyph)?;
    if let Some(ext) = &body.ext {
        validate_external_id(ext)?;
    }
    let mut entries = vec![
        (Value::from(KEY_V), Value::from(REACTION_BODY_VERSION)),
        (
            Value::from(KEY_MSG),
            Value::from(body.msg.to_hex().as_str()),
        ),
        (Value::from(KEY_BY), Value::from(body.by.to_hex().as_str())),
        (Value::from(KEY_GLYPH), Value::from(body.glyph.as_str())),
        (Value::from(KEY_AT), Value::from(body.at)),
    ];
    if let Some(ext) = &body.ext {
        entries.push((
            Value::from(KEY_EXT),
            Value::Map(vec![
                (
                    Value::from(EXT_KEY_CONNECTOR),
                    Value::from(ext.connector.as_str()),
                ),
                (Value::from(EXT_KEY_ID), Value::from(ext.id.as_str())),
            ]),
        ));
    }
    let mut out = Vec::new();
    rmpv::encode::write_value(&mut out, &Value::Map(entries))
        .map_err(|_| Error::InvariantViolation("REACTION body MessagePack encode failed"))?;
    Ok(out)
}

/// Decodes a REACTION body, fail-closed on every deviation from the ABI.
pub fn decode_reaction_body(bytes: &[u8]) -> Result<ReactionBody> {
    let mut cursor = bytes;
    let value = rmpv::decode::read_value(&mut cursor).map_err(|_| {
        Error::Record(RecordError::InvalidReactionBody(
            "body is not valid MessagePack",
        ))
    })?;
    if !cursor.is_empty() {
        return Err(Error::Record(RecordError::InvalidReactionBody(
            "trailing bytes after body map",
        )));
    }
    let Value::Map(entries) = value else {
        return Err(Error::Record(RecordError::InvalidReactionBody(
            "body must be a MessagePack map",
        )));
    };
    let mut version = false;
    let mut msg: Option<EntityId> = None;
    let mut by: Option<EntityId> = None;
    let mut glyph: Option<String> = None;
    let mut at: Option<u64> = None;
    let mut ext: Option<ReactionExternalId> = None;
    let mut seen = [false; REACTION_BODY_KEYS.len()];
    for (key, value) in &entries {
        let Some(key) = key.as_str() else {
            return Err(Error::Record(RecordError::InvalidReactionBody(
                "body keys must be strings",
            )));
        };
        let Some(index) = REACTION_BODY_KEYS.iter().position(|known| *known == key) else {
            return Err(Error::Record(RecordError::InvalidReactionBody(
                "body key is not in the pinned REACTION_BODY_KEYS set",
            )));
        };
        if seen[index] {
            return Err(Error::Record(RecordError::InvalidReactionBody(
                "duplicate body key",
            )));
        }
        seen[index] = true;
        match REACTION_BODY_KEYS[index] {
            KEY_V => {
                let v = value
                    .as_u64()
                    .ok_or(Error::Record(RecordError::InvalidReactionBody(
                        "v must be a positive integer",
                    )))?;
                if v != REACTION_BODY_VERSION {
                    return Err(Error::Record(RecordError::InvalidReactionBody(
                        "unsupported REACTION body version",
                    )));
                }
                version = true;
            }
            KEY_MSG => {
                let raw = value
                    .as_str()
                    .ok_or(Error::Record(RecordError::InvalidReactionBody(
                        "msg must be a 32-hex id",
                    )))?;
                msg = Some(EntityId::from_hex(raw).map_err(|_| {
                    Error::Record(RecordError::InvalidReactionBody("msg is not a 32-hex id"))
                })?);
            }
            KEY_BY => {
                let raw = value
                    .as_str()
                    .ok_or(Error::Record(RecordError::InvalidReactionBody(
                        "by must be a 32-hex id",
                    )))?;
                by = Some(EntityId::from_hex(raw).map_err(|_| {
                    Error::Record(RecordError::InvalidReactionBody("by is not a 32-hex id"))
                })?);
            }
            KEY_GLYPH => {
                let raw = value
                    .as_str()
                    .ok_or(Error::Record(RecordError::InvalidReactionBody(
                        "glyph must be a UTF-8 string",
                    )))?;
                validate_reaction_glyph(raw)?;
                glyph = Some(raw.to_owned());
            }
            KEY_AT => {
                let stamp =
                    value
                        .as_u64()
                        .ok_or(Error::Record(RecordError::InvalidReactionBody(
                            "at must be a positive integer",
                        )))?;
                at = Some(stamp);
            }
            KEY_EXT => {
                let Value::Map(pairs) = value else {
                    return Err(Error::Record(RecordError::InvalidReactionBody(
                        "ext must be a map",
                    )));
                };
                if pairs.len() != 2 {
                    return Err(Error::Record(RecordError::InvalidReactionBody(
                        "ext requires exactly connector and id",
                    )));
                }
                let mut connector: Option<String> = None;
                let mut id: Option<String> = None;
                for (ekey, evalue) in pairs {
                    let Some(ekey) = ekey.as_str() else {
                        return Err(Error::Record(RecordError::InvalidReactionBody(
                            "ext keys must be strings",
                        )));
                    };
                    match ekey {
                        EXT_KEY_CONNECTOR => {
                            let raw = evalue.as_str().ok_or(Error::Record(
                                RecordError::InvalidReactionBody("ext.connector must be a string"),
                            ))?;
                            if connector.is_some() {
                                return Err(Error::Record(RecordError::InvalidReactionBody(
                                    "duplicate ext.connector",
                                )));
                            }
                            connector = Some(raw.to_owned());
                        }
                        EXT_KEY_ID => {
                            let raw = evalue.as_str().ok_or(Error::Record(
                                RecordError::InvalidReactionBody("ext.id must be a string"),
                            ))?;
                            if id.is_some() {
                                return Err(Error::Record(RecordError::InvalidReactionBody(
                                    "duplicate ext.id",
                                )));
                            }
                            id = Some(raw.to_owned());
                        }
                        _ => {
                            return Err(Error::Record(RecordError::InvalidReactionBody(
                                "unknown ext key",
                            )));
                        }
                    }
                }
                let ext_value = ReactionExternalId {
                    connector: connector.ok_or(Error::Record(RecordError::InvalidReactionBody(
                        "ext is missing connector",
                    )))?,
                    id: id.ok_or(Error::Record(RecordError::InvalidReactionBody(
                        "ext is missing id",
                    )))?,
                };
                validate_external_id(&ext_value)?;
                ext = Some(ext_value);
            }
            _ => unreachable!("index resolved from REACTION_BODY_KEYS"),
        }
    }
    if !version {
        return Err(Error::Record(RecordError::InvalidReactionBody("missing v")));
    }
    Ok(ReactionBody {
        msg: msg.ok_or(Error::Record(RecordError::InvalidReactionBody(
            "missing required body key msg",
        )))?,
        by: by.ok_or(Error::Record(RecordError::InvalidReactionBody(
            "missing required body key by",
        )))?,
        glyph: glyph.ok_or(Error::Record(RecordError::InvalidReactionBody(
            "missing required body key glyph",
        )))?,
        at: at.ok_or(Error::Record(RecordError::InvalidReactionBody(
            "missing required body key at",
        )))?,
        ext,
    })
}

/// Toggle input: first-party (`ext=None`) or mirrored (`ext=Some`).
#[derive(Debug, Clone)]
pub struct ReactInput {
    pub message: EntityId,
    pub by: EntityId,
    pub glyph: String,
    pub at: u64,
    pub ext: Option<ReactionExternalId>,
}

/// Toggle outcome with the affected record id.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReactOutcome {
    pub state: ReactionState,
    pub reaction_id: EntityId,
}
/// Room outbound posture for reactions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReactionsOutbound {
    Mirrored,
    FirstPartyOnly,
}

impl ReactionsOutbound {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Mirrored => "mirrored",
            Self::FirstPartyOnly => "first_party_only",
        }
    }
}
