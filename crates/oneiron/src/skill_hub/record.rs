use rmpv::Value;

use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::skill::SkillContentHash;

use super::support::{
    MAX_HUB_TEXT_BYTES, decode_value, encode_value, exact_map, required_text, required_value,
    validate_text,
};

/// Pinned MessagePack key set for a SKILL_HUB body.
pub const SKILL_HUB_BODY_KEYS: [&str; 4] = ["kind", "endpoint", "trust_tier", "sync_policy"];

/// Pinned MessagePack key set for the structured hub provenance pointer.
pub const HUB_REF_KEYS: [&str; 3] = ["hubId", "refString", "pin"];

/// Pinned MessagePack key set for a hub-ref pin.
pub const HUB_PIN_KEYS: [&str; 2] = ["type", "value"];

/// Generic adapter kind stored on a SKILL_HUB record.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum SkillHubKind {
    Git,
    HttpIndex,
    LocalDir,
}

impl SkillHubKind {
    /// Pinned wire spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Git => "git",
            Self::HttpIndex => "http-index",
            Self::LocalDir => "local-dir",
        }
    }

    fn parse(value: &str) -> Option<Self> {
        match value {
            "git" => Some(Self::Git),
            "http-index" => Some(Self::HttpIndex),
            "local-dir" => Some(Self::LocalDir),
            _ => None,
        }
    }
}

/// Friction tier for one configurable hub endpoint.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum SkillHubTrustTier {
    Untrusted,
    Community,
    Verified,
}

impl SkillHubTrustTier {
    /// Pinned wire spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Untrusted => "untrusted",
            Self::Community => "community",
            Self::Verified => "verified",
        }
    }

    fn parse(value: &str) -> Option<Self> {
        match value {
            "untrusted" => Some(Self::Untrusted),
            "community" => Some(Self::Community),
            "verified" => Some(Self::Verified),
            _ => None,
        }
    }
}

/// Default hub policy, overridden by the policy stored with each tracked ref.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum HubSyncPolicy {
    PinnedRef,
    PinnedCommit,
    ContentHashFrozen,
    MirrorOfHub,
}

impl HubSyncPolicy {
    /// Pinned wire spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::PinnedRef => "pinned-ref",
            Self::PinnedCommit => "pinned-commit",
            Self::ContentHashFrozen => "content-hash-frozen",
            Self::MirrorOfHub => "mirror-of-hub",
        }
    }

    fn parse(value: &str) -> Option<Self> {
        match value {
            "pinned-ref" => Some(Self::PinnedRef),
            "pinned-commit" => Some(Self::PinnedCommit),
            "content-hash-frozen" => Some(Self::ContentHashFrozen),
            "mirror-of-hub" => Some(Self::MirrorOfHub),
            _ => None,
        }
    }

    pub(super) const fn allows_automatic_update(self) -> bool {
        matches!(self, Self::PinnedRef | Self::MirrorOfHub)
    }
}

/// Engine-authored maintenance record describing one configurable skill hub.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SkillHubRecord {
    pub kind: SkillHubKind,
    pub endpoint: String,
    pub trust_tier: SkillHubTrustTier,
    pub sync_policy: HubSyncPolicy,
}

impl SkillHubRecord {
    /// Constructs and validates a hub record. The endpoint is always caller data.
    pub fn new(
        kind: SkillHubKind,
        endpoint: impl Into<String>,
        trust_tier: SkillHubTrustTier,
        sync_policy: HubSyncPolicy,
    ) -> Result<Self> {
        let record = Self {
            kind,
            endpoint: endpoint.into(),
            trust_tier,
            sync_policy,
        };
        record.validate()?;
        Ok(record)
    }

    fn validate(&self) -> Result<()> {
        validate_text(
            &self.endpoint,
            MAX_HUB_TEXT_BYTES,
            "skill hub endpoint must be non-empty configurable data",
        )
    }
}

/// Encodes a SKILL_HUB body in canonical key order.
pub fn encode_skill_hub_record(record: &SkillHubRecord) -> Result<Vec<u8>> {
    record.validate()?;
    encode_value(
        &Value::Map(vec![
            (
                Value::from(SKILL_HUB_BODY_KEYS[0]),
                Value::from(record.kind.as_str()),
            ),
            (
                Value::from(SKILL_HUB_BODY_KEYS[1]),
                Value::from(record.endpoint.as_str()),
            ),
            (
                Value::from(SKILL_HUB_BODY_KEYS[2]),
                Value::from(record.trust_tier.as_str()),
            ),
            (
                Value::from(SKILL_HUB_BODY_KEYS[3]),
                Value::from(record.sync_policy.as_str()),
            ),
        ]),
        "SKILL_HUB record MessagePack encode failed",
    )
}

/// Decodes a SKILL_HUB body, rejecting unknown, missing, or duplicate keys.
pub fn decode_skill_hub_record(bytes: &[u8]) -> Result<SkillHubRecord> {
    let value = decode_value(bytes, "SKILL_HUB body is not valid MessagePack")?;
    let entries = exact_map(&value, &SKILL_HUB_BODY_KEYS, "invalid SKILL_HUB body")?;
    SkillHubRecord::new(
        required_value(entries, SKILL_HUB_BODY_KEYS[0], "invalid SKILL_HUB body")?
            .as_str()
            .and_then(SkillHubKind::parse)
            .ok_or(Error::InvalidSkillBody("invalid SKILL_HUB kind"))?,
        required_text(
            entries,
            SKILL_HUB_BODY_KEYS[1],
            MAX_HUB_TEXT_BYTES,
            "invalid SKILL_HUB endpoint",
        )?,
        required_value(entries, SKILL_HUB_BODY_KEYS[2], "invalid SKILL_HUB body")?
            .as_str()
            .and_then(SkillHubTrustTier::parse)
            .ok_or(Error::InvalidSkillBody("invalid SKILL_HUB trust tier"))?,
        required_value(entries, SKILL_HUB_BODY_KEYS[3], "invalid SKILL_HUB body")?
            .as_str()
            .and_then(HubSyncPolicy::parse)
            .ok_or(Error::InvalidSkillBody("invalid SKILL_HUB sync policy"))?,
    )
}

/// Five-way provenance pin carried by a structured hub ref.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum HubPin {
    Semver(String),
    Tag(String),
    Commit(String),
    ContentHash(String),
    None,
}

impl HubPin {
    /// Pinned wire discriminator.
    #[must_use]
    pub const fn pin_type(&self) -> &'static str {
        match self {
            Self::Semver(_) => "semver",
            Self::Tag(_) => "tag",
            Self::Commit(_) => "commit",
            Self::ContentHash(_) => "content_hash",
            Self::None => "none",
        }
    }

    fn value(&self) -> Option<&str> {
        match self {
            Self::Semver(value)
            | Self::Tag(value)
            | Self::Commit(value)
            | Self::ContentHash(value) => Some(value),
            Self::None => None,
        }
    }

    fn validate(&self) -> Result<()> {
        match self {
            Self::ContentHash(value) => {
                SkillContentHash::parse_hex(value)?;
            }
            Self::Semver(value) | Self::Tag(value) | Self::Commit(value) => {
                validate_text(value, MAX_HUB_TEXT_BYTES, "hub pin value must be non-empty")?;
            }
            Self::None => {}
        }
        Ok(())
    }
}

/// Mutable provenance pointer from one hub alias to canonical skill content.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct HubRef {
    pub hub_id: EntityId,
    pub ref_string: String,
    pub pin: HubPin,
}

impl HubRef {
    /// Constructs a validated structured hub ref.
    pub fn new(hub_id: EntityId, ref_string: impl Into<String>, pin: HubPin) -> Result<Self> {
        let hub_ref = Self {
            hub_id,
            ref_string: ref_string.into(),
            pin,
        };
        hub_ref.validate()?;
        Ok(hub_ref)
    }

    pub(super) fn validate(&self) -> Result<()> {
        validate_text(
            &self.ref_string,
            MAX_HUB_TEXT_BYTES,
            "hub ref string must be non-empty",
        )?;
        self.pin.validate()
    }

    /// Encodes the exact `{hubId, refString, pin}` wire shape.
    pub fn to_value(&self) -> Result<Value> {
        self.validate()?;
        Ok(Value::Map(vec![
            (
                Value::from(HUB_REF_KEYS[0]),
                Value::from(self.hub_id.to_hex()),
            ),
            (
                Value::from(HUB_REF_KEYS[1]),
                Value::from(self.ref_string.as_str()),
            ),
            (
                Value::from(HUB_REF_KEYS[2]),
                Value::Map(vec![
                    (
                        Value::from(HUB_PIN_KEYS[0]),
                        Value::from(self.pin.pin_type()),
                    ),
                    (
                        Value::from(HUB_PIN_KEYS[1]),
                        self.pin.value().map_or(Value::Nil, Value::from),
                    ),
                ]),
            ),
        ]))
    }

    /// Decodes the exact structured wire shape.
    pub fn from_value(value: &Value) -> Result<Self> {
        let entries = exact_map(value, &HUB_REF_KEYS, "invalid hub ref")?;
        let hub_id = required_value(entries, HUB_REF_KEYS[0], "invalid hub ref")?
            .as_str()
            .ok_or(Error::InvalidSkillBody("hubId must be an entity id"))?;
        let hub_id = EntityId::from_hex(hub_id)
            .map_err(|_| Error::InvalidSkillBody("hubId must be an entity id"))?;
        let ref_string = required_text(
            entries,
            HUB_REF_KEYS[1],
            MAX_HUB_TEXT_BYTES,
            "refString must be non-empty",
        )?;
        let pin_entries = exact_map(
            required_value(entries, HUB_REF_KEYS[2], "invalid hub ref")?,
            &HUB_PIN_KEYS,
            "invalid hub pin",
        )?;
        let pin_type = required_value(pin_entries, HUB_PIN_KEYS[0], "invalid hub pin")?
            .as_str()
            .ok_or(Error::InvalidSkillBody("invalid hub pin type"))?;
        let pin_value = required_value(pin_entries, HUB_PIN_KEYS[1], "invalid hub pin")?;
        let text_pin = |constructor: fn(String) -> HubPin| -> Result<HubPin> {
            let value = pin_value
                .as_str()
                .ok_or(Error::InvalidSkillBody("hub pin value must be text"))?;
            validate_text(value, MAX_HUB_TEXT_BYTES, "hub pin value must be non-empty")?;
            Ok(constructor(value.to_owned()))
        };
        let pin = match pin_type {
            "semver" => text_pin(HubPin::Semver)?,
            "tag" => text_pin(HubPin::Tag)?,
            "commit" => text_pin(HubPin::Commit)?,
            "content_hash" => text_pin(HubPin::ContentHash)?,
            "none" if matches!(pin_value, Value::Nil) => HubPin::None,
            "none" => return Err(Error::InvalidSkillBody("none hub pin value must be nil")),
            _ => return Err(Error::InvalidSkillBody("invalid hub pin type")),
        };
        Self::new(hub_id, ref_string, pin)
    }
}

/// Per-ref sync state. Seen and trusted observations never overwrite one another.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrackedHubRef {
    pub hub_ref: HubRef,
    pub sync_policy: HubSyncPolicy,
    pub latest_seen: Option<String>,
    pub latest_trusted: Option<String>,
}

impl TrackedHubRef {
    /// Starts tracking one ref under its per-ref policy.
    #[must_use]
    pub fn new(hub_ref: HubRef, sync_policy: HubSyncPolicy) -> Self {
        Self {
            hub_ref,
            sync_policy,
            latest_seen: None,
            latest_trusted: None,
        }
    }

    /// Records the newest observed upstream revision without trusting it.
    pub fn observe(&mut self, revision: impl Into<String>) -> Result<()> {
        let revision = revision.into();
        validate_text(
            &revision,
            MAX_HUB_TEXT_BYTES,
            "latest seen revision must be non-empty",
        )?;
        self.latest_seen = Some(revision);
        Ok(())
    }

    /// Records the newest independently trusted revision.
    pub fn trust(&mut self, revision: impl Into<String>) -> Result<()> {
        let revision = revision.into();
        validate_text(
            &revision,
            MAX_HUB_TEXT_BYTES,
            "latest trusted revision must be non-empty",
        )?;
        self.latest_trusted = Some(revision);
        Ok(())
    }
}
