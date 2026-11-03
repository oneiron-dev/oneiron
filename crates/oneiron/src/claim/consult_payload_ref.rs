use crate::Vault;
use crate::entity_id::EntityId;
use crate::error::{Error, RecordError, Result};

/// The only ref kinds a consult payload may carry. A consult asks ABOUT
/// durable state; it never transports the state itself.
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    serde::Serialize,
    serde::Deserialize,
    schemars::JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum ConsultPayloadRef {
    Claim(EntityId),
    Turn(EntityId),
}

impl ConsultPayloadRef {
    /// The referenced entity.
    #[must_use]
    pub const fn entity_ref(self) -> EntityId {
        match self {
            Self::Claim(entity_ref) | Self::Turn(entity_ref) => entity_ref,
        }
    }

    pub(crate) const fn entity_type(self) -> u8 {
        match self {
            Self::Claim(_) => crate::registry::ENTITY_TYPE_CLAIM,
            Self::Turn(_) => crate::registry::ENTITY_TYPE_TURN,
        }
    }

    const fn prefix(self) -> &'static str {
        match self {
            Self::Claim(_) => "cl",
            Self::Turn(_) => "tn",
        }
    }

    /// Canonical `cl_*` / `tn_*` rendering.
    #[must_use]
    pub fn short_ref(self) -> String {
        format!("{}_{}", self.prefix(), self.entity_ref().to_hex())
    }

    /// Parses one caller string into the typed enum and binds it to a RESOLVED
    /// entity of the matching kind. Unknown prefixes, malformed ids, and
    /// unresolved or mistyped targets are refused here — this is a shape
    /// guarantee established before persistence, not a scrubber run over
    /// arbitrary JSON afterwards.
    pub fn parse(vault: &Vault, value: &str) -> Result<Self> {
        let (prefix, hex) =
            value
                .split_once('_')
                .ok_or(Error::Record(RecordError::InvalidTaskBody(
                    "tasks.consult.ref",
                )))?;
        let entity_ref = EntityId::from_hex(hex)
            .map_err(|_| Error::Record(RecordError::InvalidTaskBody("tasks.consult.ref")))?;
        let parsed = match prefix {
            "cl" => Self::Claim(entity_ref),
            "tn" => Self::Turn(entity_ref),
            _ => {
                return Err(Error::Record(RecordError::InvalidTaskBody(
                    "tasks.consult.ref",
                )));
            }
        };
        if vault.get_entity_type(&entity_ref)? != Some(parsed.entity_type()) {
            return Err(Error::Record(RecordError::InvalidTaskBody(
                "tasks.consult.ref",
            )));
        }
        Ok(parsed)
    }
}
