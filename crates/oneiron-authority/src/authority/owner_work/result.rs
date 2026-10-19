//! An executor's result for one owner work request, and its wire codec: the
//! work was enacted, or refused for a closed, value-free reason.

use rmpv::Value;

use crate::entity_id::EntityId;
use crate::error::Result;

use super::*;

const RESULT_KEYS: [&str; 4] = [OP_KEY_KIND, "request", "executor", "outcome"];
const OUTCOME_KEYS: [&str; 2] = [OP_KEY_KIND, "reason"];

/// Why an executor refused a request. Closed and value-free: each reason
/// names a fact the executor read in its own transaction.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize, serde::Deserialize,
)]
#[serde(rename_all = "snake_case")]
pub enum OwnerWorkRefusal {
    /// The target's revision moved past the act's `seen`: a newer act
    /// carries its own work, or did it in its own commit.
    StaleRevision,
    /// The act's owner is no longer a live owner of the vault.
    OwnerNotLive,
    /// The world is not a live WORLD row on the executor.
    WorldNotLive,
    /// The executor is no longer an eligible reader of the world, or, for a
    /// bundle publication, no longer holds every key the bundle seals.
    ExecutorNotReader,
    /// The home a bundle publication names is no longer a linked install of
    /// the vault.
    HomeNotLinked,
    /// The custody record its holder holds may not leave its device:
    /// device bound, cross-vault or "this device only".
    SecretNotPortable,
    /// The custody record its holder holds is not in a state the change
    /// takes: a rotate needs it active, a rewrap not revoked.
    SecretNotActive,
    /// A recipient the owner permitted is no longer a live linked install
    /// with the encryption key he permitted: a changed key needs a fresh
    /// permit.
    RecipientChanged,
    /// The encrypted input does not open on the holder under the request's
    /// binding, or opens to something the change cannot take.
    InvalidInput,
    /// The holder already holds another record under the secret's id, or a
    /// live record under its name.
    CustodyConflict,
    /// The live custody floor on the holder no longer admits the secret's
    /// bindings.
    WiderThanFloor,
}

impl OwnerWorkRefusal {
    /// The wire tag.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::StaleRevision => "stale_revision",
            Self::OwnerNotLive => "owner_not_live",
            Self::WorldNotLive => "world_not_live",
            Self::ExecutorNotReader => "executor_not_reader",
            Self::HomeNotLinked => "home_not_linked",
            Self::SecretNotPortable => "secret_not_portable",
            Self::SecretNotActive => "secret_not_active",
            Self::RecipientChanged => "recipient_changed",
            Self::InvalidInput => "invalid_input",
            Self::CustodyConflict => "custody_conflict",
            Self::WiderThanFloor => "wider_than_floor",
        }
    }

    /// The reason a wire tag names; `None` for any other text.
    #[must_use]
    pub fn from_name(name: &str) -> Option<Self> {
        Some(match name {
            "stale_revision" => Self::StaleRevision,
            "owner_not_live" => Self::OwnerNotLive,
            "world_not_live" => Self::WorldNotLive,
            "executor_not_reader" => Self::ExecutorNotReader,
            "home_not_linked" => Self::HomeNotLinked,
            "secret_not_portable" => Self::SecretNotPortable,
            "secret_not_active" => Self::SecretNotActive,
            "recipient_changed" => Self::RecipientChanged,
            "invalid_input" => Self::InvalidInput,
            "custody_conflict" => Self::CustodyConflict,
            "wider_than_floor" => Self::WiderThanFloor,
            _ => return None,
        })
    }
}

/// What the executor did with a request: its one terminal state.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize, serde::Deserialize,
)]
#[serde(rename_all = "snake_case", tag = "kind")]
pub enum OwnerWorkOutcome {
    /// The executor did the work and committed it. It says nothing of every
    /// replica holding what it wrote; replication is the sync's.
    Enacted,
    Refused {
        reason: OwnerWorkRefusal,
    },
}

impl OwnerWorkOutcome {
    /// The wire tag of the outcome, a refusal's reason for a refusal.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Enacted => "enacted",
            Self::Refused { reason } => reason.as_str(),
        }
    }
}

/// One executor's result for one request, signed by its install key.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize, serde::Deserialize,
)]
pub struct OwnerWorkResult {
    /// The request's signed entry, one of this entry's parents.
    pub request: AuthorityEntryHash,
    /// The install that signed it: the one the request names.
    pub executor: EntityId,
    pub outcome: OwnerWorkOutcome,
}

impl OwnerWorkResult {
    pub fn validate(&self) -> Result<()> {
        if self.request == [0; 32] {
            return Err(invalid_authority());
        }
        Ok(())
    }

    /// Signed alone by an Ed25519 install key, naming the request's entry
    /// among its parents: a result never precedes what it answers.
    pub(in crate::authority) fn validate_entry(&self, entry: &AuthorityLogEntry) -> Result<()> {
        signed_alone_by_install_key(entry)?;
        if !entry.parent_hashes.contains(&self.request) {
            return Err(invalid_authority());
        }
        Ok(())
    }
}

/// Canonical field order: kind, request, executor, outcome; the outcome's
/// own map is kind, then reason (nil once enacted).
pub(in crate::authority) fn owner_work_result_value(result: &OwnerWorkResult) -> Value {
    let (outcome, reason) = match result.outcome {
        OwnerWorkOutcome::Enacted => ("enacted", Value::Nil),
        OwnerWorkOutcome::Refused { reason } => ("refused", Value::from(reason.as_str())),
    };
    Value::Map(vec![
        (
            Value::from(OP_KEY_KIND),
            Value::from(OP_KIND_OWNER_WORK_RESULT),
        ),
        (Value::from("request"), binary_value(result.request)),
        (
            Value::from("executor"),
            Value::from(result.executor.to_hex()),
        ),
        (
            Value::from("outcome"),
            Value::Map(vec![
                (Value::from(OP_KEY_KIND), Value::from(outcome)),
                (Value::from("reason"), reason),
            ]),
        ),
    ])
}

pub(in crate::authority) fn decode_owner_work_result(
    entries: &[(Value, Value)],
) -> Result<AuthorityOp> {
    validate_keys(entries, &RESULT_KEYS)?;
    let outcome = map_entries(required(entries, "outcome")?)?;
    validate_keys(outcome, &OUTCOME_KEYS)?;
    let outcome = match (
        required(outcome, OP_KEY_KIND)?.as_str(),
        required(outcome, "reason")?,
    ) {
        (Some("enacted"), Value::Nil) => OwnerWorkOutcome::Enacted,
        (Some("refused"), reason) => OwnerWorkOutcome::Refused {
            reason: reason
                .as_str()
                .and_then(OwnerWorkRefusal::from_name)
                .ok_or_else(invalid_authority)?,
        },
        _ => return Err(invalid_authority()),
    };
    let result = OwnerWorkResult {
        request: decode_hash(required(entries, "request")?)?,
        executor: decode_canonical_id(required(entries, "executor")?)?,
        outcome,
    };
    result.validate()?;
    Ok(AuthorityOp::OwnerWorkResult(result))
}
