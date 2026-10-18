//! The owner's work requests and their results, and their wire codec: the
//! key, custody or root work an owner act needs done by an install that can
//! do it.
//!
//! An install that carries the owner's act ([`OwnerAct`]) but cannot do the
//! work the act needs (it may not read the world, or holds none of its key)
//! records an [`OwnerWorkRequest`] signed with its install key, the carrier,
//! naming the one install that is to do the work, the executor. The
//! executor, and only it, signs the [`OwnerWorkResult`] with its own install
//! key, naming the request's entry among its parents: the work was enacted,
//! or refused for a closed, value-free reason. Both are main-log metadata, so
//! every linked machine folds them; neither names a person or a world's text,
//! nor carries a secret byte.
//!
//! Key, custody and root acts are the owner's own: every work kind refuses
//! an agent's act until a Grant line names it (Engine 10-19 02:2x).
//!
//! The first kind is a world's key work ([`OwnerWorkBody::WorldKey`]): ensure
//! the world's key after a settings edit, or re-assert the executor's own
//! keys of it after a pin change ([`WorldKeyMode`]). Each later kind (bundle
//! publication, custody control, a root request) adds one [`OwnerWorkBody`]
//! variant with its [`OwnerWorkKind`], the [`OwnerActKind`] its act carries
//! and the wire map it states under `work`; the request and result envelopes
//! stay as they are.

use rmpv::Value;

use crate::entity_id::EntityId;
use crate::error::Result;

use super::*;

pub const OP_KIND_OWNER_WORK_REQUEST: &str = "owner_work_request";
pub const OP_KIND_OWNER_WORK_RESULT: &str = "owner_work_result";
const REQUEST_KEYS: [&str; 5] = [OP_KEY_KIND, "carrier", OP_KEY_ACT, "executor", "work"];
const RESULT_KEYS: [&str; 4] = [OP_KEY_KIND, "request", "executor", "outcome"];
const WORLD_KEY_WORK_KEYS: [&str; 2] = [OP_KEY_KIND, "mode"];
const OUTCOME_KEYS: [&str; 2] = [OP_KEY_KIND, "reason"];

/// What kind of work a request asks for: the `kind` of its `work` map.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize, serde::Deserialize,
)]
#[serde(rename_all = "snake_case")]
pub enum OwnerWorkKind {
    /// A world's key work: mint its first key, or wrap its current key to
    /// every reader its settings allow.
    WorldKey,
}

impl OwnerWorkKind {
    /// The wire tag.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::WorldKey => "world_key",
        }
    }

    /// The kind a wire tag names; `None` for any other text.
    #[must_use]
    pub fn from_name(name: &str) -> Option<Self> {
        match name {
            "world_key" => Some(Self::WorldKey),
            _ => None,
        }
    }

    /// The act kind a request of this kind carries.
    #[must_use]
    pub fn act(self) -> OwnerActKind {
        match self {
            Self::WorldKey => OwnerActKind::WorldKeyRequest,
        }
    }
}

/// How a world's key work runs: the `mode` of its `work` map.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize, serde::Deserialize,
)]
#[serde(rename_all = "snake_case")]
pub enum WorldKeyMode {
    /// Mint the world's first key, or wrap its current key to every reader
    /// its settings allow: what a settings edit leaves a holder.
    Ensure,
    /// Re-wrap the keys the executor wrapped itself, from its own records
    /// and under the current settings and pin, keeping each key id, and only
    /// then ensure: what the owner's re-assertion of a world after a pin
    /// change leaves a holder.
    Reassert,
}

impl WorldKeyMode {
    /// The wire tag.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Ensure => "ensure",
            Self::Reassert => "reassert",
        }
    }

    /// The mode a wire tag names; `None` for any other text.
    #[must_use]
    pub fn from_name(name: &str) -> Option<Self> {
        match name {
            "ensure" => Some(Self::Ensure),
            "reassert" => Some(Self::Reassert),
            _ => None,
        }
    }
}

/// The work one request asks for. Closed: each kind is one variant, with the
/// fields its own wire map states.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize, serde::Deserialize,
)]
#[serde(rename_all = "snake_case", tag = "kind")]
pub enum OwnerWorkBody {
    /// The key work a world settings edit left to a holder. The act's target
    /// is the world, and its `seen` is the world's `PolicyRevision` right
    /// after the edit: the revision the key work is for.
    WorldKey { mode: WorldKeyMode },
}

impl OwnerWorkBody {
    #[must_use]
    pub fn kind(&self) -> OwnerWorkKind {
        match self {
            Self::WorldKey { .. } => OwnerWorkKind::WorldKey,
        }
    }
}

/// One owner work request, signed by the install key of `carrier`: a live
/// machine of the vault, in any role, that carried the owner's act. It need
/// not hold anything the work needs; `executor` does.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize, serde::Deserialize,
)]
pub struct OwnerWorkRequest {
    pub carrier: EntityId,
    /// The owner's act: who decided, from which surface, on which revision
    /// of the target. Its kind is the work kind's act and its target is the
    /// work's target.
    pub act: OwnerAct,
    /// The one install that does the work: pinned, never elected, and only
    /// a new owner act names another.
    pub executor: EntityId,
    pub work: OwnerWorkBody,
}

impl OwnerWorkRequest {
    #[must_use]
    pub fn kind(&self) -> OwnerWorkKind {
        self.work.kind()
    }

    pub fn validate(&self) -> Result<()> {
        self.act
            .validate_carried(self.work.kind().act(), self.act.target)?;
        // Key, custody and root acts are owner-only until a Grant line names
        // them (Engine 10-19 02:2x).
        if self.act.by != ActBy::Owner {
            return Err(invalid_authority());
        }
        Ok(())
    }

    /// Signed alone by an Ed25519 install key, the carrier's.
    pub(super) fn validate_entry(&self, entry: &AuthorityLogEntry) -> Result<()> {
        signed_alone_by_install_key(entry)
    }
}

/// An owner work entry is signed by one Ed25519 install key and cosigned by
/// none.
fn signed_alone_by_install_key(entry: &AuthorityLogEntry) -> Result<()> {
    if entry.signer.suite != AuthoritySignatureSuite::Ed25519 || !entry.cosigns.is_empty() {
        return Err(invalid_authority());
    }
    Ok(())
}

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
    /// The executor is no longer an eligible reader of the world.
    ExecutorNotReader,
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
    pub(super) fn validate_entry(&self, entry: &AuthorityLogEntry) -> Result<()> {
        signed_alone_by_install_key(entry)?;
        if !entry.parent_hashes.contains(&self.request) {
            return Err(invalid_authority());
        }
        Ok(())
    }
}

/// Canonical field order: kind, carrier, act, executor, work; a world key
/// work map is kind, then mode.
pub(super) fn owner_work_request_value(request: &OwnerWorkRequest) -> Value {
    let work = match request.work {
        OwnerWorkBody::WorldKey { mode } => Value::Map(vec![
            (
                Value::from(OP_KEY_KIND),
                Value::from(OwnerWorkKind::WorldKey.as_str()),
            ),
            (Value::from("mode"), Value::from(mode.as_str())),
        ]),
    };
    Value::Map(vec![
        (
            Value::from(OP_KEY_KIND),
            Value::from(OP_KIND_OWNER_WORK_REQUEST),
        ),
        (
            Value::from("carrier"),
            Value::from(request.carrier.to_hex()),
        ),
        (
            Value::from(OP_KEY_ACT),
            super::owner_act::owner_act_value(&request.act),
        ),
        (
            Value::from("executor"),
            Value::from(request.executor.to_hex()),
        ),
        (Value::from("work"), work),
    ])
}

/// The work map's own keys follow its kind; the envelope's canonical
/// re-encode pins their order.
pub(super) fn decode_owner_work_request(entries: &[(Value, Value)]) -> Result<AuthorityOp> {
    validate_keys(entries, &REQUEST_KEYS)?;
    let work = map_entries(required(entries, "work")?)?;
    let kind = required(work, OP_KEY_KIND)?
        .as_str()
        .and_then(OwnerWorkKind::from_name)
        .ok_or_else(invalid_authority)?;
    let work = match kind {
        OwnerWorkKind::WorldKey => {
            validate_keys(work, &WORLD_KEY_WORK_KEYS)?;
            OwnerWorkBody::WorldKey {
                mode: required(work, "mode")?
                    .as_str()
                    .and_then(WorldKeyMode::from_name)
                    .ok_or_else(invalid_authority)?,
            }
        }
    };
    let request = OwnerWorkRequest {
        carrier: decode_canonical_id(required(entries, "carrier")?)?,
        act: super::owner_act::decode_owner_act(required(entries, OP_KEY_ACT)?)?,
        executor: decode_canonical_id(required(entries, "executor")?)?,
        work,
    };
    request.validate()?;
    Ok(AuthorityOp::OwnerWorkRequest(request))
}

/// Canonical field order: kind, request, executor, outcome; the outcome's
/// own map is kind, then reason (nil once enacted).
pub(super) fn owner_work_result_value(result: &OwnerWorkResult) -> Value {
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

pub(super) fn decode_owner_work_result(entries: &[(Value, Value)]) -> Result<AuthorityOp> {
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
