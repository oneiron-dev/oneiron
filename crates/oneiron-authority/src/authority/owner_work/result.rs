//! An executor's result for one owner work request, and its wire codec: the
//! work was enacted, or refused for a closed, value-free reason.
//!
//! An enacted custody register whose owner's surface stated no
//! `manifest_ref` carries its holder's own judgment of the record
//! ([`CustodyRegisterCheck`], FIX 5334): checked against the manifest the
//! record names, or registered without a manifest check and why. Manifest
//! refs and a closed reason only, never a value, a name or a digest of
//! plaintext. It rides the outcome's `reason` slot, nil for every other
//! enacted result, so each result without one encodes as it always has.

use rmpv::Value;

use crate::entity_id::EntityId;
use crate::error::Result;

use super::*;

const RESULT_KEYS: [&str; 4] = [OP_KEY_KIND, "request", "executor", "outcome"];
const OUTCOME_KEYS: [&str; 2] = [OP_KEY_KIND, "reason"];
const REGISTER_CHECK_KEYS: [&str; 3] = [OP_KEY_KIND, "reason", "refs"];

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
    /// The applicable work/key owner is no longer a live owner of the vault.
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

/// Why a custody register's holder took the record without a manifest
/// check. Closed and value-free: each reason names what the holder found.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize, serde::Deserialize,
)]
#[serde(rename_all = "snake_case")]
pub enum CustodyUncheckedReason {
    /// The record names no manifest. No ref.
    NoneNamed,
    /// Its recorder found no secret manifest the vault publishes. No ref.
    NonePublished,
    /// Its recorder could not read the secret manifests the vault
    /// publishes. No ref.
    Unread,
    /// The record names a manifest the vault does not publish: the refs are
    /// the record's, then each one its recorder attached.
    OtherManifest,
    /// The record disagrees with the published manifest it names: the one
    /// ref is that manifest's.
    Disagrees,
}

impl CustodyUncheckedReason {
    /// The wire tag.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::NoneNamed => "none_named",
            Self::NonePublished => "none_published",
            Self::Unread => "unread",
            Self::OtherManifest => "other_manifest",
            Self::Disagrees => "disagrees",
        }
    }

    /// The reason a wire tag names; `None` for any other text.
    #[must_use]
    pub fn from_name(name: &str) -> Option<Self> {
        Some(match name {
            "none_named" => Self::NoneNamed,
            "none_published" => Self::NonePublished,
            "unread" => Self::Unread,
            "other_manifest" => Self::OtherManifest,
            "disagrees" => Self::Disagrees,
            _ => return None,
        })
    }

    /// Whether `count` refs are the ones this reason names.
    fn names(self, count: usize) -> bool {
        match self {
            Self::NoneNamed | Self::NonePublished | Self::Unread => count == 0,
            Self::Disagrees => count == 1,
            Self::OtherManifest => count >= 1,
        }
    }
}

/// What the holder of a sealed register whose owner's surface stated no
/// `manifest_ref` checked the record against: its own judgment, signed in
/// its enacted result (FIX 5334). Manifest refs and a closed reason only.
/// `Clone`, not `Copy`: a ref is text.
#[derive(
    Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize, serde::Deserialize,
)]
#[serde(rename_all = "snake_case", tag = "kind")]
pub enum CustodyRegisterCheck {
    /// The record names `manifest_ref`, one its recorder attached, and
    /// agrees with it.
    Checked { manifest_ref: String },
    /// Registered without a manifest check, for `reason`, naming the
    /// manifests the reason names.
    Unchecked {
        reason: CustodyUncheckedReason,
        refs: Vec<String>,
    },
}

impl CustodyRegisterCheck {
    /// No empty ref, and exactly the refs its reason names.
    pub fn validate(&self) -> Result<()> {
        let shaped = match self {
            Self::Checked { manifest_ref } => !manifest_ref.is_empty(),
            Self::Unchecked { reason, refs } => {
                reason.names(refs.len()) && refs.iter().all(|named| !named.is_empty())
            }
        };
        if !shaped {
            return Err(invalid_authority());
        }
        Ok(())
    }

    /// Whether the record was taken without a manifest check.
    #[must_use]
    pub fn unchecked(&self) -> bool {
        matches!(self, Self::Unchecked { .. })
    }
}

/// What the executor did with a request: its one terminal state. `Clone`,
/// not `Copy`: an enacted register carries its holder's manifest judgment.
#[derive(
    Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize, serde::Deserialize,
)]
#[serde(rename_all = "snake_case", tag = "kind")]
pub enum OwnerWorkOutcome {
    /// The executor did the work and committed it. It says nothing of every
    /// replica holding what it wrote; replication is the sync's. A custody
    /// register whose surface stated no `manifest_ref` carries what its
    /// holder checked the record against; every other result carries none.
    Enacted {
        detail: Option<CustodyRegisterCheck>,
    },
    Refused {
        reason: OwnerWorkRefusal,
    },
}

impl OwnerWorkOutcome {
    /// Enacted, with no detail: every enacted result but an unstated
    /// custody register's.
    #[must_use]
    pub const fn enacted() -> Self {
        Self::Enacted { detail: None }
    }

    /// The wire tag of the outcome, a refusal's reason for a refusal.
    #[must_use]
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Enacted { .. } => "enacted",
            Self::Refused { reason } => reason.as_str(),
        }
    }

    /// The holder's manifest judgment an enacted register carries.
    #[must_use]
    pub fn register_check(&self) -> Option<&CustodyRegisterCheck> {
        match self {
            Self::Enacted { detail } => detail.as_ref(),
            Self::Refused { .. } => None,
        }
    }
}

/// One executor's result for one request, signed by its install key.
/// `Clone`, not `Copy`, as its outcome is.
#[derive(
    Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize, serde::Deserialize,
)]
pub struct OwnerWorkResult {
    /// The request's signed entry, in this entry's causal past (the fold of
    /// its parents).
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
        if let Some(check) = self.outcome.register_check() {
            check.validate()?;
        }
        Ok(())
    }

    /// Signed alone by an Ed25519 install key. Its shape names no parent:
    /// the request must be in the result's causal past, which only the fold
    /// of its parents knows, so the fold judges it there and refuses a result
    /// whose request is not (CALLS "FIX 4987 causal request presence"). A
    /// result never precedes what it answers.
    pub(in crate::authority) fn validate_entry(&self, entry: &AuthorityLogEntry) -> Result<()> {
        signed_alone_by_install_key(entry)
    }
}

/// Canonical field order: kind, request, executor, outcome; the outcome's
/// own map is kind, then reason: a refusal's reason, or once enacted the
/// holder's manifest judgment, nil when there is none. A judgment's map is
/// kind, reason (nil once checked), then refs (the checked one alone once
/// checked).
pub(in crate::authority) fn owner_work_result_value(result: &OwnerWorkResult) -> Value {
    let (outcome, reason) = match &result.outcome {
        OwnerWorkOutcome::Enacted { detail } => (
            "enacted",
            detail.as_ref().map_or(Value::Nil, register_check_value),
        ),
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
        (Some("enacted"), Value::Nil) => OwnerWorkOutcome::enacted(),
        (Some("enacted"), detail) => OwnerWorkOutcome::Enacted {
            detail: Some(decode_register_check(detail)?),
        },
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

/// A judgment's map: kind, reason, then refs.
fn register_check_value(check: &CustodyRegisterCheck) -> Value {
    let (kind, reason, refs) = match check {
        CustodyRegisterCheck::Checked { manifest_ref } => {
            ("checked", Value::Nil, std::slice::from_ref(manifest_ref))
        }
        CustodyRegisterCheck::Unchecked { reason, refs } => {
            ("unchecked", Value::from(reason.as_str()), refs.as_slice())
        }
    };
    Value::Map(vec![
        (Value::from(OP_KEY_KIND), Value::from(kind)),
        (Value::from("reason"), reason),
        (
            Value::from("refs"),
            Value::Array(
                refs.iter()
                    .map(|named| Value::from(named.as_str()))
                    .collect(),
            ),
        ),
    ])
}

/// Strict keys; a checked judgment names one ref and no reason. Its shape
/// is the judgment's ([`CustodyRegisterCheck::validate`]).
fn decode_register_check(value: &Value) -> Result<CustodyRegisterCheck> {
    let entries = map_entries(value)?;
    validate_keys(entries, &REGISTER_CHECK_KEYS)?;
    let Value::Array(refs) = required(entries, "refs")? else {
        return Err(invalid_authority());
    };
    let mut refs = refs
        .iter()
        .map(|named| {
            named
                .as_str()
                .map(str::to_owned)
                .ok_or_else(invalid_authority)
        })
        .collect::<Result<Vec<_>>>()?;
    match (
        required(entries, OP_KEY_KIND)?.as_str(),
        required(entries, "reason")?,
    ) {
        (Some("checked"), Value::Nil) if refs.len() == 1 => Ok(CustodyRegisterCheck::Checked {
            manifest_ref: refs.pop().ok_or_else(invalid_authority)?,
        }),
        (Some("unchecked"), reason) => Ok(CustodyRegisterCheck::Unchecked {
            reason: reason
                .as_str()
                .and_then(CustodyUncheckedReason::from_name)
                .ok_or_else(invalid_authority)?,
            refs,
        }),
        _ => Err(invalid_authority()),
    }
}
