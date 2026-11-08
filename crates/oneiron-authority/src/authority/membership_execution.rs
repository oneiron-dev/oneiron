//! A shared-vault membership change as a carrier-signed AUTHORITY_LOG record
//! (FIX 12335, Engine 13:13 call A), and its wire codec.
//!
//! A membership change lands at once, in its own writer: a member's role
//! change, removal or leave, or a matured `transfer_ownership` or
//! `remove_owner` act. When this install holds a live host issuer, that
//! writer signs the change's grant withdrawals (`SlipGrantRevoke`) and its
//! Owner handover (`OwnerHandover`) as before. When no issuer can sign, the
//! writer keeps a value-free pending intent beside the change, and an
//! install that carries for the vault (the one carrier rule) signs this
//! record of that committed fact later, with no step from any person.
//!
//! The record states the change as its writer executed it: the shared vault,
//! the cause (the power or act that made it), the authenticated person who
//! executed it, the member whose role moved, the shared act and the receipt,
//! and the second it was executed at, which the entry's advisory time is
//! not. It withdraws every slip minted under each Grant in
//! `withdrawn_grants`, the ones a replica mints and merges later included,
//! as a `SlipGrantRevoke` does. An Owner act's record carries its handover:
//! the exact grant ids it wrote and the own-device grants it retired, the
//! same restore evidence an `OwnerHandover` signs (FIX 5765). It is never an
//! owner act and never the granting Owner's revoke: no [`OwnerAct`] rides it,
//! because an Admin's change or a member's leave is no Owner's will.

use rmpv::Value;
use serde::{Deserialize, Serialize};

use crate::entity_id::EntityId;
use crate::error::Result;

use super::*;

pub const OP_KIND_MEMBERSHIP_EXECUTION: &str = "membership_execution";
const MEMBERSHIP_EXECUTION_KEYS: [&str; 11] = [
    OP_KEY_KIND,
    "machine",
    "shared_vault",
    "cause",
    "person",
    "member",
    "act",
    "receipt",
    "executed_at",
    "withdrawn_grants",
    "handover",
];
const MEMBERSHIP_HANDOVER_KEYS: [&str; 4] = [
    "to",
    "from_keeps",
    "affected_grants",
    "retired_own_device_grants",
];

/// The power or act that made one membership change.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MembershipExecutionCause {
    /// An Admin's `org:assign-role` power moved a member to another non-root
    /// role.
    AssignRole,
    /// An Admin's `org:remove-member` power removed a member.
    RemoveMember,
    /// A member left on their own standing.
    Leave,
    /// A matured `transfer_ownership` act a live Owner executed.
    TransferOwnership,
    /// A matured `remove_owner` act a live Owner executed.
    RemoveOwner,
}

impl MembershipExecutionCause {
    /// The wire tag.
    #[must_use]
    pub const fn wire(self) -> &'static str {
        match self {
            Self::AssignRole => "assign_role",
            Self::RemoveMember => "remove_member",
            Self::Leave => "leave",
            Self::TransferOwnership => "transfer_ownership",
            Self::RemoveOwner => "remove_owner",
        }
    }

    /// The cause a wire tag names; `None` for any other text.
    #[must_use]
    pub fn parse(wire: &str) -> Option<Self> {
        Some(match wire {
            "assign_role" => Self::AssignRole,
            "remove_member" => Self::RemoveMember,
            "leave" => Self::Leave,
            "transfer_ownership" => Self::TransferOwnership,
            "remove_owner" => Self::RemoveOwner,
            _ => return None,
        })
    }

    /// The Owner handover cause an Owner act's record carries; `None` for a
    /// member change, which hands nothing over.
    #[must_use]
    pub const fn handover_cause(self) -> Option<OwnerHandoverCause> {
        match self {
            Self::TransferOwnership => Some(OwnerHandoverCause::Transfer),
            Self::RemoveOwner => Some(OwnerHandoverCause::Removal),
            Self::AssignRole | Self::RemoveMember | Self::Leave => None,
        }
    }
}

/// The Owner handover an Owner act's record carries: the fields of its
/// [`OwnerHandover`] the record does not already hold. Its leaver is the
/// record's `member`; its vault, act and receipt are the record's.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MembershipHandover {
    /// The member who becomes Owner; a transfer always names one.
    pub to: Option<EntityId>,
    /// The role the leaver keeps, by its wire name; `None` when they leave.
    pub from_keeps: Option<String>,
    /// Every grant id the change rewrote, minted or deleted, apart from the
    /// own-device grants it retired. Ascending, unique, uncapped.
    pub affected_grants: Vec<EntityId>,
    /// The own-device grant ids the leaver's demotion retired. Ascending,
    /// unique, uncapped.
    pub retired_own_device_grants: Vec<EntityId>,
}

/// One executed shared-vault membership change, signed by the install key of
/// `machine`, a live machine of the vault, after the change committed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MembershipExecution {
    /// The carrier: the machine whose install key signed the record.
    pub machine: EntityId,
    /// The shared vault's federation id.
    pub shared_vault: u64,
    pub cause: MembershipExecutionCause,
    /// The authenticated PERSON who executed the change: the Admin, the
    /// leaving member, or the live Owner who ran the act.
    pub person: EntityId,
    /// The member whose role moved; an Owner act's leaver.
    pub member: EntityId,
    /// The shared act the change executed; an Owner act's alone.
    pub act: Option<String>,
    /// The execution receipt's id.
    pub receipt: String,
    /// The second the change was executed at, on the writer's store clock.
    pub executed_at: u64,
    /// Every Grant an owner's signed mint made that the change deleted and
    /// no signed withdrawal names. Ascending, unique, uncapped.
    pub withdrawn_grants: Vec<EntityId>,
    /// An Owner act's handover; `None` for a member change.
    pub handover: Option<MembershipHandover>,
}

/// Whether `ids` ascend strictly by id bytes, within
/// [`HANDOVER_ID_LIST_LIMIT`].
fn ascending_ids(ids: &[EntityId]) -> bool {
    ids.windows(2).all(|pair| pair[0] < pair[1])
        && HANDOVER_ID_LIST_LIMIT.is_none_or(|limit| ids.len() <= limit)
}

impl MembershipExecution {
    /// The [`OwnerHandover`] an Owner act's record carries, whole: the exact
    /// restore evidence a host-signed handover of the same change names.
    #[must_use]
    pub fn owner_handover(&self) -> Option<OwnerHandover> {
        let handover = self.handover.as_ref()?;
        Some(OwnerHandover {
            shared_vault: self.shared_vault,
            cause: self.cause.handover_cause()?,
            from: self.member,
            to: handover.to,
            from_keeps: handover.from_keeps.clone(),
            act: self.act.clone(),
            proof: None,
            authorizer: None,
            receipt: self.receipt.clone(),
            affected_grants: handover.affected_grants.clone(),
            retired_own_device_grants: handover.retired_own_device_grants.clone(),
        })
    }

    pub fn validate(&self) -> Result<()> {
        let refs_ok = [Some(&self.receipt), self.act.as_ref()]
            .into_iter()
            .flatten()
            .all(|value| !value.is_empty() && value.len() <= OWNER_HANDOVER_REF_MAX);
        // An Owner act's record names its act and its handover; a member
        // change names neither, and a leave is the member's own.
        let owner_act = self.cause.handover_cause().is_some();
        let shape_ok = owner_act == self.act.is_some()
            && owner_act == self.handover.is_some()
            && (self.cause != MembershipExecutionCause::Leave || self.person == self.member);
        // A record withdraws a Grant or hands the Owner role over.
        let says_something = !self.withdrawn_grants.is_empty() || self.handover.is_some();
        if !refs_ok
            || !shape_ok
            || !says_something
            || self.executed_at == 0
            || !ascending_ids(&self.withdrawn_grants)
            || self
                .withdrawn_grants
                .iter()
                .any(|grant| *grant.as_bytes() == [0; 16])
        {
            return Err(invalid_authority());
        }
        if let Some(handover) = self.owner_handover() {
            handover.validate()?;
        } else if owner_act {
            return Err(invalid_authority());
        }
        Ok(())
    }
}

fn ids_value(ids: &[EntityId]) -> Value {
    Value::Array(ids.iter().map(|id| Value::from(id.to_hex())).collect())
}

fn decode_ids(value: &Value) -> Result<Vec<EntityId>> {
    let Value::Array(values) = value else {
        return Err(invalid_authority());
    };
    values.iter().map(decode_canonical_id).collect()
}

fn optional_text(value: &Value) -> Result<Option<String>> {
    match value {
        Value::Nil => Ok(None),
        value => value
            .as_str()
            .map(|text| Some(text.to_owned()))
            .ok_or_else(invalid_authority),
    }
}

/// Canonical field order: kind, machine, shared_vault, cause, person,
/// member, act (nil when none), receipt, executed_at, withdrawn_grants, then
/// the handover (nil for a member change) as its four keys in order: to and
/// from_keeps (each nil when none), affected and retired grant ids.
pub(super) fn membership_execution_value(record: &MembershipExecution) -> Value {
    let handover = record.handover.as_ref().map_or(Value::Nil, |handover| {
        Value::Map(vec![
            (
                Value::from("to"),
                handover
                    .to
                    .map_or(Value::Nil, |to| Value::from(to.to_hex())),
            ),
            (
                Value::from("from_keeps"),
                handover
                    .from_keeps
                    .as_deref()
                    .map_or(Value::Nil, Value::from),
            ),
            (
                Value::from("affected_grants"),
                ids_value(&handover.affected_grants),
            ),
            (
                Value::from("retired_own_device_grants"),
                ids_value(&handover.retired_own_device_grants),
            ),
        ])
    });
    Value::Map(vec![
        (
            Value::from(OP_KEY_KIND),
            Value::from(OP_KIND_MEMBERSHIP_EXECUTION),
        ),
        (Value::from("machine"), Value::from(record.machine.to_hex())),
        (
            Value::from("shared_vault"),
            Value::from(record.shared_vault),
        ),
        (Value::from("cause"), Value::from(record.cause.wire())),
        (Value::from("person"), Value::from(record.person.to_hex())),
        (Value::from("member"), Value::from(record.member.to_hex())),
        (
            Value::from("act"),
            record.act.as_deref().map_or(Value::Nil, Value::from),
        ),
        (Value::from("receipt"), Value::from(record.receipt.as_str())),
        (Value::from("executed_at"), Value::from(record.executed_at)),
        (
            Value::from("withdrawn_grants"),
            ids_value(&record.withdrawn_grants),
        ),
        (Value::from("handover"), handover),
    ])
}

/// Every key once, then the record's shape check; the envelope's canonical
/// re-encode pins the key order and every value's form.
pub(super) fn decode_membership_execution(entries: &[(Value, Value)]) -> Result<AuthorityOp> {
    validate_keys(entries, &MEMBERSHIP_EXECUTION_KEYS)?;
    let handover = match required(entries, "handover")? {
        Value::Nil => None,
        value => {
            let fields = map_entries(value)?;
            validate_keys(fields, &MEMBERSHIP_HANDOVER_KEYS)?;
            Some(MembershipHandover {
                to: match required(fields, "to")? {
                    Value::Nil => None,
                    value => Some(decode_canonical_id(value)?),
                },
                from_keeps: optional_text(required(fields, "from_keeps")?)?,
                affected_grants: decode_ids(required(fields, "affected_grants")?)?,
                retired_own_device_grants: decode_ids(required(
                    fields,
                    "retired_own_device_grants",
                )?)?,
            })
        }
    };
    let record = MembershipExecution {
        machine: decode_canonical_id(required(entries, "machine")?)?,
        shared_vault: required(entries, "shared_vault")?
            .as_u64()
            .ok_or_else(invalid_authority)?,
        cause: required(entries, "cause")?
            .as_str()
            .and_then(MembershipExecutionCause::parse)
            .ok_or_else(invalid_authority)?,
        person: decode_canonical_id(required(entries, "person")?)?,
        member: decode_canonical_id(required(entries, "member")?)?,
        act: optional_text(required(entries, "act")?)?,
        receipt: required(entries, "receipt")?
            .as_str()
            .map(str::to_owned)
            .ok_or_else(invalid_authority)?,
        executed_at: required(entries, "executed_at")?
            .as_u64()
            .ok_or_else(invalid_authority)?,
        withdrawn_grants: decode_ids(required(entries, "withdrawn_grants")?)?,
        handover,
    };
    record.validate()?;
    Ok(AuthorityOp::MembershipExecution(record))
}
