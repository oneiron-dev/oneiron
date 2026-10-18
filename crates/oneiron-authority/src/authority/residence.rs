//! The owner's residence directives to one of their machines, and each
//! machine's result for one (OF-534). A directive is an owner act through
//! the host, like any roster-signed owner action: it names one physical
//! machine and one act (sync all, sync what it opened, open an item, read
//! its thin index, prune old read caches). Only the machine it names
//! applies it, and that machine signs the result with its own install key,
//! naming the directive's entry among its parents. Neither carries content:
//! no item body, index title or window bytes ride the log.

use rmpv::Value;

use crate::entity_id::EntityId;
use crate::error::Result;

use super::*;

pub const OP_KIND_RESIDENCE_DIRECTIVE: &str = "residence_directive";
pub const OP_KIND_RESIDENCE_RESULT: &str = "residence_result";
/// The longest window key an open act names, in bytes.
pub const RESIDENCE_WINDOW_KEY_MAX: usize = 128;
/// The longest reason a refused result gives, in bytes.
pub const RESIDENCE_REASON_MAX: usize = 128;
const DIRECTIVE_KEYS: [&str; 6] = [OP_KEY_KIND, "id", "machine", "owner", "issued_at", "act"];
const RESULT_KEYS: [&str; 7] = [
    OP_KEY_KIND,
    "directive",
    "machine",
    "directive_entry",
    "finished_at",
    "status",
    "count",
];

/// What a directive asks its machine to do.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ResidenceAct {
    /// Sync every window the machine may read.
    SyncAll,
    /// Sync what the machine opened.
    SyncOpened,
    /// Open one item of one window on the machine.
    Open { window: String, item: EntityId },
    /// Read the machine's thin index.
    Index,
    /// Drop the read caches of opened items last touched before `before`
    /// (recorded-clock seconds).
    Prune { before: u64 },
}

impl ResidenceAct {
    pub const fn wire(&self) -> &'static str {
        match self {
            Self::SyncAll => "sync_all",
            Self::SyncOpened => "sync_opened",
            Self::Open { .. } => "open",
            Self::Index => "index",
            Self::Prune { .. } => "prune",
        }
    }
}

/// One owner directive to one machine.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ResidenceDirective {
    /// The directive's own id; its result names it.
    pub id: EntityId,
    /// The physical MACHINE that applies it.
    pub machine: EntityId,
    /// The owner the door authenticated.
    pub owner: EntityId,
    /// Vault-clock seconds when the owner issued it.
    pub issued_at: u64,
    pub act: ResidenceAct,
}

impl ResidenceDirective {
    pub fn validate(&self) -> Result<()> {
        if let ResidenceAct::Open { window, .. } = &self.act
            && (window.is_empty()
                || window.len() > RESIDENCE_WINDOW_KEY_MAX
                || window.contains(char::is_control))
        {
            return Err(invalid_authority());
        }
        Ok(())
    }
}

/// What the machine did with a directive.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ResidenceResultStatus {
    /// The machine applied it.
    Applied,
    /// It does not apply on the machine (its mode, its lane, a window it
    /// cannot open); the result's reason says why. It is never retried.
    Refused,
}

impl ResidenceResultStatus {
    pub const fn wire(self) -> &'static str {
        match self {
            Self::Applied => "applied",
            Self::Refused => "refused",
        }
    }

    pub fn parse(wire: &str) -> Option<Self> {
        match wire {
            "applied" => Some(Self::Applied),
            "refused" => Some(Self::Refused),
            _ => None,
        }
    }
}

/// One machine's result for one directive, signed by its install key.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ResidenceResult {
    /// The directive's id.
    pub directive: EntityId,
    /// The machine that signed it, the one the directive names.
    pub machine: EntityId,
    /// The directive's signed entry, one of this entry's parents.
    pub directive_entry: AuthorityEntryHash,
    /// Vault-clock seconds on the machine when it finished.
    pub finished_at: u64,
    pub status: ResidenceResultStatus,
    /// What the act touched: windows the home granted again (sync opened),
    /// read caches dropped (sync all, prune), windows in the thin index
    /// (index), the one item opened (open).
    pub count: u64,
    /// Why a refused directive does not apply; `None` once applied.
    pub reason: Option<String>,
}

impl ResidenceResult {
    pub fn validate(&self) -> Result<()> {
        let reason_ok = match (self.status, &self.reason) {
            (ResidenceResultStatus::Applied, None) => true,
            (ResidenceResultStatus::Refused, Some(reason)) => {
                !reason.is_empty()
                    && reason.len() <= RESIDENCE_REASON_MAX
                    && !reason.contains(char::is_control)
            }
            _ => false,
        };
        if !reason_ok || self.directive_entry == [0; 32] {
            return Err(invalid_authority());
        }
        Ok(())
    }

    /// Signed alone by an Ed25519 install key, naming the directive's entry
    /// among its parents: a result never precedes what it answers.
    pub(super) fn validate_entry(&self, entry: &AuthorityLogEntry) -> Result<()> {
        if entry.signer.suite != AuthoritySignatureSuite::Ed25519
            || !entry.cosigns.is_empty()
            || !entry.parent_hashes.contains(&self.directive_entry)
        {
            return Err(invalid_authority());
        }
        Ok(())
    }
}

/// Canonical field order: kind, id, machine, owner, issued_at, act, then the
/// act's own fields (an open's window and item; a prune's before).
pub(super) fn residence_directive_value(directive: &ResidenceDirective) -> Value {
    let mut entries = vec![
        (
            Value::from(OP_KEY_KIND),
            Value::from(OP_KIND_RESIDENCE_DIRECTIVE),
        ),
        (Value::from("id"), Value::from(directive.id.to_hex())),
        (
            Value::from("machine"),
            Value::from(directive.machine.to_hex()),
        ),
        (Value::from("owner"), Value::from(directive.owner.to_hex())),
        (Value::from("issued_at"), Value::from(directive.issued_at)),
        (Value::from("act"), Value::from(directive.act.wire())),
    ];
    match &directive.act {
        ResidenceAct::Open { window, item } => {
            entries.push((Value::from("window"), Value::from(window.as_str())));
            entries.push((Value::from("item"), Value::from(item.to_hex())));
        }
        ResidenceAct::Prune { before } => {
            entries.push((Value::from("before"), Value::from(*before)));
        }
        ResidenceAct::SyncAll | ResidenceAct::SyncOpened | ResidenceAct::Index => {}
    }
    Value::Map(entries)
}

pub(super) fn decode_residence_directive(entries: &[(Value, Value)]) -> Result<AuthorityOp> {
    let act = required(entries, "act")?
        .as_str()
        .ok_or_else(invalid_authority)?;
    let mut keys = DIRECTIVE_KEYS.to_vec();
    match act {
        "open" => keys.extend(["window", "item"]),
        "prune" => keys.push("before"),
        _ => {}
    }
    validate_keys(entries, &keys)?;
    let id = |name: &str| super::machine_profile::decode_canonical_id(required(entries, name)?);
    let number = |name: &str| {
        required(entries, name)?
            .as_u64()
            .ok_or_else(invalid_authority)
    };
    let act = match act {
        "sync_all" => ResidenceAct::SyncAll,
        "sync_opened" => ResidenceAct::SyncOpened,
        "open" => ResidenceAct::Open {
            window: required(entries, "window")?
                .as_str()
                .ok_or_else(invalid_authority)?
                .to_owned(),
            item: id("item")?,
        },
        "index" => ResidenceAct::Index,
        "prune" => ResidenceAct::Prune {
            before: number("before")?,
        },
        _ => return Err(invalid_authority()),
    };
    let directive = ResidenceDirective {
        id: id("id")?,
        machine: id("machine")?,
        owner: id("owner")?,
        issued_at: number("issued_at")?,
        act,
    };
    directive.validate()?;
    Ok(AuthorityOp::ResidenceDirective(directive))
}

/// Canonical field order: kind, directive, machine, directive_entry,
/// finished_at, status, count, then a refused result's reason.
pub(super) fn residence_result_value(result: &ResidenceResult) -> Value {
    let mut entries = vec![
        (
            Value::from(OP_KEY_KIND),
            Value::from(OP_KIND_RESIDENCE_RESULT),
        ),
        (
            Value::from("directive"),
            Value::from(result.directive.to_hex()),
        ),
        (Value::from("machine"), Value::from(result.machine.to_hex())),
        (
            Value::from("directive_entry"),
            binary_value(result.directive_entry),
        ),
        (Value::from("finished_at"), Value::from(result.finished_at)),
        (Value::from("status"), Value::from(result.status.wire())),
        (Value::from("count"), Value::from(result.count)),
    ];
    if let Some(reason) = &result.reason {
        entries.push((Value::from("reason"), Value::from(reason.as_str())));
    }
    Value::Map(entries)
}

pub(super) fn decode_residence_result(entries: &[(Value, Value)]) -> Result<AuthorityOp> {
    let has_reason = entries
        .iter()
        .any(|(key, _)| key.as_str() == Some("reason"));
    let mut keys = RESULT_KEYS.to_vec();
    if has_reason {
        keys.push("reason");
    }
    validate_keys(entries, &keys)?;
    let id = |name: &str| super::machine_profile::decode_canonical_id(required(entries, name)?);
    let number = |name: &str| {
        required(entries, name)?
            .as_u64()
            .ok_or_else(invalid_authority)
    };
    let result = ResidenceResult {
        directive: id("directive")?,
        machine: id("machine")?,
        directive_entry: decode_hash(required(entries, "directive_entry")?)?,
        finished_at: number("finished_at")?,
        status: required(entries, "status")?
            .as_str()
            .and_then(ResidenceResultStatus::parse)
            .ok_or_else(invalid_authority)?,
        count: number("count")?,
        reason: has_reason
            .then(|| {
                required(entries, "reason")?
                    .as_str()
                    .map(str::to_owned)
                    .ok_or_else(invalid_authority)
            })
            .transpose()?,
    };
    result.validate()?;
    Ok(AuthorityOp::ResidenceResult(result))
}
