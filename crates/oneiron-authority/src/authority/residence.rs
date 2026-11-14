//! The owner's residence directives to one of their machines, and each
//! machine's result for one (OF-534). A directive is an owner act through
//! the host, like any roster-signed owner action: it names one physical
//! machine and one act (sync all, sync what it opened, follow the worlds
//! the owner picked, sync what it opened plus what its home predicts, open
//! an item, read its thin index, prune old read caches). The home's own
//! prediction for a machine at the predicted level is a directive too,
//! signed by the host under the owner's predicted act it names
//! (ARCH-0023b #predicted-residence). Only the machine it names
//! applies it, and that machine signs the result with its own install key,
//! naming the directive's entry among its parents. Neither carries content:
//! no item body, index title or window bytes ride the log.

use std::collections::BTreeSet;

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
/// The most worlds one follow act names.
pub const RESIDENCE_FOLLOW_WORLDS_MAX: usize = 256;
/// The windows a predicted machine's prediction names when the owner set no
/// budget (Engine ruling L7-46-BUDGET B, 14 Nov 03:02). The owner's budget
/// has no ceiling: the prediction's entry names its set by digest.
pub const RESIDENCE_PREDICTED_WINDOWS_DEFAULT: u32 = 32;
/// The entity documents a predicted machine's prediction names when the
/// owner set no budget.
pub const RESIDENCE_PREDICTED_DOCUMENTS_DEFAULT: u32 = 128;
/// The derive-key context of a predicted set's digest.
const PREDICTED_SET_CONTEXT: &str = "oneiron predicted residence set v1";
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
    /// Sync what the machine opened, plus the windows and entity documents
    /// its home predicts it will open (ARCH-0023b #predicted-residence): the
    /// owner's approval of the home's [`ResidenceAct::Predicted`] pushes to
    /// this machine, each within this budget. A later mode act ends it.
    SyncPredicted {
        /// The most windows one prediction names.
        window_budget: u32,
        /// The most entity documents one prediction names.
        document_budget: u32,
    },
    /// The home's prediction for a machine at the predicted level: the
    /// windows and entity documents it should hold, replacing its last
    /// prediction. The host signs it; `parent` is the owner's
    /// [`ResidenceAct::SyncPredicted`] directive it executes, and the machine
    /// refuses it unless that directive is its latest mode act and the set
    /// fits that directive's budget. The set itself is a
    /// [`PredictedResidenceSet`] named by its digest, which only the named
    /// machine fetches from its home, so the entry every replica stores is
    /// the same size whatever the budget (Engine ruling
    /// L7-46-BUDGET-CEILING, 14 Nov 11:28).
    Predicted {
        parent: EntityId,
        /// [`PredictedResidenceSet::digest`] of the set.
        set_digest: [u8; 32],
        /// How many windows the set names.
        window_count: u32,
        /// How many entity documents the set names.
        document_count: u32,
    },
    /// Follow these worlds: the owner's pick of the projects whose full
    /// windows the machine syncs (ARCH-0023b #partial-sync). It replaces the
    /// machine's earlier pick; an empty pick follows none.
    Follow { worlds: BTreeSet<EntityId> },
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
            Self::SyncPredicted { .. } => "sync_predicted",
            Self::Predicted { .. } => "predicted",
            Self::Follow { .. } => "follow",
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

/// Whether `window` is a window key's shape: the full parse is the engine's.
fn window_key_shaped(window: &str) -> bool {
    !window.is_empty()
        && window.len() <= RESIDENCE_WINDOW_KEY_MAX
        && !window.contains(char::is_control)
}

impl ResidenceDirective {
    pub fn validate(&self) -> Result<()> {
        let valid = match &self.act {
            ResidenceAct::Open { window, .. } => window_key_shaped(window),
            ResidenceAct::Follow { worlds } => worlds.len() <= RESIDENCE_FOLLOW_WORLDS_MAX,
            ResidenceAct::SyncAll
            | ResidenceAct::SyncOpened
            | ResidenceAct::SyncPredicted { .. }
            | ResidenceAct::Predicted { .. }
            | ResidenceAct::Index
            | ResidenceAct::Prune { .. } => true,
        };
        if !valid {
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
    /// The directive's signed entry: one of this entry's parents, or beneath
    /// them (FIX 5412).
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

    /// Signed alone by an Ed25519 install key. Its directive's entry is a
    /// parent or beneath one, so a result never precedes what it answers:
    /// the fold judges which (FIX 5412), from the parent state's valid
    /// directives where the entry is no parent.
    pub(super) fn validate_entry(&self, entry: &AuthorityLogEntry) -> Result<()> {
        if entry.signer.suite != AuthoritySignatureSuite::Ed25519 || !entry.cosigns.is_empty() {
            return Err(invalid_authority());
        }
        Ok(())
    }
}

/// Canonical field order: kind, id, machine, owner, issued_at, act, then the
/// act's own fields (an open's window and item; a prune's before; a follow's
/// worlds, in ascending order; a sync-predicted's window and document
/// budgets; a prediction's parent, set digest, window count and document
/// count).
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
        ResidenceAct::Follow { worlds } => {
            entries.push((
                Value::from("worlds"),
                Value::Array(
                    worlds
                        .iter()
                        .map(|world| Value::from(world.to_hex()))
                        .collect(),
                ),
            ));
        }
        ResidenceAct::SyncPredicted {
            window_budget,
            document_budget,
        } => {
            entries.push((Value::from("window_budget"), Value::from(*window_budget)));
            entries.push((
                Value::from("document_budget"),
                Value::from(*document_budget),
            ));
        }
        ResidenceAct::Predicted {
            parent,
            set_digest,
            window_count,
            document_count,
        } => {
            entries.push((Value::from("parent"), Value::from(parent.to_hex())));
            entries.push((Value::from("set_digest"), binary_value(*set_digest)));
            entries.push((Value::from("window_count"), Value::from(*window_count)));
            entries.push((Value::from("document_count"), Value::from(*document_count)));
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
        "follow" => keys.push("worlds"),
        "sync_predicted" => keys.extend(["window_budget", "document_budget"]),
        "predicted" => keys.extend(["parent", "set_digest", "window_count", "document_count"]),
        _ => {}
    }
    validate_keys(entries, &keys)?;
    let id = |name: &str| super::machine_profile::decode_canonical_id(required(entries, name)?);
    let number = |name: &str| {
        required(entries, name)?
            .as_u64()
            .ok_or_else(invalid_authority)
    };
    let count = |name: &str| u32::try_from(number(name)?).map_err(|_| invalid_authority());
    let act = match act {
        "sync_all" => ResidenceAct::SyncAll,
        "sync_opened" => ResidenceAct::SyncOpened,
        "sync_predicted" => ResidenceAct::SyncPredicted {
            window_budget: count("window_budget")?,
            document_budget: count("document_budget")?,
        },
        "predicted" => ResidenceAct::Predicted {
            parent: id("parent")?,
            set_digest: decode_hash(required(entries, "set_digest")?)?,
            window_count: count("window_count")?,
            document_count: count("document_count")?,
        },
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
        "follow" => ResidenceAct::Follow {
            worlds: decode_ascending_ids(required(entries, "worlds")?)?,
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

/// The windows and entity documents one prediction names (ARCH-0023b
/// #predicted-residence): the body a [`ResidenceAct::Predicted`] names by
/// digest. The home keeps it and serves it to the machine the prediction
/// names; no other replica stores it.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PredictedResidenceSet {
    /// Window keys, as the open act names one.
    pub windows: BTreeSet<String>,
    /// Entities whose entity documents the machine should hold.
    pub documents: BTreeSet<EntityId>,
}

impl PredictedResidenceSet {
    /// The canonical body: a map of `windows` then `documents`, each in
    /// ascending order (documents as canonical ids), so one set has one
    /// body. Refused when a window key is not a window key's shape.
    pub fn encode(&self) -> Result<Vec<u8>> {
        if !self.windows.iter().all(|window| window_key_shaped(window)) {
            return Err(invalid_authority());
        }
        let windows = self
            .windows
            .iter()
            .map(|window| Value::from(window.as_str()))
            .collect();
        let documents = self
            .documents
            .iter()
            .map(|document| Value::from(document.to_hex()))
            .collect();
        encode_value(&Value::Map(vec![
            (Value::from("windows"), Value::Array(windows)),
            (Value::from("documents"), Value::Array(documents)),
        ]))
    }

    /// The digest a prediction names for the canonical body `body`.
    pub fn body_digest(body: &[u8]) -> [u8; 32] {
        let mut hasher = blake3::Hasher::new_derive_key(PREDICTED_SET_CONTEXT);
        hasher.update(body);
        *hasher.finalize().as_bytes()
    }

    /// The digest of this set's canonical body.
    pub fn digest(&self) -> Result<[u8; 32]> {
        Ok(Self::body_digest(&self.encode()?))
    }

    /// How many windows and entity documents the set names, as a
    /// prediction counts them; `None` past `u32`.
    pub fn counts(&self) -> Option<(u32, u32)> {
        Some((
            u32::try_from(self.windows.len()).ok()?,
            u32::try_from(self.documents.len()).ok()?,
        ))
    }

    /// The set a fetched `body` holds. Refused unless the body's digest is
    /// `digest` and it is the canonical body of the set it decodes to.
    pub fn decode_verified(body: &[u8], digest: &[u8; 32]) -> Result<Self> {
        if Self::body_digest(body) != *digest {
            return Err(invalid_authority());
        }
        let Value::Map(entries) =
            rmpv::decode::read_value(&mut &body[..]).map_err(|_| invalid_authority())?
        else {
            return Err(invalid_authority());
        };
        validate_keys(&entries, &["windows", "documents"])?;
        let Value::Array(windows) = required(&entries, "windows")? else {
            return Err(invalid_authority());
        };
        let set = Self {
            windows: windows
                .iter()
                .map(|value| {
                    value
                        .as_str()
                        .map(str::to_owned)
                        .ok_or_else(invalid_authority)
                })
                .collect::<Result<_>>()?,
            documents: decode_ascending_ids(required(&entries, "documents")?)?,
        };
        if set.encode()? != body {
            return Err(invalid_authority());
        }
        Ok(set)
    }
}

/// A follow act's worlds, or a predicted set's documents: canonical ids in
/// strictly ascending order, so one pick has one encoding.
fn decode_ascending_ids(value: &Value) -> Result<BTreeSet<EntityId>> {
    let Value::Array(values) = value else {
        return Err(invalid_authority());
    };
    let worlds = values
        .iter()
        .map(super::machine_profile::decode_canonical_id)
        .collect::<Result<Vec<_>>>()?;
    if !worlds.windows(2).all(|pair| pair[0] < pair[1]) {
        return Err(invalid_authority());
    }
    Ok(worlds.into_iter().collect())
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
