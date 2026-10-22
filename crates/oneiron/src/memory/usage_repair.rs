//! The authority seam of a host's usage repair (FIX 6476). A server lists
//! the stored usage events of its own metering scope that no longer decode,
//! and removes one its caller reviewed, by the hash of its bytes. Those rows
//! live in the host's side tables under the server's codec; this module
//! holds their wire shapes and the one writer the server's work runs in,
//! which admits its caller there first: a live owner of this vault by his
//! own proof, or an agent by its own live Grant from a live owner that names
//! the verb. The right to list never admits a removal, and a host's
//! operator root alone acts as nobody (FIX 2222).

use serde::{Deserialize, Serialize};

use crate::authority::{
    ActSurface, NoStanding, PACT_STANDING_LAPSED, principal_standing_or_lapse_in_txn,
};
use crate::consent::AuthenticatedOwner;
use crate::memory::{MEMORY_CODE_FORBIDDEN, Memory, MemoryError, MemoryResult};
use crate::{EdgeActorClass, EntityId};

/// `vault.usage.events.undecodable`'s input: none. The server lists its own
/// metering scope, never one a caller names.
#[derive(Debug, Clone, Default, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct UsageRepairListRequest {}

/// Why a stored usage event is listed: it does not decode. It names no part
/// of the bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum UndecodableUsageReason {
    StoredEventDecodeFailed,
}

/// One stored usage event of the metering scope that does not decode, as its
/// reviewer sees it before removing it: where it is and what it hashes to,
/// none of its bytes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct UndecodableUsageRow {
    /// The row's opaque locator: its key past the scope's event prefix, as
    /// unpadded base64url.
    pub row_ref: String,
    /// How many bytes the row holds.
    pub byte_length: u64,
    /// BLAKE3 of the row's exact bytes, 64 lowercase hex digits.
    pub hash: String,
    pub decode_reason: UndecodableUsageReason,
}

/// `vault.usage.events.undecodable`'s answer: every stored usage event of the
/// metering scope that does not decode, in key order.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct UndecodableUsageList {
    pub events: Vec<UndecodableUsageRow>,
}

/// `vault.usage.events.remove_undecodable`'s input: one listed row, and the
/// hash its review read.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct UsageRepairRemoveRequest {
    /// The row's `rowRef` as the list gave it.
    pub row_ref: String,
    /// The row's `hash` as the list gave it: the removal changes nothing
    /// unless the row still holds exactly those bytes.
    pub expected_hash: String,
}

/// Why a repair removed a row.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum UsageRepairReason {
    UndecodableEventRemoved,
}

/// The authority a repair ran under: a live owner's own proof, by the
/// authentication it was bound to, or an agent's own Grant, each by its 32
/// hex id.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(tag = "kind", content = "ref", rename_all = "snake_case")]
pub enum UsageRepairAuthority {
    Owner(String),
    Grant(String),
}

/// Where the call reached this install, for the receipt alone: no admission
/// reads it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum UsageRepairSurface {
    ThisInstall,
    /// A linked machine of the vault, by its 32 hex id.
    LinkedDevice {
        machine: String,
    },
    HostedConsole,
}

impl From<ActSurface> for UsageRepairSurface {
    fn from(surface: ActSurface) -> Self {
        match surface {
            ActSurface::ThisInstall => Self::ThisInstall,
            ActSurface::LinkedDevice { machine } => Self::LinkedDevice {
                machine: machine.to_hex(),
            },
            ActSurface::HostedConsole => Self::HostedConsole,
        }
    }
}

/// `vault.usage.events.remove_undecodable`'s answer, kept in the same write
/// that removed the row: what was removed, from which scope, by whom, under
/// which authority, where and when. It holds none of the row's bytes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct UsageRepairReceipt {
    /// 32 hex.
    pub receipt_id: String,
    /// The billing owner of the metering scope, as the host bound it.
    pub owner: String,
    pub vault_id: String,
    pub row_ref: String,
    /// BLAKE3 of the removed bytes, 64 lowercase hex digits.
    pub hash: String,
    pub byte_length: u64,
    pub reason: UsageRepairReason,
    /// The caller, 32 hex.
    pub actor_ref: String,
    /// `human`, `agent` or `system`.
    pub actor_class: String,
    pub authority: UsageRepairAuthority,
    pub surface: UsageRepairSurface,
    /// The engine's time of the removal, in seconds.
    pub recorded_at: u64,
}

/// The two usage repair verbs, each its own right: a Grant that lists one
/// never admits the other.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UsageRepairVerb {
    List,
    Remove,
}

impl UsageRepairVerb {
    /// The verb's name, as a Grant lists it.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::List => "vault.usage.events.undecodable",
            Self::Remove => "vault.usage.events.remove_undecodable",
        }
    }
}

/// The caller a usage repair admitted, in the writer its work runs in.
#[derive(Debug, Clone)]
pub struct UsageRepairCaller {
    actor: EntityId,
    class: EdgeActorClass,
    authority: UsageRepairAuthority,
    at: u64,
}

impl UsageRepairCaller {
    #[must_use]
    pub const fn actor(&self) -> EntityId {
        self.actor
    }

    #[must_use]
    pub const fn class(&self) -> EdgeActorClass {
        self.class
    }

    #[must_use]
    pub const fn authority(&self) -> &UsageRepairAuthority {
        &self.authority
    }

    /// The engine's time in the admitting writer, in seconds.
    #[must_use]
    pub const fn at(&self) -> u64 {
        self.at
    }
}

impl Memory<'_> {
    /// Runs `act` in one writer, after admitting this handle's caller for
    /// `verb` in it. With `owner`, the caller's own proof, only that proof
    /// decides: revalidated there as a live owner of this vault (a co-owner
    /// too), and this handle's own human actor. Without one, the caller is
    /// this handle's agent, and one live Grant a live owner gave it must
    /// confer now and list `verb` by name; the credential it presented must
    /// still be live. `act` reads and writes the host's rows in that same
    /// writer, so what it removes is what its caller reviewed. A refusal
    /// runs nothing.
    pub fn with_usage_repair_txn<T>(
        &self,
        owner: Option<&AuthenticatedOwner>,
        verb: UsageRepairVerb,
        act: impl FnOnce(&mut heed::RwTxn<'_>, &UsageRepairCaller) -> MemoryResult<T>,
    ) -> MemoryResult<T> {
        self.vault()
            .write_txn_door(crate::store::Callback::Opaque, |txn| {
                let caller = self.usage_repair_caller_in_txn(txn, owner, verb)?;
                act(txn, &caller)
            })
    }

    /// [`Self::with_usage_repair_txn`]'s admission alone, in a snapshot of
    /// its own (FIX 7039): a door asks it before the row's verb hooks fire,
    /// so no hook fires on a call its writer would refuse. The writer
    /// admits the caller again when it acts.
    pub fn usage_repair_admits(
        &self,
        owner: Option<&AuthenticatedOwner>,
        verb: UsageRepairVerb,
    ) -> MemoryResult<()> {
        let txn = self
            .vault()
            .store
            .env
            .read_txn()
            .map_err(crate::Error::from)?;
        self.usage_repair_caller_in_txn(&txn, owner, verb).map(drop)
    }

    /// [`Self::with_usage_repair_txn`]'s admission, in its writer.
    fn usage_repair_caller_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        owner: Option<&AuthenticatedOwner>,
        verb: UsageRepairVerb,
    ) -> MemoryResult<UsageRepairCaller> {
        super::verify_actor_binding_in_txn(self.vault(), txn, self.actor(), self.actor_class())?;
        let authority = match owner {
            Some(owner) => {
                if owner.revalidate_in_txn(self.vault(), txn)? != self.actor()
                    || self.actor_class() != EdgeActorClass::Human
                {
                    return Err(refused(
                        verb,
                        "the owner proof does not belong to this caller",
                    ));
                }
                UsageRepairAuthority::Owner(owner.decision_id().to_hex())
            }
            None => {
                if let Some(slip) = self.presented_credential()
                    && !self.vault().capability_slip_is_live_in_txn(txn, slip)?
                {
                    return Err(refused(verb, "the caller's credential is no longer live"));
                }
                let standing = match self.actor_class() {
                    EdgeActorClass::Agent | EdgeActorClass::System => {
                        principal_standing_or_lapse_in_txn(
                            self.vault(),
                            txn,
                            self.actor(),
                            self.actor_class(),
                            verb.name(),
                        )?
                    }
                    EdgeActorClass::Human => Err(NoStanding::NotStanding),
                };
                let grant = match standing.map(|standing| standing.grant) {
                    Ok(Some(grant)) => grant,
                    Err(NoStanding::PactStandingLapsed) => {
                        return Err(refused(verb, PACT_STANDING_LAPSED));
                    }
                    Ok(None) | Err(NoStanding::NotStanding) => {
                        return Err(refused(
                            verb,
                            "no live Grant from a live owner names this agent and lists the verb",
                        ));
                    }
                };
                UsageRepairAuthority::Grant(grant.to_hex())
            }
        };
        Ok(UsageRepairCaller {
            actor: self.actor(),
            class: self.actor_class(),
            authority,
            at: self.vault().instant_in_txn(txn)?.secs(),
        })
    }
}

/// The repair's refusal of a caller it does not admit.
fn refused(verb: UsageRepairVerb, why: &str) -> MemoryError {
    MemoryError::new(
        MEMORY_CODE_FORBIDDEN,
        format!(
            "{} takes the vault owner's own proof or an agent's own Grant that names it: {why}",
            verb.name()
        ),
        &[
            "Call with your own owner credential, or have the owner grant this agent the verb by name.",
        ],
    )
}
