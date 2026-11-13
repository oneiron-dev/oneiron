//! The authority seam of a host's usage repair (FIX 6476). A server lists
//! the stored usage events and pending settlements of its own metering scope
//! that no longer decode, and removes one its caller reviewed, by the hash of
//! its bytes. A pending row is invalid by redelivery's same scope and codec
//! checks, not by whether delivery has finished. Those rows
//! live in the host's side tables under the server's codec; this module
//! holds their wire shapes and the one writer the server's work runs in,
//! which admits its caller there first: a live owner of this vault by his
//! own proof, or an agent by its own live Grant from a live owner that names
//! the verb. The right to list never admits a removal, and a host's
//! operator root alone acts as nobody (FIX 2222). The receipts each removal
//! kept are read under the same admission, by their own verb (FIX 7036).

use serde::{Deserialize, Serialize};

use crate::authority::{
    ActSurface, NoStanding, PACT_STANDING_LAPSED, principal_standing_or_lapse_in_txn,
};
use crate::consent::AuthenticatedOwner;
use crate::memory::{MEMORY_CODE_FORBIDDEN, Memory, MemoryError, MemoryResult};
use crate::{EdgeActorClass, EntityId};

#[doc(hidden)]
pub use oneiron_verb_wire::memory::usage_repair::{
    UndecodableUsageList, UndecodableUsageReason, UndecodableUsageRow, UsageRepairAuthority,
    UsageRepairListRequest, UsageRepairReason, UsageRepairReceipt, UsageRepairReceiptList,
    UsageRepairReceiptsRequest, UsageRepairRemoveRequest, UsageRepairSurface,
};

/// The usage repair verbs, each its own right: a Grant that lists one never
/// admits another.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UsageRepairVerb {
    List,
    Remove,
    /// The read of the receipts removals kept (FIX 7036).
    Receipts,
}

impl UsageRepairVerb {
    /// The verb's name, as a Grant lists it.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::List => "vault.usage.events.undecodable",
            Self::Remove => "vault.usage.events.remove_undecodable",
            Self::Receipts => "vault.usage.repair.receipts",
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
