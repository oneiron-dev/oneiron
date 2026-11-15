//! The narrowing history a home move carries (STEWARD-NARROWING-RECEIPT-LOCAL;
//! Engine RULING ROW4-NARROWING-HISTORY = A, 13 Nov 21:09), as an adapter on
//! the home handoff carrier (`crate::sync::home_handoff`). The owner's signed
//! revokes and mints reach the owner's other machines; the record of each
//! narrowing the owner applied (the verbs before and after and the breaks
//! the owner confirmed) is this node's alone. A new home holds every record
//! the old home did.
//!
//! Each record travels as its facts (its recording second, the grants it
//! revoked and minted, the verbs and the confirmed breaks), which name no
//! actor, and two actor parts apart: the agent and the owner. A record lands
//! only when both parts opened here, so a record of an actor erased here or
//! wherever its key was retired drops at adoption, as the table's own actor
//! scrub drops it. An equal record here is a no-op; a different one under
//! the same key is a Conflict.

use std::collections::{BTreeMap, BTreeSet};

use heed::{RoTxn, RwTxn};
use serde::{Deserialize, Serialize};

use super::{SYSTEM_AGENT_NARROWING, SystemAgentNarrowing, SystemFunction};
use crate::Vault;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::side_table::{self, SideTableDecl};
use crate::sync::home_handoff::{
    ActorContent, HomeFence, HomeMove, HomeTable, Partitioned, TableAdopt,
};

/// Every narrowing record this node holds, as a home move carries it.
pub(crate) struct SystemAgentNarrowingRows;

/// One record's facts: everything but its agent and its owner.
#[derive(Serialize, Deserialize)]
pub(crate) struct NarrowingFacts {
    /// The recording second, the key's second part.
    at: u64,
    /// The grant the narrowing revoked, the key's third part.
    #[serde(with = "crate::serialize::entity_ref")]
    revoked: EntityId,
    /// The narrower grant it minted; none for a whole revoke.
    #[serde(default, with = "crate::serialize::entity_ref::optional")]
    minted: Option<EntityId>,
    before: BTreeSet<String>,
    after: BTreeSet<String>,
    confirmed: Vec<SystemFunction>,
}

/// Which of a record's two actors a part names.
#[derive(Serialize, Deserialize)]
pub(crate) enum NarrowingActor {
    /// The base agent whose grant was narrowed, the key's first part.
    Agent,
    /// The owner who applied the narrowing.
    Owner,
}

/// One actor of the record at index `row` among the carried facts.
#[derive(Serialize, Deserialize)]
pub(crate) struct NarrowingActorPart {
    row: u32,
    kind: NarrowingActor,
    #[serde(with = "crate::serialize::entity_ref")]
    id: EntityId,
}

impl ActorContent for NarrowingActorPart {
    fn actor(&self) -> EntityId {
        self.id
    }
}

fn row_index(index: usize) -> Result<u32> {
    u32::try_from(index).map_err(|_| Error::InvalidConfig("too many narrowing records".into()))
}

impl HomeTable for SystemAgentNarrowingRows {
    type Rows = Vec<NarrowingFacts>;
    type Actor = NarrowingActorPart;
    const TABLE: &'static SideTableDecl = &side_table::FEDERATION_SYSTEM_AGENT_NARROWING;
    const SCHEMA_VERSION: u16 = 1;

    /// A record lands in the writer of the owner's narrowing that it
    /// records: none is in flight.
    fn quiescent(_vault: &Vault, _txn: &RoTxn<'_>, _movement: &HomeMove) -> Result<bool> {
        Ok(true)
    }

    fn export(
        vault: &Vault,
        txn: &RoTxn<'_>,
        _fence: &HomeFence,
    ) -> Result<Partitioned<Self::Rows, Self::Actor>> {
        let mut facts = Vec::new();
        let mut actors = Vec::new();
        for (index, ((agent, at, revoked), record)) in SYSTEM_AGENT_NARROWING
            .scan(&vault.store, txn)?
            .into_iter()
            .enumerate()
        {
            let row = row_index(index)?;
            facts.push(NarrowingFacts {
                at,
                revoked,
                minted: record.minted,
                before: record.before,
                after: record.after,
                confirmed: record.confirmed,
            });
            actors.push(NarrowingActorPart {
                row,
                kind: NarrowingActor::Agent,
                id: agent,
            });
            actors.push(NarrowingActorPart {
                row,
                kind: NarrowingActor::Owner,
                id: record.owner,
            });
        }
        Ok(Partitioned { facts, actors })
    }

    /// Lands each carried record both of whose actor parts opened here,
    /// unless an equal record stands; a different record under its key is a
    /// Conflict.
    fn adopt(
        vault: &Vault,
        txn: &mut RwTxn<'_>,
        _fence: &HomeFence,
        rows: Partitioned<Self::Rows, Self::Actor>,
    ) -> Result<TableAdopt> {
        let mut agents = BTreeMap::new();
        let mut owners = BTreeMap::new();
        for part in rows.actors {
            match part.kind {
                NarrowingActor::Agent => agents.insert(part.row, part.id),
                NarrowingActor::Owner => owners.insert(part.row, part.id),
            };
        }
        for (index, facts) in rows.facts.into_iter().enumerate() {
            let row = row_index(index)?;
            let (Some(agent), Some(owner)) = (agents.remove(&row), owners.remove(&row)) else {
                continue;
            };
            let key = (agent, facts.at, facts.revoked);
            let record = SystemAgentNarrowing {
                owner,
                revoked: facts.revoked,
                minted: facts.minted,
                before: facts.before,
                after: facts.after,
                confirmed: facts.confirmed,
            };
            match SYSTEM_AGENT_NARROWING.get(&vault.store, txn, &key)? {
                Some(held) if held == record => {}
                Some(_) => return Ok(TableAdopt::Conflict),
                None => SYSTEM_AGENT_NARROWING.put(&vault.store, txn, &key, &record)?,
            }
        }
        Ok(TableAdopt::Applied)
    }

    fn live_keys(vault: &Vault, txn: &RoTxn<'_>) -> Result<Vec<Vec<u8>>> {
        Ok(SYSTEM_AGENT_NARROWING
            .scan_keys(&vault.store, txn, &[])?
            .iter()
            .map(|key| SYSTEM_AGENT_NARROWING.key_bytes(key))
            .collect())
    }
}
