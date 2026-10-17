//! The receiving half of the AgentPack another party shared (OF-491, FIX
//! 2041 and 3168). An active install of a travelling pack mints its agent
//! here, in the install's own writer: the World its scope names binds to the
//! one local world of that name, or the install is refused; the definition
//! is the inert imported one the projection gives; its skills already went
//! through the common skill door with the rest of the pack; and each piece
//! of selected knowledge becomes a local claim about the new agent. A
//! Candidate mints nothing. A native pack is the owner's backup, restored by
//! the archive importer, not here.
use super::{PackSource, invalid};
use crate::claim::{
    ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus, ClaimSource, ClaimSubject,
};
use crate::entity_id::{EntityId, derived_domains::AGENT_PACK_TRAVEL};
use crate::error::Result;
use crate::ports::EntityStoreRead;
use crate::share_travel::agent_pack::AgentPackScope;
use crate::{TimeRange, Vault};

/// The confidence a received agent's knowledge lands at: the pack carries
/// none, and an imported definition's own is this.
const TRAVEL_KNOWLEDGE_CONFIDENCE: f32 = 0.5;

impl Vault {
    /// Mints the agent an active travelling pack carries, once per source:
    /// its id derives from the source's content hash, so reinstalling the
    /// same bytes finds the agent it minted and writes nothing, and a local
    /// edit is never overwritten. A changed source mints a new agent beside
    /// the old. `None` for a pack that is not a travelling agent.
    pub(super) fn admit_travel_agent_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        source: &PackSource,
        at: u64,
    ) -> Result<Option<EntityId>> {
        let Some(facets) = &source.manifest.agent_facets else {
            return Ok(None);
        };
        let Some(projection) = facets.travel(&source.files)? else {
            return Ok(None);
        };
        let agent = EntityId::derive(
            AGENT_PACK_TRAVEL,
            &[b"agent", source.content_hash().as_bytes()],
        )?;
        if self.store.port_entity_record(&*txn, &agent)?.is_some() {
            return Ok(Some(agent));
        }
        let world = match &projection.policy.scope {
            AgentPackScope::World { name } => Some(
                self.local_world_named_in_txn(&*txn, name)?
                    .ok_or_else(|| invalid("the agent's world names no single local world"))?,
            ),
            AgentPackScope::All | AgentPackScope::Base => None,
        };
        let occurred = TimeRange { start: at, end: at };
        self.put_agent_definition_in_txn(
            txn,
            &agent,
            &projection.to_definition(world)?,
            occurred,
            at,
        )?;
        for (index, row) in (0u32..).zip(&projection.knowledge) {
            let mut body = ClaimBody::new(
                row.predicate.clone(),
                ClaimSubject::Entity(agent),
                rmpv::Value::from(row.text.clone()),
                TRAVEL_KNOWLEDGE_CONFIDENCE,
                ClaimApprovalStatus::Proposed,
                ClaimLifecycleStatus::Active,
            )?;
            body.source = Some(ClaimSource::Imported);
            // What is known about the agent lives where it runs: its bound
            // world, else base.
            body.world = world;
            let id = EntityId::derive(
                AGENT_PACK_TRAVEL,
                &[b"knowledge", agent.as_bytes(), &index.to_be_bytes()],
            )?;
            self.put_claim_in_txn(txn, &id, &body, occurred, at)?;
        }
        Ok(Some(agent))
    }
}
