//! The receiving half of the AgentPack another party shared (OF-491, FIX
//! 2041 and 3168). An active install of a travelling pack mints its agent
//! here, in the install's own writer: the World its scope names binds to the
//! world the owner picked, else the one local world of that name; the
//! definition is the inert imported one the projection gives; its skills
//! already went through the common skill door with the rest of the pack; and
//! each piece of selected knowledge becomes a local claim about the new
//! agent. A World scope that binds nowhere holds the install as a Candidate
//! until the owner picks the world or creates it
//! ([`Vault::place_pack_agent_world`]). A Candidate mints nothing. A native
//! pack is the owner's backup, restored by the archive importer, not here.
use super::admission::{PACK_CANDIDATE, PackCommit};
use super::{
    HookAuthor, PackCandidateReason, PackFitVerdict, PackInstallDisposition, PackSource, invalid,
};
use crate::claim::{
    ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus, ClaimSource, ClaimSubject,
};
use crate::entity_id::{EntityId, derived_domains::AGENT_PACK_TRAVEL};
use crate::error::Result;
use crate::ports::EntityStoreRead;
use crate::share_travel::AgentPackTravelProjection;
use crate::share_travel::agent_pack::AgentPackScope;
use crate::{TimeRange, Vault};

/// The confidence a received agent's knowledge lands at: the pack carries
/// none, and an imported definition's own is this.
const TRAVEL_KNOWLEDGE_CONFIDENCE: f32 = 0.5;

/// A travelling pack's agent, as this vault would place it.
pub(super) struct TravelAgent {
    projection: AgentPackTravelProjection,
    /// The local world a World scope binds to: the owner's pick, else the
    /// one live local world of its name. `None` for a base or all scope.
    world: Option<EntityId>,
}

impl TravelAgent {
    /// A World scope with no local world to run in: the install waits.
    pub(super) fn needs_world(&self) -> bool {
        matches!(self.projection.policy.scope, AgentPackScope::World { .. }) && self.world.is_none()
    }
}

impl Vault {
    /// The agent `source` carries when it is a travelling AgentPack, with the
    /// world its scope binds to on this snapshot; `picked` is the owner's.
    pub(super) fn travel_agent_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        source: &PackSource,
        picked: Option<EntityId>,
    ) -> Result<Option<TravelAgent>> {
        let Some(facets) = &source.manifest.agent_facets else {
            return Ok(None);
        };
        let Some(projection) = facets.travel(&source.files)? else {
            return Ok(None);
        };
        let world = match &projection.policy.scope {
            AgentPackScope::World { name } => match picked {
                Some(world) => Some(world),
                None => self.local_world_named_in_txn(txn, name)?,
            },
            AgentPackScope::All | AgentPackScope::Base => None,
        };
        Ok(Some(TravelAgent { projection, world }))
    }

    /// Mints the agent an active travelling pack carries, once per source:
    /// its id derives from the source's content hash, so reinstalling the
    /// same bytes finds the agent it minted and writes nothing, and a local
    /// edit is never overwritten. A changed source mints a new agent beside
    /// the old.
    pub(super) fn admit_travel_agent_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        source: &PackSource,
        travel: TravelAgent,
        at: u64,
    ) -> Result<EntityId> {
        let agent = EntityId::derive(
            AGENT_PACK_TRAVEL,
            &[b"agent", source.content_hash().as_bytes()],
        )?;
        if self.store.port_entity_record(&*txn, &agent)?.is_some() {
            return Ok(agent);
        }
        if travel.needs_world() {
            return Err(invalid("the agent's world names no single local world"));
        }
        let TravelAgent { projection, world } = travel;
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
        Ok(agent)
    }

    /// The owner's answer to a travelling AgentPack held for its world
    /// (OF-491): `world` is the live local world its agent runs in, or, when
    /// unset, the one its scope names, as the owner created it since. The
    /// install then completes in one writer, screened again, as the hub ask
    /// or the owner's put would have.
    pub fn place_pack_agent_world(
        &self,
        owner: &crate::consent::AuthenticatedOwner,
        source_id: EntityId,
        world: Option<EntityId>,
    ) -> Result<PackInstallDisposition> {
        let source = self
            .get_pack_source(&source_id)?
            .ok_or_else(|| invalid("pack source missing"))?;
        let candidate = self
            .candidate_pack(&source)?
            .ok_or_else(|| invalid("the pack is not a Candidate"))?;
        if candidate.candidate_reason != Some(PackCandidateReason::NeedsWorld) {
            return Err(invalid(
                "only a pack waiting on its agent's world takes one",
            ));
        }
        let hub = crate::skill_hub::HubRef::new(
            EntityId::from_hex(&candidate.hub_id)?,
            candidate.hub_ref.clone(),
            super::hub_pin(&candidate.pin_type, &candidate.pin_value)?,
        )?;
        self.with_write_txn_grouped(|txn| {
            owner.revalidate_in_txn(self, &*txn)?;
            if PACK_CANDIDATE
                .get(&self.store, &*txn, &candidate.content_hash)?
                .as_ref()
                != Some(&candidate)
            {
                return Err(invalid("the Candidate changed"));
            }
            if let Some(world) = world
                && !self.is_local_world_in_txn(&*txn, world)?
            {
                return Err(invalid("the picked world is not a live local world"));
            }
            let publisher = match self.hook_author_in_txn(&*txn, &candidate)? {
                HookAuthor::ForeignActor {
                    identity,
                    hub,
                    grant,
                    ..
                } => Some(crate::skill_hub::ForeignSkillPublisher {
                    identity,
                    hub,
                    grant_ref: grant,
                }),
                HookAuthor::Owner => None,
            };
            if let Some(publisher) = &publisher {
                self.check_publisher_in_txn(&*txn, publisher)?;
            }
            if let Some(reason) =
                self.screen_pack_in_txn(&*txn, &source, &[], &candidate.publisher)?
            {
                return Ok(PackInstallDisposition::Blocked { reason });
            }
            self.commit_pack_install_in_txn(
                txn,
                &source,
                &PackCommit {
                    source_id,
                    hub: &hub,
                    publisher: &candidate.publisher,
                    foreign: publisher.as_ref(),
                    verdict: PackFitVerdict {
                        fits: true,
                        rules_hit: false,
                        code_auto_install: true,
                    },
                    permissions: &candidate.permissions,
                    qualification: None,
                    world,
                },
            )
        })
    }
}
