//! The owner's writer of one agent's world access (ARCH-0067 #tiers; census
//! L2-56; rulings L2-56-VERB-SHAPE = A and L2-56-CONFIRM = A, 14 Nov 2026).
//!
//! An agent reads the worlds its owner granted it (the ALLOWED-SET tier) and,
//! when a turn names none, its default among them (the DEFAULT-SUBSET tier).
//! Both are node-local claims about the agent (RULING L2-53-CEILING). The
//! owner alone sets them, through `vault.agents.worlds.set`, under the
//! owner's proof (H), and a change records the owner's act signed by this
//! install (K): ARCH-0082's bar for "Widen another's grant".
//!
//! The set replaces. The fold meets every grant in force, so a second grant
//! row could only narrow; the setter supersedes the grant in force and writes
//! one. An empty grant revokes: the agent then reads nothing, never base
//! reality. The owner may name a default too ("owner-set or agent-proposed",
//! ARCH-0067); the newest default wins, so the agent may still move its own
//! default inside the grant later. A grant that no longer covers the default
//! in force writes the default narrowed to it in the same commit, so the
//! owner's own act never fails the agent's reads closed. A set the rows in
//! force already state writes and records nothing. Naming a default where no
//! default row is in force writes one even when the agent's reads already
//! match: with no row, the default follows the grant (base reality while the
//! grant holds it), and the named one pins it.
//!
//! `vault.agents.worlds.get` answers the owner what the agent reads now.

use serde::{Deserialize, Serialize};

use crate::authority::ActSurface;
use crate::claim::world_access::{
    PREDICATE_WORLD_ACCESS_ALLOWED_SET, PREDICATE_WORLD_ACCESS_DEFAULT_SUBSET, WorldAuthoritySet,
    world_access_claim_body,
};
use crate::claim::{ClaimApprovalStatus, ClaimSource, base_world_id};
use crate::consent::AuthenticatedOwner;
use crate::edge::EdgeActorClass;
use crate::error::{Error, Result};
use crate::memory::{Memory, MemoryResult};
use crate::pipeline::{FoldedWorldAccess, WorldGrantIndex, folded_world_access};
use crate::policy_setting_doors::{PolicySetting, record_policy_setting_act_in_txn};
use crate::registry::ENTITY_TYPE_WORLD;
use crate::vault::{LiveEntityRow, live_entity_row_in_txn};
use crate::write_envelope::{WriteEnvelope, WriteProvenance, write_envelope_evidence};
use crate::{EntityId, TimeRange, Vault, WriteActor};

/// The read verb's name, as a refusal names it.
const GET_VERB: &str = "vault.agents.worlds.get";

/// The set verb's name, as a refusal names it.
const SET_VERB: &str = "vault.agents.worlds.set";

/// A set of worlds: base reality and world ids.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Worlds {
    /// Whether base reality is in the set.
    pub include_base: bool,
    /// The worlds besides base reality, 32 hex each, ascending.
    #[serde(default)]
    pub worlds: Vec<EntityId>,
}

impl From<&WorldAuthoritySet> for Worlds {
    fn from(set: &WorldAuthoritySet) -> Self {
        Self {
            include_base: set.include_base(),
            worlds: set.worlds().iter().copied().collect(),
        }
    }
}

/// `vault.agents.worlds.get`'s input.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AgentWorldAccessRequest {
    /// The agent, 32 hex.
    pub agent: EntityId,
}

/// `vault.agents.worlds.set`'s input.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AgentWorldAccessSetRequest {
    /// The agent, 32 hex: an agent definition, a base agent or a named agent.
    pub agent: EntityId,
    /// The worlds the agent may read at most. It replaces the grant in force;
    /// an empty set revokes, and the agent then reads nothing.
    pub allowed: Worlds,
    /// The worlds a turn reads when it names none, within `allowed`. Absent
    /// keeps the default in force, narrowed to `allowed` where it no longer
    /// fits.
    #[serde(default)]
    pub default_on: Option<Worlds>,
}

/// One agent's world access as it reads now: `vault.agents.worlds.get`'s
/// answer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct AgentWorldAccess {
    /// The agent, 32 hex.
    pub agent: EntityId,
    /// Whether an owner's grant governs the agent. An agent no grant was ever
    /// written about reads base reality only; a governed agent never falls
    /// back to it.
    pub governed: bool,
    /// The worlds the agent may read at most.
    pub allowed: Worlds,
    /// The worlds a turn reads when it names none.
    pub default_on: Worlds,
    /// The grant rows in force, 32 hex each.
    pub allowed_claims: Vec<EntityId>,
    /// The default row in force, if any.
    pub default_claim: Option<EntityId>,
}

/// `vault.agents.worlds.set`'s answer: the access as it reads after the
/// set, and whether the set changed it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct AgentWorldAccessChange {
    pub access: AgentWorldAccess,
    /// False when the rows in force already state the set: nothing was
    /// written and no act recorded. A named default where no default row is
    /// in force is a change, even when the agent's reads already match.
    pub changed: bool,
}

/// What the owner's act digests: the agent with its tiers. The tiers stay a
/// node-local claim; the act on the authority log carries only digests.
#[derive(Serialize)]
struct AgentWorldAccessDigest {
    agent: EntityId,
    governed: bool,
    allowed: Worlds,
    default_on: Option<Worlds>,
}

/// What one set writes: the grant where it changed, and the default where
/// the request names another one or the new grant no longer covers the one
/// in force. Neither: the set changes nothing.
struct WorldAccessWrite {
    grant: Option<WorldAuthoritySet>,
    default: Option<WorldAuthoritySet>,
}

impl WorldAccessWrite {
    /// The rows a set of `allowed`, and of `named_default` when the request
    /// names one, writes over `prior`, the tiers the agent's reads fold to.
    /// An agent no grant governs takes a grant row whatever it names: an
    /// empty one revokes its base reality.
    fn plan(
        governed: bool,
        prior: &FoldedWorldAccess,
        allowed: WorldAuthoritySet,
        named_default: Option<WorldAuthoritySet>,
    ) -> Self {
        let default = match named_default {
            Some(default_on) => (prior.default_claim_id.is_none()
                || prior.default_subset != default_on)
                .then_some(default_on),
            // The default in force no longer fits: narrowed in the same
            // commit, so the agent's reads never fail closed.
            None => (prior.default_claim_id.is_some()
                && !prior.default_subset.is_subset_of(&allowed))
            .then(|| prior.default_subset.meet(&allowed)),
        };
        let grant = (!governed || prior.allowed_set != allowed).then_some(allowed);
        Self { grant, default }
    }

    fn changes(&self) -> bool {
        self.grant.is_some() || self.default.is_some()
    }
}

impl Vault {
    /// `agent`'s world access as it reads now, under the owner's proof.
    ///
    /// # Errors
    ///
    /// A proof that no longer holds, an id that is not a live agent
    /// principal, stored tiers that fail closed, and storage errors.
    pub fn agent_world_access_as_owner(
        &self,
        owner: &AuthenticatedOwner,
        request: AgentWorldAccessRequest,
    ) -> Result<AgentWorldAccess> {
        {
            let txn = self.store.env.read_txn()?;
            owner.revalidate_in_txn(self, &txn)?;
            require_agent(self, &txn, request.agent)?;
        }
        self.agent_world_access(request.agent)
    }

    /// The owner sets `request.agent`'s world access. The owner is
    /// revalidated in the writer. A change supersedes the grant in force with
    /// one new grant row, writes a default row (superseding the defaults in
    /// force) where the request names another one or the new grant no longer
    /// covers the default in force, and records the owner's act, all in one
    /// commit, when `surface` names where the owner said so. A set the rows
    /// in force already state writes and records nothing.
    ///
    /// # Errors
    ///
    /// A proof that no longer holds, an id that is not a live agent
    /// principal, a listed id that is not a live WORLD or that names base
    /// reality, a default outside the grant, and storage errors.
    pub fn set_agent_world_access_as_owner(
        &self,
        owner: &AuthenticatedOwner,
        surface: Option<ActSurface>,
        request: AgentWorldAccessSetRequest,
    ) -> Result<AgentWorldAccessChange> {
        let agent = request.agent;
        let changed = self.with_write_txn_grouped(|txn| {
            let actor = owner.revalidate_in_txn(self, txn)?;
            require_agent(self, txn, agent)?;
            let allowed = world_set(self, txn, &request.allowed)?;
            let named_default = match &request.default_on {
                Some(default_on) => Some(world_set(self, txn, default_on)?),
                None => None,
            };
            if named_default
                .as_ref()
                .is_some_and(|default_on| !default_on.is_subset_of(&allowed))
            {
                return Err(Error::InvalidConfig(
                    "an agent's default worlds must lie within the worlds it is allowed".to_owned(),
                ));
            }
            let now = self.store.clock.now_recorded_at();
            let governed =
                WorldGrantIndex::read(&self.store, txn)?.governs(&self.store, txn, agent)?;
            // Planned over the rows the agent's reads admit, so a row the
            // authority fold quarantines never decides the plan; every row in
            // force closes, so none comes back when its quarantine lifts.
            let rtxn: &heed::RoTxn<'_> = txn;
            let fold = self.authority_fold_readonly_in_txn(rtxn)?;
            let prior = folded_world_access(&self.store, rtxn, &agent, now, &|id, body| {
                crate::authority::claim_causal_admitted(&self.store, rtxn, &fold, id, body)
            })?;
            let in_force = folded_world_access(&self.store, rtxn, &agent, now, &|_, _| Ok(true))?;
            let write = WorldAccessWrite::plan(governed, &prior, allowed, named_default);
            if !write.changes() {
                return Ok(false);
            }
            let owner_writer = WriteActor::new(actor, EdgeActorClass::Human);
            self.write_world_access_in_txn(txn, owner_writer, agent, &in_force, &write, now)?;
            let digest =
                |governed: bool, allowed: &WorldAuthoritySet, default_on| AgentWorldAccessDigest {
                    agent,
                    governed,
                    allowed: Worlds::from(allowed),
                    default_on,
                };
            let prior_default = prior
                .default_claim_id
                .map(|_| Worlds::from(&prior.default_subset));
            let new_default = write.default.as_ref().map(Worlds::from);
            let signed = record_policy_setting_act_in_txn(
                self,
                txn,
                PolicySetting::AgentWorldAccess,
                actor,
                surface,
                &digest(governed, &prior.allowed_set, prior_default.clone()),
                &digest(
                    true,
                    write.grant.as_ref().unwrap_or(&prior.allowed_set),
                    new_default.or(prior_default),
                ),
            )?;
            // The signed record goes last, best effort (FIX 4624).
            if let Some(act) = signed {
                self.record_policy_setting_op_in_txn(txn, act);
            }
            Ok(true)
        })?;
        Ok(AgentWorldAccessChange {
            access: self.agent_world_access(agent)?,
            changed,
        })
    }

    /// Writes `write`'s rows about `agent` as `owner_writer`: each new row
    /// supersedes every row of its tier in `in_force`.
    fn write_world_access_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        owner_writer: WriteActor,
        agent: EntityId,
        in_force: &FoldedWorldAccess,
        write: &WorldAccessWrite,
        now: u64,
    ) -> Result<()> {
        let tiers = [
            (
                PREDICATE_WORLD_ACCESS_ALLOWED_SET,
                write.grant.as_ref(),
                &in_force.allowed_claim_ids,
            ),
            (
                PREDICATE_WORLD_ACCESS_DEFAULT_SUBSET,
                write.default.as_ref(),
                &in_force.default_claim_ids,
            ),
        ];
        for (predicate, worlds, closing) in tiers {
            let Some(worlds) = worlds else {
                continue;
            };
            let row = self.put_owner_world_access_in_txn(
                txn,
                owner_writer,
                predicate,
                agent,
                worlds,
                now,
            )?;
            // The meet of grants could only narrow, so the grant in force
            // closes. The defaults in force close too: a default the agent
            // writes later is newer, and wins.
            for old in closing {
                self.supersede_claim_in_txn_as(txn, &row, old, now, Some(owner_writer))?;
            }
        }
        Ok(())
    }

    /// `agent`'s tiers as its reads resolve them now.
    fn agent_world_access(&self, agent: EntityId) -> Result<AgentWorldAccess> {
        let governed = {
            let txn = self.store.env.read_txn()?;
            WorldGrantIndex::read(&self.store, &txn)?.governs(&self.store, &txn, agent)?
        };
        let resolved = self.board_world_authority(Some(agent), None)?;
        Ok(AgentWorldAccess {
            agent,
            governed,
            allowed: Worlds::from(&resolved.allowed_set),
            default_on: Worlds::from(&resolved.active_set),
            allowed_claims: resolved.allowed_claim_ids,
            default_claim: resolved.default_claim_id,
        })
    }

    /// Writes the owner's row of one world-access tier about `agent`, learned
    /// `now` with no valid-time bounds, as an agent's own default is written,
    /// so a default the agent writes later outranks it: user-stated and
    /// approved, the owner's bar the fold reads. Its evidence names the owner
    /// as its writer, as an envelope stamps one, so a read that quarantines a
    /// revoked writer's rows can tell the owner's. Answers the new row's id.
    ///
    /// The row takes the reserved door, as the owner's default facet does:
    /// this door owns the decision, with the owner's proof revalidated in its
    /// writer and the owner's act signed in the same commit. The shipped
    /// manifest names no rule for either tier, so the public door would park
    /// an Approved row at the criticality floor.
    fn put_owner_world_access_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        owner_writer: WriteActor,
        predicate: &'static str,
        agent: EntityId,
        worlds: &WorldAuthoritySet,
        now: u64,
    ) -> Result<EntityId> {
        let id = self.store.clock.entity_id()?;
        let mut body = world_access_claim_body(
            predicate,
            agent,
            worlds,
            ClaimSource::UserStated,
            ClaimApprovalStatus::Approved,
            None,
            None,
        )?;
        let envelope = WriteEnvelope::new(
            owner_writer,
            ClaimSource::UserStated,
            WriteProvenance::new(rmpv::Value::from(SET_VERB))?,
            ClaimApprovalStatus::Approved,
        );
        body.evidence = Some(write_envelope_evidence(&envelope, None));
        self.put_reserved_claim_in_txn(
            txn,
            &id,
            &body,
            TimeRange {
                start: now,
                end: now,
            },
            now,
        )?;
        Ok(id)
    }
}

/// Refuses an id that is not a live agent principal of the vault.
fn require_agent(vault: &Vault, txn: &heed::RoTxn<'_>, agent: EntityId) -> Result<()> {
    if vault.is_agent_principal_in_txn(txn, agent)? {
        Ok(())
    } else {
        Err(Error::InvalidConfig(
            "world access names a live agent principal of this vault: an agent definition, a \
             base agent or a named agent"
                .to_owned(),
        ))
    }
}

/// The requested worlds as an authority set. Base reality is named by
/// `include_base`, never by its id, and every listed id is a live WORLD.
fn world_set(vault: &Vault, txn: &heed::RoTxn<'_>, worlds: &Worlds) -> Result<WorldAuthoritySet> {
    let base = base_world_id();
    for world in &worlds.worlds {
        if *world == base {
            return Err(Error::InvalidConfig(
                "base reality is named by include_base, not by its id".to_owned(),
            ));
        }
        if !matches!(
            live_entity_row_in_txn(&vault.store, txn, world)?,
            LiveEntityRow::Live {
                entity_type: ENTITY_TYPE_WORLD,
                ..
            }
        ) {
            return Err(Error::InvalidConfig(format!(
                "world access lists {}, which is not a live WORLD",
                world.to_hex()
            )));
        }
    }
    WorldAuthoritySet::new(worlds.include_base, worlds.worlds.iter().copied())
}

/// `vault.agents.worlds.get` on the embedded owner's handle.
///
/// # Errors
///
/// A handle that is not the vault owner's, and as
/// [`Vault::agent_world_access_as_owner`].
pub fn agent_world_access_embedded(
    memory: &Memory<'_>,
    input: AgentWorldAccessRequest,
) -> MemoryResult<AgentWorldAccess> {
    Ok(memory
        .vault()
        .agent_world_access_as_owner(&memory.embedded_owner(GET_VERB)?, input)?)
}

/// `vault.agents.worlds.set` on the embedded owner's handle. The owner's act
/// records this install as where the owner said so.
///
/// # Errors
///
/// A handle that is not the vault owner's, and as
/// [`Vault::set_agent_world_access_as_owner`].
pub fn set_agent_world_access_embedded(
    memory: &Memory<'_>,
    input: AgentWorldAccessSetRequest,
) -> MemoryResult<AgentWorldAccessChange> {
    Ok(memory.vault().set_agent_world_access_as_owner(
        &memory.embedded_owner(SET_VERB)?,
        Some(ActSurface::ThisInstall),
        input,
    )?)
}
