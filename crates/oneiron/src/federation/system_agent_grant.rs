//! The Steward grant a base agent holds by default (untangle 6.3; ARCH-0043's
//! Steward role, owner 9 Nov 2026; S63-RULED, lead 9 Nov 18:0x).
//!
//! The Dreamer is an ordinary actor: it reads and lands through one
//! revocable FEDERATION_GRANT, role and preset Steward, that the host mints
//! as the embedded owner's signed act when it opens the vault
//! ([`Vault::provision_system_agent_grants`]). The first mint copies the
//! vault's live policy rows one to one: the read row gives `read`; the two
//! landing rows (the Auto actor ceiling and the `Generated` permit) give
//! `derive` and `archive`, the pair the strength archive already judges as
//! one verdict (X02); all three give the whole Steward default (`read`,
//! `derive`, `archive`, `delete`). A vault whose owner had removed all three
//! gets no grant, and its opt-out is recorded. Either way the host never
//! mints again on its own: a later grant is the owner's act
//! ([`Vault::grant_dreamer_weave`]).
//!
//! From the first mint on, the policy fold reads the agent's reach from the
//! grant this vault's marker names, and no longer from manifest rows that
//! name the agent ([`steward_rows_rewrite`]); the rows it yields are the ones
//! the manifest held. The agent's read keys are held to that grant and to
//! its live MACHINE binding ([`Vault::system_agent_reads_live_in`]), the
//! live delegation an ordinary agent's slip carries (census X04), and to the
//! grant's data axes ([`Vault::system_agent_read_scope_in`]; S67-READ-AXES =
//! C): the fold's read row carries them, and each row a key reads is judged
//! against them. A vault no host has opened keeps reading by its manifest
//! rows, as before.
//!
//! The Coach holds one too (untangle 6.6, S66-1/S66-2): `read` and
//! `engine.controls`, minted by the same host default with no rows to copy.
//! Its `read` gives one core-read row in the fold, beside its own offer row,
//! which stays; `engine.controls` lets it tune the engine's knobs
//! ([`Vault::engine_control_allowed`]).

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

use super::{
    FederationGrant, FederationGrantKind, FederationGrantPreset, FederationGrantRole,
    FederationGrantScope, Scope, ScopeAxis, decode_federation_grant_body,
    encode_federation_grant_body, grant_scope, own_device_residence_scope,
};
use crate::authority::{ActSurface, AgentGrantAct};
use crate::batch::{BatchOp, apply_ops};
use crate::consent::AuthenticatedOwner;
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::ports::EntityStoreRead;
use crate::registry::ENTITY_TYPE_FEDERATION_GRANT;
use crate::side_table::{self, Named, SideTable};
use crate::{TimeRange, Vault};

mod narrowing;
pub(crate) use narrowing::erase_narrowing_actor_in_txn;
pub use narrowing::{
    SYSTEM_AGENT_GRANT_NARROWING_WARNING, SystemAgentGrantNarrowing, SystemAgentNarrowing,
    SystemFunction,
};

/// Each base agent's Steward grant as the host's first mint left it, by the
/// agent's principal.
const SYSTEM_AGENT_GRANT: SideTable<EntityId, SystemAgentGrantState, Named> =
    SideTable::new(&side_table::FEDERATION_SYSTEM_AGENT_GRANT);

/// Where a base agent's Steward grant stands on this vault.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "state")]
pub(crate) enum SystemAgentGrantState {
    /// The host or the owner minted `grant`; the agent's reach is that
    /// grant's while it stands.
    Minted {
        #[serde(with = "crate::serialize::entity_ref")]
        grant: EntityId,
    },
    /// The owner opted out: he had removed every row the grant replaces
    /// before the first mint, or later revoked the grant whole through the
    /// narrowing door (its record says which). The agent holds nothing until
    /// the owner grants it.
    OptedOut,
}

/// A base agent whose reach a Steward grant carries once the host has
/// minted it: the Dreamer (6.3) and the Coach (6.6).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SystemAgent {
    Dreamer,
    Coach,
}

impl SystemAgent {
    /// Every base agent the host mints a Steward grant for.
    pub(crate) const ALL: [Self; 2] = [Self::Dreamer, Self::Coach];

    /// The agent's fixed principal.
    pub(crate) fn actor_id(self) -> Result<EntityId> {
        match self {
            Self::Dreamer => crate::dreamer_runner::authority::dreamer_actor_id(),
            Self::Coach => crate::dreamer_runner::authority::coach_actor_id(),
        }
    }

    /// The base agent `actor` is, if any.
    pub(crate) fn of(actor: EntityId) -> Option<Self> {
        Self::ALL
            .into_iter()
            .find(|agent| agent.actor_id().is_ok_and(|id| id == actor))
    }

    /// The vault functions its grant keeps running, for the narrowing
    /// warning.
    fn functions(self) -> &'static [SystemFunction] {
        match self {
            Self::Dreamer => &narrowing::DREAMER_FUNCTIONS,
            Self::Coach => &narrowing::COACH_FUNCTIONS,
        }
    }

    /// The verbs its default grant holds: the whole Steward default for the
    /// Dreamer; `read` and `engine.controls` for the Coach.
    fn default_verbs(self) -> BTreeSet<String> {
        let verbs: &[&str] = match self {
            Self::Dreamer => &grant_scope::STEWARD_VERBS,
            Self::Coach => &[
                grant_scope::STEWARD_READ_VERB,
                grant_scope::ENGINE_CONTROLS_VERB,
            ],
        };
        verbs.iter().map(|verb| (*verb).to_owned()).collect()
    }
}

/// Whether `actor` is a base agent whose reach a Steward grant carries once
/// the host has minted it.
#[must_use]
pub(crate) fn holds_system_agent_grant(actor: EntityId) -> bool {
    SystemAgent::of(actor).is_some()
}

/// The grant row `grant` while it stands in `txn` as a Steward grant naming
/// `agent` (role and preset Steward, an access grant with no expiry), else
/// `None`: revoked, withdrawn, rewritten or never there. Its authority scope
/// bounds the records the agent's verbs reach (untangle 6.7a).
pub(crate) fn standing_steward_grant_in(
    store: &impl crate::store::ManifestDbs,
    txn: &heed::RoTxn<'_>,
    grant: EntityId,
    agent: EntityId,
) -> Result<Option<FederationGrant>> {
    let Some(raw) = store.port_entity_record(txn, &grant)? else {
        return Ok(None);
    };
    if raw.entity_type != ENTITY_TYPE_FEDERATION_GRANT || raw.body.is_empty() {
        return Ok(None);
    }
    let Ok(row) = decode_federation_grant_body(&raw.body) else {
        return Ok(None);
    };
    Ok((row.role == FederationGrantRole::Steward
        && row.preset == FederationGrantPreset::Steward
        && row.member_ref == agent
        && row.kind == FederationGrantKind::Access
        && row.expires_at.is_none())
    .then_some(row))
}

/// The Steward verbs the grant `grant` gives `agent` in `txn`: its explicit
/// verb set while the row stands as a Steward grant naming `agent`, else
/// none (revoked, withdrawn, rewritten or never there). A Steward grant has
/// no expiry, so it stands until revoked.
pub(crate) fn standing_steward_verbs_in(
    store: &impl crate::store::ManifestDbs,
    txn: &heed::RoTxn<'_>,
    grant: EntityId,
    agent: EntityId,
) -> Result<BTreeSet<String>> {
    let Some(row) = standing_steward_grant_in(store, txn, grant, agent)? else {
        return Ok(BTreeSet::new());
    };
    Ok(match &row.authority_scope.verbs {
        ScopeAxis::Some(verbs) => verbs
            .iter()
            .filter(|verb| grant_scope::STEWARD_CEILING_VERBS.contains(&verb.as_str()))
            .cloned()
            .collect(),
        ScopeAxis::All | ScopeAxis::Bottom => BTreeSet::new(),
    })
}

/// The records `agent`'s read reaches through the grant `grant` in `txn`
/// (S67-READ-AXES = C, Engine 10 Nov): the standing grant's authority scope
/// met with the read preset. Its worlds, bands, audience and sensitivity
/// bound the read as they bound the grant, and its one verb is `read`.
/// `None` while the grant does not stand or does not name `read`. The host's
/// mint leaves every data axis whole; the owner narrows one with a Steward
/// holder override and a member-role change, which rewrite the marked row.
pub(crate) fn standing_steward_read_scope_in(
    store: &impl crate::store::ManifestDbs,
    txn: &heed::RoTxn<'_>,
    grant: EntityId,
    agent: EntityId,
) -> Result<Option<Scope>> {
    let Some(row) = standing_steward_grant_in(store, txn, grant, agent)? else {
        return Ok(None);
    };
    let reads = matches!(
        &row.authority_scope.verbs,
        ScopeAxis::Some(verbs) if verbs.contains(grant_scope::STEWARD_READ_VERB)
    );
    Ok(reads.then(|| row.authority_scope.meet(&super::scope_codec::read_preset())))
}

/// One base agent's rows as the policy fold reads them from its grant.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct StewardRows {
    pub(crate) agent: SystemAgent,
    /// The agent's principal, hex, as policy rows name it.
    pub(crate) actor_ref: String,
    /// The verbs its rows come from: empty for an opt-out or a grant that no
    /// longer stands.
    pub(crate) verbs: BTreeSet<String>,
    /// The scope its read row carries ([`standing_steward_read_scope_in`]):
    /// `None` for an opt-out or a grant that does not stand with `read`.
    pub(crate) read_scope: Option<Scope>,
}

/// How the policy fold reads the base agents' rows in `txn`: one entry per
/// agent a host has minted a grant for (or recorded the opt-out of). An
/// agent with no marker is absent, and its manifest rows stand, as before.
pub(crate) fn steward_rows_rewrite(
    store: &impl crate::store::ManifestDbs,
    txn: &heed::RoTxn<'_>,
) -> Result<Vec<StewardRows>> {
    let mut rewrites = Vec::new();
    for agent in SystemAgent::ALL {
        let actor = agent.actor_id()?;
        let (verbs, read_scope) = match SYSTEM_AGENT_GRANT.get(store, txn, &actor)? {
            None => continue,
            Some(SystemAgentGrantState::OptedOut) => (BTreeSet::new(), None),
            Some(SystemAgentGrantState::Minted { grant }) => (
                standing_steward_verbs_in(store, txn, grant, actor)?,
                standing_steward_read_scope_in(store, txn, grant, actor)?,
            ),
        };
        rewrites.push(StewardRows {
            agent,
            actor_ref: actor.to_hex(),
            verbs,
            read_scope,
        });
    }
    Ok(rewrites)
}

/// The Steward grant a base agent's marker names in `txn`: `None` with no
/// marker (the manifest rows stand), `Some(None)` for an opt-out, else the
/// grant's id (standing or not).
pub(crate) fn steward_grant_of_in(
    store: &impl crate::side_table::SideTableDbs,
    txn: &heed::RoTxn<'_>,
    agent: EntityId,
) -> Result<Option<Option<EntityId>>> {
    Ok(match SYSTEM_AGENT_GRANT.get(store, txn, &agent)? {
        None => None,
        Some(SystemAgentGrantState::OptedOut) => Some(None),
        Some(SystemAgentGrantState::Minted { grant }) => Some(Some(grant)),
    })
}

/// The verbs the first mint copies from the live rows: `read` for the read
/// row; `derive` and `archive` for the two landing rows together; the whole
/// Steward default when all three hold.
fn copied_verbs(reads: bool, lands: bool) -> BTreeSet<String> {
    let verbs: &[&str] = match (reads, lands) {
        (true, true) => &grant_scope::STEWARD_VERBS,
        (true, false) => &[grant_scope::STEWARD_READ_VERB],
        (false, true) => &[
            grant_scope::STEWARD_DERIVE_VERB,
            grant_scope::STEWARD_ARCHIVE_VERB,
        ],
        (false, false) => &[],
    };
    verbs.iter().map(|verb| (*verb).to_owned()).collect()
}

impl Vault {
    /// The base agent's Steward grant marker, if any.
    pub(crate) fn system_agent_grant_state_in(
        &self,
        txn: &heed::RoTxn<'_>,
        agent: EntityId,
    ) -> Result<Option<SystemAgentGrantState>> {
        SYSTEM_AGENT_GRANT.get(&self.store, txn, &agent)
    }

    /// Whether a read key held to base agent `agent` reads in `txn`
    /// (untangle 6.3, census X04). Before any mint, yes: the manifest rows
    /// decide, as before. After it, only while the grant the marker names
    /// stands with `read` and the agent's MACHINE binding is Active on a
    /// roster key that is not revoked.
    pub(crate) fn system_agent_reads_live_in(
        &self,
        txn: &heed::RoTxn<'_>,
        agent: EntityId,
    ) -> Result<bool> {
        let grant = match SYSTEM_AGENT_GRANT.get(&self.store, txn, &agent)? {
            None => return Ok(true),
            Some(SystemAgentGrantState::OptedOut) => return Ok(false),
            Some(SystemAgentGrantState::Minted { grant }) => grant,
        };
        if !standing_steward_verbs_in(&self.store, txn, grant, agent)?
            .contains(grant_scope::STEWARD_READ_VERB)
        {
            return Ok(false);
        }
        self.system_agent_binding_live_in(txn, agent)
    }

    /// Whether base agent `agent`'s MACHINE binding is Active on a roster
    /// key that is not revoked, in `txn`: the live delegation its grant is
    /// held to.
    pub(super) fn system_agent_binding_live_in(
        &self,
        txn: &heed::RoTxn<'_>,
        agent: EntityId,
    ) -> Result<bool> {
        let fold = self.authority_view_readonly_in_txn(txn)?;
        Ok(fold.actor_bindings.iter().any(|(key, binding)| {
            binding.actor_ref == agent
                && binding.status == crate::authority::ActorBindingStatus::Active
                && fold.roster.get(key).is_some_and(|device| !device.revoked)
        }))
    }

    /// The records a read key held to base agent `agent` reads inside in
    /// `txn` (S67-READ-AXES = C): `None` before any mint, when the manifest
    /// rows decide as before; else the read scope of the grant the marker
    /// names ([`standing_steward_read_scope_in`]), which admits nothing for
    /// an opt-out or a grant that no longer stands with `read`.
    pub(crate) fn system_agent_read_scope_in(
        &self,
        txn: &heed::RoTxn<'_>,
        agent: EntityId,
    ) -> Result<Option<Scope>> {
        Ok(match SYSTEM_AGENT_GRANT.get(&self.store, txn, &agent)? {
            None => None,
            Some(SystemAgentGrantState::OptedOut) => Some(Scope::default()),
            Some(SystemAgentGrantState::Minted { grant }) => Some(
                standing_steward_read_scope_in(&self.store, txn, grant, agent)?.unwrap_or_default(),
            ),
        })
    }

    /// The host's default for every base agent whose reach a Steward grant
    /// carries (untangle 6.3, 6.6): once per vault and agent, as the
    /// embedded owner's signed act. The Dreamer's first mint copies its live
    /// policy rows into its grant, or records the opt-out when the owner had
    /// removed them all; the Coach's holds `read` and `engine.controls`. An
    /// agent already marked is left as it is: the host never mints again.
    /// Hosts call it after `provision_engine_machine_identities`.
    ///
    /// A vault whose embedded owner cannot act here (no owner PERSON yet,
    /// not this vault's owner, or no machine profile to carry the act) is
    /// left unmarked, so its rows still stand; a later open tries again.
    /// Nothing here stops a host from opening: a refusal is logged by kind.
    ///
    /// # Errors
    ///
    /// A store failure reading the marker or resolving the Dreamer.
    pub fn provision_system_agent_grants(&self) -> Result<()> {
        // Both principals are seeded (immutable MACHINE rows) before a mint
        // names them.
        let dreamer = self.dreamer_authority()?.entity_ref();
        let coach = self.coach_authority()?.entity_ref();
        let unmarked: Vec<(SystemAgent, EntityId)> = {
            let txn = self.store.env.read_txn()?;
            let mut unmarked = Vec::new();
            for (agent, actor) in [(SystemAgent::Dreamer, dreamer), (SystemAgent::Coach, coach)] {
                if !SYSTEM_AGENT_GRANT.contains(&self.store, &txn, &actor)? {
                    unmarked.push((agent, actor));
                }
            }
            unmarked
        };
        if unmarked.is_empty() {
            return Ok(());
        }
        let Some(owner) = self.embedded_owner_proof()? else {
            return Ok(());
        };
        for (agent, actor) in unmarked {
            let outcome = self.with_write_txn_grouped(|txn| {
                if SYSTEM_AGENT_GRANT.contains(&self.store, &*txn, &actor)? {
                    return Ok(());
                }
                let verbs = match agent {
                    SystemAgent::Dreamer => {
                        let policy = crate::gate::resolve_policy_manifest(&self.store, &*txn)?;
                        let (reads, lands) =
                            crate::gate::dreamer_rows_held(&policy, &actor.to_hex())?;
                        copied_verbs(reads, lands)
                    }
                    SystemAgent::Coach => agent.default_verbs(),
                };
                let state = if verbs.is_empty() {
                    SystemAgentGrantState::OptedOut
                } else {
                    let grant = self.mint_steward_grant_in_txn(txn, &owner, actor, verbs)?;
                    SystemAgentGrantState::Minted { grant }
                };
                SYSTEM_AGENT_GRANT.put(&self.store, txn, &actor, &state)
            });
            match outcome {
                Ok(()) => {
                    // The fold's rows moved with the marker: a floor this
                    // commit moved is judged again at once (FIX 5505).
                    self.apply_pending_rebinds_after_commit();
                }
                // The embedded owner could not act here: the agent's reach
                // stays as its rows give it.
                Err(error) => tracing::warn!(
                    agent = ?agent,
                    kind = ?error.kind(),
                    "a base agent's Steward grant was not minted at this open; its policy rows stand"
                ),
            }
        }
        Ok(())
    }

    /// The owner's act (`oneiron dreamer grant`): the Dreamer holds the
    /// whole Steward default from now on. Mints it when no grant the marker
    /// names stands with every Steward verb, and marks it; `false` when one
    /// already does.
    pub(crate) fn grant_dreamer_steward(&self, owner: &AuthenticatedOwner) -> Result<bool> {
        self.grant_system_agent_default(owner, SystemAgent::Dreamer)
    }

    /// The owner's act: the Coach holds its default grant (`read`,
    /// `engine.controls`) from now on, the way back after he narrowed or
    /// revoked it (6.6). `false` when a grant the marker names already holds
    /// it.
    ///
    /// # Errors
    ///
    /// An owner refusal; a store failure; `AuthorityRefused` when this
    /// install cannot carry the owner's act.
    pub fn grant_coach_steward(&self, owner: &AuthenticatedOwner) -> Result<bool> {
        self.grant_system_agent_default(owner, SystemAgent::Coach)
    }

    /// Mints `agent`'s default Steward grant as `owner`'s act when no grant
    /// its marker names stands with every default verb, and marks it.
    fn grant_system_agent_default(
        &self,
        owner: &AuthenticatedOwner,
        agent: SystemAgent,
    ) -> Result<bool> {
        let actor = match agent {
            SystemAgent::Dreamer => self.dreamer_authority()?.entity_ref(),
            SystemAgent::Coach => self.coach_authority()?.entity_ref(),
        };
        let full = agent.default_verbs();
        let minted = self.with_write_txn_grouped(|txn| {
            owner.revalidate_in_txn(self, &*txn)?;
            if let Some(SystemAgentGrantState::Minted { grant }) =
                SYSTEM_AGENT_GRANT.get(&self.store, &*txn, &actor)?
                && standing_steward_verbs_in(&self.store, &*txn, grant, actor)? == full
            {
                return Ok(false);
            }
            let grant = self.mint_steward_grant_in_txn(txn, owner, actor, full.clone())?;
            SYSTEM_AGENT_GRANT.put(
                &self.store,
                txn,
                &actor,
                &SystemAgentGrantState::Minted { grant },
            )?;
            Ok(true)
        })?;
        if minted {
            self.apply_pending_rebinds_after_commit();
        }
        Ok(minted)
    }

    /// The owner's act (S66-1): `agent`, any agent principal that is not a
    /// base agent, may tune the engine's knobs from now on. Mints it a
    /// Steward grant naming `engine.controls` alone, as `owner`'s signed act,
    /// and returns the grant. The Coach's own grant comes back through
    /// [`Self::grant_coach_steward`].
    ///
    /// # Errors
    ///
    /// `InvalidConfig` for a base agent; an owner refusal; a store failure;
    /// `AuthorityRefused` when this install cannot carry the owner's act.
    pub fn grant_engine_controls(
        &self,
        owner: &AuthenticatedOwner,
        agent: EntityId,
    ) -> Result<EntityId> {
        if SystemAgent::of(agent).is_some() {
            return Err(crate::error::Error::InvalidConfig(
                "a base agent's grant is its default grant".into(),
            ));
        }
        let grant = self.with_write_txn_grouped(|txn| {
            owner.revalidate_in_txn(self, &*txn)?;
            self.mint_steward_grant_in_txn(
                txn,
                owner,
                agent,
                BTreeSet::from([grant_scope::ENGINE_CONTROLS_VERB.to_owned()]),
            )
        })?;
        self.apply_pending_rebinds_after_commit();
        Ok(grant)
    }

    /// The vault root a Steward grant on this vault names: the shared vault,
    /// else this install's own residence.
    pub(super) fn steward_root_scope_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
    ) -> Result<FederationGrantScope> {
        Ok(self
            .shared_vault_creation_in_txn(txn)?
            .map_or_else(own_device_residence_scope, |shared| {
                FederationGrantScope::vault(shared.vault_id)
            }))
    }

    /// Mints `agent`'s Steward grant with `verbs` as `owner`'s signed act, in
    /// the caller's writer: the act and the FEDERATION_GRANT row land
    /// together, as the owner's agent grants do.
    fn mint_steward_grant_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        owner: &AuthenticatedOwner,
        agent: EntityId,
        verbs: BTreeSet<String>,
    ) -> Result<EntityId> {
        let scope = self.steward_root_scope_in_txn(txn)?;
        let mut grant = FederationGrant::new(
            scope,
            agent,
            FederationGrantRole::Steward,
            FederationGrantPreset::Steward,
        );
        grant.authority_scope.verbs = ScopeAxis::Some(verbs);
        // Encoding validates: nothing is signed for a grant that cannot stand.
        let data = encode_federation_grant_body(&grant)?;
        let id = EntityId::now();
        let now = crate::ports::recorded_at_in_txn(&self.store, txn)?;
        self.append_agent_grant_act_in_txn(
            txn,
            owner,
            ActSurface::ThisInstall,
            AgentGrantAct::Mint {
                grant: id,
                member: agent,
                scope: grant.authority_scope.clone(),
                expires_at: None,
                repo_bounds: None,
                grant_kind: FederationGrantKind::Access,
                git_push_bounds: None,
                verb_classes: BTreeSet::new(),
                wallet_ref: None,
                steward: true,
            },
        )?;
        apply_ops(
            &self.store,
            &self.config,
            &self.analyzer,
            txn,
            vec![BatchOp::Put {
                id,
                entity_type: ENTITY_TYPE_FEDERATION_GRANT,
                occurred: TimeRange {
                    start: now,
                    end: now,
                },
                learned_at: now,
                row_version: None,
                data,
                allow_maintenance: true,
                allow_reserved_predicate: false,
                hub_sync_imported: false,
            }],
            self.text_index_trusted
                .load(std::sync::atomic::Ordering::Acquire),
            false,
            true,
        )?;
        // A base agent's grant keeps the vault working: narrowing it warns
        // and waits for the owner's confirm (6.3c).
        if let Some(system_agent) = SystemAgent::of(agent) {
            self.mark_system_critical_in_txn(txn, id, system_agent.functions())?;
        }
        Ok(id)
    }

    /// The embedded owner's proof on this install, when its owner PERSON
    /// stands and owns the vault; `None` otherwise (before the owner is
    /// seeded, for one).
    fn embedded_owner_proof(&self) -> Result<Option<AuthenticatedOwner>> {
        let owner = crate::vault::embedded_owner_actor_id()?;
        Ok(self
            .authenticate_owner(
                owner,
                &owner.to_hex(),
                true,
                crate::store::GateDecisionId::now(),
            )
            .ok())
    }
}

#[cfg(any(test, oneiron_test_support))]
impl Vault {
    /// TEST-ONLY: stands `agent`'s Steward grant with `verbs` and marks it,
    /// as a first mint leaves it, without the owner's signed act (a library
    /// fixture holds no machine profile to carry one). A later call stands a
    /// fresh grant and marks that one: the earlier one no longer counts.
    pub(crate) fn stand_steward_grant_for_test(
        &self,
        agent: EntityId,
        verbs: &[&str],
    ) -> Result<EntityId> {
        self.with_write_txn_grouped(|txn| {
            let scope = self
                .shared_vault_creation_in_txn(txn)?
                .map_or_else(own_device_residence_scope, |shared| {
                    FederationGrantScope::vault(shared.vault_id)
                });
            let mut grant = FederationGrant::new(
                scope,
                agent,
                FederationGrantRole::Steward,
                FederationGrantPreset::Steward,
            );
            grant.authority_scope.verbs =
                ScopeAxis::Some(verbs.iter().map(|verb| (*verb).to_owned()).collect());
            let id = EntityId::now();
            let now = crate::ports::recorded_at_in_txn(&self.store, txn)?;
            apply_ops(
                &self.store,
                &self.config,
                &self.analyzer,
                txn,
                vec![BatchOp::Put {
                    id,
                    entity_type: ENTITY_TYPE_FEDERATION_GRANT,
                    occurred: TimeRange {
                        start: now,
                        end: now,
                    },
                    learned_at: now,
                    row_version: None,
                    data: encode_federation_grant_body(&grant)?,
                    allow_maintenance: true,
                    allow_reserved_predicate: false,
                    hub_sync_imported: false,
                }],
                self.text_index_trusted
                    .load(std::sync::atomic::Ordering::Acquire),
                false,
                true,
            )?;
            SYSTEM_AGENT_GRANT.put(
                &self.store,
                txn,
                &agent,
                &SystemAgentGrantState::Minted { grant: id },
            )?;
            if let Some(system_agent) = SystemAgent::of(agent) {
                self.mark_system_critical_in_txn(txn, id, system_agent.functions())?;
            }
            Ok(id)
        })
    }

    /// TEST-ONLY: marks `agent` opted out, as a first mint over a policy
    /// with none of its rows leaves it.
    pub(crate) fn mark_steward_opt_out_for_test(&self, agent: EntityId) -> Result<()> {
        self.with_write_txn_grouped(|txn| {
            SYSTEM_AGENT_GRANT.put(&self.store, txn, &agent, &SystemAgentGrantState::OptedOut)
        })
    }
}
