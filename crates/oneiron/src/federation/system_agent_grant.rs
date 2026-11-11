//! The Steward grant a base agent holds by default (untangle 6.3; ARCH-0043's
//! Steward role, owner 9 Nov 2026; S63-RULED, lead 9 Nov 18:0x).
//!
//! The Dreamer is an ordinary actor: it reads and lands through one
//! revocable FEDERATION_GRANT, role and preset Steward, that the engine
//! stands as its default when the host opens the vault
//! ([`Vault::provision_system_agent_grants`]). That grant is the engine's
//! act, never the owner's: its receipt is an [`EngineDefaultGrant`] of the
//! class "engine default at vault creation", which the owner reads on first
//! open ([`Vault::engine_default_grants`]; lead 10 Nov 06:5x, S6C-PLACE-1 =
//! A). The owner narrows or revokes it as any Steward grant. The first mint copies the
//! vault's live policy rows one to one: the read row gives `read`; the two
//! landing rows (the Auto actor ceiling and the `Generated` permit) give
//! `derive` and `archive`, the pair the strength archive already judges as
//! one verdict (X02); all three give the whole Steward default (`read`,
//! `derive`, `archive`, `delete`). A vault whose owner had removed all three
//! gets a row with no verbs, the record of his opt-out. Either way the
//! engine never stands one again on its own: a later grant is the owner's
//! signed act ([`Vault::grant_dreamer_weave`]).
//!
//! The grant rows decide (ruling S63-P13-STATE = A, Engine 11 Nov; review of
//! #6913): a base agent's reach is the meet of every Steward grant row that
//! stands naming it ([`steward_reach_in`]). The rows are entity rows, so they
//! reach each of the owner's linked machines, and a home move carries them;
//! no table local to one node says which grant is in force. While no such
//! row stands, no host has stood the grant yet: the manifest rows that name
//! the agent stand, as before. Once one stands, the policy fold reads the
//! agent's reach from the rows and no longer from manifest rows that name
//! it ([`steward_rows_rewrite`]); the rows it yields are the ones the
//! manifest held. An opt-out is a standing row with no verbs: a whole
//! revoke, or a first mint over a policy the owner had emptied, leaves one,
//! and it holds on every machine the rows reach. A row another machine
//! stood before it saw the owner's act can only narrow the meet, never
//! widen it; the owner's next act revokes every row it sees.
//!
//! The agent's read keys are held to that reach and to its live MACHINE
//! binding ([`Vault::system_agent_reads_live_in`]), the live delegation an
//! ordinary agent's slip carries (census X04), and to the rows' data axes
//! ([`Vault::system_agent_read_scope_in`]; S67-READ-AXES = C): the fold's
//! read row carries them, and each row a key reads is judged against them.
//!
//! The Coach holds one too (untangle 6.6, S66-1/S66-2): `read` and the four
//! `engine.controls` classes, minted by the same host default with no rows
//! to copy. Its `read` gives one core-read row in the fold, beside its own
//! offer row, which stays; each `engine.controls` class lets it tune the
//! engine's knobs of that class ([`Vault::engine_control_allowed`]).

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
use crate::store::ManifestDbs;
use crate::{TimeRange, Vault};

mod narrowing;
pub(crate) use narrowing::erase_narrowing_actor_in_txn;
pub use narrowing::{
    SYSTEM_AGENT_GRANT_NARROWING_WARNING, SystemAgentGrantNarrowing, SystemAgentNarrowing,
    SystemFunction,
};

/// The receipt of every grant the engine stood by default, by the grant's
/// id.
const ENGINE_DEFAULT_GRANT: SideTable<EntityId, EngineDefaultGrant, Named> =
    SideTable::new(&side_table::FEDERATION_ENGINE_DEFAULT_GRANT);

/// Why the engine stood a grant on its own.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EngineDefaultOrigin {
    /// The engine's default at vault creation: a base agent's Steward grant,
    /// stood when a host first opened the vault.
    EngineDefaultAtVaultCreation,
}

/// The receipt of a grant the engine stood by default (lead 10 Nov 06:5x):
/// the engine's act, which no owner signed. The owner reads it on first
/// open and narrows or revokes the grant as any Steward grant.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EngineDefaultGrant {
    /// The agent the grant names.
    #[serde(with = "crate::serialize::entity_ref")]
    pub agent: EntityId,
    /// The verbs it held when the engine stood it.
    pub verbs: BTreeSet<String>,
    pub origin: EngineDefaultOrigin,
    pub created_at: u64,
}

/// Where a base agent's Steward grant stands on this vault, as its standing
/// rows give it ([`steward_reach_in`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SystemAgentGrantState {
    /// The engine or the owner stood a grant with verbs; `grant` is the
    /// newest standing row, and the agent's reach is the meet of them all.
    Minted { grant: EntityId },
    /// The owner opted out: he had removed every row the grant replaces
    /// before the first mint, or later revoked the grant whole through the
    /// narrowing door (its record says which). A row with no verbs stands as
    /// the record. The agent holds nothing until the owner grants it.
    OptedOut,
}

/// A base agent's reach, read from every Steward grant row that stands
/// naming it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct StewardReach {
    /// The newest standing row: the grant a receipt names, and the one the
    /// narrowing door's confirm binds.
    pub(crate) grant: EntityId,
    /// The verbs every standing row gives: empty for an opt-out.
    pub(crate) verbs: BTreeSet<String>,
    /// The meet of the standing rows' authority scopes: the data axes that
    /// bound each verb's records.
    pub(crate) scope: Scope,
}

impl StewardReach {
    /// The records the agent's read reaches (S67-READ-AXES = C, Engine 10
    /// Nov): the rows' scope met with the read preset. Its worlds, bands,
    /// audience and sensitivity bound the read as they bound each grant, and
    /// its one verb is `read`. `None` while the reach holds no `read`.
    pub(crate) fn read_scope(&self) -> Option<Scope> {
        self.verbs
            .contains(grant_scope::STEWARD_READ_VERB)
            .then(|| self.scope.meet(&super::scope_codec::read_preset()))
    }

    /// Whether the reach is already the default grant of `verbs`: every
    /// standing row gives exactly those verbs, and none narrows a data axis
    /// (review of #7057: the verbs alone decided, so a grant back left the
    /// narrower worlds, facets, record kinds, audience or sensitivity of a
    /// standing row in force).
    fn is_default_of(&self, verbs: &BTreeSet<String>) -> bool {
        let mut whole = grant_scope::membership_preset(FederationGrantRole::Steward);
        whole.verbs = self.scope.verbs.clone();
        self.verbs == *verbs && self.scope == whole
    }

    /// The state the rows give: opted out when no verb is left.
    pub(crate) fn state(&self) -> SystemAgentGrantState {
        if self.verbs.is_empty() {
            SystemAgentGrantState::OptedOut
        } else {
            SystemAgentGrantState::Minted { grant: self.grant }
        }
    }
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
    /// Dreamer; `read` and the four `engine.controls` classes for the Coach.
    fn default_verbs(self) -> BTreeSet<String> {
        let verbs: &[&str] = match self {
            Self::Dreamer => &grant_scope::STEWARD_VERBS,
            Self::Coach => &[
                grant_scope::STEWARD_READ_VERB,
                grant_scope::ENGINE_CONTROLS_MAINTENANCE_CADENCE_VERB,
                grant_scope::ENGINE_CONTROLS_WORK_BUDGET_VERB,
                grant_scope::ENGINE_CONTROLS_WAKE_CADENCE_VERB,
                grant_scope::ENGINE_CONTROLS_KNOWLEDGE_RECIPE_VERB,
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

/// Whether `row` is a base agent's Steward grant: role and preset Steward, an
/// access grant with no expiry, naming an agent whose reach such a grant
/// carries ([`holds_system_agent_grant`]). A person's Steward membership is
/// not one.
#[must_use]
pub(crate) fn is_system_agent_steward_grant(row: &FederationGrant) -> bool {
    row.role == FederationGrantRole::Steward
        && row.preset == FederationGrantPreset::Steward
        && row.kind == FederationGrantKind::Access
        && row.expires_at.is_none()
        && holds_system_agent_grant(row.member_ref)
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

/// TEST-ONLY: the Steward verbs the one grant `grant` gives `agent` in
/// `txn`: its explicit verb set while the row stands as a Steward grant
/// naming `agent`, else none (revoked, withdrawn, rewritten or never there).
/// The engine reads an agent's verbs from every standing row
/// ([`steward_reach_in`]), never from one.
#[cfg(any(test, oneiron_test_support))]
pub(crate) fn standing_steward_verbs_in(
    store: &impl crate::store::ManifestDbs,
    txn: &heed::RoTxn<'_>,
    grant: EntityId,
    agent: EntityId,
) -> Result<BTreeSet<String>> {
    Ok(standing_steward_grant_in(store, txn, grant, agent)?
        .map(|row| steward_verbs_of(&row))
        .unwrap_or_default())
}

/// The Steward verbs the row `row` gives: its explicit verb set, none for an
/// open or an empty one.
fn steward_verbs_of(row: &FederationGrant) -> BTreeSet<String> {
    match &row.authority_scope.verbs {
        ScopeAxis::Some(verbs) => verbs
            .iter()
            .filter(|verb| grant_scope::STEWARD_CEILING_VERBS.contains(&verb.as_str()))
            .cloned()
            .collect(),
        ScopeAxis::All | ScopeAxis::Bottom => BTreeSet::new(),
    }
}

/// Base agent `agent`'s reach in `txn`: the meet of every grant row that
/// stands as a Steward grant naming it ([`standing_steward_grant_in`]). The
/// verbs are those every row gives, and each data axis is the narrowest any
/// row holds, so a row can only narrow what the others give. `None` while
/// no such row stands: no host has stood the agent's grant on this vault,
/// and its manifest rows decide.
pub(crate) fn steward_reach_in(
    store: &impl ManifestDbs,
    txn: &heed::RoTxn<'_>,
    agent: EntityId,
) -> Result<Option<StewardReach>> {
    let mut newest: Option<EntityId> = None;
    let mut met: Option<(BTreeSet<String>, Scope)> = None;
    for id in store.port_entity_ids_by_type(txn, ENTITY_TYPE_FEDERATION_GRANT, None)? {
        let id = id?;
        let Some(row) = standing_steward_grant_in(store, txn, id, agent)? else {
            continue;
        };
        let verbs = steward_verbs_of(&row);
        met = Some(match met {
            None => (verbs, row.authority_scope),
            Some((held, scope)) => (
                held.intersection(&verbs).cloned().collect(),
                scope.meet(&row.authority_scope),
            ),
        });
        newest = newest.max(Some(id));
    }
    Ok(newest.zip(met).map(|(grant, (verbs, scope))| StewardReach {
        grant,
        verbs,
        scope,
    }))
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
    /// The scope its read row carries ([`StewardReach::read_scope`]):
    /// `None` for an opt-out or a reach without `read`.
    pub(crate) read_scope: Option<Scope>,
}

/// How the policy fold reads the base agents' rows in `txn`: one entry per
/// agent a Steward grant row stands for (an opt-out's row among them). An
/// agent with no standing row is absent, and its manifest rows stand, as
/// before.
pub(crate) fn steward_rows_rewrite(
    store: &impl crate::store::ManifestDbs,
    txn: &heed::RoTxn<'_>,
) -> Result<Vec<StewardRows>> {
    let mut rewrites = Vec::new();
    for agent in SystemAgent::ALL {
        let actor = agent.actor_id()?;
        let Some(reach) = steward_reach_in(store, txn, actor)? else {
            continue;
        };
        rewrites.push(StewardRows {
            agent,
            actor_ref: actor.to_hex(),
            read_scope: reach.read_scope(),
            verbs: reach.verbs,
        });
    }
    Ok(rewrites)
}

/// The Steward grant in force for a base agent in `txn`: `None` while no
/// row stands (the manifest rows decide), `Some(None)` for an opt-out, else
/// the newest standing row. The agent's reach is the meet of every standing
/// row ([`steward_reach_in`]), never this one row's alone.
pub(crate) fn steward_grant_of_in(
    store: &impl ManifestDbs,
    txn: &heed::RoTxn<'_>,
    agent: EntityId,
) -> Result<Option<Option<EntityId>>> {
    Ok(
        steward_reach_in(store, txn, agent)?.map(|reach| match reach.state() {
            SystemAgentGrantState::OptedOut => None,
            SystemAgentGrantState::Minted { grant } => Some(grant),
        }),
    )
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
    /// Where the base agent's Steward grant stands, as its rows give it;
    /// `None` while no row stands.
    pub(crate) fn system_agent_grant_state_in(
        &self,
        txn: &heed::RoTxn<'_>,
        agent: EntityId,
    ) -> Result<Option<SystemAgentGrantState>> {
        Ok(steward_reach_in(&self.store, txn, agent)?.map(|reach| reach.state()))
    }

    /// Whether a read key held to base agent `agent` reads in `txn`
    /// (untangle 6.3, census X04). While no grant row stands, yes: the
    /// manifest rows decide, as before. After, only while every standing row
    /// gives `read` and the agent's MACHINE binding is Active on a roster
    /// key that is not revoked.
    pub(crate) fn system_agent_reads_live_in(
        &self,
        txn: &heed::RoTxn<'_>,
        agent: EntityId,
    ) -> Result<bool> {
        let Some(reach) = steward_reach_in(&self.store, txn, agent)? else {
            return Ok(true);
        };
        if !reach.verbs.contains(grant_scope::STEWARD_READ_VERB) {
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
    /// `txn` (S67-READ-AXES = C): `None` while no grant row stands, when the
    /// manifest rows decide as before; else the read scope of its reach
    /// ([`StewardReach::read_scope`]), which admits nothing for an opt-out
    /// or a reach without `read`.
    pub(crate) fn system_agent_read_scope_in(
        &self,
        txn: &heed::RoTxn<'_>,
        agent: EntityId,
    ) -> Result<Option<Scope>> {
        Ok(steward_reach_in(&self.store, txn, agent)?
            .map(|reach| reach.read_scope().unwrap_or_default()))
    }

    /// The engine's default for every base agent whose reach a Steward grant
    /// carries (untangle 6.3, 6.6): once per vault and agent, the engine's
    /// own act with its [`EngineDefaultGrant`] receipt, never the owner's
    /// signed act (lead 10 Nov 06:5x). The Dreamer's first grant copies its
    /// live policy rows, or records the opt-out (a row with no verbs and no
    /// receipt) when the owner had removed them all; the Coach's holds
    /// `read` and the four `engine.controls` classes. An agent a grant row
    /// already stands for is left as it is, whichever machine stood the row:
    /// the engine never stands one again. Hosts call it after
    /// `provision_engine_machine_identities`.
    ///
    /// Nothing here stops a host from opening: a refusal is logged by kind,
    /// and the agent's rows still stand until a later open.
    ///
    /// # Errors
    ///
    /// A store failure reading the grant rows or resolving the Dreamer.
    pub fn provision_system_agent_grants(&self) -> Result<()> {
        // Both principals are seeded (immutable MACHINE rows) before a mint
        // names them.
        let dreamer = self.dreamer_authority()?.entity_ref();
        let coach = self.coach_authority()?.entity_ref();
        let unmarked: Vec<(SystemAgent, EntityId)> = {
            let txn = self.store.env.read_txn()?;
            let mut unmarked = Vec::new();
            for (agent, actor) in [(SystemAgent::Dreamer, dreamer), (SystemAgent::Coach, coach)] {
                if steward_reach_in(&self.store, &txn, actor)?.is_none() {
                    unmarked.push((agent, actor));
                }
            }
            unmarked
        };
        if unmarked.is_empty() {
            return Ok(());
        }
        for (agent, actor) in unmarked {
            let outcome = self.with_write_txn_grouped(|txn| {
                if steward_reach_in(&self.store, &*txn, actor)?.is_some() {
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
                if verbs.is_empty() {
                    // The owner had removed every row: the record of his
                    // opt-out, which grants nothing and so has no receipt.
                    self.put_steward_grant_row_in_txn(txn, actor, verbs, None)?;
                } else {
                    self.stand_engine_default_grant_in_txn(txn, actor, verbs)?;
                }
                Ok(())
            });
            match outcome {
                Ok(()) => {
                    // The fold's rows moved with the grant row: a floor
                    // this commit moved is judged again at once (FIX 5505).
                    self.apply_pending_rebinds_after_commit();
                }
                // The grant could not stand here: the agent's reach stays as
                // its rows give it.
                Err(error) => tracing::warn!(
                    agent = ?agent,
                    kind = ?error.kind(),
                    "a base agent's default Steward grant did not stand at this open; its policy rows stand"
                ),
            }
        }
        Ok(())
    }

    /// The owner's act (`oneiron dreamer grant`): the Dreamer holds the
    /// whole Steward default from now on. Mints it unless its standing rows
    /// already give every Steward verb with every data axis whole (`false`
    /// then). Every row that stands is revoked first, an opt-out's record
    /// among them, by the owner's signed act in the same writer, so the
    /// Dreamer holds one Steward grant.
    pub(crate) fn grant_dreamer_steward(&self, owner: &AuthenticatedOwner) -> Result<bool> {
        self.grant_system_agent_default(owner, SystemAgent::Dreamer)
    }

    /// The owner's act: the Coach holds its default grant (`read`,
    /// the four `engine.controls` classes) from now on, the way back after he narrowed or
    /// revoked it (6.6). `false` when its standing rows already give it with
    /// every data axis whole.
    ///
    /// # Errors
    ///
    /// An owner refusal; a store failure; `AuthorityRefused` when this
    /// install cannot carry the owner's act.
    pub fn grant_coach_steward(&self, owner: &AuthenticatedOwner) -> Result<bool> {
        self.grant_system_agent_default(owner, SystemAgent::Coach)
    }

    /// Mints `agent`'s default Steward grant as `owner`'s act unless its
    /// standing rows already give it ([`StewardReach::is_default_of`]): a
    /// row that holds a narrower data axis is revoked with the rest, so the
    /// grant back restores the records as well as the verbs.
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
            if steward_reach_in(&self.store, &*txn, actor)?
                .is_some_and(|reach| reach.is_default_of(&full))
            {
                return Ok(false);
            }
            self.revoke_standing_steward_grants_in_txn(txn, owner, actor)?;
            self.mint_steward_grant_in_txn(txn, owner, actor, full.clone(), None)?;
            Ok(true)
        })?;
        if minted {
            self.apply_pending_rebinds_after_commit();
        }
        Ok(minted)
    }

    /// The owner's act (S66-1): `agent`, any agent principal that is not a
    /// base agent, may tune the engine's knobs of `classes` from now on.
    /// Mints it a Steward grant naming those classes' verbs alone, as
    /// `owner`'s signed act, and returns the grant. The Coach's own grant
    /// comes back through [`Self::grant_coach_steward`].
    ///
    /// # Errors
    ///
    /// `InvalidConfig` for a base agent or no class; an owner refusal; a
    /// store failure; `AuthorityRefused` when this install cannot carry the
    /// owner's act.
    pub fn grant_engine_controls(
        &self,
        owner: &AuthenticatedOwner,
        agent: EntityId,
        classes: &BTreeSet<super::EngineControlClass>,
    ) -> Result<EntityId> {
        if SystemAgent::of(agent).is_some() {
            return Err(crate::error::Error::InvalidConfig(
                "a base agent's grant is its default grant".into(),
            ));
        }
        if classes.is_empty() {
            return Err(crate::error::Error::InvalidConfig(
                "an engine.controls grant names at least one class".into(),
            ));
        }
        let grant = self.with_write_txn_grouped(|txn| {
            owner.revalidate_in_txn(self, &*txn)?;
            self.mint_steward_grant_in_txn(
                txn,
                owner,
                agent,
                classes
                    .iter()
                    .map(|class| class.grant_verb().to_owned())
                    .collect(),
                None,
            )
        })?;
        self.apply_pending_rebinds_after_commit();
        Ok(grant)
    }

    /// The owner's act: takes back every `engine.controls` grant he gave
    /// `agent` ([`Self::grant_engine_controls`]), by his signed revoke of
    /// each, and returns them. No membership door moves such a grant of a
    /// principal that is no Steward member, so this door is its way out. A
    /// base agent's grant is narrowed through its own door
    /// ([`Self::narrow_system_agent_grant`]).
    ///
    /// # Errors
    ///
    /// `InvalidConfig` for a base agent; an owner refusal; a store failure;
    /// `AuthorityRefused` when this install cannot carry the owner's act.
    pub fn revoke_engine_controls(
        &self,
        owner: &AuthenticatedOwner,
        agent: EntityId,
    ) -> Result<Vec<EntityId>> {
        if SystemAgent::of(agent).is_some() {
            return Err(crate::error::Error::InvalidConfig(
                "a base agent's grant is narrowed through its own door".into(),
            ));
        }
        let revoked = self.with_write_txn_grouped(|txn| {
            owner.revalidate_in_txn(self, &*txn)?;
            let mut grants = Vec::new();
            for grant in self.standing_steward_grants_of_in(txn, agent)? {
                if standing_steward_grant_in(&self.store, txn, grant, agent)?
                    .is_some_and(|row| super::is_engine_controls_grant(&row))
                {
                    grants.push(grant);
                }
            }
            for grant in &grants {
                self.revoke_steward_grant_in_txn(txn, owner, *grant)?;
            }
            Ok(grants)
        })?;
        if !revoked.is_empty() {
            self.apply_pending_rebinds_after_commit();
        }
        Ok(revoked)
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

    /// Every grant row that stands in `txn` as a Steward grant naming
    /// `agent` ([`standing_steward_grant_in`]), a base agent's opt-out record
    /// among them.
    pub(crate) fn standing_steward_grants_of_in(
        &self,
        txn: &heed::RoTxn<'_>,
        agent: EntityId,
    ) -> Result<Vec<EntityId>> {
        let mut standing = Vec::new();
        for id in self
            .store
            .port_entity_ids_by_type(txn, ENTITY_TYPE_FEDERATION_GRANT, None)?
        {
            let id = id?;
            if standing_steward_grant_in(&self.store, txn, id, agent)?.is_some() {
                standing.push(id);
            }
        }
        Ok(standing)
    }

    /// Revokes every Steward grant of base agent `agent` that stands, as
    /// `owner`'s signed act, in the caller's writer: the revoke and the row
    /// delete land together (review of #6913: a grant back left the grant it
    /// replaced standing, with no door to revoke it). Every row counts, one
    /// another machine stood among them, so the grant minted next is the one
    /// row that stands here. The revoked grants.
    pub(super) fn revoke_standing_steward_grants_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        owner: &AuthenticatedOwner,
        agent: EntityId,
    ) -> Result<Vec<EntityId>> {
        let standing = self.standing_steward_grants_of_in(txn, agent)?;
        for grant in &standing {
            self.revoke_steward_grant_in_txn(txn, owner, *grant)?;
        }
        Ok(standing)
    }

    /// Revokes the Steward grant row `grant` as `owner`'s signed act, in the
    /// caller's writer: the revoke and the row delete land together.
    fn revoke_steward_grant_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        owner: &AuthenticatedOwner,
        grant: EntityId,
    ) -> Result<()> {
        let acknowledged_topology =
            crate::identity_topology::acknowledged_grant_seals_in_txn(&self.store, txn, grant)
                .unwrap_or_default();
        self.append_agent_grant_act_in_txn(
            txn,
            owner,
            ActSurface::ThisInstall,
            AgentGrantAct::Revoke {
                grant,
                acknowledged_topology,
            },
        )?;
        self.delete_agent_grant_row_in_txn(txn, grant)
    }

    /// Mints `agent`'s Steward grant with `verbs` as `owner`'s signed act, in
    /// the caller's writer: the act and the FEDERATION_GRANT row land
    /// together, as the owner's agent grants do. The act signs the scope the
    /// row holds, its `data_axes` among it
    /// ([`Self::put_steward_grant_row_in_txn`]).
    fn mint_steward_grant_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        owner: &AuthenticatedOwner,
        agent: EntityId,
        verbs: BTreeSet<String>,
        data_axes: Option<&Scope>,
    ) -> Result<EntityId> {
        let (id, grant) = self.put_steward_grant_row_in_txn(txn, agent, verbs, data_axes)?;
        self.append_agent_grant_act_in_txn(
            txn,
            owner,
            ActSurface::ThisInstall,
            AgentGrantAct::Mint {
                grant: id,
                member: agent,
                scope: grant.authority_scope,
                expires_at: None,
                repo_bounds: None,
                grant_kind: FederationGrantKind::Access,
                git_push_bounds: None,
                verb_classes: BTreeSet::new(),
                wallet_ref: None,
                steward: true,
            },
        )?;
        Ok(id)
    }

    /// Stands `agent`'s Steward grant with `verbs` as the engine's default at
    /// vault creation, in the caller's writer: the FEDERATION_GRANT row and
    /// its [`EngineDefaultGrant`] receipt, and no owner act.
    fn stand_engine_default_grant_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        agent: EntityId,
        verbs: BTreeSet<String>,
    ) -> Result<EntityId> {
        let (id, _) = self.put_steward_grant_row_in_txn(txn, agent, verbs.clone(), None)?;
        let created_at = crate::ports::recorded_at_in_txn(&self.store, txn)?;
        ENGINE_DEFAULT_GRANT.put(
            &self.store,
            txn,
            &id,
            &EngineDefaultGrant {
                agent,
                verbs,
                origin: EngineDefaultOrigin::EngineDefaultAtVaultCreation,
                created_at,
            },
        )?;
        Ok(id)
    }

    /// Puts `agent`'s Steward grant row with `verbs` on this vault's root in
    /// the caller's writer, with no act. No verbs is the record of an
    /// opt-out: the row stands and gives nothing. `data_axes` is the scope
    /// whose worlds, facets, record kinds, audience and sensitivity the row
    /// holds: the reach of the rows it replaces, for the narrowing door
    /// (review of #7057: its row came with every axis whole, so taking a
    /// verb gave back the records a standing row had taken). `None` leaves
    /// each axis whole, as a default grant has it. Returns its id and body.
    fn put_steward_grant_row_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        agent: EntityId,
        verbs: BTreeSet<String>,
        data_axes: Option<&Scope>,
    ) -> Result<(EntityId, FederationGrant)> {
        let scope = self.steward_root_scope_in_txn(txn)?;
        let mut grant = FederationGrant::new(
            scope,
            agent,
            FederationGrantRole::Steward,
            FederationGrantPreset::Steward,
        );
        if let Some(data_axes) = data_axes {
            grant.authority_scope = data_axes.clone();
        }
        // An empty set is the bottom axis, never an open one.
        grant.authority_scope.verbs = verbs.into_iter().collect();
        // Encoding validates: no row stands, and nothing is signed, for a
        // grant that cannot stand.
        let data = encode_federation_grant_body(&grant)?;
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
        Ok((id, grant))
    }

    /// Every grant the engine stood by default, oldest first, with its
    /// receipt: what the owner is shown on first open (lead 10 Nov 06:5x).
    ///
    /// # Errors
    ///
    /// An owner refusal; a store failure.
    pub fn engine_default_grants(
        &self,
        owner: &AuthenticatedOwner,
    ) -> Result<Vec<(EntityId, EngineDefaultGrant)>> {
        let txn = self.store.env.read_txn()?;
        owner.revalidate_in_txn(self, &txn)?;
        let mut grants = ENGINE_DEFAULT_GRANT.scan(&self.store, &txn)?;
        grants.sort_by_key(|(id, receipt)| (receipt.created_at, *id));
        Ok(grants)
    }
}

#[cfg(any(test, oneiron_test_support))]
impl Vault {
    /// TEST-ONLY: stands `agent`'s Steward grant with `verbs` as the one
    /// row that stands, as a first mint leaves it, without the owner's
    /// signed act (a library fixture holds no machine profile to carry one).
    /// Every row that stood before is deleted first, so a later call
    /// replaces the earlier grant.
    pub(crate) fn stand_steward_grant_for_test(
        &self,
        agent: EntityId,
        verbs: &[&str],
    ) -> Result<EntityId> {
        self.with_write_txn_grouped(|txn| {
            for standing in self.standing_steward_grants_of_in(txn, agent)? {
                self.delete_agent_grant_row_in_txn(txn, standing)?;
            }
            let (id, _) = self.put_steward_grant_row_in_txn(
                txn,
                agent,
                verbs.iter().map(|verb| (*verb).to_owned()).collect(),
                None,
            )?;
            Ok(id)
        })
    }

    /// TEST-ONLY: leaves `agent` opted out, as a first mint over a policy
    /// with none of its rows leaves it: one standing row with no verbs.
    pub(crate) fn mark_steward_opt_out_for_test(&self, agent: EntityId) -> Result<()> {
        self.stand_steward_grant_for_test(agent, &[]).map(|_| ())
    }
}
