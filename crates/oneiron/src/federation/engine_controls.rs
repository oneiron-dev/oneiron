//! The `engine.controls` grants (untangle 6.6; S66-MAP ruled A, Engine 9 Nov
//! 18:5x; one verb per class, lead 10 Nov 06:5x): four Steward verbs bound
//! the engine's tunable knobs, one per class of knob: maintenance cadence,
//! work budgets inside the owner's caps, system-agent wake cadence, and
//! which recipe a knowledge job runs. A holder changes a stored vault knob
//! of a class its grant names. The Coach holds all four by default, as
//! Steward; the owner can give any of them to any agent
//! ([`Vault::grant_engine_controls`]).
//!
//! Owner acts stay outside it: grant changes and widening, model swaps,
//! destructive erase, caps and billing, consent, home picks; and the five
//! knobs that mix work with consent (cleanup posture, action-mode policy,
//! excluded conversations, proactivity presentation, failure rules).
//! Host-config knobs stay host-owned.
//!
//! One check admits the owner or a live holder of the knob's class
//! ([`Vault::engine_control_allowed`]); every change through the door
//! ([`Vault::apply_engine_control`]) writes a receipt naming who made it.
//! The knob doors join one family at a time (6.6b); the verbs come after
//! slice 4.2.

use serde::{Deserialize, Serialize};

use super::system_agent_grant::{SystemAgent, steward_grant_of_in};
use super::{
    FederationGrantKind, FederationGrantPreset, FederationGrantRole, Scope, ScopeAxis,
    decode_federation_grant_body, grant_scope, standing_steward_verbs_in,
};
use crate::Vault;
use crate::consent::AuthenticatedOwner;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::ports::EntityStoreRead;
use crate::registry::ENTITY_TYPE_FEDERATION_GRANT;
use crate::side_table::{self, Named, SideTable};

/// Every engine-control change, by its id.
const ENGINE_CONTROL_CHANGE: SideTable<EntityId, EngineControlChange, Named> =
    SideTable::new(&side_table::FEDERATION_ENGINE_CONTROL_CHANGE);

/// The class of knob a change touches. Each class has its own grant verb
/// ([`Self::grant_verb`]); the class names the change in its receipt.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EngineControlClass {
    /// Maintenance schedules and cadences: compaction, cleanup, retention
    /// sweeps, consolidation and nightly passes, recall upkeep.
    MaintenanceCadence,
    /// Per-pass and per-job budgets, clamped to the owner's caps.
    WorkBudget,
    /// The system agents' wake cadence, quiet hours and trigger thresholds.
    WakeCadence,
    /// Which skill or recipe a knowledge job runs.
    KnowledgeRecipe,
}

impl EngineControlClass {
    /// Every class, in the order the grants list them.
    pub const ALL: [Self; 4] = [
        Self::MaintenanceCadence,
        Self::WorkBudget,
        Self::WakeCadence,
        Self::KnowledgeRecipe,
    ];

    /// The Steward verb a holder's grant names to change a knob of this
    /// class.
    #[must_use]
    pub const fn grant_verb(self) -> &'static str {
        match self {
            Self::MaintenanceCadence => grant_scope::ENGINE_CONTROLS_MAINTENANCE_CADENCE_VERB,
            Self::WorkBudget => grant_scope::ENGINE_CONTROLS_WORK_BUDGET_VERB,
            Self::WakeCadence => grant_scope::ENGINE_CONTROLS_WAKE_CADENCE_VERB,
            Self::KnowledgeRecipe => grant_scope::ENGINE_CONTROLS_KNOWLEDGE_RECIPE_VERB,
        }
    }
}

/// Who asks to change a knob: the owner, by proof, or an actor that may
/// hold an `engine.controls` class.
#[derive(Debug, Clone, Copy)]
pub enum EngineControlActor<'a> {
    Owner(&'a AuthenticatedOwner),
    Holder(EntityId),
}

/// One change made through the engine-control door: the receipt.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EngineControlChange {
    /// Who made it: the owner's PERSON or the holder's principal.
    #[serde(with = "crate::serialize::entity_ref")]
    pub by: EntityId,
    /// Whether `by` acted as the owner rather than as a holder.
    pub owner: bool,
    pub class: EngineControlClass,
    /// The knob, by its stored name.
    pub knob: String,
    /// The value it was set to, as the knob's door renders it.
    pub value: String,
    pub changed_at: u64,
}

impl Vault {
    /// Whether `actor` may change a knob of `class` now: the owner by a
    /// proof that still holds, or a live holder of that class's grant verb.
    ///
    /// # Errors
    ///
    /// A store failure. An owner proof that no longer holds is `false`.
    pub fn engine_control_allowed(
        &self,
        actor: EngineControlActor<'_>,
        class: EngineControlClass,
    ) -> Result<bool> {
        let txn = self.store.env.read_txn()?;
        Ok(self
            .engine_control_actor_in_txn(&txn, actor, class)?
            .is_some())
    }

    /// The actor [`Self::engine_control_allowed`] admits in `txn`, with
    /// whether it acts as the owner. Each class rides its own grant verb.
    /// - A base agent holds it through the grant its marker names, while
    ///   that grant stands with the class's verb and its MACHINE binding is
    ///   live.
    /// - Any other actor holds it through a live Steward grant on this
    ///   vault's root that names the class's verb itself: a grant whose
    ///   verbs are left open (an Owner's or an Admin's) does not count, so
    ///   only an owner's grant gives it.
    pub(crate) fn engine_control_actor_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        actor: EngineControlActor<'_>,
        class: EngineControlClass,
    ) -> Result<Option<(EntityId, bool)>> {
        let holder = match actor {
            EngineControlActor::Owner(owner) => {
                return Ok(owner
                    .revalidate_in_txn(self, txn)
                    .ok()
                    .map(|owner| (owner, true)));
            }
            EngineControlActor::Holder(holder) => holder,
        };
        Ok(self
            .engine_controls_grant_in(txn, holder, class)?
            .map(|_| (holder, false)))
    }

    /// The grant through which `holder` holds the `engine.controls` class
    /// `class` now, if any ([`Self::steward_grant_with_verb_in`] for its
    /// verb).
    pub(crate) fn engine_controls_grant_in(
        &self,
        txn: &heed::RoTxn<'_>,
        holder: EntityId,
        class: EngineControlClass,
    ) -> Result<Option<EntityId>> {
        self.steward_grant_with_verb_in(txn, holder, class.grant_verb())
    }

    /// The grant through which `holder` may use the Steward verb `verb` now,
    /// if any, checked live at each use (untangle 6.6c): for a base agent the
    /// grant its marker names, while that grant stands with `verb` and its
    /// MACHINE binding is live; for any other actor a live Steward grant on
    /// this vault's root that names `verb` itself. A grant whose verbs are
    /// left open (an Owner's or an Admin's) does not count.
    pub(crate) fn steward_grant_with_verb_in(
        &self,
        txn: &heed::RoTxn<'_>,
        holder: EntityId,
        verb: &str,
    ) -> Result<Option<EntityId>> {
        self.steward_grant_reaching_in(txn, holder, verb, GrantReach::Any)
    }

    /// [`Self::steward_grant_with_verb_in`], counting only a grant that
    /// reaches the whole vault ([`reaches_whole_vault`]). A read whose rows
    /// no reader filters by project, world, band or sensitivity asks this
    /// one, so a grant narrowed to part of the vault reads none of them
    /// (review of #6996).
    pub(crate) fn whole_vault_steward_grant_with_verb_in(
        &self,
        txn: &heed::RoTxn<'_>,
        holder: EntityId,
        verb: &str,
    ) -> Result<Option<EntityId>> {
        self.steward_grant_reaching_in(txn, holder, verb, GrantReach::WholeVault)
    }

    fn steward_grant_reaching_in(
        &self,
        txn: &heed::RoTxn<'_>,
        holder: EntityId,
        verb: &str,
        reach: GrantReach,
    ) -> Result<Option<EntityId>> {
        if SystemAgent::of(holder).is_none() {
            return self.root_steward_grant_with_verb_in(txn, holder, verb, reach);
        }
        Ok(match steward_grant_of_in(&self.store, txn, holder)? {
            Some(Some(grant))
                if standing_steward_verbs_in(&self.store, txn, grant, holder)?.contains(verb)
                    && self.system_agent_binding_live_in(txn, holder)?
                    && (reach == GrantReach::Any
                        || self.grant_reaches_whole_vault_in(txn, grant)?) =>
            {
                Some(grant)
            }
            _ => None,
        })
    }

    /// Whether the stored grant `grant` reaches the whole vault
    /// ([`reaches_whole_vault`]); a row that is gone or does not decode
    /// reaches nothing.
    fn grant_reaches_whole_vault_in(&self, txn: &heed::RoTxn<'_>, grant: EntityId) -> Result<bool> {
        let Some(raw) = self.store.port_entity_record(txn, &grant)? else {
            return Ok(false);
        };
        Ok(decode_federation_grant_body(&raw.body)
            .is_ok_and(|row| reaches_whole_vault(&row.authority_scope)))
    }

    /// The live Steward grant on this vault's root that names `holder` and
    /// the verb `verb` itself, and reaches as far as `reach` asks, if any.
    fn root_steward_grant_with_verb_in(
        &self,
        txn: &heed::RoTxn<'_>,
        holder: EntityId,
        verb: &str,
        reach: GrantReach,
    ) -> Result<Option<EntityId>> {
        let root = self.steward_root_scope_in_txn(txn)?;
        let now = self.store.clock.now_recorded_at();
        for id in self
            .store
            .port_entity_ids_by_type(txn, ENTITY_TYPE_FEDERATION_GRANT, None)?
        {
            let id = id?;
            let Some(raw) = self.store.port_entity_record(txn, &id)? else {
                continue;
            };
            if raw.body.is_empty()
                || !crate::vault::live_entity_row_in_txn(&self.store, txn, &id)?.is_live()
            {
                continue;
            }
            let Ok(grant) = decode_federation_grant_body(&raw.body) else {
                continue;
            };
            if grant.member_ref == holder
                && grant.scope == root
                && grant.role == FederationGrantRole::Steward
                && grant.preset == FederationGrantPreset::Steward
                && grant.kind == FederationGrantKind::Access
                && grant.is_live_at(now)
                && matches!(&grant.authority_scope.verbs, ScopeAxis::Some(verbs)
                    if verbs.contains(verb))
                && (reach == GrantReach::Any || reaches_whole_vault(&grant.authority_scope))
            {
                return Ok(Some(id));
            }
        }
        Ok(None)
    }

    /// The engine-control door: when `actor` may change a knob of `class`,
    /// `write` changes knob `knob` to `value` in one writer with its
    /// receipt, which names who made the change. The knob's own door clamps
    /// a budget to the owner's cap inside `write`. Returns the receipt's id.
    ///
    /// # Errors
    ///
    /// `InvalidConfig` when `actor` may not; `write`'s error; a store
    /// failure.
    pub fn apply_engine_control(
        &self,
        actor: EngineControlActor<'_>,
        class: EngineControlClass,
        knob: &str,
        value: &str,
        write: impl FnOnce(&mut heed::RwTxn<'_>) -> Result<()>,
    ) -> Result<EntityId> {
        self.with_write_txn_grouped(|txn| {
            let Some((by, owner)) = self.engine_control_actor_in_txn(&*txn, actor, class)? else {
                return Err(Error::InvalidConfig(
                    "changing this knob needs the owner or its engine.controls class grant".into(),
                ));
            };
            write(txn)?;
            let id = self.store.clock.entity_id()?;
            let changed_at = crate::ports::recorded_at_in_txn(&self.store, txn)?;
            ENGINE_CONTROL_CHANGE.put(
                &self.store,
                txn,
                &id,
                &EngineControlChange {
                    by,
                    owner,
                    class,
                    knob: knob.to_owned(),
                    value: value.to_owned(),
                    changed_at,
                },
            )?;
            Ok(id)
        })
    }
}

/// How far a Steward grant must reach to count at a door.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum GrantReach {
    /// Any live grant naming the verb: an engine control is one vault knob,
    /// not a record at a position.
    Any,
    /// Only a grant that reaches the whole vault ([`reaches_whole_vault`]).
    WholeVault,
}

/// Whether a grant's scope reaches the whole vault: no axis but `verbs` is
/// narrowed. A vault or holder override row narrows a member's grant by a
/// meet (worlds, facets, bands, audience, sensitivity), and a member works
/// "exactly as its scopes allow" (ARCH-0043).
fn reaches_whole_vault(scope: &Scope) -> bool {
    *scope
        == Scope {
            verbs: scope.verbs.clone(),
            ..Scope::top()
        }
}

/// A holder's change, rendered for its receipt.
pub(crate) fn rendered_change(value: &impl Serialize) -> Result<String> {
    serde_json::to_string(value)
        .map_err(|_| Error::InvalidConfig("an engine-control value that does not render".into()))
}

impl Vault {
    /// Every engine-control change, oldest first, for the owner to read.
    ///
    /// # Errors
    ///
    /// An owner refusal; a store failure.
    pub fn engine_control_changes(
        &self,
        owner: &AuthenticatedOwner,
    ) -> Result<Vec<(EntityId, EngineControlChange)>> {
        let txn = self.store.env.read_txn()?;
        owner.revalidate_in_txn(self, &txn)?;
        let mut changes = ENGINE_CONTROL_CHANGE.scan(&self.store, &txn)?;
        changes.sort_by_key(|(id, change)| (change.changed_at, *id));
        Ok(changes)
    }

    /// The receipt [`Self::apply_engine_control`] wrote under `id`, for the
    /// verb that made the change to answer with (untangle 6.6d).
    ///
    /// # Errors
    ///
    /// `InvalidConfig` when no receipt has this id; a store failure.
    pub(crate) fn engine_control_change(&self, id: EntityId) -> Result<EngineControlChange> {
        let txn = self.store.env.read_txn()?;
        ENGINE_CONTROL_CHANGE
            .get(&self.store, &txn, &id)?
            .ok_or_else(|| Error::InvalidConfig("no engine-control receipt has this id".into()))
    }
}

/// The engine-control receipts' actor scrub, named in the table's
/// declaration (review of #6918): a hard erase of an actor takes out every
/// receipt of a change it made, and every receipt whose knob or rendered
/// value names it, so no row keeps naming an erased actor. The knobs stay as
/// they were set.
pub(crate) fn erase_engine_control_actor_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    actor: &EntityId,
) -> Result<()> {
    if crate::deletion::names_no_actor(vault, txn, actor)? {
        return Ok(());
    }
    let named = actor.to_hex();
    for (id, change) in ENGINE_CONTROL_CHANGE.scan(&vault.store, txn)? {
        if change.by == *actor
            || change.knob.contains(named.as_str())
            || change.value.contains(named.as_str())
        {
            ENGINE_CONTROL_CHANGE.delete(&vault.store, txn, &id)?;
        }
    }
    Ok(())
}

/// The five knobs that mix work with consent (S66-3), by their stored
/// tables: no holder changes them; each stays an owner act at its own door.
pub const ENGINE_CONTROLS_OWNER_ONLY_KNOBS: [&str; 5] = [
    "VAULT_CLEANUP_POSTURE",
    "DREAMER_ACTION_MODE_POLICY",
    "DREAMER_EXCLUDED_CONVERSATIONS",
    "DREAMER_PROACTIVITY_PRESENTATION",
    "DREAMER_FAILURE_RULES",
];

#[cfg(test)]
mod tests;
