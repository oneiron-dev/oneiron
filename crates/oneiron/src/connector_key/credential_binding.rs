//! FIX 988 (ARCH-0054 identity drift; ARCH-0072 "every row that depended on
//! the old issuer"): one durable binding per connector credential.
//!
//! A binding names one catalog connector's credential slot. It records the
//! issuer the slot answers for, the custody pointer it presents (a reference
//! or a fingerprint, never a value), a monotonic generation, and the
//! concrete (key, row) set that depends on it. Its baseline comes only from
//! an authenticated observation. A later observation of another issuer at
//! the binding's generation first records a durable transition, then drafts
//! a forced delta slate that re-asks every dependent row. Until the owner
//! accepts that revision at the generation, calls on exactly those rows
//! hold, live and on replay. Unrelated keys, actors, credentials and rows
//! keep running, and the shared catalog is never suspended for a subset. A
//! same-issuer custody rotation is not drift, and an OAuth response's `iss`
//! mismatch stays a refused response, never a rebind.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

use super::lifecycle::{catalog_key_in_txn, derived_key_catalog_in_txn};
use super::record::{
    ConnectorKeyRecord, ScopedCapabilityProvenance, invalid_body, normalize_connector_key,
};
use super::slate::{SlateCapability, read_slate_in_store_txn};
use super::slate_revision::{SlateRevisionCause, draft_forced_revision_in_txn};
use super::slate_setting::governing_slate_in_txn;
use super::txn::{append_connector_key_op_record, read_connector_key_in_txn};
use crate::consent::AuthenticatedOwner;
use crate::error::{Error, Result};
use crate::outbound_grant::standing_outbound_grant_in_txn;
use crate::side_table::{self, Named, SideTable};
use crate::store::Store;
use crate::{EntityId, Vault};

/// One credential slot's binding. Key: the binding ref.
const BINDINGS: SideTable<EntityId, ConnectorCredentialBinding, Named> =
    SideTable::new(&side_table::CONNECTOR_CREDENTIAL_BINDING);
/// A binding's ref: its catalog key and credential slot.
const BINDING_DOMAIN: &[u8] = b"oneiron:connector-credential-binding:v1";

/// Why a call on a row an issuer change halted holds (FIX 988).
pub const CONNECTOR_ISSUER_HOLD_REASON: &str = "connector_credential_issuer_changed";

/// One key, or one row of it, that depends on a credential binding.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConnectorBindingDependent {
    pub key_ref: EntityId,
    /// The row's key (a tool, or the elicitation row); `None`: every row the
    /// key calls.
    pub tool: Option<String>,
}

/// Where an issuer change stands.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConnectorIssuerTransitionState {
    /// Recorded; its forced re-ask is not drafted yet.
    Detected,
    /// Its forced re-ask waits on the owner's stamp.
    Drafted { slate_ref: EntityId },
    /// The owner stamped it: the binding answers for the new issuer.
    Accepted { slate_ref: EntityId },
}

/// One observed issuer change on a binding, kept after acceptance as its
/// evidence.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConnectorIssuerTransition {
    pub old_issuer: String,
    pub new_issuer: String,
    /// The custody pointer the new issuer's credential presents.
    pub proposed_credential_ref: String,
    /// What the observer saw, in its own words: never a credential.
    pub witness: String,
    pub detected_at: u64,
    /// The binding generation it was detected at; acceptance names it.
    pub expected_generation: u64,
    /// The rows it halts.
    pub dependents: BTreeSet<ConnectorBindingDependent>,
    pub state: ConnectorIssuerTransitionState,
}

impl ConnectorIssuerTransition {
    /// Whether it still waits on the owner, halting its dependents.
    #[must_use]
    pub fn halts(&self) -> bool {
        !matches!(self.state, ConnectorIssuerTransitionState::Accepted { .. })
    }
}

/// One connector's open issuer transition, as the steady-state views
/// surface it: the issuers, when it was detected, and the catalog slate
/// rows it holds. Value-less: no witness or credential pointers.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct ConnectorIssuerHaltView {
    pub old_issuer: String,
    pub new_issuer: String,
    pub detected_at: u64,
    /// Catalog slate rows the halt holds, by tool name.
    pub dependent_rows: Vec<String>,
}

/// One catalog connector credential slot's durable binding.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConnectorCredentialBinding {
    pub binding_ref: EntityId,
    /// The catalog connector, normalized.
    pub connector: String,
    pub catalog_key: EntityId,
    /// The credential slot: the route's own, or a custody record's name.
    pub slot: String,
    /// The accepted issuer.
    pub issuer: String,
    /// The accepted custody pointer or fingerprint, never a value.
    pub credential_ref: String,
    pub generation: u64,
    pub dependents: BTreeSet<ConnectorBindingDependent>,
    /// The latest issuer change, open or accepted.
    pub transition: Option<ConnectorIssuerTransition>,
}

/// An authenticated observation of the issuer a credential slot answers for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConnectorIssuerObservation {
    /// The catalog connector's name.
    pub connector: String,
    pub slot: String,
    pub issuer: String,
    /// The custody pointer or fingerprint presented now, never a value.
    pub credential_ref: String,
    /// The binding generation the observer read: 0 for the baseline.
    pub expected_generation: u64,
    /// The keys and rows that depend on the slot; empty keeps the binding's.
    pub dependents: Vec<ConnectorBindingDependent>,
    pub witness: String,
}

fn covers(
    dependents: &BTreeSet<ConnectorBindingDependent>,
    key_id: &EntityId,
    catalog: Option<EntityId>,
    tool: &str,
) -> bool {
    dependents.iter().any(|dependent| {
        dependent.tool.as_deref().is_none_or(|row| row == tool)
            && (dependent.key_ref == *key_id || Some(dependent.key_ref) == catalog)
    })
}

/// The catalog key a per-grant key derives from; `None` for a catalog key.
fn catalog_of_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    key: &ConnectorKeyRecord,
) -> Result<Option<EntityId>> {
    Ok(derived_key_catalog_in_txn(store, txn, key)?.map(|(id, _, _)| id))
}

/// Whether a call on `tool` under key `key_id` (record `key`) meets an issuer
/// change, not yet accepted, on a binding its row depends on. A key or row
/// no binding names never holds here.
pub(crate) fn connector_issuer_hold_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    key_id: &EntityId,
    key: &ConnectorKeyRecord,
    tool: &str,
) -> Result<bool> {
    let halting: Vec<ConnectorIssuerTransition> = BINDINGS
        .scan(store, txn)?
        .into_iter()
        .filter_map(|(_, binding)| binding.transition.filter(ConnectorIssuerTransition::halts))
        .collect();
    if halting.is_empty() {
        return Ok(false);
    }
    let catalog = catalog_of_in_txn(store, txn, key)?;
    Ok(halting
        .iter()
        .any(|transition| covers(&transition.dependents, key_id, catalog, tool)))
}

/// The generation of each binding a call on `tool` under `key_id` depends
/// on: part of the authority a scope signal was observed under.
pub(super) fn binding_generations_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    key_id: &EntityId,
    key: &ConnectorKeyRecord,
    tool: &str,
) -> Result<Vec<u64>> {
    let bindings = BINDINGS.scan(store, txn)?;
    if bindings.is_empty() {
        return Ok(Vec::new());
    }
    let catalog = catalog_of_in_txn(store, txn, key)?;
    Ok(bindings
        .into_iter()
        .filter(|(_, binding)| covers(&binding.dependents, key_id, catalog, tool))
        .map(|(_, binding)| binding.generation)
        .collect())
}

/// Checks each observed dependent is this catalog's key or one derived from
/// it, and that a named row is on the slate the key meets.
fn dependents_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    catalog_key: EntityId,
    observed: &[ConnectorBindingDependent],
) -> Result<BTreeSet<ConnectorBindingDependent>> {
    let mut dependents = BTreeSet::new();
    for dependent in observed {
        let key = read_connector_key_in_txn(store, txn, &dependent.key_ref)?
            .ok_or_else(|| invalid_body("a dependent key does not resolve"))?;
        if dependent.key_ref != catalog_key
            && catalog_of_in_txn(store, txn, &key)? != Some(catalog_key)
        {
            return Err(invalid_body("a dependent key is not this connector's"));
        }
        if let Some(tool) = &dependent.tool {
            let on_slate = governing_slate_in_txn(store, txn, &key)?.is_some_and(|(_, slate)| {
                slate.capability_row(SlateCapability::parse(tool)).is_some()
            });
            if !on_slate {
                return Err(invalid_body("a dependent row is not on its key's slate"));
            }
        }
        dependents.insert(dependent.clone());
    }
    Ok(dependents)
}

/// The tool a per-grant key's live grant names.
fn derived_key_tool_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    key_ref: &EntityId,
) -> Result<Option<String>> {
    let Some(key) = read_connector_key_in_txn(store, txn, key_ref)? else {
        return Ok(None);
    };
    let Some(capability) = ScopedCapabilityProvenance::parse_owner_capability_key(&key.connector)
    else {
        return Ok(None);
    };
    Ok(
        standing_outbound_grant_in_txn(store, txn, &capability.grant_id())?.and_then(|grant| {
            grant
                .scope
                .scoped_mcp_grant()
                .map(|scope| scope.tool.to_owned())
        }),
    )
}

/// The catalog slate rows `dependents` call: every row for the catalog key
/// itself, its grant's tool for a per-grant key, else the named row.
fn dependent_rows_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    binding: &ConnectorCredentialBinding,
    catalog: &ConnectorKeyRecord,
    dependents: &BTreeSet<ConnectorBindingDependent>,
) -> Result<BTreeSet<String>> {
    let slate = match catalog.slate_ref {
        Some(id) => read_slate_in_store_txn(store, txn, id)?,
        None => None,
    };
    let mut rows = BTreeSet::new();
    for dependent in dependents {
        match &dependent.tool {
            Some(tool) => {
                rows.insert(tool.clone());
            }
            None if dependent.key_ref == binding.catalog_key => rows.extend(
                slate
                    .iter()
                    .flat_map(|slate| slate.rows().iter().map(|row| row.draft.tool.clone())),
            ),
            None => rows.extend(derived_key_tool_in_txn(store, txn, &dependent.key_ref)?),
        }
    }
    Ok(rows)
}

fn issuer_cause(
    binding: &ConnectorCredentialBinding,
    transition: &ConnectorIssuerTransition,
    dependent_rows: BTreeSet<String>,
) -> SlateRevisionCause {
    SlateRevisionCause::CredentialIssuerChanged {
        binding_ref: binding.binding_ref,
        expected_generation: transition.expected_generation,
        old_issuer: transition.old_issuer.clone(),
        new_issuer: transition.new_issuer.clone(),
        proposed_credential_ref: transition.proposed_credential_ref.clone(),
        dependent_rows,
    }
}

fn append_binding_op(
    store: &Store,
    txn: &mut heed::RwTxn<'_>,
    catalog_key: &EntityId,
    op: &'static str,
    catalog: &ConnectorKeyRecord,
    at: u64,
) -> Result<()> {
    let policy = crate::gate::resolve_policy_manifest(store, txn)?;
    append_connector_key_op_record(
        store,
        txn,
        catalog_key,
        op,
        catalog,
        policy.read_frontier_hash()?,
        at,
    )
}

/// Every issuer change waiting on the owner: its connector, its drafted
/// revision if any, and its cause.
pub(super) fn open_issuer_revisions_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
) -> Result<Vec<(String, Option<EntityId>, SlateRevisionCause)>> {
    let mut open = Vec::new();
    for (_, binding) in BINDINGS.scan(store, txn)? {
        let Some(transition) = binding.transition.as_ref().filter(|open| open.halts()) else {
            continue;
        };
        let Some(catalog) = read_connector_key_in_txn(store, txn, &binding.catalog_key)? else {
            continue;
        };
        let rows = dependent_rows_in_txn(store, txn, &binding, &catalog, &transition.dependents)?;
        let drafted = match transition.state {
            ConnectorIssuerTransitionState::Drafted { slate_ref } => Some(slate_ref),
            _ => None,
        };
        open.push((
            binding.connector.clone(),
            drafted,
            issuer_cause(&binding, transition, rows),
        ));
    }
    Ok(open)
}

/// One connector's open issuer transition, if any halts its rows: the
/// earliest detected one across the connector's bindings. `None` when no
/// binding holds an open transition for it.
pub(in crate::connector_key) fn open_issuer_halt_for_connector_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    connector: &str,
) -> Result<Option<ConnectorIssuerHaltView>> {
    let wanted = normalize_connector_key(connector);
    let mut best: Option<ConnectorIssuerHaltView> = None;
    for (_, binding) in BINDINGS.scan(store, txn)? {
        if normalize_connector_key(&binding.connector) != wanted {
            continue;
        }
        let Some(transition) = binding.transition.as_ref().filter(|open| open.halts()) else {
            continue;
        };
        let Some(catalog) = read_connector_key_in_txn(store, txn, &binding.catalog_key)? else {
            continue;
        };
        let rows = dependent_rows_in_txn(store, txn, &binding, &catalog, &transition.dependents)?;
        let view = ConnectorIssuerHaltView {
            old_issuer: transition.old_issuer.clone(),
            new_issuer: transition.new_issuer.clone(),
            detected_at: transition.detected_at,
            dependent_rows: rows.into_iter().collect(),
        };
        let earlier = best
            .as_ref()
            .is_none_or(|current| view.detected_at < current.detected_at);
        if earlier {
            best = Some(view);
        }
    }
    Ok(best)
}

/// An issuer revision's acceptance, in the stamping writer: the binding's
/// drafted revision must be this slate at the expected generation. The
/// binding then answers for the new issuer at the next generation, and the
/// transition stays as the evidence.
pub(super) fn accept_issuer_in_txn(
    store: &Store,
    txn: &mut heed::RwTxn<'_>,
    slate_id: EntityId,
    binding_ref: EntityId,
    expected_generation: u64,
) -> Result<EntityId> {
    let mut binding = BINDINGS
        .get(store, txn, &binding_ref)?
        .ok_or_else(|| invalid_body("the revision's credential binding is gone"))?;
    let generation = binding.generation;
    let drafted = ConnectorIssuerTransitionState::Drafted {
        slate_ref: slate_id,
    };
    let transition = binding
        .transition
        .as_mut()
        .filter(|transition| transition.state == drafted)
        .ok_or_else(|| invalid_body("the slate is not the binding's drafted issuer revision"))?;
    if generation != expected_generation || transition.expected_generation != expected_generation {
        return Err(Error::ConcurrentWrite(
            "connector credential binding generation",
        ));
    }
    transition.state = ConnectorIssuerTransitionState::Accepted {
        slate_ref: slate_id,
    };
    binding.issuer = transition.new_issuer.clone();
    binding.credential_ref = transition.proposed_credential_ref.clone();
    binding.generation = generation
        .checked_add(1)
        .ok_or(Error::ArithmeticOverflow("credential binding generation"))?;
    BINDINGS.put(store, txn, &binding_ref, &binding)?;
    if let Some(catalog) = read_connector_key_in_txn(store, txn, &binding.catalog_key)? {
        append_binding_op(
            store,
            txn,
            &binding.catalog_key,
            "gate.connector_key.issuer_accepted",
            &catalog,
            crate::unix_seconds_now(),
        )?;
    }
    Ok(binding.catalog_key)
}

impl Vault {
    /// An authenticated owner's observation of the issuer one catalog
    /// connector's credential slot answers for (CALL
    /// SLATE-988-binding-baseline). With no binding yet it is the baseline,
    /// read at generation 0. At the binding's generation, the same issuer
    /// only moves the custody pointer: never drift. Another issuer records
    /// the transition in its own writer first, so a failed draft loses no
    /// evidence and a repeat observation resumes it, then drafts the forced
    /// re-ask of every dependent row. A stale generation changes nothing.
    pub fn observe_connector_credential_issuer(
        &self,
        owner: &AuthenticatedOwner,
        observation: &ConnectorIssuerObservation,
    ) -> Result<ConnectorCredentialBinding> {
        let named = [
            &observation.slot,
            &observation.issuer,
            &observation.credential_ref,
            &observation.witness,
        ];
        if named.iter().any(|value| value.trim().is_empty()) {
            return Err(invalid_body(
                "an issuer observation names its slot, issuer, credential and witness",
            ));
        }
        let at = crate::unix_seconds_now();
        let binding = self.with_write_txn_grouped(|txn| {
            owner.revalidate_as_vault_owner_in_txn(self, txn)?;
            let (catalog_key, catalog) =
                catalog_key_in_txn(&self.store, txn, &observation.connector)?
                    .ok_or_else(|| invalid_body("no catalog connector by that name"))?;
            let dependents =
                dependents_in_txn(&self.store, txn, catalog_key, &observation.dependents)?;
            let binding_ref = EntityId::derive(
                BINDING_DOMAIN,
                &[catalog_key.as_bytes(), observation.slot.as_bytes()],
            )?;
            let Some(mut binding) = BINDINGS.get(&self.store, txn, &binding_ref)? else {
                if observation.expected_generation != 0 {
                    return Err(Error::ConcurrentWrite(
                        "connector credential binding generation",
                    ));
                }
                let binding = ConnectorCredentialBinding {
                    binding_ref,
                    connector: normalize_connector_key(&observation.connector),
                    catalog_key,
                    slot: observation.slot.clone(),
                    issuer: observation.issuer.clone(),
                    credential_ref: observation.credential_ref.clone(),
                    generation: 1,
                    dependents,
                    transition: None,
                };
                BINDINGS.put(&self.store, txn, &binding_ref, &binding)?;
                append_binding_op(
                    &self.store,
                    txn,
                    &catalog_key,
                    "gate.connector_key.issuer_bound",
                    &catalog,
                    at,
                )?;
                return Ok(binding);
            };
            if binding.generation != observation.expected_generation {
                return Err(Error::ConcurrentWrite(
                    "connector credential binding generation",
                ));
            }
            if !observation.dependents.is_empty() {
                binding.dependents = dependents;
            }
            if observation.issuer == binding.issuer {
                // A same-issuer custody rotation is not drift.
                binding
                    .credential_ref
                    .clone_from(&observation.credential_ref);
            } else if binding
                .transition
                .as_ref()
                .is_none_or(|open| !open.halts() || open.new_issuer != observation.issuer)
            {
                binding.transition = Some(ConnectorIssuerTransition {
                    old_issuer: binding.issuer.clone(),
                    new_issuer: observation.issuer.clone(),
                    proposed_credential_ref: observation.credential_ref.clone(),
                    witness: observation.witness.clone(),
                    detected_at: at,
                    expected_generation: binding.generation,
                    dependents: binding.dependents.clone(),
                    state: ConnectorIssuerTransitionState::Detected,
                });
                append_binding_op(
                    &self.store,
                    txn,
                    &catalog_key,
                    "gate.connector_key.issuer_changed",
                    &catalog,
                    at,
                )?;
            }
            BINDINGS.put(&self.store, txn, &binding_ref, &binding)?;
            Ok(binding)
        })?;
        if binding
            .transition
            .as_ref()
            .is_some_and(|open| open.state == ConnectorIssuerTransitionState::Detected)
        {
            return self.draft_issuer_revision(binding.binding_ref);
        }
        Ok(binding)
    }

    /// Drafts a detected issuer change's forced re-ask of the catalog slate,
    /// rechecking in its writer that the change is still the detected one at
    /// its generation.
    fn draft_issuer_revision(&self, binding_ref: EntityId) -> Result<ConnectorCredentialBinding> {
        self.with_write_txn_grouped(|txn| {
            let mut binding = BINDINGS
                .get(&self.store, txn, &binding_ref)?
                .ok_or(Error::EntityNotFound)?;
            let Some(transition) = binding.transition.clone().filter(|open| {
                open.state == ConnectorIssuerTransitionState::Detected
                    && open.expected_generation == binding.generation
            }) else {
                return Ok(binding);
            };
            let Some(catalog) = read_connector_key_in_txn(&self.store, txn, &binding.catalog_key)?
            else {
                return Ok(binding);
            };
            let Some(prior) = catalog.slate_ref else {
                return Ok(binding);
            };
            let rows = dependent_rows_in_txn(
                &self.store,
                txn,
                &binding,
                &catalog,
                &transition.dependents,
            )?;
            let cause = issuer_cause(&binding, &transition, rows.clone());
            let Some(slate_ref) =
                draft_forced_revision_in_txn(&self.store, txn, prior, rows, cause)?
            else {
                return Ok(binding);
            };
            binding.transition = Some(ConnectorIssuerTransition {
                state: ConnectorIssuerTransitionState::Drafted { slate_ref },
                ..transition
            });
            BINDINGS.put(&self.store, txn, &binding_ref, &binding)?;
            Ok(binding)
        })
    }
}

impl Vault {
    /// One connector's open issuer transition, if any halts its rows (FIX
    /// 9305): the read the steady-state views surface. `None` when no
    /// binding holds an open transition for it.
    pub fn open_issuer_halt_for_connector(
        &self,
        connector: &str,
    ) -> Result<Option<ConnectorIssuerHaltView>> {
        let txn = self.store.env.read_txn()?;
        open_issuer_halt_for_connector_in_txn(&self.store, &txn, connector)
    }
}
