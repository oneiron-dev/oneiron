//! Cumulative semantic mutations of one native agent setup execution.

use std::cell::RefCell;
use std::collections::{BTreeMap, BTreeSet};
use std::rc::Rc;

use crate::EntityId;
use crate::batch::EntityMetadataHeader;
use crate::error::{Error, Result};
use crate::federation::Scope;
use crate::side_table::SideTableDbs;
use crate::store::key_custody::{CustodySubject, KeyCustody, RetireCause, RetirementIntent};
use crate::store::{ManifestDbs, Store};

thread_local! {
    static TRACES: RefCell<Vec<Rc<RefCell<Trace>>>> = const { RefCell::new(Vec::new()) };
}

#[derive(Clone)]
struct Position {
    id: EntityId,
    scope: Option<Scope>,
    unborn: bool,
}

#[derive(Clone)]
pub(crate) enum SetupRetirementEvent {
    Staged(RetirementIntent),
    Withdrawn(CustodySubject),
}

#[derive(Clone)]
pub(crate) enum SetupConsentEvent {
    StandingGrantRevoked {
        grant_ref: String,
        row: crate::consent::ConsentGrantRow,
    },
    OwnerReasonRetired {
        grant_ref: String,
        rule_decision_id: [u8; 16],
    },
}

struct Trace {
    owner: usize,
    positions: Vec<Position>,
    mutated: BTreeSet<EntityId>,
    retired_positions: BTreeMap<EntityId, Option<Scope>>,
    position_resets: BTreeSet<EntityId>,
    retirements: Vec<SetupRetirementEvent>,
    consent_events: Vec<SetupConsentEvent>,
}

fn active(store: &impl ManifestDbs) -> Option<Rc<RefCell<Trace>>> {
    if store.is_union() {
        return None;
    }
    active_owner(store.key_custody())
}

fn active_owner(owner: &KeyCustody) -> Option<Rc<RefCell<Trace>>> {
    let owner = std::ptr::from_ref(owner) as usize;
    TRACES.with(|traces| {
        traces
            .borrow()
            .iter()
            .rev()
            .find(|trace| trace.borrow().owner == owner)
            .cloned()
    })
}

/// Lexical, thread-bound capture. It observes actual semantic mutations rather
/// than diffing final rows, so deleting a row born earlier still counts.
pub(crate) struct SetupMutationTrace<'store> {
    _owner: &'store crate::store::key_custody::KeyCustody,
    state: Rc<RefCell<Trace>>,
}

impl<'store> SetupMutationTrace<'store> {
    pub(crate) fn open(store: &'store impl ManifestDbs) -> Self {
        let state = Rc::new(RefCell::new(Trace {
            owner: std::ptr::from_ref(store.key_custody()) as usize,
            positions: Vec::new(),
            mutated: BTreeSet::new(),
            retired_positions: BTreeMap::new(),
            position_resets: BTreeSet::new(),
            retirements: Vec::new(),
            consent_events: Vec::new(),
        }));
        TRACES.with(|traces| traces.borrow_mut().push(Rc::clone(&state)));
        Self {
            _owner: store.key_custody(),
            state,
        }
    }

    fn detach(&self) {
        TRACES.with(|traces| {
            traces
                .borrow_mut()
                .retain(|trace| !Rc::ptr_eq(trace, &self.state))
        });
    }

    /// Only the adapter that completed the entire native program may call this.
    /// A future birth resolves an edge's genuinely unborn endpoint, never an
    /// existing unstamped row. Every observed position remains in the footprint.
    pub(crate) fn finish(self) -> Result<ObservedSetupMutations> {
        self.detach();
        let mut trace = self.state.borrow_mut();
        let mut positions = std::mem::take(&mut trace.positions);
        for index in 0..positions.len() {
            if positions[index].unborn {
                let id = positions[index].id;
                let scope = positions[index + 1..]
                    .iter()
                    .find(|later| later.id == id && !later.unborn && later.scope.is_some())
                    .and_then(|later| later.scope.clone());
                positions[index].scope = scope;
            }
        }
        let blast_radius = u64::try_from(trace.mutated.len())
            .map_err(|_| Error::ArithmeticOverflow("agent setup entity count"))?;
        Ok(ObservedSetupMutations {
            positions,
            entities: std::mem::take(&mut trace.mutated),
            retired_positions: std::mem::take(&mut trace.retired_positions),
            position_resets: std::mem::take(&mut trace.position_resets),
            retirements: std::mem::take(&mut trace.retirements),
            consent_events: std::mem::take(&mut trace.consent_events),
            blast_radius,
        })
    }
}

impl Drop for SetupMutationTrace<'_> {
    fn drop(&mut self) {
        self.detach();
    }
}

pub(crate) struct ObservedSetupMutations {
    positions: Vec<Position>,
    entities: BTreeSet<EntityId>,
    retired_positions: BTreeMap<EntityId, Option<Scope>>,
    position_resets: BTreeSet<EntityId>,
    retirements: Vec<SetupRetirementEvent>,
    consent_events: Vec<SetupConsentEvent>,
    blast_radius: u64,
}

impl ObservedSetupMutations {
    pub(crate) fn positions(&self) -> impl Iterator<Item = (EntityId, Option<&Scope>)> {
        self.positions
            .iter()
            .map(|position| (position.id, position.scope.as_ref()))
    }

    pub(crate) fn entities(&self) -> impl Iterator<Item = EntityId> + '_ {
        self.entities.iter().copied()
    }

    pub(crate) fn retirements(&self) -> &[SetupRetirementEvent] {
        &self.retirements
    }

    pub(crate) fn consent_events(&self) -> &[SetupConsentEvent] {
        &self.consent_events
    }

    pub(crate) fn blast_radius(&self) -> u64 {
        self.blast_radius
    }
}

/// A nested setup contributes only once its actual child has committed into
/// the parent. An aborted child never contributes its provisional mutations.
pub(super) fn observe_merged_child(store: &impl ManifestDbs, child: &ObservedSetupMutations) {
    let Some(parent) = active(store) else {
        return;
    };
    let mut parent = parent.borrow_mut();
    parent.mutated.extend(child.entities.iter().copied());
    parent.positions.extend(child.positions.iter().cloned());
    parent.retirements.extend(child.retirements.iter().cloned());
    parent
        .consent_events
        .extend(child.consent_events.iter().cloned());
    for id in &child.position_resets {
        parent.retired_positions.remove(id);
    }
    parent
        .position_resets
        .extend(child.position_resets.iter().copied());
    parent.retired_positions.extend(
        child
            .retired_positions
            .iter()
            .map(|(id, scope)| (*id, scope.clone())),
    );
}

fn stored_position(
    store: &impl ManifestDbs,
    txn: &heed::RoTxn<'_>,
    id: EntityId,
) -> Result<Position> {
    let Some(row) = store.entities().get(txn, id.as_bytes())? else {
        return Ok(Position {
            id,
            scope: None,
            unborn: true,
        });
    };
    let header = EntityMetadataHeader::parse(&row).ok_or(Error::CorruptedIndex("entity header"))?;
    let mut scope =
        crate::federation::record_scope::setup_stored_position(store, txn, id, header.entity_type)?;
    if scope.is_none() {
        // A nested child can still see the body whose stamp its parent retired.
        // Read that actual execution history, without changing the parent.
        let owner = std::ptr::from_ref(store.key_custody()) as usize;
        scope = TRACES.with(|traces| {
            traces
                .borrow()
                .iter()
                .rev()
                .find_map(|trace| {
                    let trace = trace.borrow();
                    (trace.owner == owner)
                        .then(|| trace.retired_positions.get(&id).cloned())
                        .flatten()
                })
                .flatten()
        });
    }
    Ok(Position {
        id,
        scope,
        unborn: false,
    })
}

pub(crate) fn observe_entity_put(
    store: &impl ManifestDbs,
    txn: &heed::RoTxn<'_>,
    id: EntityId,
    encoded: &[u8],
) -> Result<()> {
    let Some(trace) = active(store) else {
        return Ok(());
    };
    let prior = store.entities().get(txn, id.as_bytes())?;
    if prior.as_deref() == Some(encoded) {
        return Ok(());
    }
    let before = stored_position(store, txn, id)?;
    let mut trace = trace.borrow_mut();
    trace.mutated.insert(id);
    // A fresh row takes its position only from the real later stamp, not a
    // candidate derived against a prefix the native program has not written.
    trace.positions.push(before);
    Ok(())
}

pub(crate) fn observe_entity_delete(
    store: &impl ManifestDbs,
    txn: &heed::RoTxn<'_>,
    id: EntityId,
) -> Result<()> {
    let Some(trace) = active(store) else {
        return Ok(());
    };
    let position = stored_position(store, txn, id)?;
    if !position.unborn {
        let mut trace = trace.borrow_mut();
        trace.mutated.insert(id);
        trace.positions.push(position);
    }
    Ok(())
}

pub(crate) fn observe_edge(
    store: &impl ManifestDbs,
    txn: &heed::RoTxn<'_>,
    src: EntityId,
    kind: crate::EdgeKind,
    dst: EntityId,
    after: Option<&[u8]>,
) -> Result<()> {
    let Some(trace) = active(store) else {
        return Ok(());
    };
    let key = Store::encode_edge_key(&src, kind, &dst);
    if store.edges_out().get(txn, &key)?.as_deref() == after {
        return Ok(());
    }
    let positions = [
        stored_position(store, txn, src)?,
        stored_position(store, txn, dst)?,
    ];
    let mut trace = trace.borrow_mut();
    trace.mutated.extend([src, dst]);
    trace.positions.extend(positions);
    Ok(())
}

pub(crate) fn observe_position(store: &impl ManifestDbs, id: EntityId, scope: &Scope) {
    if let Some(trace) = active(store) {
        let mut trace = trace.borrow_mut();
        trace.mutated.insert(id);
        trace.retired_positions.remove(&id);
        trace.position_resets.insert(id);
        trace.positions.push(Position {
            id,
            scope: Some(scope.clone()),
            unborn: false,
        });
    }
}

/// Runs before the native stamp removal; later physical body/edge cleanup can
/// then retain this actual pre-retirement position instead of inventing one.
pub(crate) fn observe_position_retirement(
    store: &impl ManifestDbs,
    txn: &heed::RoTxn<'_>,
    id: EntityId,
) -> Result<()> {
    let Some(trace) = active(store) else {
        return Ok(());
    };
    let position = stored_position(store, txn, id)?;
    if !position.unborn {
        let mut trace = trace.borrow_mut();
        trace.retired_positions.insert(id, position.scope.clone());
        trace.positions.push(position);
    }
    Ok(())
}

/// Records the effective intent written successfully, not the weaker request
/// that may have joined an older, stronger intent.
pub(crate) fn observe_custody_retirement(
    dbs: &impl SideTableDbs,
    subject: &CustodySubject,
    through: u64,
    cause: RetireCause,
) {
    let Some(trace) = dbs.side_key_custody().and_then(active_owner) else {
        return;
    };
    trace
        .borrow_mut()
        .retirements
        .push(SetupRetirementEvent::Staged(RetirementIntent {
            subject: subject.clone(),
            through,
            cause,
        }));
}

pub(crate) fn observe_retirement_withdrawal(dbs: &impl SideTableDbs, subject: &CustodySubject) {
    let Some(trace) = dbs.side_key_custody().and_then(active_owner) else {
        return;
    };
    trace
        .borrow_mut()
        .retirements
        .push(SetupRetirementEvent::Withdrawn(subject.clone()));
}

/// A successful fence changes authority at this address even if no row is
/// stored here. Absence is not a future birth whose position can be filled in.
pub(crate) fn observe_row_fence(
    store: &impl ManifestDbs,
    txn: &heed::RoTxn<'_>,
    id: EntityId,
) -> Result<()> {
    let Some(trace) = active(store) else {
        return Ok(());
    };
    let mut position = stored_position(store, txn, id)?;
    position.unborn = false;
    let mut trace = trace.borrow_mut();
    trace.mutated.insert(id);
    trace.positions.push(position);
    Ok(())
}

/// The native row was successfully revoked at this exact key. Its consent
/// bound is not an ENTITY position or a federation Scope.
pub(crate) fn observe_standing_grant_revocation(
    store: &impl ManifestDbs,
    grant_ref: &str,
    row: &crate::consent::ConsentGrantRow,
) {
    let Some(trace) = active(store) else {
        return;
    };
    trace
        .borrow_mut()
        .consent_events
        .push(SetupConsentEvent::StandingGrantRevoked {
            grant_ref: grant_ref.to_owned(),
            row: row.clone(),
        });
}

/// Records the native rule key only after its retired row was written. A
/// decision id in this key is not an ENTITY id or an admitted row position.
pub(crate) fn observe_owner_reason_retirement(
    store: &impl ManifestDbs,
    grant_ref: &str,
    rule_decision_id: [u8; 16],
) {
    let Some(trace) = active(store) else {
        return;
    };
    trace
        .borrow_mut()
        .consent_events
        .push(SetupConsentEvent::OwnerReasonRetired {
            grant_ref: grant_ref.to_owned(),
            rule_decision_id,
        });
}
