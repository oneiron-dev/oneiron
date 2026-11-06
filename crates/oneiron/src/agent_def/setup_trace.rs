//! Cumulative semantic mutations of one native agent setup execution.

use std::cell::RefCell;
use std::collections::{BTreeMap, BTreeSet};
use std::rc::Rc;

use crate::EntityId;
use crate::batch::EntityMetadataHeader;
use crate::error::{Error, Result};
use crate::federation::Scope;
use crate::store::{ManifestDbs, Store};

thread_local! {
    static TRACES: RefCell<Vec<Rc<RefCell<Trace>>>> = const { RefCell::new(Vec::new()) };
}

struct Position {
    id: EntityId,
    scope: Option<Scope>,
    unborn: bool,
}

struct Trace {
    owner: usize,
    positions: Vec<Position>,
    mutated: BTreeSet<EntityId>,
    retired_positions: BTreeMap<EntityId, Option<Scope>>,
    retires_keys: bool,
}

fn active(store: &impl ManifestDbs) -> Option<Rc<RefCell<Trace>>> {
    if store.is_union() {
        return None;
    }
    let owner = std::ptr::from_ref(store.key_custody()) as usize;
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
            retires_keys: false,
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
            positions: positions
                .into_iter()
                .map(|position| (position.id, position.scope))
                .collect(),
            entities: std::mem::take(&mut trace.mutated),
            blast_radius,
            retires_keys: trace.retires_keys,
        })
    }
}

impl Drop for SetupMutationTrace<'_> {
    fn drop(&mut self) {
        self.detach();
    }
}

pub(crate) struct ObservedSetupMutations {
    positions: Vec<(EntityId, Option<Scope>)>,
    entities: BTreeSet<EntityId>,
    blast_radius: u64,
    retires_keys: bool,
}

impl ObservedSetupMutations {
    pub(crate) fn positions(&self) -> impl Iterator<Item = (EntityId, Option<&Scope>)> {
        self.positions
            .iter()
            .map(|(id, scope)| (*id, scope.as_ref()))
    }

    pub(crate) fn entities(&self) -> impl Iterator<Item = EntityId> + '_ {
        self.entities.iter().copied()
    }

    pub(crate) fn retires_keys(&self) -> bool {
        self.retires_keys
    }

    pub(crate) fn blast_radius(&self) -> u64 {
        self.blast_radius
    }
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
    if scope.is_none()
        && let Some(trace) = active(store)
    {
        // The native deindex may retire a stamp before removing its body or
        // edges. Keep that SAME execution's observed pre-retirement position.
        scope = trace.borrow().retired_positions.get(&id).cloned().flatten();
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

pub(crate) fn observe_position(store: &impl ManifestDbs, id: EntityId, scope: Scope) {
    if let Some(trace) = active(store) {
        let mut trace = trace.borrow_mut();
        trace.mutated.insert(id);
        trace.retired_positions.remove(&id);
        trace.positions.push(Position {
            id,
            scope: Some(scope),
            unborn: false,
        });
    }
}

pub(crate) fn observe_key_retirement(store: &impl ManifestDbs) {
    if let Some(trace) = active(store) {
        trace.borrow_mut().retires_keys = true;
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
