//! Custody entries held by one native setup execution until its verdict.

use std::cell::RefCell;
use std::collections::BTreeMap;
use std::rc::Rc;

use heed::RoTxn;
use zeroize::Zeroizing;

use super::body_history::HistoryRow;
use super::{BINDING, CustodyBinding, CustodyId, CustodySecret, KeyCustody, STORE_IDENTITY};
use super::{EntryState, LocalCustody, binding_mismatch};
use crate::error::Result;
use crate::side_table::SideTableDbs;

thread_local! {
    static PUBLICATIONS: RefCell<Vec<Rc<RefCell<PrivatePublications>>>> = const {
        RefCell::new(Vec::new())
    };
}

enum Publication {
    Entry(CustodyId),
    Mint(CustodyId),
    History(Vec<HistoryRow>),
}

struct PrivatePublications {
    owner: usize,
    binding: Option<CustodyBinding>,
    entries: BTreeMap<CustodyId, CustodySecret>,
    publications: Vec<Publication>,
}

fn for_owner(owner: &KeyCustody) -> Option<Rc<RefCell<PrivatePublications>>> {
    let owner = std::ptr::from_ref(owner) as usize;
    PUBLICATIONS.with(|publications| {
        publications
            .borrow()
            .iter()
            .rev()
            .find(|entry| entry.borrow().owner == owner)
            .cloned()
    })
}

fn for_custody(custody: &LocalCustody<'_>) -> Option<Rc<RefCell<PrivatePublications>>> {
    let owner = custody.private_owner()?;
    PUBLICATIONS.with(|publications| {
        publications
            .borrow()
            .iter()
            .rev()
            .find(|entry| {
                let entry = entry.borrow();
                entry.owner == owner && entry.binding.as_ref() == Some(custody.binding())
            })
            .cloned()
    })
}

fn copy_secret(secret: &CustodySecret) -> CustodySecret {
    CustodySecret::from_bytes(Zeroizing::new(secret.expose().to_vec()))
}

/// The same thread and writer run the native program and retain its entries.
/// Dropping this scope discards them without publishing a binding or a file.
/// The owner removes it before publishing the retained bytes, never re-running
/// the native program that sealed its rows.
pub(crate) struct PrivateCustodyPublications<'a> {
    owner: &'a KeyCustody,
    state: Rc<RefCell<PrivatePublications>>,
}

impl<'a> PrivateCustodyPublications<'a> {
    pub(crate) fn open(owner: &'a KeyCustody) -> Self {
        let state = Rc::new(RefCell::new(PrivatePublications {
            owner: std::ptr::from_ref(owner) as usize,
            binding: owner.binding.get().cloned(),
            entries: BTreeMap::new(),
            publications: Vec::new(),
        }));
        PUBLICATIONS.with(|publications| publications.borrow_mut().push(Rc::clone(&state)));
        Self { owner, state }
    }

    fn detach(&self) {
        PUBLICATIONS.with(|publications| {
            publications
                .borrow_mut()
                .retain(|entry| !Rc::ptr_eq(entry, &self.state));
        });
    }

    /// Called only after the real Allow while the ultimate writer is held.
    /// Every entry is the exact key the once-executed native program used.
    /// A different live entry is an error, never a replacement sealing key.
    pub(crate) fn publish(self) -> Result<()> {
        self.detach();
        let mut state = self.state.borrow_mut();
        let Some(binding) = state.binding.as_ref() else {
            return Ok(());
        };
        self.owner.adopt(Some(binding))?;
        let custody = self.owner.checked(Some(binding))?;
        for publication in &state.publications {
            match publication {
                Publication::Entry(id) => custody.publish(id, &state.entries[id])?,
                Publication::Mint(id) => custody.journal_mint(id)?,
                Publication::History(rows) => self.owner.journal_body_history(rows.clone())?,
            }
        }
        state.publications.clear();
        Ok(())
    }
}

impl Drop for PrivateCustodyPublications<'_> {
    fn drop(&mut self) {
        self.detach();
    }
}

pub(super) fn local(owner: &KeyCustody) -> Option<Option<LocalCustody<'static>>> {
    let state = for_owner(owner)?;
    let state = state.borrow();
    Some(
        state
            .binding
            .clone()
            .map(|binding| LocalCustody::owned(state.owner, binding)),
    )
}

pub(super) fn adopt(owner: &KeyCustody, committed: Option<&CustodyBinding>) -> Option<Result<()>> {
    let state = for_owner(owner)?;
    let mut state = state.borrow_mut();
    if state.binding.is_none()
        && let Some(committed) = committed
    {
        if committed.root() != owner.home.as_path() {
            return Some(Err(binding_mismatch()));
        }
        state.binding = Some(committed.clone());
    }
    Some(Ok(()))
}

pub(super) fn bind(
    owner: &KeyCustody,
    dbs: &impl SideTableDbs,
    txn: &RoTxn<'_>,
) -> Option<Result<LocalCustody<'static>>> {
    let state = for_owner(owner)?;
    Some((|| {
        let committed = BINDING.get(dbs, txn, &())?;
        let mut state = state.borrow_mut();
        if state.binding.is_none()
            && let Some(committed) = &committed
        {
            if committed.root() != owner.home.as_path() {
                return Err(binding_mismatch());
            }
            state.binding = Some(committed.clone());
        }
        if state.binding.is_none() {
            let vault = STORE_IDENTITY.get(dbs, txn, &())?;
            state.binding = Some(CustodyBinding::mint(owner.home.clone(), vault));
        }
        let binding = state.binding.as_ref().ok_or_else(binding_mismatch)?;
        if committed
            .as_ref()
            .is_some_and(|committed| committed != binding)
        {
            return Err(binding_mismatch());
        }
        Ok(LocalCustody::owned(state.owner, binding.clone()))
    })())
}

pub(super) fn read(custody: &LocalCustody<'_>, id: &CustodyId) -> Option<Result<CustodySecret>> {
    let state = for_custody(custody)?;
    if !state.borrow().entries.contains_key(id) {
        return None;
    }
    Some((|| {
        if custody.retired(id)? {
            return Err(id.kind().corrupt());
        }
        state
            .borrow()
            .entries
            .get(id)
            .map(copy_secret)
            .ok_or_else(|| id.kind().corrupt())
    })())
}

pub(super) fn contains(custody: &LocalCustody<'_>, id: &CustodyId) -> bool {
    for_custody(custody).is_some_and(|state| state.borrow().entries.contains_key(id))
}

pub(super) fn ids(custody: &LocalCustody<'_>) -> Vec<CustodyId> {
    for_custody(custody).map_or_else(Vec::new, |state| {
        state.borrow().entries.keys().cloned().collect()
    })
}

pub(super) fn get_or_create(
    custody: &LocalCustody<'_>,
    id: &CustodyId,
) -> Option<Result<CustodySecret>> {
    let state = for_custody(custody)?;
    Some((|| {
        if custody.retired(id)? {
            return Err(id.kind().corrupt());
        }
        let held = state.borrow().entries.get(id).map(copy_secret);
        if let Some(secret) = held {
            let mut state = state.borrow_mut();
            state.publications.push(Publication::Entry(id.clone()));
            state.publications.push(Publication::Mint(id.clone()));
            return Ok(secret);
        }
        let secret = match custody.physical_state(id)? {
            EntryState::Retired => return Err(id.kind().corrupt()),
            EntryState::Live => custody.read_after_pending_cleanup(id)?,
            EntryState::Missing => CustodySecret::random(id.kind().secret_len()),
        };
        let returned = copy_secret(&secret);
        let mut state = state.borrow_mut();
        state.entries.insert(id.clone(), secret);
        state.publications.push(Publication::Entry(id.clone()));
        state.publications.push(Publication::Mint(id.clone()));
        Ok(returned)
    })())
}

pub(super) fn publish(
    custody: &LocalCustody<'_>,
    id: &CustodyId,
    secret: &CustodySecret,
) -> Option<Result<()>> {
    let state = for_custody(custody)?;
    Some((|| {
        if secret.expose().len() != id.kind().secret_len() {
            return Err(id.kind().corrupt());
        }
        if custody.retired(id)? {
            return Err(id.kind().corrupt());
        }
        if let Some(held) = state.borrow().entries.get(id) {
            if held.expose() != secret.expose() {
                return Err(id.kind().corrupt());
            }
        } else {
            match custody.physical_state(id)? {
                EntryState::Retired => return Err(id.kind().corrupt()),
                EntryState::Live => {
                    if custody.read_after_pending_cleanup(id)?.expose() != secret.expose() {
                        return Err(id.kind().corrupt());
                    }
                }
                EntryState::Missing => {}
            }
        }
        let mut state = state.borrow_mut();
        state
            .entries
            .entry(id.clone())
            .or_insert_with(|| copy_secret(secret));
        state.publications.push(Publication::Entry(id.clone()));
        Ok(())
    })())
}

pub(super) fn journal_mint(custody: &LocalCustody<'_>, id: &CustodyId) -> bool {
    let Some(state) = for_custody(custody) else {
        return false;
    };
    state
        .borrow_mut()
        .publications
        .push(Publication::Mint(id.clone()));
    true
}

pub(super) fn journal_history(owner: &KeyCustody, rows: &[HistoryRow]) -> bool {
    let Some(state) = for_owner(owner) else {
        return false;
    };
    if state.borrow().binding.is_some() {
        state
            .borrow_mut()
            .publications
            .push(Publication::History(rows.to_vec()));
    }
    true
}
