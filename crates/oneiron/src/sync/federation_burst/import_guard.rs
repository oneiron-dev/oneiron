//! Revalidate the retained batch and its acting proof in every import writer.
use std::cell::RefCell;
use super::{FederationBurstWorkState, FederationPeer, ledger};
use crate::{Result, Vault};

struct ActiveImport {
    vault: std::path::PathBuf,
    peer: FederationPeer,
    batch: [u8; 32],
    authority: [u8; 32],
}

thread_local! {
    static ACTIVE: RefCell<Vec<ActiveImport>> = const { RefCell::new(Vec::new()) };
}

struct Guard;
impl Drop for Guard {
    fn drop(&mut self) { ACTIVE.with(|active| { active.borrow_mut().pop(); }); }
}

pub(in crate::sync) fn with_import_guard<T>(
    vault: &Vault, peer: &FederationPeer, batch: &[u8; 32], authority: &[u8; 32], act: impl FnOnce() -> T,
) -> T {
    ACTIVE.with(|active| active.borrow_mut().push(ActiveImport {
        vault: vault.store.env.path().to_owned(), peer: peer.clone(), batch: *batch, authority: *authority,
    }));
    let _guard = Guard;
    act()
}

pub(crate) fn check_active_in_txn(vault: &Vault, txn: &heed::RoTxn<'_>) -> Result<()> {
    ACTIVE.with(|active| {
        for import in active.borrow().iter().filter(|import| import.vault.as_path() == vault.store.env.path()) {
            if import.peer.authority_digest_in_txn(vault, txn)? != import.authority {
                return Err(crate::Error::InvalidConfig("federation batch authority changed during import".into()));
            }
            if ledger::load(vault, txn, &import.peer, &import.batch)?
                .is_none_or(|row| row.state != FederationBurstWorkState::Pending)
            {
                return Err(crate::Error::InvalidConfig("federation batch is no longer pending".into()));
            }
        }
        Ok(())
    })
}
