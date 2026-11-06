//! Core half of `store::proposal_spool`: its store-layer items live in `oneiron_store::proposal_spool` and are
//! re-exported here; the items below stay in the engine.

pub use oneiron_store::proposal_spool::*;

use crate::error::CodeError;
use crate::{Error, Vault};
use std::{io, path::PathBuf, sync::Arc};

impl Vault {
    /// Lends the proposal spools of this vault's runs the host's measured
    /// disk floor (FIX 7650): the one its uploads keep, never one per run.
    /// The first lend holds.
    pub fn lend_proposal_spool(&self, spool: Arc<dyn ProposalSpoolFloor>) {
        let _ = self.proposal_spool.set(spool);
    }

    /// The floor this vault's host lent proposal spools, if it lent one.
    #[must_use]
    pub fn proposal_spool(&self) -> Option<Arc<dyn ProposalSpoolFloor>> {
        self.proposal_spool.get().cloned()
    }
}
