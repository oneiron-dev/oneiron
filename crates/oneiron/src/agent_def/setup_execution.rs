//! The once-executed native setup in an abortable child of its real writer.

use super::setup_plan::PreparedAgentSetup;
use super::setup_trace::{ObservedSetupMutations, SetupMutationTrace};
use crate::Vault;
use crate::error::Result;
use crate::store::ManifestDbs;
use crate::store::key_custody::PrivateCustodyPublications;

/// The child transaction and private custody handles stay inside this value.
/// The caller keeps original authority separately while the child borrows its
/// writer. Dropping this value aborts the child and discards private resources.
pub(super) struct ExecutedAgentSetup<'vault, 'write> {
    child: heed::RwTxn<'write>,
    store: &'vault crate::store::Store,
    publications: PrivateCustodyPublications<'vault>,
    mutations: ObservedSetupMutations,
}

impl<'vault, 'write> ExecutedAgentSetup<'vault, 'write> {
    pub(super) fn execute(
        vault: &'vault Vault,
        parent: &'write mut heed::RwTxn<'_>,
        setup: PreparedAgentSetup,
    ) -> Result<Self>
    where
        'vault: 'write,
    {
        let publications = PrivateCustodyPublications::open(vault.store.key_custody());
        let trace = SetupMutationTrace::open(&vault.store);
        let mut child = vault.store.env.nested_write_txn(parent)?;
        setup.apply_in_private_child(vault, &mut child)?;
        let mutations = trace.finish()?;
        Ok(Self {
            child,
            store: &vault.store,
            publications,
            mutations,
        })
    }

    pub(super) fn mutations(&self) -> &ObservedSetupMutations {
        &self.mutations
    }

    /// The caller has the real Allow. This merges exactly the executed child;
    /// no native callback, allocation, sealing or preparation runs a second time.
    /// The parent still owns commit. As with ordinary native custody, a later
    /// error can leave published key/history surplus, not a rolled-back file.
    pub(super) fn merge_after_allow(self) -> Result<ObservedSetupMutations> {
        let Self {
            child,
            store,
            publications,
            mutations,
        } = self;
        child.commit()?;
        super::setup_trace::observe_merged_child(store, &mutations);
        publications.publish()?;
        Ok(mutations)
    }
}
