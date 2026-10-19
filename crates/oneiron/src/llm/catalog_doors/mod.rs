//! Catalog refresh is evidence, never permission to route. All writes validate
//! the owner's own proof in the same transaction as their guarded state.
mod bindings;
mod trials;
mod types;
pub use types::*;

use crate::consent::AuthenticatedOwner;
use crate::llm::registry::invalid;
use crate::side_table::{self, Named, SideTable};
use crate::{EntityId, Error, Result, Vault};
use std::collections::{BTreeMap, BTreeSet};

const REVISIONS: SideTable<String, ModelCatalogRevision, Named> =
    SideTable::new(&side_table::LLM_CATALOG_REVISION);
const HEAD: SideTable<(), String, Named> = SideTable::new(&side_table::LLM_CATALOG_HEAD);
const TRIAL_CATALOG: SideTable<EntityId, String, Named> =
    SideTable::new(&side_table::LLM_TRIAL_CATALOG);
const PROPOSALS: SideTable<EntityId, ModelBindingProposal, Named> =
    SideTable::new(&side_table::LLM_BINDING_PROPOSAL);

fn revision(vault: &Vault, txn: &heed::RoTxn<'_>, id: &str) -> Result<ModelCatalogRevision> {
    REVISIONS.get(&vault.store, txn, &id.to_owned())?.ok_or(Error::EntityNotFound)
}

fn current(vault: &Vault, txn: &heed::RoTxn<'_>, expected: &str) -> Result<ModelCatalogRevision> {
    if HEAD.get(&vault.store, txn, &())?.as_deref() != Some(expected) {
        return Err(Error::ConcurrentWrite("model catalog revision changed"));
    }
    revision(vault, txn, expected)
}

impl Vault {
    pub fn refresh_model_catalog_as_owner(
        &self,
        owner: &AuthenticatedOwner,
        input: ModelCatalogRefresh,
    ) -> Result<ModelCatalogRevision> {
        let mut txn = self.store.env.write_txn()?;
        owner.revalidate_in_txn(self, &txn)?;
        if input.revision.trim().is_empty() || input.revision.len() > 256 || input.revision.contains('\0') {
            return Err(invalid("invalid model catalog revision"));
        }
        let previous_revision = HEAD.get(&self.store, &txn, &())?;
        if previous_revision != input.expected_revision {
            return Err(Error::ConcurrentWrite("model catalog revision changed"));
        }
        if REVISIONS.get(&self.store, &txn, &input.revision)?.is_some() {
            return Err(invalid("model catalog revision is immutable"));
        }
        let prior = previous_revision.as_deref().map(|id| revision(self, &txn, id)).transpose()?;
        self.refresh_model_catalog_in_txn(&mut txn, &input.catalog, prior.as_ref().map(|value| &value.catalog))?;
        let score_diffs = self.apply_model_score_snapshots_in_txn(&mut txn, &input.scores)?;
        let result = ModelCatalogRevision {
            revision: input.revision,
            previous_revision,
            catalog: input.catalog,
            rows: self.model_registry_rows_in_txn(&txn)?,
            score_diffs,
            refreshed_at: crate::ports::recorded_at_in_txn(&self.store, &mut txn)?,
        };
        REVISIONS.put(self, &mut txn, &result.revision, &result)?;
        HEAD.put(self, &mut txn, &(), &result.revision)?;
        txn.commit()?;
        Ok(result)
    }

    pub fn model_catalog_as_owner(&self, owner: &AuthenticatedOwner, input: ModelCatalogGet) -> Result<ModelCatalogRevision> {
        let txn = self.store.env.read_txn()?;
        owner.revalidate_in_txn(self, &txn)?;
        let id = input.revision.or(HEAD.get(&self.store, &txn, &())?).ok_or(Error::EntityNotFound)?;
        revision(self, &txn, &id)
    }

    pub fn diff_model_catalog_as_owner(&self, owner: &AuthenticatedOwner, input: ModelCatalogDiffRequest) -> Result<ModelCatalogDiff> {
        let txn = self.store.env.read_txn()?;
        owner.revalidate_in_txn(self, &txn)?;
        let from = revision(self, &txn, &input.from)?;
        let to = revision(self, &txn, &input.to)?;
        let old: BTreeMap<_, _> = from.rows.into_iter().map(|row| (row.catalog.model.clone(), row)).collect();
        let new: BTreeMap<_, _> = to.rows.into_iter().map(|row| (row.catalog.model.clone(), row)).collect();
        let models: BTreeSet<_> = old.keys().chain(new.keys()).cloned().collect();
        let changes = models.into_iter().filter_map(|model| {
            let previous = old.get(&model).cloned();
            let current = new.get(&model).cloned();
            (previous != current).then_some(ModelCatalogChange { model, previous, current })
        }).collect();
        Ok(ModelCatalogDiff { from: input.from, to: input.to, changes })
    }
}
