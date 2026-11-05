//! Current phone-call consent, conjoined with every entity row admission.

use super::*;

impl ScopedRead<'_> {
    pub(super) fn phone_lines_allow_in(
        &self,
        txn: &heed::RoTxn<'_>,
        id: &EntityId,
        raw: &[u8],
    ) -> Result<bool> {
        if self.actor_key.phone_lines.is_empty() {
            return Ok(true);
        }
        let record = match self.session_view {
            Some(view) => crate::federation::record_scope::scope_for_blob(view, txn, *id, raw)?,
            None => {
                crate::federation::record_scope::scope_for_blob(&self.vault.store, txn, *id, raw)?
            }
        };
        let Some(record) = record else {
            return Ok(false);
        };
        for ceiling in &self.actor_key.phone_lines {
            let Some(scope) =
                ceiling.current_scope_in(self.vault, txn, self.actor_key.actor_ref())?
            else {
                return Ok(false);
            };
            let scope = ScopedReadActorKey::read_authority(&scope);
            if !scope.admits("read", &record, &crate::federation::Scope::top()) {
                return Ok(false);
            }
            // Facets use the native placement rule, not Scope::admits, and
            // explicit line consent has no owner-facet exemption.
            let facets = match self.session_view {
                Some(view) => crate::federation::facet_read::facets_admit_in(
                    self.vault,
                    view,
                    txn,
                    *id,
                    raw,
                    &scope.facets,
                )?,
                None => crate::federation::facet_read::facets_admit_in(
                    self.vault,
                    &self.vault.store,
                    txn,
                    *id,
                    raw,
                    &scope.facets,
                )?,
            };
            if !facets {
                return Ok(false);
            }
        }
        Ok(true)
    }
}
