//! What a resolved policy lets one Dreamer actor do: read the whole vault,
//! and land a `Generated`-lineage claim as Auto at the unstamped band.
use super::PolicyManifestResolution;
use crate::claim::{ClaimSource, ScopedReadActorKey, UNSTAMPED_CLAIM_SENSITIVITY_BAND};
use crate::federation::Scope;
use crate::federation::scope_codec::read_preset;
use crate::gate::PolicyApprovalCeiling;
use crate::gate::grants::{scoped_read_actor_matches, scoped_read_grant_has_read_effector};

impl PolicyManifestResolution {
    /// A receipt-free, unbudgeted read grant whose authority covers every
    /// record a read can name (the read preset: every world, band and
    /// audience) with no purpose selectors narrowing it: a narrower grant
    /// would let some queued turn be unreadable.
    pub(in crate::gate) fn reads_whole_vault(&self, key: &ScopedReadActorKey) -> bool {
        !self.is_fail_closed()
            && !self.diagnostics().loaded_manifest_forces_fail_closed()
            && self.scoped_grants().iter().any(|grant| {
                scoped_read_grant_has_read_effector(grant)
                    && scoped_read_actor_matches(grant, key)
                    && !grant.receipt_required
                    && grant.budget.is_none()
                    && matches!(grant.scope, None | Some(rmpv::Value::Nil))
                    && grant
                        .authority_scope
                        .admits("read", &read_preset(), &Scope::top())
            })
    }

    /// An Auto actor ceiling and an actor-bound, receipted and warned
    /// `Generated` permit that reaches the band an unstamped consolidation
    /// claim carries.
    pub(in crate::gate) fn lands_generated_auto(&self, actor_class: &str, actor_ref: &str) -> bool {
        self.actor_ceiling(actor_class, Some(actor_ref)) == PolicyApprovalCeiling::Auto
            && !self.source_trust.malformed_manifest_seen
            && self
                .source_trust
                .row_for_actor(ClaimSource::Generated, Some(actor_ref))
                .is_some_and(|row| {
                    // Promotion admits Generated Auto only when receipted and
                    // warned, at a band the claim reaches.
                    row.actor_ref.is_some()
                        && row.receipted
                        && row.warned
                        && row
                            .max_auto_sensitivity
                            .is_some_and(|band| band >= UNSTAMPED_CLAIM_SENSITIVITY_BAND)
                })
    }
}
