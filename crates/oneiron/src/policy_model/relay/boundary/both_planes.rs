//! The dual-plane door: both planes asked at once, and both receipted in one
//! final transaction.

use crate::Vault;
use crate::error::Result;
use crate::policy_model::clock::PolicyCallClock;
use crate::policy_model::concurrent::join2;
use crate::policy_model::request::{PolicyClassifyRequest, PolicyModelConfig};

use super::super::outcome::{DualPlanePass, RelaySafeguardTier, VaultSideVerdictSource};
use super::super::registry::EdgeServiceRegistry;
use super::super::trust::AttestedRelayDomain;
use super::RelayReceipt;

impl Vault {
    /// Both planes, one round trip.
    ///
    /// For content that BOTH leaves a vault under its owner's policy AND
    /// transits our relay under a hosted legal policy, the two model calls are
    /// independent — different documents, different rows, different machinery —
    /// so they are ISSUED CONCURRENTLY rather than one after the other. The
    /// latency of asking two planes is the latency of asking one.
    ///
    /// Each verdict is routed to its own plane: the hosted pass decides whether
    /// the relay may proceed, and the owner's verdict is the vault's to enforce.
    /// Neither is allowed to stand in for the other.
    ///
    /// BOTH planes are receipted, HERE, because this is the door that made
    /// both decisions. The relay pass writes its own row on the way through;
    /// the owner pass gets one under owner-plane keys, so a vault owner
    /// reading their own ledger finds their plane's verdict about their own
    /// content beside the hosted service's. A model that failed leaves a row
    /// too, saying the plane fell open.
    ///
    /// The owner verdict is handed back raw for the vault to enforce, and
    /// [`Vault::enforce_policy_model_verdict`] is where it goes. That door
    /// deliberately writes nothing: the decision is already in the ledger, and
    /// a second row for it under a second outcome would double every count
    /// read off those rows.
    pub async fn classify_both_planes(
        &self,
        request: PolicyClassifyRequest,
        domain: &AttestedRelayDomain,
        registry: &EdgeServiceRegistry,
        config: &PolicyModelConfig,
        safeguard: Option<RelaySafeguardTier<'_>>,
        verdicts: &dyn VaultSideVerdictSource,
    ) -> Result<DualPlanePass> {
        let owner_safeguard = safeguard.map(|tier| (tier.backend, tier.lease));
        let owner_clock = PolicyCallClock::start();
        let verify_at = self.relay_verify_at(&request, domain, config)?;
        let (owner, relay) = join2(
            self.owner_plane_pass_pinned(&request, config, owner_safeguard, &owner_clock),
            self.relay_boundary_pass_at(
                request.clone(),
                domain,
                registry,
                config,
                safeguard,
                verdicts,
                verify_at,
            ),
        )
        .await;
        let mut owner = owner?;
        let relay = relay?;
        // The owner half settled first and then waited on the hosted half,
        // so the manifest may have moved since it was pinned. Pin it again.
        if self.policy_model_verdict_is_stale_with_config(&owner.verdict, &request, config)? {
            owner = self
                .owner_plane_pass_pinned(&request, config, owner_safeguard, &owner_clock)
                .await?;
        }
        // Both halves are settled against the policy in force in ONE final
        // transaction, which writes their rows: the owner half to its answer
        // there, the hosted half (run here or reused) to the halting
        // binding-moved degrade if its binding moved. Checked in two
        // transactions, an edit between them would leave one half answering
        // a policy already replaced. No retry — the degrade is the typed
        // answer to a policy that will not hold.
        #[cfg(test)]
        crate::policy_model::in_force::before_settling(
            crate::policy_model::in_force::SettlingDoor::DualPlane,
        );
        let mut wtxn = self.store.env.write_txn()?;
        let owner = self.record_owner_plane_receipt_in_txn(&mut wtxn, &request, owner, config)?;
        let moved = self.relay_pass_moved_in_txn(
            &mut wtxn,
            &RelayReceipt {
                request: &request,
                domain,
                pass: &relay,
                receipt_breach: None,
                hosted: registry.hosted_legal_policy(domain.service_identity()),
                config,
                verify_at,
            },
        )?;
        wtxn.commit()?;
        let owner_model_skipped = owner.model_skipped();
        Ok(DualPlanePass {
            owner: owner.verdict,
            relay: moved.map(|(pass, _)| pass).unwrap_or(relay),
            owner_model_skipped,
        })
    }
}
