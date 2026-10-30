//! The claim-authoring campaign a wake's consolidation admissions read
//! (OF-366 R2, FIX 897). The host binds a root, never an admission: each
//! admission re-reads the campaign bound there against the promoted default.

use super::*;
use crate::attempt_queue::AttemptId;
use crate::autoreason_campaign::authoring::{
    AuthoringCampaign, ClaimAuthoringChoice, authoring_campaign, claim_authoring_admission,
};
use crate::autoreason_campaign::beam_promotion::{AuthoringStrategyPin, default_strategy};
use crate::dreamer_runner::{DreamerClaimAuthoringAdmission, DreamerTournamentClaim};
use crate::dreamer_wake::types::ClaimAuthoringFallback;

/// The claim-authoring campaign bound to one root. It holds the root only,
/// never a cached admission or one claim's metadata.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BoundClaimAuthoringSelector {
    root: AttemptId,
}

impl BoundClaimAuthoringSelector {
    /// Selects the campaign bound to `root`.
    #[must_use]
    pub const fn new(root: AttemptId) -> Self {
        Self { root }
    }

    /// The root the campaign is bound to.
    #[must_use]
    pub const fn root(self) -> AttemptId {
        self.root
    }

    /// The per-claim door: the strategy skill's typed `choice` for one fresh
    /// `claim`, under the bound campaign. Single-pass while no default is
    /// promoted.
    /// # Errors
    /// A missing campaign, one whose strategy is not the promoted default,
    /// any [`claim_authoring_admission`] refusal, or storage errors.
    pub fn claim_admission(
        self,
        vault: &Vault,
        choice: ClaimAuthoringChoice,
        claim: &DreamerTournamentClaim,
    ) -> Result<DreamerClaimAuthoringAdmission> {
        let Some(default) = default_strategy(vault)? else {
            return Ok(DreamerClaimAuthoringAdmission::single_pass());
        };
        self.promoted(vault, &default)?;
        claim_authoring_admission(vault, self.root, choice, claim.clone())
    }

    /// The batch admission: no one claim is fresh where a consolidation is
    /// admitted, so the bound campaign's single pass.
    fn batch_admission(
        self,
        vault: &Vault,
        default: &AuthoringStrategyPin,
    ) -> Result<DreamerClaimAuthoringAdmission> {
        Ok(self
            .promoted(vault, default)?
            .config
            .single_pass_admission())
    }

    /// The bound campaign, refused when it is missing or pins another
    /// strategy than the promoted default.
    fn promoted(self, vault: &Vault, default: &AuthoringStrategyPin) -> Result<AuthoringCampaign> {
        let Some(campaign) = authoring_campaign(vault, self.root)? else {
            return Err(crate::Error::InvalidConfig(
                "the selected claim-authoring campaign is not bound".into(),
            ));
        };
        if campaign.strategy != *default {
            return Err(crate::Error::InvalidConfig(
                "loaded authoring candidate does not match the promoted default".into(),
            ));
        }
        Ok(campaign)
    }
}

/// What a host binds for its wake's claim authoring.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ClaimAuthoringSelection {
    /// No bound campaign carries the promoted default.
    None,
    /// The one that does.
    Bound(BoundClaimAuthoringSelector),
    /// Several do: the pass authors single-pass and records their roots,
    /// never the first or newest (Engine 10-18).
    Ambiguous { roots: Vec<AttemptId> },
}

impl DreamerWakeDriver<'_> {
    /// Binds the campaign each consolidation admission re-reads.
    #[must_use]
    pub fn with_claim_authoring_selector(mut self, selector: BoundClaimAuthoringSelector) -> Self {
        self.claim_authoring = ClaimAuthoringSelection::Bound(selector);
        self
    }

    /// Several bound campaigns carry the promoted default: the pass authors
    /// single-pass and its report names `roots`.
    #[must_use]
    pub fn with_ambiguous_claim_authoring(mut self, roots: Vec<AttemptId>) -> Self {
        self.claim_authoring = ClaimAuthoringSelection::Ambiguous { roots };
        self
    }

    /// The admission a consolidation admission reads: single-pass with no
    /// promoted default; the bound campaign's, revalidated, with one; a
    /// visible single-pass when several campaigns carry it.
    pub(super) fn selected_claim_authoring(
        &self,
        report: &mut WakePassReport,
    ) -> Result<DreamerClaimAuthoringAdmission> {
        let Some(default) = default_strategy(self.vault)? else {
            return Ok(DreamerClaimAuthoringAdmission::single_pass());
        };
        match &self.claim_authoring {
            ClaimAuthoringSelection::None => Err(crate::Error::InvalidConfig(
                "promoted authoring strategy is not loaded by this wake driver".into(),
            )),
            ClaimAuthoringSelection::Bound(selector) => {
                selector.batch_admission(self.vault, &default)
            }
            ClaimAuthoringSelection::Ambiguous { roots } => {
                if report.claim_authoring_fallback.is_none() {
                    report.claim_authoring_fallback =
                        Some(ClaimAuthoringFallback::AmbiguousCampaigns {
                            roots: roots.clone(),
                        });
                }
                Ok(DreamerClaimAuthoringAdmission::single_pass())
            }
        }
    }
}
