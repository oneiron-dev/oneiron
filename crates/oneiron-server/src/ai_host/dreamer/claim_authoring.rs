//! The claim-authoring campaign a Dreamer pass binds (OF-366 R2, FIX 897):
//! the root its consolidation admissions re-read, never an admission.

use oneiron::autoreason_campaign::{authoring, beam_promotion, research};
use oneiron::dreamer_wake::{BoundClaimAuthoringSelector, ClaimAuthoringSelection};
use oneiron::{AttemptId, Vault};

/// The binding policy (a CALL; canon is silent): the bound roots whose
/// claim-authoring campaign pins the promoted default. One binds; several
/// bind none, and the pass authors single-pass and records them, never the
/// first or newest (Engine 10-18). A read that fails binds none, so the
/// driver's consolidation admission refuses as it did before.
pub(super) fn claim_authoring_selection(vault: &Vault) -> ClaimAuthoringSelection {
    let roots = match promoted_roots(vault) {
        Ok(roots) => roots,
        Err(error) => {
            tracing::warn!(
                kind = ?error.kind(),
                "claim-authoring campaigns were not read; the pass binds none"
            );
            return ClaimAuthoringSelection::None;
        }
    };
    match roots.as_slice() {
        [] => ClaimAuthoringSelection::None,
        [root] => ClaimAuthoringSelection::Bound(BoundClaimAuthoringSelector::new(*root)),
        _ => ClaimAuthoringSelection::Ambiguous { roots },
    }
}

/// The bound roots whose campaign pins the promoted default, in root order;
/// none while no default is promoted.
fn promoted_roots(vault: &Vault) -> oneiron::Result<Vec<AttemptId>> {
    let Some(default) = beam_promotion::default_strategy(vault)? else {
        return Ok(Vec::new());
    };
    let mut roots = Vec::new();
    for root in research::bound_research_roots(vault)? {
        if authoring::authoring_campaign(vault, root)?
            .is_some_and(|campaign| campaign.strategy == default)
        {
            roots.push(root);
        }
    }
    Ok(roots)
}
