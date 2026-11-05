//! The live CLAIM projected from its authenticated history.

use super::*;

/// Projects the live CLAIM id under its authenticated history. The verifier
/// never accepts a caller body merely because its key is enrolled.
impl Vault {
    pub fn resolved_machine_claim(&self, target: EntityId) -> Result<ResolvedMachineClaim> {
        let txn = self.store.env.read_txn()?;
        let fold = self.authority_fold_readonly_in_txn(&txn)?;
        let projection = resolved_machine_history(&self.store, &txn, &fold, target)?;
        let rows = machine_history_rows(&self.store, &txn, target)?;
        let handoff = trusted_machine_handoff(&self.store, &txn, target)?;
        Ok(ResolvedMachineClaim {
            claim_id: target,
            signed_origin: projection.birth.clone(),
            current: project_machine_claim(&projection),
            birth_digest: rows.birth.digest,
            transition_heads: projection.frontier,
            handoff_digest: handoff.content_hash().map_err(|_| bad())?,
        })
    }
}

/// Derive the public claim id's current body from immutable authored content
/// plus the closed, authenticated operation history. No peer-supplied body
/// or Loro LWW position participates in this projection.
pub(crate) fn project_machine_claim(projection: &ClaimTransitionProjection) -> ClaimBody {
    machine_claim_projector(projection)(projection.birth.clone())
}

/// Transfers the already-owned birth when no later caller needs the projection.
pub(crate) fn into_projected_machine_claim(projection: ClaimTransitionProjection) -> ClaimBody {
    let project = machine_claim_projector(&projection);
    project(projection.birth)
}

fn machine_claim_projector(
    projection: &ClaimTransitionProjection,
) -> impl FnOnce(ClaimBody) -> ClaimBody + use<> {
    let approval = projection.approval;
    let lifecycle = projection.lifecycle;
    let valid_to = projection.valid_to;
    let confidence = projection.confidence;
    let stale = projection.stale;
    let demotion_rung = projection.demotion_rung;
    let scope_band_floor = projection.scope_band_floor;
    move |mut body| {
        body.approval = approval;
        body.lifecycle = lifecycle;
        body.valid_to = valid_to;
        // The band and basis project as the birth stored them: a signed
        // weakening carries its number only, and a reader invents no pair for
        // it (FIX 7761).
        body.confidence = confidence;
        body.stale = stale;
        if demotion_rung.is_some() || scope_band_floor.is_some() {
            let mut scope = match body.scope.take() {
                Some(Value::Map(entries)) => entries,
                _ => Vec::new(),
            };
            if let Some(rung) = demotion_rung {
                scope.retain(|(key, _)| {
                    key.as_str() != Some(super::super::CLAIM_SCOPE_DEMOTION_RUNG_KEY)
                });
                let label = match rung {
                    super::super::ClaimDemotionRung::Decayed => "decayed",
                    super::super::ClaimDemotionRung::Weakened => "weakened",
                    super::super::ClaimDemotionRung::Stale => "stale",
                };
                scope.push((
                    Value::from(super::super::CLAIM_SCOPE_DEMOTION_RUNG_KEY),
                    Value::from(label),
                ));
            }
            if let Some(band) = scope_band_floor {
                scope.retain(|(key, _)| key.as_str() != Some("sensitivity"));
                scope.push((Value::from("sensitivity"), Value::from(band)));
            }
            body.scope = Some(Value::Map(scope));
        }
        body
    }
}
