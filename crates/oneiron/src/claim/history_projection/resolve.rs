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
    let mut body = projection.birth.clone();
    body.approval = projection.approval;
    body.lifecycle = projection.lifecycle;
    body.valid_to = projection.valid_to;
    // The band and basis project as the birth stored them: a signed
    // weakening carries its number only, and a reader invents no pair for
    // it (FIX 7761).
    body.confidence = projection.confidence;
    body.stale = projection.stale;
    if projection.demotion_rung.is_some() || projection.scope_band_floor.is_some() {
        let mut scope = match body.scope.take() {
            Some(Value::Map(entries)) => entries,
            _ => Vec::new(),
        };
        if let Some(rung) = projection.demotion_rung {
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
        if let Some(band) = projection.scope_band_floor {
            scope.retain(|(key, _)| key.as_str() != Some("sensitivity"));
            scope.push((Value::from("sensitivity"), Value::from(band)));
        }
        body.scope = Some(Value::Map(scope));
    }
    body
}
