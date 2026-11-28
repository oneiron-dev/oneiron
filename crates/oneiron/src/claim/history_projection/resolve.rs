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
        // The signed origin is the birth copy's whole first body, so it
        // returns only while that row reads: a birth withdrawn with its
        // sources (an erased MESSAGE, SIGNED-BIRTH-MESSAGE-SOURCES-UNREGISTERED)
        // withholds the resolution as an incomplete history does, whether the
        // gate verdict above was cached or read carrier by carrier.
        if !birth_reads_in_txn(&self.store, &txn, &rows.birth.event_id()?)? {
            return Err(missing());
        }
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

/// Whether the signed birth row `birth` reads by the raw doors' rule: stored,
/// its own words not withdrawn, and no source it derives from withdrawn.
fn birth_reads_in_txn(store: &Store, txn: &heed::RoTxn<'_>, birth: &EntityId) -> Result<bool> {
    match crate::ports::EntityStoreRead::port_entity_raw(store, txn, birth)? {
        Some(raw) => crate::ports::raw_readable_in_txn(store, txn, birth, &raw),
        None => Ok(false),
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
