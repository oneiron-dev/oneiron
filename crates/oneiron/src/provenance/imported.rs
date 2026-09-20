//! Internal imported-edge admission. No permit is created by this door.

use super::writes::EdgeProvenanceWrite;
use super::*;
use crate::WriteActor;
use crate::claim::ClaimSource;
use crate::error::ClaimError;
use crate::ports::EdgeStoreRead;
use crate::ports::EntityStoreRead;

/// Provider identity belongs to the imported relationship's scope. The canonical
/// provenance wrapper leaves `evid` absent: any value there conflicts with the
/// record's `actor_class` under the pinned parser. This scope is data, never actor
/// or permit authority.
const IMPORTED_EVIDENCE_SCOPE_KEY: &str = "imported_evidence";

fn imported_evidence_scope(evidence: Value) -> Value {
    Value::Map(vec![(Value::from(IMPORTED_EVIDENCE_SCOPE_KEY), evidence)])
}

pub(super) fn stamp_imported_source(body: &mut ClaimBody, evidence: Value) {
    body.source = Some(ClaimSource::Imported);
    body.scope = Some(imported_evidence_scope(evidence));
}

/// Provider-owned identity and evidence; the actor is always the actual importer.
pub(crate) struct ImportedEdgeProvenance {
    pub(crate) claim_id: EntityId,
    pub(crate) subject: EdgeRef,
    pub(crate) actor: WriteActor,
    pub(crate) evidence: Value,
    pub(crate) weight: f32,
    pub(crate) learned_at: u64,
}

impl Vault {
    /// Returns true on creation. An existing edge must have the exact imported
    /// identity and canonical flags; it is never upgraded or overwritten here.
    pub(crate) fn resolve_imported_edge_provenance(
        &self,
        import: ImportedEdgeProvenance,
    ) -> Result<bool> {
        if import.evidence.is_nil() {
            return Err(Error::Claim(ClaimError::InvalidProvenanceBody(
                "imported evidence is required",
            )));
        }
        self.with_write_txn(|wtxn| {
            let subject = &import.subject;

            if let Some(edge) =
                self.store
                    .port_edge_get(wtxn, &subject.source, subject.kind, &subject.target)?
            {
                if !self.store.port_edge_consistent(
                    wtxn,
                    &subject.source,
                    subject.kind,
                    &subject.target,
                )? {
                    return Err(Error::CorruptedIndex("imported edge directions disagree"));
                }
                let stored = self.load_provenance_claim_in_txn(wtxn, &import.claim_id)?;
                if stored.subject != *subject
                    || stored.wrapper.source != Some(ClaimSource::Imported)
                    || stored.wrapper.scope.as_ref()
                        != Some(&imported_evidence_scope(import.evidence.clone()))
                    || stored.record.actor_entity_ref != import.actor.entity_ref()
                    || stored.actor_class != import.actor.actor_class()
                {
                    return Err(Error::Claim(ClaimError::InvalidProvenanceBody(
                        "imported edge identity mismatch",
                    )));
                }
                let actor_raw = self
                    .store
                    .port_entity_record(wtxn, &import.actor.entity_ref())?
                    .ok_or(Error::EntityNotFound)?;
                validate_actor_class(actor_raw.entity_type, import.actor.actor_class())?;
                let live = self.live_edge_provenance_claims_in_txn(wtxn, subject, None)?;
                let precedence: Vec<_> =
                    live.iter().map(StoredProvenanceClaim::precedence).collect();
                let verified = match winner_index(&precedence) {
                    Some(index) => live[index].id == import.claim_id,
                    None => {
                        stored.wrapper.lifecycle == ClaimLifecycleStatus::Retracted
                            && self
                                .retracted_edge_provenance_claims_in_txn(wtxn, subject, None)?
                                .iter()
                                .any(|claim| claim.id == import.claim_id)
                    }
                };
                if !verified || edge.provenance != Some(stored.flags()) {
                    return Err(Error::Claim(ClaimError::InvalidProvenanceBody(
                        "imported edge provenance is not authoritative",
                    )));
                }
                let policy = crate::gate::resolve_policy_manifest(&self.store, wtxn)?;
                crate::gate::check_edge_provenance_claim_policy(
                    &self.store,
                    wtxn,
                    &stored.wrapper,
                    &stored.record,
                    stored.actor_class,
                    &policy,
                )?;
                return Ok(false);
            }
            // Staging an absent edge is not a bare-edge bypass: canonical
            // provenance validation and Gate must succeed before this txn commits.
            self.batch_in()
                .edge(
                    &subject.source,
                    subject.kind,
                    &subject.target,
                    import.weight,
                )
                .apply(wtxn)?;
            let record = EdgeProvenanceClaimBody::new(
                import.actor.entity_ref(),
                1.0,
                SupersessionStatus::Proposed,
            );
            self.write_edge_provenance_in_txn(
                wtxn,
                EdgeProvenanceWrite {
                    claim_id: &import.claim_id,
                    subject,
                    body: &record,
                    actor_class: import.actor.actor_class(),
                    learned_at: import.learned_at,
                    explicit_prior: None,
                    imported_evidence: Some(import.evidence),
                    generated_evidence: None,
                },
            )?;
            Ok(true)
        })
    }
}

#[cfg(test)]
mod tests;
