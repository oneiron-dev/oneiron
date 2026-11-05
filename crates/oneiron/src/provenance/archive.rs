//! Foreign archive provenance reconstructed through the owning lifecycle.
use super::writes::EdgeProvenanceWrite;
use super::*;
use crate::claim::{ClaimApprovalStatus, ClaimSource, ClaimSubject};
use crate::edge::{EdgeValueLayout, edge_value_layout_for_kind};
use crate::temporal::TimeRange;
use std::collections::BTreeMap;

/// Decode a canonical foreign row into its deterministic imported wrapper.
/// MODEL refs bind by name/version through the caller's owning-domain prepass.
pub(crate) fn archived_provenance_body(
    body: &ClaimBody,
    models: &BTreeMap<EntityId, EntityId>,
) -> Result<ClaimBody> {
    if body.predicate != PREDICATE_EDGE_PROVENANCE
        || !matches!(body.subject, ClaimSubject::Edge { .. })
    {
        return Err(invalid("archive row is not edge provenance"));
    }
    if body.world.is_some()
        || body.rel.is_some()
        || body.salience.is_some()
        || body.session_tag.is_some()
        || body.stale
    {
        return Err(invalid("archive provenance has unsupported wrapper fields"));
    }
    let mut record = decode_edge_provenance_body(&body.value)?;
    let class = resolve_persisted_actor_class(&record, body.evidence.as_ref())?;
    if record.confidence != body.confidence
        || record.valid_from != body.valid_from
        || record.valid_to != body.valid_to
        || !matches!(
            body.approval,
            ClaimApprovalStatus::Auto | ClaimApprovalStatus::Approved
        )
    {
        return Err(invalid("archive provenance wrapper disagrees with record"));
    }
    if let Some(id) = record.substrate_ref {
        record.substrate_ref = Some(
            *models
                .get(&id)
                .ok_or_else(|| invalid("archive provenance MODEL missing"))?,
        );
    }
    record.actor_class = Some(class);
    let mut result = body.clone();
    result.value = encode_edge_provenance_value(&record);
    result.approval = ClaimApprovalStatus::Auto;
    result.evidence = None;
    // Archive scope is retained as data, not installed as local trust policy.
    let evidence = Value::Map(vec![(
        "archive_scope".into(),
        body.scope.clone().unwrap_or(Value::Nil),
    )]);
    imported::stamp_imported_source(&mut result, evidence);
    Ok(result)
}
impl Vault {
    /// One new row, in ascending learned-at order. Closed history is staged in
    /// the same uncommitted transaction; caller must compare the final cohort.
    /// `cut` marks an authored-cut cohort (blind-review P1c, REVIEW-4389):
    /// its subject edge is gone, so the restore replays the claim chain
    /// without the edge and never recreates the deleted link.
    pub(crate) fn restore_archived_provenance_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        id: &EntityId,
        body: &ClaimBody,
        occurred: TimeRange,
        learned_at: u64,
        explicit_prior: Option<&EntityId>,
        cut: bool,
    ) -> Result<()> {
        if body.source != Some(ClaimSource::Imported) {
            return Err(invalid("archive source floor missing"));
        }
        let record = decode_edge_provenance_body(&body.value)?;
        if occurred.start != record.valid_from.unwrap_or(learned_at)
            || occurred.end != record.valid_to.unwrap_or(u64::MAX)
        {
            return Err(invalid("archive provenance time envelope disagrees"));
        }
        let class = resolve_persisted_actor_class(&record, body.evidence.as_ref())?;
        let ClaimSubject::Edge {
            source,
            kind,
            target,
        } = body.subject
        else {
            return Err(invalid("archive provenance subject"));
        };
        // The archived assertion status travels in the put body exactly as a
        // native write carries it (FIX 9594): a Confirmed or Disputed row is
        // never flattened to Proposed; supersession closures preserve it, and
        // the retract below still stamps Retracted.
        let scope = body
            .scope
            .as_ref()
            .and_then(Value::as_map)
            .and_then(|entries| {
                entries
                    .iter()
                    .find(|(key, _)| key.as_str() == Some("imported_evidence"))
            })
            .map(|(_, value)| value.clone())
            .ok_or_else(|| invalid("archive evidence scope missing"))?;
        // A validated archived structural wrapper restores through the
        // structural-aware inlet (blind-review P1c, REVIEW-4389): it was
        // authored through the structural door, so ordinary writes keep
        // their static-kind rejection while this restore replays its own.
        let allow_structural =
            edge_value_layout_for_kind(kind, false) == EdgeValueLayout::Structural;
        let write = EdgeProvenanceWrite {
            claim_id: id,
            subject: &EdgeRef::new(source, kind, target),
            body: &record,
            actor_class: class,
            learned_at,
            explicit_prior,
            scope_project: Some(body.scope_project),
            imported_evidence: Some(scope),
            generated_evidence: None,
        };
        if cut {
            self.restore_cut_edge_provenance_in_txn(txn, write, allow_structural)?;
        } else {
            self.restore_edge_provenance_in_txn(txn, write, allow_structural)?;
        }
        if body.lifecycle == ClaimLifecycleStatus::Retracted {
            self.retract_edge_provenance_in_txn(
                txn,
                id,
                body.valid_to
                    .ok_or_else(|| invalid("retracted archive missing close time"))?,
                cut,
            )?;
        }
        Ok(())
    }
}
fn invalid(reason: &str) -> Error {
    Error::InvalidConfig(format!("provenance archive: {reason}"))
}
