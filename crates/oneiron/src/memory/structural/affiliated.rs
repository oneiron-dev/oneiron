//! Attributed takes, companion records, and imported-claim admission verbs.

use crate::claim::{ClaimApprovalStatus, ClaimSource};
use crate::companion::{
    CompanionExportClassification, CompanionProvenance, CompanionRecord, CompanionScope,
};
use crate::edge::EdgeKind;
use crate::entity_id::EntityId;
use crate::error::ErrorKind;
use crate::ingest::{
    INGEST_SOURCE_REGISTRY, ImportedEvidenceAdmission, ImportedEvidenceEntityResolution,
    NormalizedIngestClaim, admit_imported_evidence_claim,
};
use crate::memory::claims::parse_claim_source;
use crate::memory::support::{
    facade_provenance, hard_deleted_refusal, id_from_optional_hex, json_to_rmpv,
};
use crate::memory::{CommitReceipt, Memory, MemoryError, MemoryResult};
use crate::note::{NoteBody, NoteKind, TakeTarget, encode_note_body};
use crate::registry::ENTITY_TYPE_CLAIM;
use crate::temporal::TimeRange;
use crate::write_envelope::{WriteActor, WriteEnvelope, WriteProvenance};

use super::{
    AdmitImportedClaimInput, CompanionRecordInput, EntityRefReceipt, registered_edge_weight,
};
impl Memory<'_> {
    // ── B2 migrator write-verb group ────────────────────────────────────

    /// Appends one attributed `opinion/take` NOTE beside `target`
    /// (ARCH-0032 · OF-330).
    ///
    /// Attribution is engine-stamped: the stored `author_ref` and the
    /// mandatory `NOTE ─AuthoredBy→ actor` edge both come from the actor
    /// bound to this facade, revalidated against the store inside this write
    /// transaction. The input carries no author field, so there is nothing a
    /// caller can spoof, and this is the only NOTE writer there is: the raw
    /// batch put refuses the type, leaving no second door to hand-write a
    /// body through.
    ///
    /// Neutrality is the whole point (ARCH-0003). A take over a CLAIM writes
    /// a NOTE plus an inbound `ClaimOf` edge and NOTHING else — no put,
    /// supersede, or retract reaches the target — so the target's raw body,
    /// lifecycle, learned-at, and content hash are byte-identical afterwards.
    /// Takes are append-only entities, not an upsert keyed by
    /// `(actor, target)`: two actors over one claim produce two NOTE ids and
    /// two independent `AuthoredBy` edges.
    ///
    /// Every rejection — unbound or wrong-class actor, missing target, and a
    /// `TakeTarget::Claim` that is not type-0 — happens before a single row is
    /// staged, so a refused take leaves no orphan NOTE or edge.
    ///
    /// Exempt from the hard-delete recreation refusal BY CONSTRUCTION: the
    /// NOTE id is a fresh [`EntityId::now`], never caller-supplied.
    pub fn author_take(
        &self,
        target: TakeTarget,
        markdown: impl Into<String>,
    ) -> MemoryResult<EntityRefReceipt> {
        let body = encode_note_body(&NoteBody {
            kind: NoteKind::OpinionTake,
            author_ref: self.actor,
            markdown: markdown.into(),
        })?;
        let note_id = EntityId::now();
        let at = crate::unix_seconds_now();
        let occurred = TimeRange { start: at, end: at };
        let (target_id, link, target_must_be_claim) = match target {
            TakeTarget::Subject(id) => (id, EdgeKind::About, false),
            TakeTarget::Claim(id) => (id, EdgeKind::ClaimOf, true),
        };

        self.with_verified_actor_write_txn(|wtxn| {
            let Some(stored_type) = self.vault.get_entity_type_in_txn(&*wtxn, &target_id)? else {
                return Err(MemoryError::not_found(format!(
                    "take target {} does not exist",
                    target_id.to_hex()
                )));
            };
            if target_must_be_claim && stored_type != ENTITY_TYPE_CLAIM {
                return Err(MemoryError::bad_request_with(
                    format!("take target {} is not a CLAIM", target_id.to_hex()),
                    &["Use TakeTarget::Subject to take a position on a non-claim entity."],
                ));
            }
            self.vault
                .batch_in()
                .put_authored_note(&note_id, &self.actor, occurred, at, &body)
                .edge(
                    &note_id,
                    EdgeKind::AuthoredBy,
                    &self.actor,
                    registered_edge_weight(EdgeKind::AuthoredBy),
                )
                .edge(&note_id, link, &target_id, registered_edge_weight(link))
                .apply(wtxn)?;
            Ok(())
        })?;
        self.entity_ref_receipt(&note_id)
    }

    /// Registers a companion persona record (personal scope) with a
    /// `created` lifecycle event, retiring it when `retired_at` is set.
    pub fn put_companion_record(
        &self,
        input: &CompanionRecordInput,
    ) -> MemoryResult<EntityRefReceipt> {
        let id = id_from_optional_hex(input.id.as_deref())?;
        self.refuse_hard_deleted_id(&id)?;
        let owner = self.resolve_ref(&input.owner_ref)?;
        let persona = self.resolve_ref(&input.persona_ref)?;
        let source = match &input.source {
            Some(source) => parse_claim_source(source)?,
            None => ClaimSource::UserStated,
        };
        let envelope = WriteEnvelope::new(
            WriteActor::new(self.actor, self.actor_class),
            source,
            WriteProvenance::new(facade_provenance("put_companion_record"))?,
            ClaimApprovalStatus::Approved,
        );
        let record = CompanionRecord::persona(
            CompanionScope::personal(owner),
            persona,
            json_to_rmpv(&input.value),
            CompanionProvenance::from_envelope(&envelope),
            CompanionExportClassification::LocalOnly,
        );
        self.with_verified_actor_write_txn(|wtxn| {
            // The early refusal above is only a fast path. Recheck in this
            // transaction so a concurrent hard delete cannot land between
            // the probe and companion creation, resurrecting a purged id.
            if self
                .vault
                .local_hard_delete_marker_exists_in_txn(wtxn, &id)?
            {
                return Err(hard_deleted_refusal(&id));
            }
            self.vault
                .create_companion_record_in_txn(wtxn, &id, &record, input.learned_at)?;
            if let Some(retired_at) = input.retired_at {
                self.vault
                    .retire_companion_record_in_txn(wtxn, &id, retired_at)?;
            }
            Ok(())
        })?;
        self.entity_ref_receipt(&id)
    }

    /// Admits one imported-evidence claim through the registered ingest
    /// source's trust ceiling (B1a). Unknown sources fail closed. The
    /// requested approval is `auto` only when the ceiling permits it at
    /// band 0; the gate still decides, and a refused `auto` request is
    /// resubmitted `proposed`.
    pub fn admit_imported_claim(
        &self,
        input: &AdmitImportedClaimInput,
    ) -> MemoryResult<CommitReceipt> {
        self.verified_actor_class()?;
        let Some(config) = INGEST_SOURCE_REGISTRY.get_config(&input.source_id) else {
            return Err(MemoryError::bad_request_with(
                format!("unknown ingest source {:?}", input.source_id),
                &["Register the source in the ingest source registry first."],
            ));
        };
        let id = id_from_optional_hex(input.id.as_deref())?;
        self.refuse_hard_deleted_id(&id)?;
        let subject = self.resolve_ref(&input.subject_ref)?;
        if self.vault.get_entity_type(&subject)?.is_none() {
            return Err(MemoryError::not_found(format!(
                "claim subject {} does not exist",
                subject.to_hex()
            )));
        }
        let claim = NormalizedIngestClaim {
            source_record_id: input.source_record_id.clone(),
            predicate: input.predicate.clone(),
            value: input.value.clone(),
        };
        let occurred = TimeRange {
            start: input.occurred_at,
            end: input.occurred_at,
        };
        let learned_at = input.learned_at.unwrap_or(input.occurred_at);
        let mut approval = if config.trust_ceiling.permits_auto(Some(0)) {
            ClaimApprovalStatus::Auto
        } else {
            config.default_admission
        };
        let admit = |approval: ClaimApprovalStatus| {
            let admission = ImportedEvidenceAdmission::proposed(
                input.source_id.clone(),
                id,
                ImportedEvidenceEntityResolution::subject(subject),
                WriteActor::new(self.actor, self.actor_class),
                occurred,
                learned_at,
            )
            .with_approval(approval);
            admit_imported_evidence_claim(self.vault, &claim, admission)
        };
        match admit(approval) {
            Ok(()) => {}
            Err(err)
                if approval == ClaimApprovalStatus::Auto
                    && err.kind() == ErrorKind::GateWriteRejected =>
            {
                approval = ClaimApprovalStatus::Proposed;
                admit(approval)?;
            }
            Err(err) => return Err(err.into()),
        }
        let final_approval = self.vault.get_claim(&id)?.map_or_else(
            || approval.as_str().to_owned(),
            |b| b.approval.as_str().to_owned(),
        );
        let receipt_ref = self
            .latest_decision_ref_for(&id)?
            .unwrap_or_else(|| format!("claim:{}", id.to_hex()));
        Ok(CommitReceipt {
            claim_short_id: self.short_ref_or_hex(&id)?,
            approval: final_approval,
            superseded_short_id: None,
            receipt_ref,
        })
    }
}
