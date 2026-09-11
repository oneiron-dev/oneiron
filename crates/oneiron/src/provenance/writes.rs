//! Vault write doors: put, supersede, retract, model substrate, and the shared writer.

use super::imported;
use super::lifecycle::{closed_claim_put_payload, provenance_materialization_op};
use super::{
    EdgeProvenanceClaimBody, EdgeRef, PREDICATE_EDGE_PROVENANCE, ProvenancePrecedence,
    StoredProvenanceClaim, close_record_for_supersession, decode_model_entity_body,
    derive_confirmation_status, encode_edge_provenance_value, encode_model_entity_body,
    restamp_edge_flags, retract_record, validate_actor_class, validate_edge_provenance_value,
    validate_model_substrate_field, winner_index,
};
use crate::Vault;
use crate::batch::{BatchOp, ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader, apply_ops};
use crate::claim::{
    ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus, ClaimSubject, encode_claim_body,
    validate_claim_body_bytes,
};
use crate::edge::{
    EdgeActorClass, EdgeConfirmationStatus, EdgeKind, EdgeProvenanceFlags, EdgeValueLayout,
    edge_value_layout_for_kind,
};
use crate::entity_id::EntityId;
use crate::error::{ClaimError, Error, Result};
use crate::ppr;
use crate::registry::ENTITY_TYPE_MODEL;
use crate::store::Store;
use crate::temporal::TimeRange;
use crate::vault::{CLAIM_OF_DEFAULT_WEIGHT, require_key_len};
use heed::RwTxn;
use rmpv::Value;

/// One `edge.provenance` Claim as the canonical writer receives it: the
/// wrapper's id, the semantic edge it attaches to, the record body, the
/// validated actor class, and the two optional halves an import or an
/// explicit supersession adds.
pub(super) struct EdgeProvenanceWrite<'a> {
    pub(super) claim_id: &'a EntityId,
    pub(super) subject: &'a EdgeRef,
    pub(super) body: &'a EdgeProvenanceClaimBody,
    pub(super) actor_class: EdgeActorClass,
    pub(super) learned_at: u64,
    pub(super) explicit_prior: Option<&'a EntityId>,
    pub(super) imported_evidence: Option<Value>,
}

impl Vault {
    /// Writes an `edge.provenance` Claim for an EXISTING semantic edge,
    /// applies the contract's SUPERSEDE lifecycle to prior live Claims, and
    /// re-stamps the edge's two hot flags from the deterministic WINNER —
    /// the atomic provenanced-write API and (with
    /// [`Vault::supersede_edge_provenance`] and
    /// [`Vault::retract_edge_provenance`]) the ONLY public door to
    /// provenance flags (D10: the Claim is truth; the 26-byte stamp
    /// primitive stays `pub(crate)`).
    ///
    /// One LMDB write transaction performs ALL of:
    ///
    /// 1. write-once id gate — `claim_id` must not already name a stored
    ///    entity ([`ClaimError::ProvenanceClaimIdInUse`](crate::error::ClaimError::ProvenanceClaimIdInUse); re-putting an existing
    ///    id would resurrect a closed Claim in place — the lifecycle
    ///    operations are the only mutators of a stored provenance Claim);
    /// 2. subject-edge gate — `subject.kind` must be a SEMANTIC kind
    ///    ([`ClaimError::ProvenanceOnStructuralEdge`](crate::error::ClaimError::ProvenanceOnStructuralEdge) otherwise) and the edge must
    ///    already exist ([`Error::EdgeNotFound`]; the path never upserts — it
    ///    would have to invent `weight`/`created_at`);
    /// 3. actor gate (D13) — `body.actor_entity_ref` must exist
    ///    ([`Error::EntityNotFound`]) and the CALLER-SUPPLIED `actor_class`
    ///    must be compatible with the actor entity's kind
    ///    ([`ClaimError::ActorClassMismatch`](crate::error::ClaimError::ActorClassMismatch); never defaulted). The validated
    ///    class is persisted as the value record's `actor_class` BODY key
    ///    (ONE-1138 / ONE-1112 C2 relocation — the wrapper's `evid` stays
    ///    empty) so a later winner refresh can restamp a HISTORICAL Claim's
    ///    flags (see the provenance module docs). A caller-set
    ///    `body.actor_class` that CONFLICTS with the `actor_class` parameter
    ///    is rejected typed ([`ClaimError::InvalidProvenanceBody`](crate::error::ClaimError::InvalidProvenanceBody));
    /// 4. substrate gate (ONE-1138) — when `body.substrate_ref` is present
    ///    it must name a stored MODEL (type byte 121) entity
    ///    ([`ClaimError::InvalidModelSubstrate`](crate::error::ClaimError::InvalidModelSubstrate) otherwise); absent =
    ///    unrecorded-and-valid;
    /// 5. supersession (retractionRules SUPERSEDE + D14) — an incoming
    ///    `learned_at` OLDER than the live frontier for this EdgeRef is
    ///    rejected typed ([`ClaimError::ProvenancePrecedenceViolation`](crate::error::ClaimError::ProvenancePrecedenceViolation)); every
    ///    live Claim STRICTLY older than the incoming one is closed in the
    ///    same transaction (`life` = superseded, `valid_to` set to the
    ///    incoming `learned_at` when absent, envelope `occurred.end`
    ///    refreshed per D15 — closed, not deleted, still readable);
    ///    equal-`learned_at` Claims COEXIST live;
    /// 6. the Claim entity (type 0, predicate
    ///    [`crate::provenance::PREDICATE_EDGE_PROVENANCE`], `subj` = the
    ///    33-byte EdgeRef, `val` = the pinned 10-key record) is written
    ///    through the `pub(crate)` reserved-namespace door with full ONE-1104
    ///    structural validation;
    /// 7. a `claim_of` edge (u8 = 5, structural 12 B) is written from the
    ///    Claim to the subject edge's SOURCE entity (D12);
    /// 8. the subject edge value is re-stamped to 26 bytes from the WINNER
    ///    among post-write live Claims under the documented total D14 order
    ///    (greatest `learned_at`, then `confidence`, then claim-id bytes) —
    ///    NOT necessarily this Claim — with IDENTICAL bytes in `edges_out`
    ///    and `edges_in` and the first 24 bytes preserved verbatim;
    /// 9. PPR caches for the subject edge's endpoints are invalidated.
    ///
    /// The Claim envelope's `occurred` interval derives from the validity
    /// window per D15: absent `valid_from` → `learned_at`; absent `valid_to`
    /// → `u64::MAX`. A derived interval with `start > end` is rejected with
    /// [`ClaimError::InvalidProvenanceBody`](crate::error::ClaimError::InvalidProvenanceBody) — never reordered. The wrapping
    /// Claim stores `conf` = `body.confidence` and `from`/`to` =
    /// `valid_from`/`valid_to` (claim-layer mirrors of the authoritative
    /// 10-key record) with `appr` = `auto`, `life` = `active`.
    pub fn put_edge_provenance(
        &self,
        claim_id: &EntityId,
        subject: &EdgeRef,
        body: &EdgeProvenanceClaimBody,
        actor_class: EdgeActorClass,
        learned_at: u64,
    ) -> Result<()> {
        self.write_edge_provenance(claim_id, subject, body, actor_class, learned_at, None)
    }

    /// Explicitly supersedes the live `edge.provenance` Claim
    /// `prior_claim_id` with the NEWER Claim `new_claim_id` for the SAME
    /// EdgeRef (retractionRules SUPERSEDE + D14): one write transaction
    /// writes the new Claim exactly like [`Vault::put_edge_provenance`],
    /// closes the named prior (`life` = superseded, `valid_to` set to
    /// `learned_at` when the record had none, envelope `occurred.end`
    /// refreshed — the prior Claim entity stays readable), closes any other
    /// live Claim strictly older than `learned_at`, and re-stamps the edge
    /// from the deterministic WINNER among the surviving live Claims.
    ///
    /// Unlike the implicit path, the named prior is closed even on a
    /// `learned_at` tie.
    ///
    /// Typed failure modes (nothing is written on any of them):
    /// * `prior_claim_id == new_claim_id` →
    ///   [`ClaimError::ProvenanceSelfSupersession`](crate::error::ClaimError::ProvenanceSelfSupersession);
    /// * `new_claim_id` already names a stored entity →
    ///   [`ClaimError::ProvenanceClaimIdInUse`](crate::error::ClaimError::ProvenanceClaimIdInUse) (claim ids are write-once);
    /// * prior entity missing → [`Error::EntityNotFound`];
    /// * prior is not a type-0 Claim or its predicate is not
    ///   `edge.provenance` → [`ClaimError::NotAProvenanceClaim`](crate::error::ClaimError::NotAProvenanceClaim);
    /// * prior addresses a different EdgeRef than `subject` →
    ///   [`ClaimError::ProvenanceSubjectMismatch`](crate::error::ClaimError::ProvenanceSubjectMismatch);
    /// * prior is no longer live → [`ClaimError::ProvenanceClaimAlreadyClosed`](crate::error::ClaimError::ProvenanceClaimAlreadyClosed);
    /// * `learned_at` older than the live frontier →
    ///   [`ClaimError::ProvenancePrecedenceViolation`](crate::error::ClaimError::ProvenancePrecedenceViolation).
    pub fn supersede_edge_provenance(
        &self,
        prior_claim_id: &EntityId,
        new_claim_id: &EntityId,
        subject: &EdgeRef,
        body: &EdgeProvenanceClaimBody,
        actor_class: EdgeActorClass,
        learned_at: u64,
    ) -> Result<()> {
        self.write_edge_provenance(
            new_claim_id,
            subject,
            body,
            actor_class,
            learned_at,
            Some(prior_claim_id),
        )
    }

    /// Retracts a live `edge.provenance` Claim (retractionRules RETRACT):
    /// ONE write transaction sets the value record's `supersession_status` =
    /// retracted and `valid_to` = `now`, mirrors `life` = retracted / `to` =
    /// `now` on the wrapping Claim, re-puts the Claim with the envelope
    /// `occurred.end` refreshed per D15, and re-stamps the subject edge:
    ///
    /// * other live Claims remain → flags refresh from the deterministic
    ///   D14 WINNER among them (greatest `learned_at`, then `confidence`,
    ///   then claim-id bytes);
    /// * no live Claim remains → `confirmation_status` = retracted (3) with
    ///   the retracted Claim's own persisted `actor_class` — "the edge is
    ///   KEPT … the edge is not physically removed on retraction".
    ///
    /// Typed failure modes (nothing is written on any of them): missing
    /// claim → [`Error::EntityNotFound`]; not an `edge.provenance` Claim →
    /// [`ClaimError::NotAProvenanceClaim`](crate::error::ClaimError::NotAProvenanceClaim); already closed (double-retract /
    /// retract-after-supersede) → [`ClaimError::ProvenanceClaimAlreadyClosed`](crate::error::ClaimError::ProvenanceClaimAlreadyClosed);
    /// `now` earlier than the record's `valid_from` (or derived envelope
    /// start) → [`ClaimError::InvalidProvenanceBody`](crate::error::ClaimError::InvalidProvenanceBody); subject edge missing →
    /// [`Error::EdgeNotFound`].
    pub fn retract_edge_provenance(&self, claim_id: &EntityId, now: u64) -> Result<()> {
        let mut wtxn = self.store.env.write_txn()?;

        let claim = self.load_provenance_claim_in_txn(&wtxn, claim_id)?;
        if claim.wrapper.lifecycle != ClaimLifecycleStatus::Active {
            return Err(Error::Claim(ClaimError::ProvenanceClaimAlreadyClosed {
                lifecycle: claim.wrapper.lifecycle.as_str(),
            }));
        }
        let retracted = retract_record(&claim.record, now)?;
        let (occurred, learned_at, retracted_claim_body, data) =
            closed_claim_put_payload(&claim, &retracted, ClaimLifecycleStatus::Retracted)?;

        // The subject edge must still exist — the retraction KEEPS it and
        // only refreshes the two flag bytes.
        let subject = claim.subject;
        let edge_key = Store::encode_edge_key(&subject.source, subject.kind, &subject.target);
        if self.store.edges_out.get(&wtxn, &edge_key)?.is_none() {
            return Err(Error::EdgeNotFound);
        }

        let policy = crate::gate::resolve_policy_manifest(&self.store, &wtxn)?;
        crate::gate::check_edge_provenance_claim_policy(
            &self.store,
            &wtxn,
            &retracted_claim_body,
            &retracted,
            claim.actor_class,
            &policy,
        )?;

        // Flags refresh: the D14 winner among REMAINING live Claims, else
        // the contract's retracted stamp with this Claim's persisted class.
        let survivors = self.live_edge_provenance_claims_in_txn(&wtxn, &subject, Some(claim_id))?;
        let precedence: Vec<ProvenancePrecedence> = survivors
            .iter()
            .map(StoredProvenanceClaim::precedence)
            .collect();
        let flags = match winner_index(&precedence) {
            Some(index) => survivors[index].flags(),
            None => EdgeProvenanceFlags {
                confirmation_status: EdgeConfirmationStatus::Retracted,
                actor_class: claim.actor_class,
            },
        };

        let (op, binding) = provenance_materialization_op(
            &self.store,
            &wtxn,
            *claim_id,
            occurred,
            learned_at,
            data,
        )?;
        crate::batch::apply_owner_bound_claim_puts(self, &mut wtxn, vec![op], vec![binding], true)?;
        restamp_edge_flags(&self.store, &mut wtxn, &subject, flags)?;
        ppr::invalidate_ppr_for_edge(&self.store, &mut wtxn, &subject.source, &subject.target)?;
        // The edge bytes changed without an edge BatchOp in this txn, so the
        // graph version is bumped explicitly (apply_ops does it for edge ops).
        ppr::increment_graph_version(&self.store, &mut wtxn)?;
        wtxn.commit()?;
        Ok(())
    }

    /// Engine-authored get-or-create door for MODEL substrate entities
    /// (type byte 121, maintenance band — ONE-1138 ratified): a MODEL entity
    /// is "written when a substrate first appears in a write path", keyed by
    /// `(name, version)`. Model name + version live ON the MODEL entity so
    /// provenance records dedup to a 16-byte ref — the returned id is what
    /// [`EdgeProvenanceClaimBody`]'s `substrate_ref` should carry.
    ///
    /// Behavior, all in ONE write transaction:
    /// * an existing MODEL entity whose body matches `(name, version)` →
    ///   its id is returned and NOTHING is written (idempotent get);
    /// * otherwise a new MODEL entity (engine-shaped MessagePack body
    ///   `{"name", "version"}`) is created through the engine-internal
    ///   maintenance door with the full `apply_put` index footprint
    ///   (type_index, temporal point event at `now`, reserved `mo`
    ///   short-id);
    /// * `name` / `version` must be non-empty and at most
    ///   [`crate::provenance::MODEL_SUBSTRATE_FIELD_MAX_BYTES`] bytes —
    ///   [`ClaimError::InvalidModelSubstrate`](crate::error::ClaimError::InvalidModelSubstrate) otherwise;
    /// * a stored MODEL entity whose body fails the engine-shape decode
    ///   is on-disk corruption → [`Error::CorruptedIndex`], never skipped.
    ///
    /// Public puts of type byte 121 stay rejected with
    /// [`RegistryError::MaintenanceKindNotWritable`](crate::error::RegistryError::MaintenanceKindNotWritable): this method is the ONLY public
    /// door, and it only ever writes the engine-shaped body.
    pub fn ensure_model_substrate(&self, name: &str, version: &str, now: u64) -> Result<EntityId> {
        validate_model_substrate_field(name, "model name must be non-empty and at most 256 bytes")?;
        validate_model_substrate_field(
            version,
            "model version must be non-empty and at most 256 bytes",
        )?;
        let body = encode_model_entity_body(name, version)?;

        let mut wtxn = self.store.env.write_txn()?;

        // GET: scan the MODEL partition of type_index — one row per distinct
        // substrate, so the partition stays tiny — for a (name, version)
        // match. The scan and the create share the write transaction, so the
        // get-or-create is race-free under LMDB's single-writer model.
        let mut existing: Option<EntityId> = None;
        for entry in self
            .store
            .type_index
            .prefix_iter(&wtxn, &[ENTITY_TYPE_MODEL])?
        {
            let (key, _) = entry?;
            require_key_len(&key, 17, "type index key")?;
            let id = EntityId::from_bytes(
                key[1..17]
                    .try_into()
                    .map_err(|_| Error::CorruptedIndex("type index key"))?,
            )
            .map_err(|_| Error::CorruptedIndex("type index key"))?;
            let raw = self
                .store
                .entities
                .get(&wtxn, id.as_bytes())?
                .ok_or(Error::CorruptedIndex("type index row without entity"))?;
            let (stored_name, stored_version) =
                decode_model_entity_body(&raw[ENTITY_METADATA_HEADER_LEN..])?;
            if stored_name == name && stored_version == version {
                existing = Some(id);
                break;
            }
        }
        if let Some(id) = existing {
            return Ok(id);
        }

        // CREATE: engine-internal maintenance door (allow_maintenance), the
        // same admit flag the sync replay path uses for REDACTION_AUDIT —
        // public puts of the byte keep failing MaintenanceKindNotWritable.
        let id = EntityId::now();
        let ops = vec![BatchOp::Put {
            id,
            entity_type: ENTITY_TYPE_MODEL,
            occurred: TimeRange {
                start: now,
                end: now,
            },
            learned_at: now,
            data: body,
            allow_maintenance: true,
            allow_reserved_predicate: false,
            hub_sync_imported: false,
        }];
        apply_ops(
            &self.store,
            &self.config,
            &self.analyzer,
            &mut wtxn,
            ops,
            self.text_index_trusted
                .load(std::sync::atomic::Ordering::Acquire),
            false,
            true,
        )?;
        wtxn.commit()?;
        Ok(id)
    }

    /// Shared implementation of [`Vault::put_edge_provenance`] (implicit
    /// supersession) and [`Vault::supersede_edge_provenance`] (explicit
    /// prior). See those methods for the full documented semantics.
    fn write_edge_provenance(
        &self,
        claim_id: &EntityId,
        subject: &EdgeRef,
        body: &EdgeProvenanceClaimBody,
        actor_class: EdgeActorClass,
        learned_at: u64,
        explicit_prior: Option<&EntityId>,
    ) -> Result<()> {
        self.with_write_txn(|wtxn| {
            self.write_edge_provenance_in_txn(
                wtxn,
                EdgeProvenanceWrite {
                    claim_id,
                    subject,
                    body,
                    actor_class,
                    learned_at,
                    explicit_prior,
                    imported_evidence: None,
                },
            )
        })
    }

    pub(super) fn write_edge_provenance_in_txn(
        &self,
        wtxn: &mut RwTxn<'_>,
        write: EdgeProvenanceWrite<'_>,
    ) -> Result<()> {
        let EdgeProvenanceWrite {
            claim_id,
            subject,
            body,
            actor_class,
            learned_at,
            explicit_prior,
            imported_evidence,
        } = write;
        if explicit_prior == Some(claim_id) {
            return Err(Error::Claim(ClaimError::ProvenanceSelfSupersession));
        }

        // ONE-1138 / ONE-1112 C2: the validated caller-supplied class is
        // persisted as the record's `actor_class` BODY key. A caller-set
        // body class that disagrees with the parameter is ambiguous —
        // rejected, never reconciled silently.
        if let Some(body_class) = body.actor_class
            && body_class != actor_class
        {
            return Err(Error::Claim(ClaimError::InvalidProvenanceBody(
                "body actor_class conflicts with the caller-supplied actor_class parameter",
            )));
        }
        let mut record = body.clone();
        record.actor_class = Some(actor_class);

        // Pure validation before any transaction is opened. Encoding does
        // not validate; the decode validator is the single gate.
        let value = encode_edge_provenance_value(&record);
        validate_edge_provenance_value(&value)?;

        // Provenance only attaches to SEMANTIC kinds — a static property of
        // the kind, checked before any I/O.
        if edge_value_layout_for_kind(subject.kind, false) == EdgeValueLayout::Structural {
            return Err(Error::Claim(ClaimError::ProvenanceOnStructuralEdge {
                kind: subject.kind as u8,
            }));
        }

        // D15 envelope sentinels (index-key derivation only; the
        // authoritative optionality stays in the MessagePack body).
        let occurred = TimeRange {
            start: body.valid_from.unwrap_or(learned_at),
            end: body.valid_to.unwrap_or(u64::MAX),
        };
        if occurred.start > occurred.end {
            return Err(Error::Claim(ClaimError::InvalidProvenanceBody(
                "derived occurred envelope start exceeds end (valid_to before valid_from/learned_at)",
            )));
        }

        let mut claim_body = ClaimBody::new(
            PREDICATE_EDGE_PROVENANCE,
            ClaimSubject::from(*subject),
            value,
            body.confidence,
            ClaimApprovalStatus::Auto,
            ClaimLifecycleStatus::Active,
        );
        claim_body.valid_from = body.valid_from;
        claim_body.valid_to = body.valid_to;
        if let Some(evidence) = imported_evidence {
            imported::stamp_imported_source(&mut claim_body, evidence);
        }
        // The write-time validated actor_class is persisted as the record's
        // BODY key (set above, ONE-1138); the wrapper's `evid` stays empty —
        // evidence purity, no legacy `{"actor_class": u8}` map.
        let data = encode_claim_body(&claim_body)?;
        validate_claim_body_bytes(&data, true)?;

        // WRITE-ONCE ids: a `claim_id` that already names ANY stored entity
        // is rejected before a single byte moves. Re-putting an existing id
        // would overwrite the stored Claim in place — resurrecting a
        // retracted/superseded wrapper as a fresh `active` body and
        // bypassing [`ClaimError::ProvenanceClaimAlreadyClosed`](crate::error::ClaimError::ProvenanceClaimAlreadyClosed) (ARCH-0003:
        // "claims are never silently deleted"). The lifecycle operations
        // (retract / supersede) are the ONLY mutators of an existing
        // provenance Claim.
        if self
            .store
            .entities
            .get(wtxn, claim_id.as_bytes())?
            .is_some()
        {
            return Err(Error::Claim(ClaimError::ProvenanceClaimIdInUse));
        }

        // Subject edge must exist — no upsert.
        let edge_key = Store::encode_edge_key(&subject.source, subject.kind, &subject.target);
        if self.store.edges_out.get(wtxn, &edge_key)?.is_none() {
            return Err(Error::EdgeNotFound);
        }

        // Actor entity must exist; the caller-supplied class is validated
        // against its kind (D13) — never defaulted.
        let actor_raw = self
            .store
            .entities
            .get(wtxn, body.actor_entity_ref.as_bytes())?
            .ok_or(Error::EntityNotFound)?;
        let actor_header = EntityMetadataHeader::parse(&actor_raw)
            .ok_or(Error::CorruptedIndex("entity header"))?;
        validate_actor_class(actor_header.entity_type, actor_class)?;

        // Substrate gate (ONE-1138): a present substrate_ref must name a
        // stored MODEL (type byte 121) entity — actor = WHO, substrate =
        // WITH-WHAT; any other kind is never a substrate. Absent =
        // unrecorded-and-valid, no gate.
        if let Some(substrate_ref) = record.substrate_ref {
            let substrate_raw = self
                .store
                .entities
                .get(wtxn, substrate_ref.as_bytes())?
                .ok_or(Error::Claim(ClaimError::InvalidModelSubstrate(
                    "substrate_ref does not name a stored entity",
                )))?;
            let substrate_header = EntityMetadataHeader::parse(&substrate_raw)
                .ok_or(Error::CorruptedIndex("entity header"))?;
            if substrate_header.entity_type != ENTITY_TYPE_MODEL {
                return Err(Error::Claim(ClaimError::InvalidModelSubstrate(
                    "substrate_ref must name a MODEL (type byte 121) entity",
                )));
            }
            // A present, type-correct (MODEL) substrate row whose body
            // fails the engine MODEL shape ({name, version} ≤256B) is
            // ambiguous on-disk corruption — e.g. a remote-replay-deposited
            // malformed MODEL row — and is rejected fail-closed as
            // CorruptedIndex("model entity body") BEFORE the provenance Claim
            // is staged, mirroring the get-or-create GET scan's own strict
            // decode (single decoder, one source of truth). Never downgraded
            // to a silent skip; InvalidModelSubstrate stays reserved for the
            // clean referential rejections above (wrong kind, dangling ref).
            decode_model_entity_body(&substrate_raw[ENTITY_METADATA_HEADER_LEN..])?;
        }

        let policy = crate::gate::resolve_policy_manifest(&self.store, wtxn)?;
        crate::gate::check_edge_provenance_claim_policy(
            &self.store,
            wtxn,
            &claim_body,
            &record,
            actor_class,
            &policy,
        )?;

        // Explicit-prior gates (supersede path): the named Claim must be a
        // live edge.provenance Claim addressing the SAME EdgeRef.
        let prior_id = explicit_prior
            .map(|prior_id| -> Result<EntityId> {
                let prior = self.load_provenance_claim_in_txn(wtxn, prior_id)?;
                if prior.subject != *subject {
                    return Err(Error::Claim(ClaimError::ProvenanceSubjectMismatch));
                }
                if prior.wrapper.lifecycle != ClaimLifecycleStatus::Active {
                    return Err(Error::Claim(ClaimError::ProvenanceClaimAlreadyClosed {
                        lifecycle: prior.wrapper.lifecycle.as_str(),
                    }));
                }
                Ok(prior.id)
            })
            .transpose()?;

        // D14 precedence: the incoming Claim may never be OLDER than the
        // live frontier — it could never take precedence.
        let live = self.live_edge_provenance_claims_in_txn(wtxn, subject, Some(claim_id))?;
        if let Some(frontier) = live.iter().map(|claim| claim.learned_at).max()
            && learned_at < frontier
        {
            return Err(Error::Claim(ClaimError::ProvenancePrecedenceViolation {
                incoming_learned_at: learned_at,
                frontier_learned_at: frontier,
            }));
        }
        if let Some(prior_id) = prior_id
            && !live.iter().any(|claim| claim.id == prior_id)
        {
            // The prior passed the live + same-subject gates, so its
            // claim_of edge must surface it in the live scan.
            return Err(Error::CorruptedIndex("provenance claim_of edge"));
        }

        // Closures: every live Claim strictly older than the incoming one,
        // plus the explicitly named prior (closed even on a learned_at tie).
        let close_at = learned_at;
        let (closures, survivors): (Vec<&StoredProvenanceClaim>, Vec<&StoredProvenanceClaim>) =
            live.iter()
                .partition(|claim| claim.learned_at < learned_at || Some(claim.id) == prior_id);

        // Deterministic winner among the post-write live cohort (D14).
        let mut precedence: Vec<ProvenancePrecedence> =
            survivors.iter().map(|claim| claim.precedence()).collect();
        precedence.push(ProvenancePrecedence {
            learned_at,
            confidence: body.confidence,
            claim_id: *claim_id,
        });
        let winner = winner_index(&precedence)
            .ok_or(Error::InvariantViolation("provenance winner set is empty"))?;
        let flags = if winner == precedence.len() - 1 {
            EdgeProvenanceFlags {
                confirmation_status: derive_confirmation_status(body.supersession_status),
                actor_class,
            }
        } else {
            survivors[winner].flags()
        };

        let mut closure_payloads = Vec::with_capacity(closures.len());
        for closure in &closures {
            let closed_record = close_record_for_supersession(&closure.record, close_at)?;
            let (closed_occurred, closed_learned_at, closed_claim_body, closed_data) =
                closed_claim_put_payload(
                    closure,
                    &closed_record,
                    ClaimLifecycleStatus::Superseded,
                )?;
            crate::gate::check_edge_provenance_claim_policy(
                &self.store,
                wtxn,
                &closed_claim_body,
                &closed_record,
                closure.actor_class,
                &policy,
            )?;
            closure_payloads.push((closure.id, closed_occurred, closed_learned_at, closed_data));
        }

        // New Claim through the reserved-namespace door + claim_of → the
        // subject edge's SOURCE entity (D12) + closure re-puts, all with
        // full Gate checks before apply and full type-0 validation at apply,
        // all in this one transaction.
        let (op, binding) = provenance_materialization_op(
            &self.store,
            wtxn,
            *claim_id,
            occurred,
            learned_at,
            data,
        )?;
        let mut ops = vec![
            op,
            BatchOp::Edge {
                src: *claim_id,
                kind: EdgeKind::ClaimOf,
                tgt: subject.source,
                weight: CLAIM_OF_DEFAULT_WEIGHT,
                vad: crate::affect::Vad::NEUTRAL,
            },
        ];
        let mut bindings = vec![binding];
        for (closure_id, closed_occurred, closed_learned_at, closed_data) in closure_payloads {
            let (op, binding) = provenance_materialization_op(
                &self.store,
                wtxn,
                closure_id,
                closed_occurred,
                closed_learned_at,
                closed_data,
            )?;
            ops.push(op);
            bindings.push(binding);
        }
        crate::batch::apply_owner_bound_claim_puts(self, wtxn, ops, bindings, true)?;

        // Re-stamp the subject edge (both directions, identical bytes) and
        // invalidate the PPR caches its endpoints feed.
        restamp_edge_flags(&self.store, wtxn, subject, flags)?;
        ppr::invalidate_ppr_for_edge(&self.store, wtxn, &subject.source, &subject.target)?;

        Ok(())
    }
}
