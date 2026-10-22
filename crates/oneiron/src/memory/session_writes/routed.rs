//! The room's two writes, prepared before they stage (WILL L11-01, S01-2a).
//!
//! Each write is prepared first, outside any transaction: its route admitted,
//! its checks and its gate run, its rows built. It stages afterwards, inside a
//! segment its writer opens on the route it holds: a run's own captured
//! route, beside the receipt the run keeps in the same segment
//! ([`PreparedSessionWrite::stage_in_txn`]), or a route the one-shot doors
//! mint for one call ([`PreparedSessionWrite::stage`]).
//!
//! A claim's subject resolves in the room's view the run's door opened for
//! its caller, when it opened one; every other ref resolves as the vault
//! resolves it. Nothing here asks where a caller or the vault runs.
//!
//! Each write stages its birth beside its row, and a NOTE its document's
//! birth (FIX 4280, 4281): the evidence refs its caller supplied are read
//! here, before the segment opens, and kept whether or not the room reads
//! them as TURNs (Engine 10-22: no new refusal).

use super::super::support::{id_from_optional_hex, json_to_rmpv, requested_approval};
use super::super::{
    AllRelationships, ClaimInput, ClaimRelationships, CommitReceipt, EntityRefReceipt,
    MEMORY_CODE_INVALID_STATE, Memory, MemoryError, MemoryResult, ScopedClaimInput,
    SessionReadContext,
};
use crate::affect::Vad;
use crate::batch::BatchOp;
use crate::claim::{ClaimApprovalStatus, ClaimSubject};
use crate::edge::EdgeKind;
use crate::entity_id::EntityId;
use crate::error::ErrorKind;
use crate::note::{NoteBody, encode_note_body};
use crate::off_record::{OffRecordSession, RoomRowAttachments};
use crate::provenance::birth::room::SuppliedEvidence;
use crate::session_overlay::{JournalEntry, SessionWriteRoute};
use crate::temporal::TimeRange;
use crate::write_envelope::{ClaimCandidate, WriteEnvelope};

/// A room write's receipt, which names the room's short id for its row once
/// the row is staged.
pub(crate) trait SessionReceipt {
    /// This receipt for its row staged as `short`.
    fn staged_as(self, short: String) -> Self;
}

impl SessionReceipt for EntityRefReceipt {
    fn staged_as(mut self, short: String) -> Self {
        self.entity_ref = short;
        self
    }
}

impl SessionReceipt for CommitReceipt {
    fn staged_as(mut self, short: String) -> Self {
        self.claim_short_id = short;
        self
    }
}

/// One room write, prepared to stage: the room's shell read for it, its row,
/// the rows it needs the room to read, its ops, what stages beside the row
/// (its birth, a NOTE's document birth), and the receipt it answers.
pub(crate) struct PreparedSessionWrite<R> {
    conversation: EntityId,
    row: EntityId,
    occurred: TimeRange,
    learned_at: u64,
    needs: Vec<EntityId>,
    ops: Vec<BatchOp>,
    attachments: RoomRowAttachments,
    receipt: R,
}

impl<R: SessionReceipt> PreparedSessionWrite<R> {
    /// Stages the write inside the segment its writer opened on its own
    /// route, on that segment's transaction and apply, and answers its
    /// receipt.
    ///
    /// # Errors
    ///
    /// As `OffRecordSession::stage_session_rows_in_txn`, with nothing
    /// staged.
    pub(crate) fn stage_in_txn(
        self,
        session: &OffRecordSession<'_>,
        wtxn: &mut heed::RwTxn<'_>,
        apply: &dyn Fn(&mut heed::RwTxn<'_>, JournalEntry) -> crate::Result<()>,
    ) -> crate::Result<R> {
        let short = session.stage_session_rows_in_txn(
            wtxn,
            apply,
            self.conversation,
            self.row,
            self.occurred,
            self.learned_at,
            &self.needs,
            self.ops,
            &self.attachments,
        )?;
        Ok(self.receipt.staged_as(short))
    }

    /// Stages the write in a segment of its own on `route`, the route a
    /// one-shot door minted for the call, and answers its receipt.
    pub(super) fn stage(
        self,
        session: &OffRecordSession<'_>,
        route: &SessionWriteRoute,
    ) -> crate::Result<R> {
        let short = session.stage_session_rows(
            route,
            self.row,
            self.occurred,
            self.learned_at,
            &self.needs,
            self.ops,
            &self.attachments,
        )?;
        Ok(self.receipt.staged_as(short))
    }
}

impl Memory<'_> {
    /// [`Self::create_note_in_session`] prepared on `route`, a route through
    /// `session`'s room its writer holds, naming `evidence` as its caller
    /// supplied it.
    ///
    /// # Errors
    ///
    /// As [`Self::create_note_in_session`] before its rows stage.
    pub(crate) fn prepare_note_in_session(
        &self,
        session: &OffRecordSession<'_>,
        route: &SessionWriteRoute,
        kind: &str,
        markdown: &str,
        evidence: &[String],
    ) -> MemoryResult<PreparedSessionWrite<EntityRefReceipt>> {
        self.admit_session_route(session, route, "vault.notes.create")?;
        let kind = self.vault.note_kind(kind)?;
        self.vault
            .check_auto_note_birth(&kind, self.actor_class, markdown)?;
        let id = self.vault.store.clock.entity_id()?;
        let at = self.vault.store.clock.now_recorded_at();
        let occurred = TimeRange { start: at, end: at };
        let body = encode_note_body(&NoteBody {
            source_revision_ref: *self.vault.store.clock.entity_id()?.as_bytes(),
            kind,
            author_ref: crate::note::NoteActor::Actor(self.actor),
            markdown: markdown.to_owned(),
        })?;
        // The NOTE's birth facet: the one a NOTE born in the vault without a
        // batch facet is born under, the vault's default, while it is a
        // stored FACET (WILL L11-01). The room places the NOTE there, as base
        // stamps a NOTE from its `FacetOf`; with none, it stays unplaced.
        let default = self.vault.default_facet()?;
        let stored = self.vault.get_entity_type(&default)?;
        let facet = (stored == Some(crate::registry::ENTITY_TYPE_FACET)).then_some(default);
        let mut ops = vec![
            BatchOp::Put {
                id,
                entity_type: crate::registry::ENTITY_TYPE_NOTE,
                occurred,
                learned_at: at,
                data: body,
                allow_maintenance: false,
                allow_reserved_predicate: false,
                hub_sync_imported: false,
            },
            BatchOp::Text {
                id,
                fields: vec![("content".to_owned(), markdown.to_owned())],
            },
            BatchOp::Edge {
                src: id,
                kind: EdgeKind::AuthoredBy,
                tgt: self.actor,
                weight: 1.0,
                vad: Vad::NEUTRAL,
            },
        ];
        let mut needs = vec![self.actor];
        if let Some(facet) = facet {
            ops.push(BatchOp::Edge {
                src: id,
                kind: EdgeKind::FacetOf,
                tgt: facet,
                weight: 1.0,
                vad: Vad::NEUTRAL,
            });
            needs.push(facet);
        }
        let evidence = self.supplied_evidence(session, route, None, evidence)?;
        Ok(PreparedSessionWrite {
            conversation: session.overlay_conversation_shell()?,
            row: id,
            occurred,
            learned_at: at,
            needs,
            ops,
            attachments: RoomRowAttachments::note(
                crate::WriteActor::new(self.actor, self.actor_class),
                "vault.notes.create",
                evidence,
                at,
            ),
            receipt: EntityRefReceipt {
                entity_ref: String::new(),
                id_hex: id.to_hex(),
                receipt_ref: format!("put:{}", id.to_hex()),
                record: None,
            },
        })
    }

    /// [`Self::claim_upsert_in_session`] prepared on `route`, a route
    /// through `session`'s room its writer holds: its checks, its gate (an
    /// `auto` request the gate refuses asked again as `proposed`) and its
    /// rows. Its subject resolves in `reader`, the room's view a run's door
    /// opened for its caller, when it opened one.
    ///
    /// # Errors
    ///
    /// As [`Self::claim_upsert_in_session`] before its rows stage.
    pub(crate) fn prepare_claim_in_session(
        &self,
        session: &OffRecordSession<'_>,
        route: &SessionWriteRoute,
        reader: Option<&SessionReadContext<'_>>,
        input: &ScopedClaimInput,
    ) -> MemoryResult<PreparedSessionWrite<CommitReceipt>> {
        self.admit_session_route(session, route, "vault.claims.upsert")?;
        if input.predicate == crate::claim::KEY_VALUE_PREDICATE
            || crate::claim::is_expression_preference_predicate(&input.predicate)
        {
            return Err(MemoryError::new(
                MEMORY_CODE_INVALID_STATE,
                "keyed memory and expression preferences are written through their own doors",
                &["Write it through its own door, on record."],
            ));
        }
        let world = self.resolve_ref(&input.scope.world_id)?;
        let facet = self.resolve_ref(&input.scope.scope_facet_id)?;
        let project = self.resolve_ref(&input.scope.scope_project_id)?;
        let relationship = match &input.scope.scope_relationship_id {
            ClaimRelationships::All(AllRelationships::All) => None,
            ClaimRelationships::Relationships(ids) if ids.len() == 1 => {
                Some(self.resolve_ref(&ids[0])?)
            }
            ClaimRelationships::Relationships(_) => {
                return Err(MemoryError::bad_request(
                    "a claim relationship position is all or exactly one relationship",
                ));
            }
        };
        if input.sensitivity.is_some_and(|band| band > 3) {
            return Err(MemoryError::bad_request("sensitivity must be in 0..=3"));
        }
        let mut annotations = serde_json::Map::from_iter([
            ("facet".into(), serde_json::Value::String(facet.to_hex())),
            (
                "scopeProjectId".into(),
                serde_json::Value::String(project.to_hex()),
            ),
        ]);
        if let Some(band) = input.sensitivity {
            annotations.insert("sensitivity".into(), band.into());
        }
        let scope = serde_json::Value::Object(annotations);
        super::super::caps::check_claim_input(&ClaimInput {
            id: input.id.clone(),
            predicate: input.predicate.clone(),
            subject_ref: input.subject_ref.clone(),
            value: input.value.clone(),
            confidence: input.confidence,
            source: input.source.clone(),
            world_ref: (world != crate::claim::base_world_id()).then(|| world.to_hex()),
            relationship_ref: relationship.map(|id| id.to_hex()),
            scope: Some(scope.clone()),
            valid_from: input.valid_from,
            valid_to: input.valid_to,
            occurred_at: input.occurred_at,
            learned_at: input.learned_at,
            salience: input.salience,
        })?;
        self.verified_actor_class()?;
        let id = id_from_optional_hex(self.vault, input.id.as_deref())?;
        // A run's door opened the room's view for its caller: the subject
        // is a row that view names, the room's own alias included.
        let subject = match reader {
            Some(reader) => reader.write_subject(&input.subject_ref)?,
            None => self.resolve_ref(&input.subject_ref)?,
        };
        let source = self.claim_source(&input.source)?;
        let now = self.vault.store.clock.now_recorded_at();
        let occurred_at = input.occurred_at.unwrap_or(now);
        let learned_at = input.learned_at.unwrap_or(now);
        let occurred = TimeRange {
            start: occurred_at,
            end: occurred_at,
        };
        let mut candidate = ClaimCandidate::new(
            input.predicate.clone(),
            ClaimSubject::Entity(subject),
            json_to_rmpv(&input.value),
            input.confidence,
        )
        .with_validity(input.valid_from, input.valid_to)
        .with_scope(json_to_rmpv(&scope));
        if let Some(salience) = input.salience {
            candidate = candidate.with_salience(salience);
        }
        if world != crate::claim::base_world_id() {
            candidate = candidate.with_world(world);
        }
        if let Some(relationship) = relationship {
            candidate = candidate.with_relationship(relationship);
        }
        let rows = |approval: ClaimApprovalStatus| -> crate::Result<(Vec<BatchOp>, Vec<EntityId>)> {
            let envelope = self.claim_envelope(source, "vault.claims.upsert", approval)?;
            self.session_claim_rows(
                session,
                id,
                candidate.clone(),
                &envelope,
                occurred,
                learned_at,
            )
        };
        let requested = requested_approval(source, Some(&scope));
        let (approval, (ops, needs)) = match rows(requested) {
            Ok(rows) => (requested, rows),
            Err(refused)
                if requested == ClaimApprovalStatus::Auto
                    && refused.kind() == ErrorKind::GateWriteRejected =>
            {
                (
                    ClaimApprovalStatus::Proposed,
                    rows(ClaimApprovalStatus::Proposed)?,
                )
            }
            Err(refused) => return Err(refused.into()),
        };
        let evidence = self.supplied_evidence(session, route, reader, &input.evidence_turn_refs)?;
        let envelope = self.claim_envelope(source, "vault.claims.upsert", approval)?;
        Ok(PreparedSessionWrite {
            conversation: session.overlay_conversation_shell()?,
            row: id,
            occurred,
            learned_at,
            needs,
            ops,
            attachments: RoomRowAttachments::claim(&envelope, "vault.claims.upsert", evidence, now),
            receipt: CommitReceipt {
                claim_short_id: String::new(),
                approval: approval.as_str().to_owned(),
                superseded_short_id: None,
                receipt_ref: format!("claim:{}", id.to_hex()),
                claim: None,
                superseded: None,
            },
        })
    }

    /// The evidence refs `refs` a room write's caller supplied (FIX 4281),
    /// read in `reader`, the room's view a run's door opened for its caller,
    /// or else in a view of `session`'s room on `route` under this handle's
    /// read key. Each is kept, read as a TURN or not; none refuses.
    ///
    /// # Errors
    ///
    /// The view's own refusal; storage errors.
    fn supplied_evidence(
        &self,
        session: &OffRecordSession<'_>,
        route: &SessionWriteRoute,
        reader: Option<&SessionReadContext<'_>>,
        refs: &[String],
    ) -> MemoryResult<Vec<SuppliedEvidence>> {
        if refs.is_empty() {
            return Ok(Vec::new());
        }
        if let Some(reader) = reader {
            return reader.supplied_evidence(refs);
        }
        SessionReadContext::new(self.vault, session, route, self.read_key()?)?
            .supplied_evidence(refs)
    }

    /// One claim candidate's rows in `session`'s room, after its gate
    /// (`OffRecordSession::session_gate_check`): the CLAIM row `id` base
    /// would store for a new row, at the vault's default facet unless the
    /// candidate stamps one, and its `claim_of` edge to an entity subject,
    /// which the room must read. As `OffRecordSession::stage_session_claim`
    /// builds them before it stages them.
    fn session_claim_rows(
        &self,
        session: &OffRecordSession<'_>,
        id: EntityId,
        candidate: ClaimCandidate,
        envelope: &WriteEnvelope,
        occurred: TimeRange,
        learned_at: u64,
    ) -> crate::Result<(Vec<BatchOp>, Vec<EntityId>)> {
        crate::batch::reject_family_owned_candidate(&candidate)?;
        let body = candidate.into_claim_body(envelope, self.vault.default_facet()?)?;
        session.session_gate_check(id, &body, envelope)?;
        let data = crate::claim::encode_claim_body(&body)?;
        let mut ops = vec![BatchOp::Put {
            id,
            entity_type: crate::registry::ENTITY_TYPE_CLAIM,
            occurred,
            learned_at,
            data,
            allow_maintenance: false,
            allow_reserved_predicate: false,
            hub_sync_imported: false,
        }];
        let mut needs = Vec::new();
        if let ClaimSubject::Entity(subject) = body.subject {
            needs.push(subject);
            ops.push(BatchOp::Edge {
                src: id,
                kind: EdgeKind::ClaimOf,
                tgt: subject,
                weight: crate::vault::CLAIM_OF_DEFAULT_WEIGHT,
                vad: Vad::NEUTRAL,
            });
        }
        Ok((ops, needs))
    }
}
