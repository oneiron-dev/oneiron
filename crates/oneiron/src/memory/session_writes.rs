//! NOTE and claim writes through an off-record session's handle (DOOR-127;
//! Engine ruling 10-18 on ARCH-0052 D1/D2). While the room is off record,
//! the row this handle writes stages in the room's overlay
//! (`OffRecordSession::stage_session_rows`): own union reads find it, base
//! readers cannot address it, and close drops it. The same checks the
//! ordinary doors run come first; the room only changes where the row lands.
//!
//! A room on record writes ordinary memory through the ordinary doors, and
//! an anonymous room keeps nothing, so both refuse here.

use super::support::{id_from_optional_hex, json_to_rmpv, requested_approval};
use super::{
    AllRelationships, ClaimInput, ClaimRelationships, CommitReceipt, EntityRefReceipt,
    MEMORY_CODE_INVALID_STATE, Memory, MemoryError, MemoryResult, ScopedClaimInput,
};
use crate::affect::Vad;
use crate::batch::BatchOp;
use crate::claim::{ClaimApprovalStatus, ClaimSubject};
use crate::edge::EdgeKind;
use crate::error::ErrorKind;
use crate::note::{NoteBody, encode_note_body};
use crate::off_record::OffRecordSession;
use crate::session_overlay::{RouteTarget, SessionWriteRoute};
use crate::temporal::TimeRange;
use crate::write_envelope::ClaimCandidate;

impl Memory<'_> {
    /// The route a write through `session` stages under: the room's own,
    /// while it is off record.
    fn session_write_route(
        &self,
        session: &OffRecordSession<'_>,
        ordinary: &str,
    ) -> MemoryResult<SessionWriteRoute> {
        if session.vault_id() != self.vault.vault_id() {
            return Err(MemoryError::bad_request(
                "off-record session belongs to a different vault than this memory facade",
            ));
        }
        let route = session.write_route()?;
        // An anonymous room keeps nothing: the talk-only refusal.
        route.require_recording(session.session_ref())?;
        if route.target() != RouteTarget::Overlay {
            let hint = format!("Write it through {ordinary}.");
            return Err(MemoryError::new(
                MEMORY_CODE_INVALID_STATE,
                format!(
                    "off-record session {} is on record: its writes are ordinary memory",
                    session.session_ref()
                ),
                &[hint.as_str()],
            ));
        }
        Ok(route)
    }

    /// Creates one NOTE of a registered kind in `session`'s room, its first
    /// authored text as its birth, as [`Self::create_note`] creates one in
    /// the vault. The receipt names the room's short id for it and no
    /// record ref: the row is no vault record unless the vault comes to hold
    /// it.
    ///
    /// # Errors
    ///
    /// As [`Self::create_note`]; `FORBIDDEN` when the room is anonymous or
    /// full; `INVALID_STATE` when it is on record or closing.
    pub fn create_note_in_session(
        &self,
        session: &OffRecordSession<'_>,
        kind: &str,
        markdown: &str,
    ) -> MemoryResult<EntityRefReceipt> {
        let route = self.session_write_route(session, "vault.notes.create")?;
        let kind = self.vault.note_kind(kind)?;
        self.vault
            .check_auto_note_birth(&kind, self.actor_class, markdown)?;
        let id = self.vault.store.clock.entity_id()?;
        let at = self.vault.store.clock.now_recorded_at();
        let occurred = TimeRange { start: at, end: at };
        let body = encode_note_body(&NoteBody {
            source_revision_ref: *self.vault.store.clock.entity_id()?.as_bytes(),
            kind,
            author_ref: self.actor,
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
        let short = session.stage_session_rows(&route, id, occurred, at, &needs, ops)?;
        Ok(EntityRefReceipt {
            entity_ref: short,
            id_hex: id.to_hex(),
            receipt_ref: format!("put:{}", id.to_hex()),
            record: None,
        })
    }

    /// Admits one explicitly placed claim into `session`'s room, as
    /// [`Self::claim_upsert_scoped`] admits one into the vault: the same
    /// positions, the same caps, the caller's source and the gate's ruling
    /// on base policy, an `auto` request that the gate refuses asked again
    /// as `proposed`. In the room it supersedes nothing: base's heads stay
    /// as they are, and the room's claim stands beside them until close.
    ///
    /// # Errors
    ///
    /// As [`Self::claim_upsert_scoped`] before its write; the gate's
    /// refusal; `NOT_FOUND` when the room reads no subject;
    /// `FORBIDDEN` when the room is anonymous or full; `INVALID_STATE` when
    /// it is on record or closing, or for a keyed or expression claim.
    pub fn claim_upsert_in_session(
        &self,
        session: &OffRecordSession<'_>,
        input: &ScopedClaimInput,
    ) -> MemoryResult<CommitReceipt> {
        let route = self.session_write_route(session, "vault.claims.upsert")?;
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
        super::caps::check_claim_input(&ClaimInput {
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
        let subject = self.resolve_ref(&input.subject_ref)?;
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
        let stage = |approval: ClaimApprovalStatus| -> crate::Result<String> {
            let envelope = self.claim_envelope(source, "vault.claims.upsert", approval)?;
            session.stage_session_claim(
                &route,
                id,
                candidate.clone(),
                &envelope,
                occurred,
                learned_at,
            )
        };
        let requested = requested_approval(source, Some(&scope));
        let (approval, short) = match stage(requested) {
            Ok(short) => (requested, short),
            Err(refused)
                if requested == ClaimApprovalStatus::Auto
                    && refused.kind() == ErrorKind::GateWriteRejected =>
            {
                (
                    ClaimApprovalStatus::Proposed,
                    stage(ClaimApprovalStatus::Proposed)?,
                )
            }
            Err(refused) => return Err(refused.into()),
        };
        Ok(CommitReceipt {
            claim_short_id: short,
            approval: approval.as_str().to_owned(),
            superseded_short_id: None,
            receipt_ref: format!("claim:{}", id.to_hex()),
            claim: None,
            superseded: None,
        })
    }
}
