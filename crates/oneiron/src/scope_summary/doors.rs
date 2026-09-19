//! Transactional spawn, summary mint, merge-header and drill doors.

use super::codec::{
    ScopeSummaryBody, decode_scope_summary_body, encode_scope_summary_body, invalid, scope_value,
};
use crate::affect::Vad;
use crate::batch::EdgeValueFields;
use crate::claim::{ClaimApprovalStatus, ClaimSource, ClaimSubject};
use crate::conversation_dag::{
    AppendRecord, ScopePath, ScopeSelector, actor_in_txn, append_in_txn, conversation_of, edge_ids,
    require_type, resolve_in_txn,
};
use crate::edge::EdgeKind;
use crate::error::{Error, Result};
use crate::limits::MAX_ANCESTOR_DEPTH;
use crate::registry::{
    ENTITY_TYPE_CLAIM, ENTITY_TYPE_SESSION, ENTITY_TYPE_SUMMARY, ENTITY_TYPE_TURN,
};
use crate::{
    ClaimCandidate, EntityId, TimeRange, Vault, WriteActor, WriteEnvelope, WriteProvenance,
};
use heed::{RoTxn, RwTxn};
use rmpv::Value;

/// Result of one merge move. A record is optional; the claim always exists.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LandedHeader {
    /// One gate-admitted merge.summary claim on the asking turn.
    pub claim: EntityId,
    /// New trunk reply when as_record was requested.
    pub record: Option<EntityId>,
}

fn summary_in_txn(vault: &Vault, txn: &RoTxn<'_>, summary: &EntityId) -> Result<ScopeSummaryBody> {
    decode_scope_summary_body(&require_type(
        &vault.store,
        txn,
        summary,
        ENTITY_TYPE_SUMMARY,
    )?)
}

fn mint_in_txn(
    vault: &Vault,
    txn: &mut RwTxn<'_>,
    scope: &ScopeSelector,
    text: &str,
    actor: WriteActor,
    now: u64,
) -> Result<EntityId> {
    actor_in_txn(&vault.store, txn, actor)?;
    let resolved = resolve_in_txn(vault, txn, scope)?;
    let id = EntityId::now();
    let body = ScopeSummaryBody {
        v: 1,
        scope: scope.clone(),
        text: text.to_owned(),
        actor: actor.entity_ref().to_hex(),
        covers: resolved.records,
        minted_at: now,
    };
    let encoded = encode_scope_summary_body(&body)?;
    let mut batch = vault
        .batch_in()
        .put(
            &id,
            ENTITY_TYPE_SUMMARY,
            TimeRange {
                start: now,
                end: now,
            },
            now,
            &encoded,
        )
        .text(&id, &[("text", text)]);
    for covered in body.covers.iter().take(256) {
        batch = batch.edge(&id, EdgeKind::DerivedFrom, covered, 1.0);
    }
    batch.apply(txn)?;
    Ok(id)
}

fn land_in_txn(
    vault: &Vault,
    txn: &mut RwTxn<'_>,
    summary: &EntityId,
    turn: &EntityId,
    actor: WriteActor,
    as_record: bool,
    now: u64,
) -> Result<LandedHeader> {
    actor_in_txn(&vault.store, txn, actor)?;
    let body = summary_in_txn(vault, txn, summary)?;
    if conversation_of(&vault.store, txn, turn)? != body.scope.conversation {
        return Err(invalid("landing turn is in another conversation"));
    }
    if let ScopePath::SubSession(session) = body.scope.path {
        let spawned = edge_ids(&vault.store, txn, &session, EdgeKind::SpawnedBy, false, 2)?;
        if spawned != [*turn] {
            return Err(invalid(
                "sub-session summary must land on its spawning turn",
            ));
        }
    }
    let source = Value::Map(vec![
        (Value::from("kind"), Value::from("scope_summary")),
        (Value::from("scope"), scope_value(&body.scope)),
    ]);
    // ClaimSource is the engine's fixed trust vocabulary. The more specific
    // source descriptor belongs in provenance, never a forged new enum value.
    let envelope = WriteEnvelope::new(
        actor,
        ClaimSource::Generated,
        WriteProvenance::new(source)?,
        ClaimApprovalStatus::Auto,
    );
    let candidate = ClaimCandidate::new(
        "merge.summary",
        ClaimSubject::Entity(*turn),
        Value::from(summary.to_hex()),
        1.0,
    )
    .with_evidence(Value::Array(
        body.covers
            .iter()
            .map(|id| Value::from(id.to_hex()))
            .collect(),
    ));
    let claim = EntityId::now();
    vault
        .batch_in()
        .claim_candidate(
            &claim,
            candidate,
            &envelope,
            TimeRange {
                start: now,
                end: now,
            },
            now,
        )
        .apply(txn)?;
    let record = if as_record {
        let scope = ScopeSelector {
            conversation: body.scope.conversation,
            session: None,
            path: ScopePath::Canonical,
            include_forks: false,
        };
        let head = resolve_in_txn(vault, txn, &scope)?.records.last().copied();
        let mut record_body = Vec::new();
        rmpv::encode::write_value(
            &mut record_body,
            &Value::Map(vec![(Value::from("txt"), Value::from(body.text.clone()))]),
        )
        .map_err(|_| invalid("reply body encode failed"))?;
        let appended = append_in_txn(
            vault,
            txn,
            &AppendRecord {
                conversation: body.scope.conversation,
                parent: head,
                advance: true,
                kind: ENTITY_TYPE_TURN,
                occurred: TimeRange {
                    start: now,
                    end: now,
                },
                learned_at: now,
                body: record_body,
                text: vec![("txt".to_owned(), body.text)],
                session: None,
                actor,
            },
            Some((*turn, *summary)),
        )?;
        Some(appended.id)
    } else {
        None
    };
    Ok(LandedHeader { claim, record })
}

impl Vault {
    /// Mints an independent retained SESSION. It never takes the global
    /// open-session pointer or aliases an existing sitting.
    pub fn spawn_sub_session(&self, turn: &EntityId, actor: WriteActor) -> Result<EntityId> {
        let now = crate::unix_seconds_now();
        self.with_write_txn(|txn| {
            actor_in_txn(&self.store, txn, actor)?;
            conversation_of(&self.store, txn, turn)?;
            let id = EntityId::now();
            let mut body = Vec::new();
            rmpv::encode::write_value(
                &mut body,
                &Value::Map(vec![(
                    Value::from("actor"),
                    Value::from(actor.entity_ref().to_hex()),
                )]),
            )
            .map_err(|_| invalid("session encode failed"))?;
            self.batch_in()
                .put(
                    &id,
                    ENTITY_TYPE_SESSION,
                    TimeRange {
                        start: now,
                        end: now,
                    },
                    now,
                    &body,
                )
                .edge_with_value_fields(
                    &id,
                    EdgeKind::SpawnedBy,
                    turn,
                    EdgeValueFields {
                        weight: 1.0,
                        created_at: now,
                        vad: Vad::NEUTRAL,
                        provenance: None,
                    },
                )
                .apply(txn)?;
            Ok(id)
        })
    }

    /// Lists live retained sub-sessions, proving each reverse index entry.
    pub fn sub_sessions(&self, turn: &EntityId) -> Result<Vec<EntityId>> {
        let txn = self.store.env.read_txn()?;
        conversation_of(&self.store, &txn, turn)?;
        let sessions = edge_ids(
            &self.store,
            &txn,
            turn,
            EdgeKind::SpawnedBy,
            true,
            MAX_ANCESTOR_DEPTH,
        )?;
        let mut result = Vec::new();
        for id in sessions {
            match crate::vault::live_entity_row_in_txn(&self.store, &txn, &id)? {
                crate::vault::LiveEntityRow::Absent | crate::vault::LiveEntityRow::DeletedShell => {
                    continue;
                }
                _ => {}
            }
            require_type(&self.store, &txn, &id, ENTITY_TYPE_SESSION)?;
            if edge_ids(&self.store, &txn, &id, EdgeKind::SpawnedBy, false, 2)? != [*turn] {
                return Err(invalid("session has inconsistent SpawnedBy edges"));
            }
            result.push(id);
        }
        Ok(result)
    }

    /// Resolves the selector and mints a summary in one transaction.
    pub fn mint_scope_summary(
        &self,
        scope: &ScopeSelector,
        text: &str,
        actor: WriteActor,
    ) -> Result<EntityId> {
        self.with_write_txn(|txn| {
            mint_in_txn(self, txn, scope, text, actor, crate::unix_seconds_now())
        })
    }

    /// Mints and optionally lands a summary atomically, for the HTTP mutation.
    /// A gate refusal cannot leave an orphan summary behind.
    pub fn mint_and_land_scope_summary(
        &self,
        scope: &ScopeSelector,
        text: &str,
        actor: WriteActor,
        land_on: Option<EntityId>,
        as_record: bool,
    ) -> Result<(EntityId, Option<LandedHeader>)> {
        if as_record && land_on.is_none() {
            return Err(invalid("as_record requires land_on"));
        }
        self.with_write_txn(|txn| {
            let now = crate::unix_seconds_now();
            let summary = mint_in_txn(self, txn, scope, text, actor, now)?;
            let landed = land_on
                .map(|turn| land_in_txn(self, txn, &summary, &turn, actor, as_record, now))
                .transpose()?;
            Ok((summary, landed))
        })
    }

    /// Lands exactly one write-gated claim, optionally with one visible trunk
    /// reply. Neither mode changes any retained sub-session record.
    pub fn land_header(
        &self,
        summary: &EntityId,
        turn: &EntityId,
        actor: WriteActor,
        as_record: bool,
    ) -> Result<LandedHeader> {
        self.with_write_txn(|txn| {
            land_in_txn(
                self,
                txn,
                summary,
                turn,
                actor,
                as_record,
                crate::unix_seconds_now(),
            )
        })
    }

    /// Reads the complete body truth list, not just the first 256 edges.
    pub fn scope_summary_covers(&self, summary: &EntityId) -> Result<Vec<EntityId>> {
        let txn = self.store.env.read_txn()?;
        Ok(summary_in_txn(self, &txn, summary)?.covers)
    }

    /// Drills a merge header into the exact historic covers set.
    pub fn drill(&self, claim: &EntityId) -> Result<Vec<EntityId>> {
        let txn = self.store.env.read_txn()?;
        require_type(&self.store, &txn, claim, ENTITY_TYPE_CLAIM)?;
        let body = self
            .get_claim_in_txn(&txn, claim)?
            .ok_or(Error::EntityNotFound)?;
        if body.predicate != "merge.summary" {
            return Err(invalid("claim is not a merge header"));
        }
        let summary = EntityId::from_hex(
            body.value
                .as_str()
                .ok_or_else(|| invalid("header value must be a summary id"))?,
        )?;
        let summary = summary_in_txn(self, &txn, &summary)?;
        let ClaimSubject::Entity(turn) = body.subject else {
            return Err(invalid("header subject must be a turn"));
        };
        if conversation_of(&self.store, &txn, &turn)? != summary.scope.conversation {
            return Err(invalid("header and summary conversations differ"));
        }
        Ok(summary.covers)
    }
}
