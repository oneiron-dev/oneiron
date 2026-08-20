//! `Vault` write/read/retract surface for typed expression preferences:
//! source-precedence resolution and recency ordering over the
//! `companion.expression.*` claims validated in `predicate_validators.rs`.

use std::collections::BTreeMap;

use rmpv::Value;

use super::*;
use crate::Vault;
use crate::batch::{ApplyOpsGateMode, BatchOp, EntityMetadataHeader, apply_ops_with_gate_mode};
use crate::edge::{EdgeActorClass, EdgeKind};
use crate::entity_id::{ENTITY_ID_LEN, EntityId};
use crate::error::{Error, Result};
use crate::registry::ENTITY_TYPE_CLAIM;
use crate::temporal::TimeRange;
use crate::vault::{MAX_EDGE_QUERY_RESULTS, edge_kind_prefix, require_key_len};
use crate::write_envelope::{ClaimCandidate, WriteEnvelope, WriteProvenance};

impl Vault {
    /// Ranks a claim source for expression-preference precedence, highest first.
    fn expression_source_rank(source: Option<ClaimSource>) -> u8 {
        match source {
            Some(ClaimSource::UserStated) => 3,
            Some(ClaimSource::Observed) => 2,
            Some(ClaimSource::Inferred) => 1,
            _ => 0,
        }
    }

    fn expression_preference_order(
        source: Option<ClaimSource>,
        valid_from: Option<u64>,
        learned_at: u64,
        id: EntityId,
    ) -> (u8, u64, u64, EntityId) {
        (
            Self::expression_source_rank(source),
            valid_from.unwrap_or(0),
            learned_at,
            id,
        )
    }

    fn expression_preference_wins(
        candidate: (Option<ClaimSource>, Option<u64>, u64, EntityId),
        incumbent: (Option<ClaimSource>, Option<u64>, u64, EntityId),
    ) -> bool {
        Self::expression_preference_order(candidate.0, candidate.1, candidate.2, candidate.3)
            > Self::expression_preference_order(incumbent.0, incumbent.1, incumbent.2, incumbent.3)
    }

    /// Writes one typed expression preference through the ordinary claim gate.
    pub fn set_expression_preference(
        &self,
        actor: &crate::write_envelope::WriteActor,
        claim_id: EntityId,
        change: ExpressionPreferenceChange,
        occurred: TimeRange,
        learned_at: u64,
    ) -> Result<ExpressionPreferenceWriteResult> {
        if matches!(change.origin, ExpressionPreferenceOrigin::ExplicitUser)
            && !matches!(actor.actor_class(), EdgeActorClass::Human)
        {
            return Err(Error::InvalidClaimBody(
                "explicit expression preference requires a human actor",
            ));
        }
        let (predicate, wire) = match &change.value {
            ExpressionPreferenceValue::Language(v) => {
                (PREDICATE_COMPANION_EXPRESSION_LANGUAGE, v.clone())
            }
            ExpressionPreferenceValue::Register(v) => (
                PREDICATE_COMPANION_EXPRESSION_REGISTER,
                match v {
                    ExpressionRegister::Casual => EXPRESSION_REGISTER_CASUAL,
                    ExpressionRegister::Neutral => EXPRESSION_REGISTER_NEUTRAL,
                    ExpressionRegister::Formal => EXPRESSION_REGISTER_FORMAL,
                }
                .to_owned(),
            ),
            ExpressionPreferenceValue::Keigo(v) => (
                PREDICATE_COMPANION_EXPRESSION_KEIGO,
                match v {
                    ExpressionKeigo::None => EXPRESSION_KEIGO_NONE,
                    ExpressionKeigo::Teineigo => EXPRESSION_KEIGO_TEINEIGO,
                    ExpressionKeigo::Sonkeigo => EXPRESSION_KEIGO_SONKEIGO,
                    ExpressionKeigo::Kenjogo => EXPRESSION_KEIGO_KENJOGO,
                    ExpressionKeigo::Adaptive => EXPRESSION_KEIGO_ADAPTIVE,
                }
                .to_owned(),
            ),
            ExpressionPreferenceValue::Style(v) => {
                (PREDICATE_COMPANION_EXPRESSION_STYLE, v.clone())
            }
        };
        let source = match change.origin {
            ExpressionPreferenceOrigin::ExplicitUser => ClaimSource::UserStated,
            ExpressionPreferenceOrigin::Inferred => ClaimSource::Inferred,
        };
        let candidate = ClaimCandidate::new(
            predicate,
            ClaimSubject::Entity(change.subject),
            Value::from(wire),
            1.0,
        )
        .with_validity(Some(change.valid_from), None);
        let provenance = WriteProvenance::new(Value::from("expression_preference"))?;
        let envelope = WriteEnvelope::new(*actor, source, provenance, ClaimApprovalStatus::Auto);
        let mut wtxn = self.store.env.write_txn()?;
        let mut prior_ids = Vec::new();
        for (old_id, body) in self.claims_with_predicate_in_txn(&wtxn, predicate)? {
            if old_id == claim_id
                || body.subject != ClaimSubject::Entity(change.subject)
                || body.lifecycle != ClaimLifecycleStatus::Active
            {
                continue;
            }
            let old_learned_at = self
                .store
                .entities
                .get(&wtxn, old_id.as_bytes())?
                .and_then(|raw| EntityMetadataHeader::parse(&raw).map(|h| h.learned_at))
                .ok_or(Error::CorruptedIndex("expression preference header"))?;
            if Self::expression_preference_wins(
                (Some(source), Some(change.valid_from), learned_at, claim_id),
                (body.source, body.valid_from, old_learned_at, old_id),
            ) {
                prior_ids.push(old_id);
            }
        }

        apply_ops_with_gate_mode(
            &self.store,
            &self.config,
            &self.analyzer,
            &mut wtxn,
            vec![BatchOp::ClaimCandidate {
                id: claim_id,
                candidate: Box::new(candidate),
                envelope,
                occurred,
                learned_at,
                internal_lexical_query_hint: false,
            }],
            self.text_index_trusted
                .load(std::sync::atomic::Ordering::Acquire),
            ApplyOpsGateMode::new(true, true).with_source_in_gate_input(),
        )?;
        let mut superseded_claim_ids = Vec::new();
        for old_id in prior_ids {
            match self.supersede_claim_in_txn(&mut wtxn, &claim_id, &old_id, learned_at) {
                Ok(()) => superseded_claim_ids.push(old_id),
                Err(Error::InvalidClaimBody(_)) if source == ClaimSource::Inferred => {}
                Err(err) => return Err(err),
            }
        }
        wtxn.commit()?;
        Ok(ExpressionPreferenceWriteResult {
            claim_id,
            approval: ClaimApprovalStatus::Auto,
            superseded_claim_ids,
        })
    }

    /// Resolves active typed preferences with source precedence and recency.
    pub fn expression_preferences(
        &self,
        subject: &EntityId,
        at: u64,
    ) -> Result<ExpressionPreferenceSet> {
        let rtxn = self.store.env.read_txn()?;
        let mut best: BTreeMap<ExpressionPreferenceKind, (EntityId, ClaimBody, u64)> =
            BTreeMap::new();
        for predicate in [
            PREDICATE_COMPANION_EXPRESSION_LANGUAGE,
            PREDICATE_COMPANION_EXPRESSION_REGISTER,
            PREDICATE_COMPANION_EXPRESSION_KEIGO,
            PREDICATE_COMPANION_EXPRESSION_STYLE,
        ] {
            for (id, body) in self.claims_with_predicate_in_txn(&rtxn, predicate)? {
                let learned_at = self
                    .store
                    .entities
                    .get(&rtxn, id.as_bytes())?
                    .and_then(|raw| EntityMetadataHeader::parse(&raw).map(|h| h.learned_at))
                    .ok_or(Error::CorruptedIndex("expression preference header"))?;
                if body.subject != ClaimSubject::Entity(*subject)
                    || body.lifecycle != ClaimLifecycleStatus::Active
                {
                    continue;
                }
                if body.valid_from.is_some_and(|v| v > at) || body.valid_to.is_some_and(|v| v <= at)
                {
                    continue;
                }
                let kind = match predicate {
                    PREDICATE_COMPANION_EXPRESSION_LANGUAGE => ExpressionPreferenceKind::Language,
                    PREDICATE_COMPANION_EXPRESSION_REGISTER => ExpressionPreferenceKind::Register,
                    PREDICATE_COMPANION_EXPRESSION_KEIGO => ExpressionPreferenceKind::Keigo,
                    _ => ExpressionPreferenceKind::Style,
                };
                let replace = best.get(&kind).is_none_or(|(old_id, old, old_learned_at)| {
                    Self::expression_preference_wins(
                        (body.source, body.valid_from, learned_at, id),
                        (old.source, old.valid_from, *old_learned_at, *old_id),
                    )
                });
                if replace {
                    best.insert(kind, (id, body, learned_at));
                }
            }
        }
        let mut out = ExpressionPreferenceSet::default();
        for (kind, (id, body, _learned_at)) in best {
            let Some(v) = body.value.as_str() else {
                continue;
            };
            out.winning_claim_ids.insert(kind, id);
            match kind {
                ExpressionPreferenceKind::Language => out.language = Some(v.to_owned()),
                ExpressionPreferenceKind::Style => out.style = Some(v.to_owned()),
                ExpressionPreferenceKind::Register => {
                    out.register = match v {
                        "casual" => Some(ExpressionRegister::Casual),
                        "neutral" => Some(ExpressionRegister::Neutral),
                        "formal" => Some(ExpressionRegister::Formal),
                        _ => None,
                    }
                }
                ExpressionPreferenceKind::Keigo => {
                    out.keigo = match v {
                        "none" => Some(ExpressionKeigo::None),
                        "teineigo" => Some(ExpressionKeigo::Teineigo),
                        "sonkeigo" => Some(ExpressionKeigo::Sonkeigo),
                        "kenjogo" => Some(ExpressionKeigo::Kenjogo),
                        "adaptive" => Some(ExpressionKeigo::Adaptive),
                        _ => None,
                    }
                }
            };
        }
        Ok(out)
    }

    /// Actor binding and authorship for [`Vault::retract_expression_preference`],
    /// evaluated inside the caller's write transaction so a revocation landing
    /// after the check cannot still authorize the lifecycle write.
    ///
    /// The asserted actor is resolved against the store (an actor key asserts
    /// identity; the store decides whether it holds). An actor the claim's
    /// write envelope does not name is retracting SOMEONE ELSE'S claim, which
    /// is an owner power: it needs `human` class plus an ACTIVE owner binding
    /// in the authority log. A vault that has declared no authority root keeps
    /// the store-truth check only; a multi-root fold fails closed.
    fn verify_expression_preference_retract_actor_in_txn(
        &self,
        wtxn: &heed::RwTxn<'_>,
        actor: &crate::write_envelope::WriteActor,
        head: &ClaimBody,
    ) -> Result<()> {
        let entity_type = self
            .get_raw_in(wtxn, &actor.entity_ref())?
            .and_then(|raw| EntityMetadataHeader::parse(&raw).map(|header| header.entity_type))
            .ok_or(Error::InvalidClaimBody(
                "retracting actor does not exist in this vault",
            ))?;
        crate::provenance::validate_actor_class(entity_type, actor.actor_class())?;
        if session_claim_producer(head) == Some(actor.entity_ref()) {
            return Ok(());
        }
        if actor.actor_class() != EdgeActorClass::Human {
            return Err(Error::InvalidClaimBody(
                "actor may not retract an expression preference it did not write",
            ));
        }
        let fold = self.authority_fold_readonly_in_txn(wtxn)?;
        if fold.vault_root_is_conflicted() {
            return Err(Error::InvalidClaimBody(
                "authority log folds to conflicting vault roots",
            ));
        }
        if fold.vault_id.is_some()
            && !crate::authority::actor_binding_is_active(&fold, &actor.entity_ref(), "human")
        {
            return Err(Error::InvalidClaimBody(
                "actor holds no active owner binding in the authority log",
            ));
        }
        Ok(())
    }

    /// Retracts a typed expression preference claim and restores its direct predecessor.
    ///
    /// Authority is composed into the SAME write transaction as the lifecycle
    /// change, per `Vault::retract_claim_in_txn`'s contract — see
    /// `Self::verify_expression_preference_retract_actor_in_txn`.
    pub fn retract_expression_preference(
        &self,
        actor: &crate::write_envelope::WriteActor,
        claim_id: &EntityId,
        now: u64,
    ) -> Result<()> {
        let mut wtxn = self.store.env.write_txn()?;
        let (head, _) = self.claim_for_lifecycle_in(&wtxn, claim_id)?;
        if !is_expression_preference_predicate(&head.predicate) {
            return Err(Error::InvalidClaimBody(
                "claim is not an expression preference",
            ));
        }
        self.verify_expression_preference_retract_actor_in_txn(&wtxn, actor, &head)?;

        let prefix = edge_kind_prefix(claim_id, EdgeKind::Supersedes);
        let mut predecessors = Vec::new();
        for entry in self.store.edges_out.prefix_iter(&wtxn, &prefix)? {
            if predecessors.len() >= MAX_EDGE_QUERY_RESULTS {
                return Err(Error::IndexOverflow("expression preference predecessors"));
            }
            let (key, _) = entry?;
            require_key_len(
                &key,
                ENTITY_ID_LEN + 1 + ENTITY_ID_LEN,
                "supersedes edge key",
            )?;
            let id = EntityId::from_bytes(
                key[ENTITY_ID_LEN + 1..]
                    .try_into()
                    .map_err(|_| Error::CorruptedIndex("supersedes edge key"))?,
            )
            .map_err(|_| Error::CorruptedIndex("supersedes edge key"))?;
            predecessors.push(id);
        }

        self.retract_claim_in_txn(&mut wtxn, claim_id, now)?;
        let mut ops = Vec::new();
        for id in predecessors {
            let (mut body, header) = self.claim_for_lifecycle_in(&wtxn, &id)?;
            if body.subject != head.subject
                || body.predicate != head.predicate
                || body.lifecycle != ClaimLifecycleStatus::Superseded
            {
                continue;
            }
            body.lifecycle = ClaimLifecycleStatus::Active;
            body.valid_to = None;
            ops.push(BatchOp::Put {
                id,
                entity_type: ENTITY_TYPE_CLAIM,
                occurred: TimeRange {
                    start: header.occurred_start,
                    end: now,
                },
                learned_at: header.learned_at,
                data: encode_claim_body(&body)?,
                allow_maintenance: false,
                allow_reserved_predicate: false,
                hub_sync_imported: false,
            });
        }
        if !ops.is_empty() {
            apply_ops_with_gate_mode(
                &self.store,
                &self.config,
                &self.analyzer,
                &mut wtxn,
                ops,
                self.text_index_trusted
                    .load(std::sync::atomic::Ordering::Acquire),
                ApplyOpsGateMode::new(false, false),
            )?;
        }
        wtxn.commit()?;
        Ok(())
    }
}
