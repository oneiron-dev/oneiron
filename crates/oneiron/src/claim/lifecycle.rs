//! Claim lifecycle transitions: the supersession-chain walk, the write-verb
//! validity guard, `supersede_claim` / `retract_claim` and their reserved-door
//! twins, and the `apply_claim_demotion` state machine.
//!
//! These stay in one file because the private chain-walk and gating helpers
//! (`claim_for_lifecycle_in`, `require_active_claim`, the chain-head walk) are
//! shared across the supersede, retract and demotion paths.

use std::collections::HashSet;

use rmpv::Value;

use super::*;
use crate::Vault;
use crate::affect::Vad;
use crate::batch::{BatchOp, ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader, apply_ops};
use crate::edge::{EdgeKind, validate_edge_weight};
use crate::entity_id::{ENTITY_ID_LEN, EntityId};
use crate::error::{Error, Result};
use crate::registry::ENTITY_TYPE_CLAIM;
use crate::store::GateDecisionRecord;
use crate::temporal::TimeRange;
use crate::vault::{
    MAX_EDGE_QUERY_RESULTS, SUPERSEDES_DEFAULT_WEIGHT, edge_kind_prefix, parse_edge_record,
    require_key_len,
};

/// Bound on the supersession-chain walk behind the write-verb validity guard
/// (ONE-1936). Cycles are caught by the walk's visited set; this caps the WORK
/// a single corrupt-but-acyclic chain can demand. Real revision chains are
/// short, so a walk this deep is evidence of a damaged graph, not of long
/// history, and it ends in a typed refusal rather than an unbounded traversal.
const MAX_SUPERSESSION_CHAIN_WALK: usize = 64;

impl Vault {
    /// Reads, decodes, and gates a claim for a generic lifecycle transition
    /// (`supersede_claim` / `retract_claim`). Fail-closed:
    ///
    /// * no entity under `id` → [`Error::EntityNotFound`];
    /// * entity is not type 0 → [`Error::InvalidClaimBody`];
    /// * any reserved predicate → [`Error::ProvenanceClaimLifecycle`]. Edge
    ///   provenance drives derived hot flags and skill claims are owned by the
    ///   skill-hub doors; generic lifecycle operations never delegate either
    ///   class of reserved record.
    pub(super) fn claim_for_lifecycle_in(
        &self,
        rtxn: &heed::RoTxn<'_>,
        id: &EntityId,
    ) -> Result<(ClaimBody, EntityMetadataHeader)> {
        let Some(raw) = self.store.entities.get(rtxn, id.as_bytes())? else {
            return Err(Error::EntityNotFound);
        };
        let header =
            EntityMetadataHeader::parse(&raw).ok_or(Error::CorruptedIndex("entity header"))?;
        if header.entity_type != ENTITY_TYPE_CLAIM {
            return Err(Error::InvalidClaimBody("entity is not a type-0 CLAIM"));
        }
        let body = crate::claim::decode_claim_body(&raw[ENTITY_METADATA_HEADER_LEN..], true)?;
        if is_reserved_predicate(&body.predicate) {
            return Err(Error::ProvenanceClaimLifecycle {
                predicate: body.predicate,
            });
        }
        Ok((body, header))
    }

    /// Reads a Claim for the reserved lifecycle door. Only the engine-driven
    /// namespaces (`skill.*`, `actor.*`) are admitted: `edge.*` remains
    /// exclusively owned by edge provenance and receives the same typed
    /// rejection as the generic lifecycle API.
    fn reserved_claim_for_lifecycle_in(
        &self,
        rtxn: &heed::RoTxn<'_>,
        id: &EntityId,
    ) -> Result<(ClaimBody, EntityMetadataHeader)> {
        let Some(raw) = self.store.entities.get(rtxn, id.as_bytes())? else {
            return Err(Error::EntityNotFound);
        };
        let header =
            EntityMetadataHeader::parse(&raw).ok_or(Error::CorruptedIndex("entity header"))?;
        if header.entity_type != ENTITY_TYPE_CLAIM {
            return Err(Error::InvalidClaimBody("entity is not a type-0 CLAIM"));
        }
        let body = crate::claim::decode_claim_body(&raw[ENTITY_METADATA_HEADER_LEN..], true)?;
        if is_edge_reserved_predicate(&body.predicate) {
            return Err(Error::ProvenanceClaimLifecycle {
                predicate: body.predicate,
            });
        }
        if !is_engine_owned_reserved_predicate(&body.predicate) {
            return Err(Error::InvalidClaimBody(
                "reserved claim lifecycle door only admits skill and actor predicates",
            ));
        }
        Ok((body, header))
    }

    /// Gates a lifecycle transition on the claim still being open: any
    /// non-`active` `life` status is closed history and rejects with
    /// [`Error::ClaimAlreadyClosed`] (ARCH-0003: superseded carries history,
    /// retracted is a deliberate withdrawal — never edited again).
    pub(super) fn require_active_claim(body: &ClaimBody) -> Result<()> {
        if body.lifecycle != ClaimLifecycleStatus::Active {
            return Err(Error::ClaimAlreadyClosed {
                status: body.lifecycle,
            });
        }
        Ok(())
    }

    /// The write-verb validity guard (ONE-1936): grounds `target` inside the
    /// CALLER'S transaction and returns its body only while it is still the
    /// head of its lifecycle chain.
    ///
    /// The claim id a verb NAMES is its version token — there is no
    /// generation counter, ETag, or revision integer to compare, and this
    /// guard adds none. A target whose `life` has moved off `active` is a
    /// decision made against a replaced view, so it fails with
    /// [`Error::WriteVerbTargetStale`] carrying the terminal head's public
    /// `short_id:content_hash` ref (see
    /// [`Self::successor_chain_head_short_ref_in`]). The caller reads that ref
    /// and issues a NEW decision: the engine never retargets the verb, never
    /// rewrites the caller's ref, and never downgrades to a warning.
    ///
    /// Composing INSIDE the caller's transaction is the whole point. A read
    /// check followed by a second transaction for the mutation would recreate
    /// the grounding-read race this guard closes.
    pub fn require_named_claim_target_active_in(
        &self,
        rtxn: &heed::RoTxn<'_>,
        target: &EntityId,
    ) -> Result<ClaimBody> {
        self.guarded_claim_target_parts_in(rtxn, target)
            .map(|(body, _header)| body)
    }

    /// [`Self::require_named_claim_target_active_in`] keeping the envelope
    /// header, which the in-engine chokepoints need for the closing re-put.
    /// One grounded read serves both the guard and the mutation.
    pub(super) fn guarded_claim_target_parts_in(
        &self,
        rtxn: &heed::RoTxn<'_>,
        target: &EntityId,
    ) -> Result<(ClaimBody, EntityMetadataHeader)> {
        let (body, header) = self.claim_for_lifecycle_in(rtxn, target)?;
        if body.lifecycle == ClaimLifecycleStatus::Active {
            return Ok((body, header));
        }
        Err(Error::WriteVerbTargetStale {
            target: *target,
            lifecycle: body.lifecycle,
            successor_short_id: self.successor_chain_head_short_ref_in(rtxn, target)?,
        })
    }

    /// [`Self::require_named_claim_target_active_in`] on its own read
    /// transaction — the door for callers that only need to REPORT the stale
    /// condition (an MCP dry run), never for one that goes on to write.
    /// A writer must pass its own transaction so guard and mutation stay
    /// atomic.
    pub fn require_named_claim_target_active(&self, target: &EntityId) -> Result<ClaimBody> {
        let rtxn = self.store.env.read_txn()?;
        self.require_named_claim_target_active_in(&rtxn, target)
    }

    /// Walks the supersession chain from `target` to its unique terminal head
    /// and returns that head's public `short_id:content_hash` ref.
    ///
    /// The stored edge direction is `new_claim ─Supersedes→ old_claim`, so
    /// "newer" is found by following INBOUND `Supersedes` sources. A directly
    /// retracted claim has no newer entity at all: its terminal head is
    /// itself, and the returned ref is its own. Self-reporting is exclusive to
    /// that end state — a SUPERSEDED node with no successor is a missing
    /// supersedes row, not a head.
    ///
    /// Fail-closed at every step — a stale-target report that guessed would be
    /// worse than no report. A cycle, a branch (more than one successor at any
    /// hop, which would mean more than one terminal head), a dangling edge, a
    /// non-CLAIM node, a body that will not decode, a superseded node whose
    /// successor row is gone, or a missing `short_ids_reverse` row all return
    /// typed errors. The successor is never chosen by iteration order, and the
    /// ref is never a hex fallback: a hex id is not resolvable at the public
    /// short-ref doors, so emitting one would hand the caller a token it
    /// cannot re-get with.
    fn successor_chain_head_short_ref_in(
        &self,
        rtxn: &heed::RoTxn<'_>,
        target: &EntityId,
    ) -> Result<String> {
        let mut head = *target;
        let mut visited = HashSet::from([head]);
        for _ in 0..MAX_SUPERSESSION_CHAIN_WALK {
            let next = match self.supersession_successors_in(rtxn, &head)?.as_slice() {
                // Nothing newer. Only a node that ENDED its own lifecycle can
                // be its own terminal head: a retracted claim was withdrawn
                // rather than replaced, and an active claim is the live head.
                // A SUPERSEDED node with no successor means the row recording
                // its replacement is gone (a deleted successor takes both
                // incident edges with it), so there is no head to name —
                // answering with the node's own ref would hand the caller back
                // the very token it already knows is stale.
                [] => return self.terminal_head_short_ref_in(rtxn, &head),
                [only] => *only,
                // Two successors mean two terminal heads. There is no
                // principled choice between them, so the walk refuses rather
                // than taking whichever the index yielded first.
                _ => {
                    return Err(Error::InvariantViolation(
                        "supersession chain branches: a claim has more than one superseding successor",
                    ));
                }
            };
            if !visited.insert(next) {
                return Err(Error::CycleDetected);
            }
            head = next;
        }
        Err(Error::IndexOverflow("supersession chain walk"))
    }

    /// The public ref of a chain node that has no successor — but only when
    /// its own lifecycle says it is genuinely terminal (active = the live
    /// head, retracted = withdrawn, never replaced). A superseded node without
    /// a successor fails closed: its supersedes row is missing, and the
    /// alternative is reporting the stale target as its own successor.
    fn terminal_head_short_ref_in(
        &self,
        rtxn: &heed::RoTxn<'_>,
        head: &EntityId,
    ) -> Result<String> {
        if self.chain_node_lifecycle_in(rtxn, head)? == ClaimLifecycleStatus::Superseded {
            return Err(Error::InvariantViolation(
                "superseded claim has no superseding successor: the supersedes row is missing",
            ));
        }
        self.claim_short_ref_in(rtxn, head)
    }

    /// The `life` of one grounded supersession-chain node, under the same
    /// grounding rules as [`Self::supersession_successors_in`]: a missing row,
    /// a non-CLAIM node, or an undecodable body is corruption, never a skip.
    fn chain_node_lifecycle_in(
        &self,
        rtxn: &heed::RoTxn<'_>,
        id: &EntityId,
    ) -> Result<ClaimLifecycleStatus> {
        let raw = self
            .store
            .entities
            .get(rtxn, id.as_bytes())?
            .ok_or(Error::CorruptedIndex("supersession chain node"))?;
        let header =
            EntityMetadataHeader::parse(&raw).ok_or(Error::CorruptedIndex("entity header"))?;
        if header.entity_type != ENTITY_TYPE_CLAIM {
            return Err(Error::InvalidClaimBody(
                "supersession chain node is not a type-0 CLAIM",
            ));
        }
        Ok(decode_claim_body(&raw[ENTITY_METADATA_HEADER_LEN..], true)?.lifecycle)
    }

    /// The CLAIM entities that supersede `id`, resolved through the inbound
    /// `Supersedes` index. Every candidate is grounded — a dangling edge, a
    /// non-CLAIM node, or an undecodable body is corruption, never a skip.
    fn supersession_successors_in(
        &self,
        rtxn: &heed::RoTxn<'_>,
        id: &EntityId,
    ) -> Result<Vec<EntityId>> {
        let prefix = edge_kind_prefix(id, EdgeKind::Supersedes);
        let mut successors = Vec::new();
        for entry in self.store.edges_in.prefix_iter(rtxn, &prefix)? {
            if successors.len() >= MAX_EDGE_QUERY_RESULTS {
                return Err(Error::IndexOverflow("supersedes successors"));
            }
            let (key, _) = entry?;
            require_key_len(
                &key,
                ENTITY_ID_LEN + 1 + ENTITY_ID_LEN,
                "supersedes edge key",
            )?;
            let successor = EntityId::from_bytes(
                key[ENTITY_ID_LEN + 1..]
                    .try_into()
                    .map_err(|_| Error::CorruptedIndex("supersedes edge key"))?,
            )
            .map_err(|_| Error::CorruptedIndex("supersedes edge key"))?;
            let raw = self
                .store
                .entities
                .get(rtxn, successor.as_bytes())?
                .ok_or(Error::CorruptedIndex("supersedes edge without entity"))?;
            let header =
                EntityMetadataHeader::parse(&raw).ok_or(Error::CorruptedIndex("entity header"))?;
            if header.entity_type != ENTITY_TYPE_CLAIM {
                return Err(Error::InvalidClaimBody(
                    "supersession chain node is not a type-0 CLAIM",
                ));
            }
            decode_claim_body(&raw[ENTITY_METADATA_HEADER_LEN..], true)?;
            successors.push(successor);
        }
        Ok(successors)
    }

    /// The public `short_id:content_hash` ref of a stored claim, read from the
    /// entity-id-keyed `short_ids_reverse` row (ARCH-0019 row n4). A missing
    /// row fails closed: the ref exists to be re-got with, so half a ref is no
    /// ref.
    pub(crate) fn claim_short_ref_in(
        &self,
        rtxn: &heed::RoTxn<'_>,
        id: &EntityId,
    ) -> Result<String> {
        let raw = self
            .store
            .short_ids_reverse
            .get(rtxn, id.as_bytes())?
            .ok_or(Error::CorruptedIndex("claim short id reverse row"))?;
        let (short_id, content_hash) = crate::batch::parse_short_id_value(&raw)?;
        Ok(format!("{short_id}:{content_hash:02x}"))
    }

    /// Blocks generated-origin claims from superseding protected user truth.
    /// New generated code-revision claims are rejected first so they keep the
    /// fail-closed code-revision diagnostic; otherwise old code-revision truth
    /// gets its own diagnostic, and non-code user/legacy truth uses the
    /// general claim-body error. Missing old `src` is protected as legacy
    /// user truth for this guard.
    pub(super) fn require_source_trust_supersession_rights(
        new_body: &ClaimBody,
        old_body: &ClaimBody,
    ) -> Result<()> {
        let old_is_protected_user_truth =
            matches!(old_body.source, None | Some(ClaimSource::UserStated));
        if !claim_generated_origin(new_body) || !old_is_protected_user_truth {
            return Ok(());
        }
        if new_body.predicate == crate::code_revision::CODE_REVISION_CLAIM_PREDICATE {
            return Err(Error::InvalidCodeArtifactBody(
                "generated code revision claim cannot supersede user-stated truth",
            ));
        }
        if old_body.predicate == crate::code_revision::CODE_REVISION_CLAIM_PREDICATE {
            return Err(Error::InvalidCodeArtifactBody(
                "generated claim cannot supersede user-stated code revision truth",
            ));
        }
        Err(Error::InvalidClaimBody(
            "generated claim cannot supersede user-stated truth",
        ))
    }

    /// Supersedes the active claim `old_id` with the claim `new_id` — the
    /// general ARCH-0003 claim lifecycle mechanics, in ONE write
    /// transaction:
    ///
    /// * the old claim's body is closed: `life` = `superseded`, `to` = `now`;
    /// * the old claim's envelope `occurred_end` is refreshed to `now` (the
    ///   envelope copy mirrors the body's validity window for temporal
    ///   index-key derivation, per the D15 principle);
    /// * a `supersedes` edge (u8 = 3, structural 12 B, weight 0.3) is
    ///   written `new_id` → `old_id` — the edge is canonical; no
    ///   `supersedesId` body field is stored (D11).
    ///
    /// The old claim is KEPT fully readable: superseded carries history —
    /// "all non-current states are still stored — claims are never silently
    /// deleted" (ARCH-0003). Fail-closed, nothing written on any rejection:
    ///
    /// * `new_id == old_id` → [`Error::ClaimSelfSupersession`];
    /// * either id missing → [`Error::EntityNotFound`]; either entity not
    ///   type 0 → [`Error::InvalidClaimBody`];
    /// * either claim carrying a reserved predicate →
    ///   [`Error::ProvenanceClaimLifecycle`] (its crate-private owner door
    ///   owns that lifecycle; see `Vault::claim_for_lifecycle_in`);
    /// * either claim's `life` ≠ `active` → [`Error::ClaimAlreadyClosed`]
    ///   (closed claims neither supersede nor get superseded again).
    ///
    /// Deciding WHICH claims conflict (conflictSet), consent routing, and
    /// predicate semantics stay above the engine (ARCH-0003 §G.1, D20) —
    /// this method is transition mechanics only.
    pub fn supersede_claim(&self, new_id: &EntityId, old_id: &EntityId, now: u64) -> Result<()> {
        let mut wtxn = self.store.env.write_txn()?;
        self.supersede_claim_in_txn(&mut wtxn, new_id, old_id, now)?;
        wtxn.commit()?;
        Ok(())
    }

    /// Supersedes `old_id` with `new_id` INSIDE the caller's write
    /// transaction, running the same fail-closed guards as
    /// [`Vault::supersede_claim`] (self-supersession, type-0 / reserved
    /// predicate, both-`active`, source-trust) but composing into an existing
    /// txn instead of opening its own. A caller that first writes the
    /// replacement head and then supersedes the old head in one `wtxn` commits
    /// or rolls back BOTH together, so a rejected supersession never leaves a
    /// torn two-`active`-heads window. `new_id` must already have been written
    /// into the same `wtxn` before this is called.
    pub(crate) fn supersede_claim_in_txn(
        &self,
        wtxn: &mut heed::RwTxn<'_>,
        new_id: &EntityId,
        old_id: &EntityId,
        now: u64,
    ) -> Result<()> {
        if new_id == old_id {
            return Err(Error::ClaimSelfSupersession);
        }

        let (new_body, _new_header) = self.claim_for_lifecycle_in(&*wtxn, new_id)?;
        Self::require_active_claim(&new_body)?;
        // The NAMED target: stale here means the caller decided against a view
        // the store has replaced, and the guard runs in the caller's txn so a
        // replacement staged earlier in the same txn rolls back with it.
        let (mut old_body, old_header) = self.guarded_claim_target_parts_in(&*wtxn, old_id)?;
        Self::require_source_trust_supersession_rights(&new_body, &old_body)?;

        old_body.lifecycle = ClaimLifecycleStatus::Superseded;
        old_body.valid_to = Some(now);
        let data = encode_claim_body(&old_body)?;

        let ops = vec![
            BatchOp::Put {
                id: *old_id,
                entity_type: ENTITY_TYPE_CLAIM,
                occurred: TimeRange {
                    start: old_header.occurred_start,
                    end: now.max(old_header.occurred_start),
                },
                learned_at: old_header.learned_at,
                data,
                allow_maintenance: false,
                allow_reserved_predicate: false,
                hub_sync_imported: false,
            },
            BatchOp::EdgeWithCreatedAt {
                src: *new_id,
                kind: EdgeKind::Supersedes,
                tgt: *old_id,
                weight: SUPERSEDES_DEFAULT_WEIGHT,
                created_at: now,
                vad: Vad::NEUTRAL,
                provenance: None,
            },
        ];
        apply_ops(
            &self.store,
            &self.config,
            &self.analyzer,
            wtxn,
            ops,
            self.text_index_trusted
                .load(std::sync::atomic::Ordering::Acquire),
            false,
            true,
        )?;
        Ok(())
    }

    /// Supersedes an engine-owned `skill.*` / `actor.*` Claim inside the
    /// caller's write transaction. This crate-private door deliberately
    /// continues to reject `edge.*`, whose lifecycle must re-stamp
    /// provenance-derived edge state.
    pub(crate) fn supersede_reserved_claim_in_txn(
        &self,
        wtxn: &mut heed::RwTxn<'_>,
        new_id: &EntityId,
        old_id: &EntityId,
        now: u64,
    ) -> Result<()> {
        if new_id == old_id {
            return Err(Error::ClaimSelfSupersession);
        }

        let (new_body, _new_header) = self.reserved_claim_for_lifecycle_in(&*wtxn, new_id)?;
        Self::require_active_claim(&new_body)?;
        let (mut old_body, old_header) = self.reserved_claim_for_lifecycle_in(&*wtxn, old_id)?;
        Self::require_active_claim(&old_body)?;
        Self::require_source_trust_supersession_rights(&new_body, &old_body)?;

        old_body.lifecycle = ClaimLifecycleStatus::Superseded;
        old_body.valid_to = Some(now);
        let data = encode_claim_body(&old_body)?;

        let ops = vec![
            BatchOp::Put {
                id: *old_id,
                entity_type: ENTITY_TYPE_CLAIM,
                occurred: TimeRange {
                    start: old_header.occurred_start,
                    end: now,
                },
                learned_at: old_header.learned_at,
                data,
                allow_maintenance: false,
                allow_reserved_predicate: true,
                hub_sync_imported: false,
            },
            BatchOp::EdgeWithCreatedAt {
                src: *new_id,
                kind: EdgeKind::Supersedes,
                tgt: *old_id,
                weight: SUPERSEDES_DEFAULT_WEIGHT,
                created_at: now,
                vad: Vad::NEUTRAL,
                provenance: None,
            },
        ];
        apply_ops(
            &self.store,
            &self.config,
            &self.analyzer,
            wtxn,
            ops,
            self.text_index_trusted
                .load(std::sync::atomic::Ordering::Acquire),
            false,
            true,
        )?;
        Ok(())
    }

    /// Retracts the active claim `id` — a deliberate withdrawal (ARCH-0003
    /// general claim lifecycle), in ONE write transaction: the body is
    /// closed (`life` = `retracted`, `to` = `now`) and the envelope
    /// `occurred_end` is refreshed to `now` (body ↔ envelope mirror, D15
    /// principle). A parked consent is atomically closed with a terminal
    /// retraction receipt while preserving the consent's original binding.
    /// The record is PRESERVED — retraction never deletes.
    ///
    /// Fail-closed, nothing written on any rejection: missing id →
    /// [`Error::EntityNotFound`]; not type 0 → [`Error::InvalidClaimBody`];
    /// any reserved predicate → [`Error::ProvenanceClaimLifecycle`];
    /// `life` ≠ `active` → [`Error::ClaimAlreadyClosed`]. There is
    /// Public callers intentionally have no reserved retract door: skill-hub
    /// lifecycle is owned by a crate-private door, while edge provenance owns
    /// its retraction mechanics.
    pub fn apply_claim_demotion(
        &self,
        claim_id: &EntityId,
        action: ClaimDemotionAction,
        now: u64,
    ) -> Result<ClaimDemotionRung> {
        let mut wtxn = self.store.env.write_txn()?;
        let (mut body, header) = self.claim_for_lifecycle_in(&wtxn, claim_id)?;
        Self::require_active_claim(&body)?;
        let rung = claim_demotion_rung(&body)?;
        let (next, edge_update) = match action {
            ClaimDemotionAction::Decay {
                new_claim_of_weight,
            } => {
                validate_edge_weight(new_claim_of_weight)?;
                if matches!(
                    rung,
                    Some(ClaimDemotionRung::Weakened | ClaimDemotionRung::Stale)
                ) {
                    return Err(Error::InvalidClaimBody("decay is out of order"));
                }
                let ClaimSubject::Entity(subject) = body.subject else {
                    return Err(Error::InvalidClaimBody("decay requires entity subject"));
                };
                let prefix = edge_kind_prefix(claim_id, EdgeKind::ClaimOf);
                let mut found = None;
                for entry in self.store.edges_out.prefix_iter(&wtxn, &prefix)? {
                    let (key, value) = entry?;
                    let edge = parse_edge_record(&key, &value)?;
                    if edge.target == subject {
                        if found.is_some() {
                            return Err(Error::InvalidClaimBody("duplicate ClaimOf edge"));
                        }
                        found = Some(edge.weight);
                    }
                }
                let current = found.ok_or(Error::InvalidClaimBody("ClaimOf edge missing"))?;
                if new_claim_of_weight > current {
                    return Err(Error::InvalidEdgeWeight {
                        value: new_claim_of_weight,
                    });
                }
                (
                    ClaimDemotionRung::Decayed,
                    Some((subject, new_claim_of_weight)),
                )
            }
            ClaimDemotionAction::Weaken { new_confidence } => {
                if !matches!(
                    rung,
                    Some(ClaimDemotionRung::Decayed | ClaimDemotionRung::Weakened)
                ) {
                    return Err(Error::InvalidClaimBody("weaken requires decayed rung"));
                }
                if !new_confidence.is_finite() || !(0.0..=1.0).contains(&new_confidence) {
                    return Err(Error::InvalidClaimBody(
                        "confidence must be finite in [0, 1]",
                    ));
                }
                if new_confidence > body.confidence {
                    return Err(Error::InvalidClaimBody("confidence increase"));
                }
                body.confidence = new_confidence;
                (ClaimDemotionRung::Weakened, None)
            }
            ClaimDemotionAction::MarkStale => {
                if rung != Some(ClaimDemotionRung::Weakened) {
                    return Err(Error::InvalidClaimBody("stale requires weakened rung"));
                }
                body.stale = true;
                (ClaimDemotionRung::Stale, None)
            }
        };
        let scope = match body.scope.take() {
            None => vec![(
                Value::from(CLAIM_SCOPE_DEMOTION_RUNG_KEY),
                Value::from(match next {
                    ClaimDemotionRung::Decayed => "decayed",
                    ClaimDemotionRung::Weakened => "weakened",
                    ClaimDemotionRung::Stale => "stale",
                }),
            )],
            Some(Value::Map(mut entries)) => {
                entries.retain(|(k, _)| k.as_str() != Some(CLAIM_SCOPE_DEMOTION_RUNG_KEY));
                entries.push((
                    Value::from(CLAIM_SCOPE_DEMOTION_RUNG_KEY),
                    Value::from(match next {
                        ClaimDemotionRung::Decayed => "decayed",
                        ClaimDemotionRung::Weakened => "weakened",
                        ClaimDemotionRung::Stale => "stale",
                    }),
                ));
                entries
            }
            Some(_) => return Err(Error::InvalidClaimBody("scope must be a map")),
        };
        body.scope = Some(Value::Map(scope));
        let data = encode_claim_body(&body)?;
        let mut ops = vec![BatchOp::Put {
            id: *claim_id,
            entity_type: ENTITY_TYPE_CLAIM,
            occurred: TimeRange {
                start: header.occurred_start,
                end: now,
            },
            learned_at: header.learned_at,
            data,
            allow_maintenance: false,
            allow_reserved_predicate: false,
            hub_sync_imported: false,
        }];
        if let Some((subject, weight)) = edge_update {
            ops.push(BatchOp::SetEdgeWeight {
                src: *claim_id,
                kind: EdgeKind::ClaimOf,
                tgt: subject,
                weight,
            });
        }
        apply_ops(
            &self.store,
            &self.config,
            &self.analyzer,
            &mut wtxn,
            ops,
            self.text_index_trusted
                .load(std::sync::atomic::Ordering::Acquire),
            false,
            false,
        )?;
        wtxn.commit()?;
        Ok(next)
    }

    pub fn retract_claim(&self, id: &EntityId, now: u64) -> Result<()> {
        let mut wtxn = self.store.env.write_txn()?;
        self.retract_claim_in_txn(&mut wtxn, id, now)?;
        wtxn.commit()?;
        Ok(())
    }

    /// Transaction-composable [`Vault::retract_claim`]. A pending consent is
    /// closed before the lifecycle write, in the same transaction, so a later
    /// gate or storage failure rolls both changes back. Pending persistence is
    /// disabled for the terminal body write: a policy that evaluates the
    /// retracted body as `pending` must not recreate an actionable tray row.
    /// The caller owns commit/abort; facade callers compose actor binding and
    /// authorship authorization into this same transaction.
    pub(crate) fn retract_claim_in_txn(
        &self,
        wtxn: &mut heed::RwTxn<'_>,
        id: &EntityId,
        now: u64,
    ) -> Result<Option<GateDecisionRecord>> {
        // The NAMED target, guarded before the pending-consent closure and the
        // gate receipt below: a stale retract must leave the consent row and
        // every receipt exactly as it found them.
        let (mut body, header) = self.guarded_claim_target_parts_in(&*wtxn, id)?;

        let consent_receipt = self.store.close_pending_gate_consent_in_txn(
            wtxn,
            id,
            now,
            "retracted",
            vec!["gate.pending.claim_retracted".to_owned()],
            None,
        )?;
        body.lifecycle = ClaimLifecycleStatus::Retracted;
        body.valid_to = Some(now);
        let data = encode_claim_body(&body)?;

        let mut write_receipt = None;
        if consent_receipt.is_none() {
            let policy = crate::gate::resolve_policy_manifest(&self.store, &*wtxn)?;
            crate::gate::check_claim_policy_for_write_with_record(
                &self.store,
                wtxn,
                id,
                crate::gate::ClaimGateWrite {
                    body: &body,
                    envelope: None,
                    defer_metrics_until_commit: false,
                },
                &policy,
                crate::gate::GateWriteMode {
                    record_decision: true,
                    persist_pending_consent: false,
                    resolve_pending: true,
                    can_resolve_pending_consent: true,
                    include_source_in_gate_input: false,
                },
                &mut write_receipt,
            )?;
        }

        let ops = vec![BatchOp::Put {
            id: *id,
            entity_type: ENTITY_TYPE_CLAIM,
            occurred: TimeRange {
                start: header.occurred_start,
                end: now.max(header.occurred_start),
            },
            learned_at: header.learned_at,
            data,
            allow_maintenance: false,
            allow_reserved_predicate: false,
            hub_sync_imported: false,
        }];
        apply_ops(
            &self.store,
            &self.config,
            &self.analyzer,
            wtxn,
            ops,
            self.text_index_trusted
                .load(std::sync::atomic::Ordering::Acquire),
            false,
            false,
        )?;
        Ok(consent_receipt
            .or(write_receipt.map(crate::gate::RecordedClaimGateDecision::into_record)))
    }
}
