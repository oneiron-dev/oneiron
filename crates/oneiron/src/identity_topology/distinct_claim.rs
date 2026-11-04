//! The ARCH-0055 §6 anti-merge assertion: the normalized `entity.distinct_from`
//! pair key, its claim wire value and structural validator, the apply/promote
//! doors, and the suppression reads that consume them.

use crate::ports::EntityStoreRead;
use std::collections::BTreeSet;

use crate::batch::{ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader};
use crate::claim::{ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus, ClaimSubject};
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::temporal::TimeRange;
use crate::vault::Vault;

use super::ledger_fold::{IdentityTopologyAction, fold_identity_topology_log};
use super::op_apply::{IdentityOpWrite, is_effective_approval};
use super::op_vocabulary::{IdentityTopologyOp, MergeOp};
use super::wire_keys::PREDICATE_ENTITY_DISTINCT_FROM;
use crate::write_envelope::identity_pair::decode_distinct_claim_pair;
pub(super) use crate::write_envelope::identity_pair::distinct_claim_value;
pub use crate::write_envelope::identity_pair::distinct_pair_key;
pub(crate) use crate::write_envelope::identity_pair::validate_distinct_from_claim_structure;

/// One lifecycle-`Active` `entity.distinct_from` claim as the family's
/// readers see it: the row, its consent axis, and the pair it covers.
#[derive(Debug, Clone, Copy)]
pub(super) struct DistinctClaimRow {
    pub(super) claim: EntityId,
    approval: ClaimApprovalStatus,
    pub(super) pair: (EntityId, EntityId),
}

impl Vault {
    /// The CLAIM one `assert_distinct` op asserts through: the live row for
    /// the pair when there already is one, a freshly minted row otherwise.
    ///
    /// This is what makes the op IDEMPOTENT — asserting a covered pair adds a
    /// ledger event, never a duplicate claim. ONE pair is ONE row, whichever
    /// order the two consent axes arrive in.
    ///
    /// An EFFECTIVE write over a `Proposed` row PROMOTES that row in place and
    /// returns its id: the effective op IS the ruling on the park, because
    /// this family has no other resolution door for the kind
    /// ([`proposal_scope_target`](super::proposal_resolution::proposal_scope_target) is unarmed for it). The abusable direction
    /// stays shut — a `Proposed` write never demotes an effective row — so
    /// proposing a pair first still cannot neutralize an owner-ruled
    /// assertion; it can only pre-park the row that ruling promotes.
    ///
    /// Only the approval cell moves. The proposer's value, subject,
    /// confidence, source and occurred window are their artifact and stay
    /// verbatim; WHO ruled is recorded on the ruling's own type-76 event,
    /// which is the same split [`crate::Vault::merge_session_bundle`] keeps
    /// when it approves a parked claim.
    ///
    /// The claim rides the ENGINE claim door — same D18 structural validator,
    /// same subject-existence check, same `claim_of` wiring an agent's direct
    /// write gets, minus the public gate's criticality ladder. That asymmetry
    /// is the consent design, not a hole in it: ARCH-0055 r3 makes `Auto` this
    /// family's default and states that the propose lane is a caller's choice,
    /// never an engine-imposed gate, so this door decides for the same reason
    /// merge and split write their edges here without one. An agent minting
    /// the predicate through [`crate::Vault::put_claim`] instead keeps the
    /// full gate — and until that write is approved it suppresses nothing,
    /// which is exactly the ratified §6 rule.
    pub(super) fn assert_distinct_claim_in_txn(
        &self,
        wtxn: &mut heed::RwTxn<'_>,
        write: &IdentityOpWrite,
        pair: (EntityId, EntityId),
        now: u64,
    ) -> Result<EntityId> {
        let live = self
            .active_distinct_claims_in_txn(&*wtxn, &pair.0)?
            .into_iter()
            .find(|row| row.pair == pair);
        if let Some(row) = live {
            if write.is_effective() && !is_effective_approval(row.approval) {
                self.promote_distinct_claim_approval_in_txn(wtxn, &row.claim, write.approval)?;
            }
            return Ok(row.claim);
        }

        let claim = self.store.clock.entity_id()?;
        let mut body = ClaimBody::new(
            PREDICATE_ENTITY_DISTINCT_FROM,
            ClaimSubject::Entity(pair.0),
            distinct_claim_value(pair),
            write.confidence,
            write.approval,
            ClaimLifecycleStatus::Active,
        )?;
        body.source = Some(write.source);
        self.put_reserved_claim_in_txn(
            wtxn,
            &claim,
            &body,
            TimeRange {
                start: now,
                end: now,
            },
            now,
        )?;
        Ok(claim)
    }

    /// Rules a parked `entity.distinct_from` row effective, in place: the
    /// approval cell takes the ruling write's axis and every other cell —
    /// including the occurred window and `learned_at` read back off the
    /// stored header — is rewritten exactly as the proposer left it, so the
    /// promotion moves consent and nothing else.
    ///
    /// Rewriting the row rather than minting a replacement is the whole
    /// point: the parked claim's id is what the proposer holds and what the
    /// ledger's `AssertDistinct` action names, so a second id would strand
    /// both, and the pair would carry two Active rows.
    ///
    /// The write rides the same reserved door the mint does, so the
    /// source-trust check runs on the PROMOTED body — an `Auto` ruling over
    /// an untrusted source is refused here exactly as it would be on a fresh
    /// mint, and refusal fails the whole op closed.
    fn promote_distinct_claim_approval_in_txn(
        &self,
        wtxn: &mut heed::RwTxn<'_>,
        claim: &EntityId,
        approval: ClaimApprovalStatus,
    ) -> Result<()> {
        let (mut body, occurred, learned_at) = {
            let raw = self
                .store
                .port_entity_record(wtxn, claim)?
                .map(|row| row.encode())
                .ok_or(Error::EntityNotFound)?;
            let header =
                EntityMetadataHeader::parse(&raw).ok_or(Error::CorruptedIndex("entity header"))?;
            (
                crate::claim::decode_claim_body(&raw[ENTITY_METADATA_HEADER_LEN..], true)?,
                TimeRange {
                    start: header.occurred_start,
                    end: header.occurred_end,
                },
                header.learned_at,
            )
        };
        body.approval = approval;
        self.put_reserved_claim_in_txn(wtxn, claim, &body, occurred, learned_at)
    }

    /// Parked `Proposed` merge events still awaiting a ruling whose
    /// participant set names BOTH `a` and `b` — the "is this pair still being
    /// re-asked?" read the §6 suppression contract is stated against
    /// (ONE-1746).
    ///
    /// A suppressed proposal never reaches the ledger, so it never appears
    /// here; a resolved one drops out through the fold's resolution witness.
    pub fn open_merge_proposals_for_pair(
        &self,
        a: &EntityId,
        b: &EntityId,
    ) -> Result<Vec<EntityId>> {
        let rtxn = self.store.env.read_txn()?;
        self.open_merge_proposals_for_pair_in_txn(&rtxn, a, b)
    }

    pub(crate) fn open_merge_proposals_for_pair_in_txn(
        &self,
        rtxn: &heed::RoTxn<'_>,
        a: &EntityId,
        b: &EntityId,
    ) -> Result<Vec<EntityId>> {
        let fold =
            fold_identity_topology_log(&self.fold_effective_identity_topology_events_in_txn(rtxn)?);
        let mut open = Vec::new();
        for event in self.identity_topology_events_in_txn(&rtxn)? {
            let IdentityTopologyAction::Apply(IdentityTopologyOp::Merge(merge)) = &event.action
            else {
                continue;
            };
            if event.approval != ClaimApprovalStatus::Proposed
                || fold.resolved_proposals.contains_key(&event.event_id)
                || fold.moot_proposals.contains(&event.event_id)
            {
                continue;
            }
            let named: BTreeSet<EntityId> = merge
                .sources
                .iter()
                .copied()
                .chain(std::iter::once(merge.survivor))
                .collect();
            if named.contains(a) && named.contains(b) {
                open.push(event.event_id);
            }
        }
        Ok(open)
    }

    /// SUPPRESSING `entity.distinct_from` claims covering the unordered pair
    /// (ARCH-0055 §6, ONE-1746): lifecycle-`Active` AND approval in
    /// {`Approved`, `Auto`}.
    ///
    /// That predicate — not bare lifecycle — is the definition, because it is
    /// the one the suppression gate acts on, and ONE derivation cannot drift
    /// from itself. A `Proposed` assertion is therefore correctly absent: it
    /// is a proposal about the pair, not yet an assertion of it, and
    /// superseding or retracting a live claim empties this set (no shadow
    /// state).
    ///
    /// Symmetric by construction: the claim's subject is the pair's
    /// lexicographically-first entity ([`distinct_pair_key`]), which is where
    /// this looks, so argument order cannot change the answer.
    pub fn distinct_claims_for_pair(&self, a: &EntityId, b: &EntityId) -> Result<Vec<EntityId>> {
        let rtxn = self.store.env.read_txn()?;
        self.distinct_claims_for_pair_in_txn(&rtxn, a, b)
    }

    pub(crate) fn distinct_claims_for_pair_in_txn(
        &self,
        rtxn: &heed::RoTxn<'_>,
        a: &EntityId,
        b: &EntityId,
    ) -> Result<Vec<EntityId>> {
        let pair = distinct_pair_key(*a, *b);
        let mut claims = Vec::new();
        for row in self.active_distinct_claims_in_txn(&rtxn, &pair.0)? {
            if row.pair == pair && is_effective_approval(row.approval) {
                claims.push(row.claim);
            }
        }
        Ok(claims)
    }

    /// Every lifecycle-`Active` `entity.distinct_from` claim ANCHORED on
    /// `subject`, with its approval axis and the normalized pair it covers.
    ///
    /// Anchored is enough for every caller: the write path pins the subject to
    /// the pair's lexicographically-first entity, so for any pair whose two
    /// sides are both in a caller's candidate set, the covering claim hangs
    /// off a member of that set. One sweep per candidate finds them all
    /// without a scan per candidate PAIR.
    ///
    /// The approval axis is returned rather than filtered here because the two
    /// callers ask different questions of it: suppression counts only
    /// effective rows, while the assert door has to see a `Proposed` one too —
    /// to keep proposals from stacking on one pair, and to PROMOTE the parked
    /// row when an effective assertion rules it.
    pub(super) fn active_distinct_claims_in_txn(
        &self,
        rtxn: &heed::RoTxn<'_>,
        subject: &EntityId,
    ) -> Result<Vec<DistinctClaimRow>> {
        let mut rows = Vec::new();
        for claim in self.claims_for_subject_in_txn(rtxn, subject)? {
            let Some(body) = self.get_claim_in_txn(rtxn, &claim)? else {
                continue;
            };
            if body.predicate != PREDICATE_ENTITY_DISTINCT_FROM
                || body.lifecycle != ClaimLifecycleStatus::Active
            {
                continue;
            }
            rows.push(DistinctClaimRow {
                claim,
                approval: body.approval,
                // Stored bodies passed the D18 validator, so a malformed pair
                // here is corruption — surfaced, never skipped.
                pair: decode_distinct_claim_pair(&body.value)?,
            });
        }
        Ok(rows)
    }

    /// The pair a PROPOSED merge would conflate against an effective
    /// `entity.distinct_from` claim, if any (ARCH-0055 §6).
    ///
    /// Pair-EXACT: only a pair whose BOTH sides the op names counts, so an
    /// assertion about (a, b) leaves a merge of (a, c) untouched. Bounded by
    /// one claim sweep per participant, never a sweep per candidate pair.
    pub(super) fn suppressed_merge_pair_in_txn(
        &self,
        rtxn: &heed::RoTxn<'_>,
        merge: &MergeOp,
    ) -> Result<Option<(EntityId, EntityId)>> {
        let mut named: BTreeSet<EntityId> = merge.sources.iter().copied().collect();
        named.insert(merge.survivor);
        for subject in &named {
            for row in self.active_distinct_claims_in_txn(rtxn, subject)? {
                // `row.pair.0` IS `subject`, so naming the other side is the
                // whole both-sides-named test.
                if is_effective_approval(row.approval) && named.contains(&row.pair.1) {
                    return Ok(Some(row.pair));
                }
            }
        }
        Ok(None)
    }
}
