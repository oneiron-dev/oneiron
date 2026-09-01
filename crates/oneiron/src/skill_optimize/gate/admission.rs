//! Admission, its pinned keys, and the record-shape questions both doors ask.

use super::*;

/// `vault_meta` key prefix of the durable optimizer-BIRTH marker: this prefix ‖
/// the entity id, exactly the [`admission_ticket_key`] key pattern.
///
/// Written beside a LOCAL create whose record is optimizer-born, and never
/// again for the life of that id. It is what makes optimizer origin survive
/// DELETION: without it, `delete` + same-id `put` re-presented the id as a
/// virgin create, the create door saw an ordinary candidate, and the record
/// walked to `active` through the owner's door carrying an id whose gate
/// history said "accepted". The row itself is inert to every other reader.
const OPTIMIZER_ORIGIN_MARKER_PREFIX: &[u8] = b"skill_optimize/origin/v1\0";

/// Schema version of one origin-marker row. Fail-closed like the verdict row:
/// an unreadable marker refuses the create rather than admitting it.
const ORIGIN_MARKER_SCHEMA_VERSION: u64 = 1;

const ORIGIN_MARKER_LABEL: &str = "skill optimizer origin marker";

/// `vault_meta` key prefix of the same-transaction admission precheck.
///
/// NOT a capability token: the ticket is written, consumed and deleted inside
/// ONE write transaction by [`admit_optimized_skill_revision`], so it cannot
/// outlive the admission it authorizes — a rollback takes it with the body.
/// It exists because the chokepoint that must refuse a bare flip
/// ([`check_optimizer_admission_in_txn`]) sees a `Store` and a transaction, not
/// a `Vault`, and re-deriving the whole gate verdict there would be a second
/// implementation of this module's decision.
const ADMISSION_TICKET_PREFIX: &[u8] = b"skill_optimize/admission_ticket/v1\0";

// ---------------------------------------------------------------------------
// Admission
// ---------------------------------------------------------------------------

/// Arms `candidate → active` for a gate-passed optimizer-born proposal.
///
/// The one door an optimizer-born candidate can reach canon through; a bare
/// state flip is refused at the batch chokepoint
/// ([`check_optimizer_admission_in_txn`]). It does NOT supersede the
/// predecessor: freezing the old revision stays
/// [`crate::Vault::supersede_skill_record`]'s act, so the landed archive chain
/// is unchanged and callers admit, then supersede — the order that door already
/// requires.
///
/// Every check runs inside ONE write transaction against the snapshot the flip
/// commits into, and a refusal writes its verdict row and rolls back nothing
/// else: the active record is never touched on any path but success.
///
/// # Errors
///
/// [`Error::EntityNotFound`] when the proposal is gone;
/// [`Error::InvalidSkillBody`] when the proposal is not an open optimizer-born
/// candidate, when no [`SkillEditDisposition::Accepted`] verdict stands for it,
/// and for every refusal arm (protected or moved tier on either record, moved
/// or purged target, lost or malformed cited source).
pub fn admit_optimized_skill_revision(
    vault: &Vault,
    proposal: &EntityId,
    occurred: TimeRange,
    learned_at: u64,
) -> Result<()> {
    let refused = vault.with_write_txn(|wtxn| {
        let staged = vault.read_skill_record_in_txn(&*wtxn, proposal)?;
        require_open_optimizer_proposal(&staged)?;
        let target = target_of(&staged)?;

        // The gate's standing answer, read from the ledger rather than
        // recomputed: re-scoring here would ask the LLM tier a second time and
        // could answer differently, which would make "passed the gate" a claim
        // no receipt backs. The WHOLE verdict is read, not just its
        // disposition — the scores, the evidence identity, the bound tier and
        // the two body digests are what the checks below are against, and what
        // a refusal from here carries forward.
        //
        // Read BEFORE the target, deliberately: a target that has been purged
        // since the acceptance is a refusal this door must be able to WRITE,
        // and it can only write one derived from the acceptance it supersedes.
        // Exiting on a bare `EntityNotFound` instead left the acceptance
        // standing, the proposal open, and the real score pair unrecorded.
        let Some(accepted) = standing_verdict_in_txn(vault, &*wtxn, proposal)?
            .filter(|verdict| verdict.disposition.admits())
        else {
            return Err(invalid(
                "an optimizer-born candidate is admitted only on a standing accepted gate verdict",
            ));
        };
        let current = readable_target(vault.read_skill_record_in_txn(&*wtxn, &target).map(Some))?;
        let refusal = admission_refusal_in_txn(
            vault,
            &*wtxn,
            proposal,
            &staged,
            current.as_ref(),
            &target,
            &accepted,
            learned_at,
        )?;
        if let Some(verdict) = refusal {
            return record_refusal_in_txn(vault, wtxn, verdict);
        }

        let mut admitted = staged.clone();
        admitted.approval_status = ClaimApprovalStatus::Approved;
        admitted.lifecycle_status = SkillLifecycle::Active;
        validate_skill_update(&staged, &admitted)?;
        let data = crate::skill::encode_skill_record(&admitted)?;
        // Written, consumed and deleted inside this transaction: the ticket is
        // how the chokepoint below knows this flip came through this door, and
        // it cannot outlive the flip it authorizes.
        vault.store.vault_meta.put(
            wtxn,
            &admission_ticket_key(proposal),
            admitted.version.as_bytes(),
        )?;
        let landed =
            vault.apply_skill_record_body(wtxn, proposal, occurred, learned_at, data, false);
        vault
            .store
            .vault_meta
            .delete(wtxn, &admission_ticket_key(proposal))?;
        landed?;
        Ok(None)
    })?;
    match refused {
        Some(disposition) => Err(disposition.refusal_error()),
        None => Ok(()),
    }
}

/// Every reason a standing acceptance is still refused at the door.
///
/// Ordered by which fact is the newer ruling, and the order is load-bearing: a
/// target that moved and an owner's fresh identity mark are answers about the
/// WORLD, so they are reported as themselves rather than collapsed into the
/// binding arm they would also trip.
///
/// Every refusal is derived from `accepted`
/// ([`HeldOutVerdict::refused_at_admission`]), so it carries the real score
/// pair, the evidence basis and both body digests of the ruling it supersedes,
/// and names that ruling. A refusal that reported `0.0 → 0.0` over no evidence
/// would read as an unscored tie, which is not what happened.
#[expect(
    clippy::too_many_arguments,
    reason = "every refusal arm names the exact snapshot value it rests on; a struct would only move the list"
)]
fn admission_refusal_in_txn(
    vault: &Vault,
    wtxn: &heed::RwTxn<'_>,
    proposal: &EntityId,
    staged: &SkillRecord,
    current: Option<&SkillRecord>,
    target: &EntityId,
    accepted: &HeldOutVerdict,
    at: u64,
) -> Result<Option<HeldOutVerdict>> {
    // Every arm answers with the SAME acceptance, restated: the pair, the
    // basis and the bindings travel; only the disposition changes.
    let refused = |disposition| Some(accepted.refused_at_admission(disposition, at));
    // Purged, replaced by another kind, or simply unreadable: the revision this
    // acceptance was scored against is not there to be superseded, and that is
    // a durable answer carrying the acceptance's real numbers — not a bare exit
    // that leaves the permission standing.
    let Some(current) = current else {
        return Ok(refused(SkillEditDisposition::RefusedStaleTarget));
    };
    if !target_is_current(staged, current) {
        return Ok(refused(SkillEditDisposition::RefusedStaleTarget));
    }
    // Re-marked between the verdict and the admission: the owner's ruling
    // is the newer fact, and it wins.
    if tier_verdict_in_txn(vault, wtxn, target, current)?
        .tier()
        .is_none_or(SkillGovernanceTier::is_protected)
    {
        return Ok(refused(SkillEditDisposition::RefusedProtectedTier));
    }
    // The same question asked of the PROPOSAL, independently and in this same
    // snapshot: an owner who marks the candidate itself `identity` after the
    // gate passed has ruled on the body that is one write from becoming canon.
    // Protected, ambiguous, or no longer the tier the acceptance bound are one
    // answer — and it is checked BEFORE the binding arm so the receipt names
    // the owner's mark rather than the digest mismatch it would also trip.
    let proposal_tier = tier_verdict_in_txn(vault, wtxn, proposal, staged)?.tier();
    if proposal_tier.is_none_or(SkillGovernanceTier::is_protected)
        || proposal_tier != accepted.proposal_tier
    {
        return Ok(refused(SkillEditDisposition::RefusedProtectedTier));
    }
    // THE binding check, in the snapshot the flip commits into: is the body
    // about to become canon the body that was scored, is the predecessor it
    // improves on still the one it was compared against, and is the reserved
    // evidence still the set that judged them? A verdict that recorded only
    // "proposal X was accepted" would let any of the three be swapped after the
    // fact, which makes the strict gate a formality.
    let committed = held_out_receipts_in_txn(vault, wtxn, target)?;
    if !ScoredBasis::of(staged, current, &committed, proposal_tier)?.matches(accepted) {
        return Ok(refused(SkillEditDisposition::RefusedBindingMismatch));
    }
    // ONE-1447's gap, closed at the door that owns it: the stale sweep
    // deliberately steps past CANDIDATES (ARCH-0053 §6 has no
    // `Candidate → Stale` edge), so a candidate whose cited source was
    // erased carries no mark to read. Resolve every cited id DIRECTLY in
    // the active store — the reverse index is source→skills, the wrong
    // direction for this question, and it is a cache besides.
    let Ok(cited) = source_message_refs(staged) else {
        return Ok(refused(SkillEditDisposition::RefusedSourceMalformed));
    };
    let mut missing = Vec::new();
    for source in cited {
        if vault.store.entities.get(wtxn, source.as_bytes())?.is_none() {
            missing.push(source);
        }
    }
    if missing.is_empty() {
        return Ok(None);
    }
    let mut verdict = accepted.refused_at_admission(SkillEditDisposition::RefusedSourceLoss, at);
    verdict.missing_sources = missing;
    Ok(Some(verdict))
}

/// Writes a refusal row, closes the proposal it answers, and reports the
/// disposition the caller errors with.
fn record_refusal_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    verdict: HeldOutVerdict,
) -> Result<Option<SkillEditDisposition>> {
    let disposition = verdict.disposition;
    record_verdict_in_txn(vault, wtxn, &verdict)?;
    if disposition.closes_proposal() {
        close_answered_proposal_in_txn(vault, wtxn, &verdict.proposal, verdict.at)?;
    }
    Ok(Some(disposition))
}

/// Provenance keys that say WHERE a record came from and what it revises.
///
/// Immutable together, because they are load-bearing together: the birth path
/// is what makes the admission floor apply at all, the target entity and
/// version are what "this revises that revision" means, and the cycle is what
/// the accept cap is counted against.
const OPTIMIZER_ORIGIN_KEYS: [&str; 5] = [
    PROVENANCE_BIRTH_KEY,
    PROVENANCE_OPTIMIZE_OF_KEY,
    PROVENANCE_OPTIMIZE_OF_ENTITY_KEY,
    PROVENANCE_OPTIMIZE_OF_VERSION_KEY,
    PROVENANCE_OPTIMIZE_CYCLE_KEY,
];

/// The `vault_meta` key the optimizer-birth marker for one entity lives at.
pub(in crate::skill_optimize) fn optimizer_origin_marker_key(id: &EntityId) -> Vec<u8> {
    let mut key = Vec::with_capacity(OPTIMIZER_ORIGIN_MARKER_PREFIX.len() + ENTITY_ID_LEN);
    key.extend_from_slice(OPTIMIZER_ORIGIN_MARKER_PREFIX);
    key.extend_from_slice(id.as_bytes());
    key
}

/// The five origin values a record carries, in the pinned key order.
fn optimizer_origin_values(record: &SkillRecord) -> Vec<Option<String>> {
    OPTIMIZER_ORIGIN_KEYS
        .iter()
        .map(|key| provenance_str(record, key))
        .collect()
}

fn encode_origin_marker(values: &[Option<String>]) -> Result<Vec<u8>> {
    let row = Value::Array(
        std::iter::once(Value::from(ORIGIN_MARKER_SCHEMA_VERSION))
            .chain(values.iter().map(|value| match value {
                Some(value) => Value::from(value.as_str()),
                None => Value::Nil,
            }))
            .collect(),
    );
    let mut encoded = Vec::new();
    rmpv::encode::write_value(&mut encoded, &row)
        .map_err(|_| invalid("skill optimizer origin marker MessagePack encode failed"))?;
    Ok(encoded)
}

fn decode_origin_marker(raw: &[u8]) -> Result<Vec<Option<String>>> {
    let value = rmpv::decode::read_value(&mut std::io::Cursor::new(raw))
        .map_err(|_| Error::CorruptedIndex(ORIGIN_MARKER_LABEL))?;
    let Value::Array(entries) = &value else {
        return Err(Error::CorruptedIndex(ORIGIN_MARKER_LABEL));
    };
    let Some((version, rest)) = entries.split_first() else {
        return Err(Error::CorruptedIndex(ORIGIN_MARKER_LABEL));
    };
    if version.as_u64() != Some(ORIGIN_MARKER_SCHEMA_VERSION)
        || rest.len() != OPTIMIZER_ORIGIN_KEYS.len()
    {
        return Err(Error::CorruptedIndex(ORIGIN_MARKER_LABEL));
    }
    rest.iter()
        .map(|entry| match entry {
            Value::Nil => Ok(None),
            other => other
                .as_str()
                .map(|value| Some(value.to_owned()))
                .ok_or(Error::CorruptedIndex(ORIGIN_MARKER_LABEL)),
        })
        .collect()
}

/// The optimizer-birth half of the origin law, at the LOCAL create door.
///
/// [`check_optimizer_admission_in_txn`] freezes origin provenance for the life
/// of an entity by comparing a create-against-prior pair — but DELETION ends
/// that life while the id survives, and the id is what the verdict ledger, the
/// admission ticket and every "this proposal was accepted" row are keyed by. So
/// `delete` + same-id `put` used to launder an optimizer-born id into an
/// ordinary candidate, which the owner's own door then walked to `active` with
/// no ticket and no verdict: two writes, no gate, and a gate history that still
/// said yes.
///
/// The marker closes that road by outliving the body. It is written beside the
/// first LOCAL optimizer-born create and never rewritten (the birth stamp is
/// immutable, cycle included), no delete road clears it, and thereafter any
/// create at that id must present byte-identical origin provenance. The answer
/// is one of four:
///
/// - marked, and the create carries the same five values → allowed, and the
///   record is optimizer-born again, so every update-door rule applies to it
///   unchanged;
/// - marked, and the create carries different or absent origin → refused: that
///   is the laundering this exists to stop;
/// - unmarked, and the create is optimizer-born → the marker is born with it
///   (returned for the caller to stage in the SAME transaction);
/// - unmarked, ordinary create → untouched. The owner's skills are not
///   optimizer-born, so this rule costs them nothing.
///
/// Read-only, and it returns the row to write rather than writing it, so the
/// create arm can run the check while the transaction is still borrowed for
/// reads and stage the marker at its one pre-write site (the ONE-1604-D1
/// posture in the same file).
///
/// Sync-remat creates reach here too (ONE-1449 K3 M-5). The marker is a fact
/// about the ID, and the id is what survives the delete: a replica that first
/// met an optimizer-born id through remat and recorded nothing could be walked
/// through `delete` + ordinary same-id create into an unmarked active skill
/// whose gate history still said "accepted", and that body then travelled back.
/// Marking a replicated create re-decides nothing — the peer's bytes are stored
/// exactly as sent — and the four answers below are the same four on both
/// roads.
///
/// # Errors
///
/// [`Error::InvalidSkillBody`] on an origin-laundering create;
/// [`Error::CorruptedIndex`] on an unreadable marker — fail closed, because a
/// marker nobody can read is exactly the case the bypass would hide behind.
pub(crate) fn optimizer_birth_marker_for_create_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    id: &EntityId,
    created: &SkillRecord,
) -> Result<Option<(Vec<u8>, Vec<u8>)>> {
    let key = optimizer_origin_marker_key(id);
    let origin = optimizer_origin_values(created);
    let Some(marked) = store
        .vault_meta
        .get(txn, &key)?
        .as_deref()
        .map(decode_origin_marker)
        .transpose()?
    else {
        return if born_on_optimize_road(created) {
            Ok(Some((key, encode_origin_marker(&origin)?)))
        } else {
            Ok(None)
        };
    };
    if marked != origin {
        return Err(invalid(
            "this entity id was born on the optimize road; a create that does not carry its origin provenance is refused",
        ));
    }
    Ok(None)
}

/// The chokepoint rule, in two halves: an optimizer-born candidate never
/// becomes canon by a bare state flip, and it never stops being optimizer-born.
///
/// Called from `batch::put_apply` — the one arm every SKILL body update
/// converges on — so `put_entity`, a raw `batch().put`, the typed update door
/// and sync replay are all governed by it.
///
/// # What a REPLICATED row is held to
///
/// Both halves apply on the sync-replay road; only the PROOF the second half
/// asks for changes, because the two roads can prove different things.
///
/// - Origin immutability is absolute, whatever the road. A lawful peer never
///   edits these five values (its own door forbids it, this same function),
///   so refusing a row that does costs convergence nothing and closes the
///   laundering loop the create-side marker opens the other end of: strip the
///   birth path on one replica and the stripped body used to travel back and
///   overwrite an optimizer-born record at its origin, gate history intact.
/// - `candidate → active` asks for the same-transaction ticket LOCALLY. A
///   replicated row cannot show one — the ticket lives and dies inside the
///   admitting device's transaction and the verdict ledger is `vault_meta`,
///   which does not travel — so demanding it would quarantine every lawfully
///   admitted edit a peer sends and permanently diverge the replicas. What
///   this vault CAN check is what a lawful admission actually is: a pure state
///   flip, the two axes moving and nothing else
///   ([`admit_optimized_skill_revision`] writes exactly that). So a replicated
///   activation must carry the candidate body this vault already holds, and a
///   row that activates while also moving content is refused — unscored
///   content reaching canon through a state flip is the one thing this floor
///   exists to stop, and a peer that has genuinely re-drafted has a new
///   revision to send, not a rewrite of this one.
///
/// The refusal is [`Error::InvalidSkillBody`], which `sync::quarantine`
/// classifies as a REMOTE rejection: the row is quarantined and the window
/// continues, so a fail-closed answer here is never a stalled replica.
///
/// # Origin is a birth fact, not a field
///
/// The admission floor asks the PRIOR record whether it was optimizer-born, so
/// an origin that could be edited away would be an origin worth editing away:
/// one lawful candidate→candidate content update to drop the birth key, and a
/// second update flips the record active as an ordinary candidate, with no
/// ticket and no verdict. Two writes, no gate. So the origin keys are frozen
/// for the entity's lifetime, in both directions — a record cannot shed the
/// road it was born on, and a record born on another road cannot claim this
/// one.
///
/// This is a rule ABOUT machine-born records and it costs the owner nothing:
/// their own skills are not optimizer-born, and on a record that IS, every
/// other field — the text, the version, the tier, the states — still moves
/// through the ordinary door exactly as before.
///
/// The rule holds over a record's LIFE; deletion ends that life while the id
/// outlives it, so the CREATE half of the same law
/// ([`optimizer_birth_marker_for_create_in_txn`]) closes the delete/recreate
/// road with a durable marker no delete clears.
///
/// Read-only by construction: it runs while the prior body is still borrowed
/// from the transaction, and the ticket it verifies is deleted by the door that
/// wrote it.
///
/// # Errors
///
/// [`Error::InvalidSkillBody`] when an optimizer-born record's origin
/// provenance is edited, when a LOCAL optimizer-born candidate is flipped
/// active without [`admit_optimized_skill_revision`] having authorized exactly
/// this revision in this transaction, and when a REPLICATED one is activated by
/// anything other than a pure state flip of the body this vault holds.
pub(crate) fn check_optimizer_admission_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    id: &EntityId,
    prior: &SkillRecord,
    updated: &SkillRecord,
    replicated: bool,
) -> Result<()> {
    if !born_on_optimize_road(prior) {
        return if born_on_optimize_road(updated) {
            Err(invalid(
                "optimizer birth provenance is a birth fact; an existing record cannot adopt it",
            ))
        } else {
            Ok(())
        };
    }
    for key in OPTIMIZER_ORIGIN_KEYS {
        if provenance_str(prior, key) != provenance_str(updated, key) {
            return Err(invalid(
                "an optimizer-born skill's origin provenance is immutable for the life of the entity",
            ));
        }
    }
    if prior.lifecycle_status != SkillLifecycle::Candidate
        || updated.lifecycle_status != SkillLifecycle::Active
    {
        return Ok(());
    }
    if replicated {
        // The settled-admission shape, and nothing weaker: the body becoming
        // active must be the candidate body this vault already holds, with only
        // the state axes moved. The digest normalizes exactly those axes (plus
        // the demoted `confidence` cache and the separately-checked tier), so
        // this asks the substrate's own question — did the CONTENT change
        // (`skill::skill_content_changed`)? — of the one transition where the
        // answer must be no.
        if skill_body_binding_digest(prior)? != skill_body_binding_digest(updated)? {
            return Err(invalid(
                "a replicated optimizer-born candidate is activated only as a settled admission of the body this vault holds",
            ));
        }
        return Ok(());
    }
    let Some(ticket) = store.vault_meta.get(txn, &admission_ticket_key(id))? else {
        return Err(invalid(
            "an optimizer-born candidate is admitted by the ONE-1449 score gate, not by a bare state flip",
        ));
    };
    if ticket.as_ref() != updated.version.as_bytes() {
        return Err(invalid(
            "the optimizer admission ticket does not name this revision",
        ));
    }
    Ok(())
}

fn admission_ticket_key(proposal: &EntityId) -> Vec<u8> {
    let mut key = Vec::with_capacity(ADMISSION_TICKET_PREFIX.len() + ENTITY_ID_LEN);
    key.extend_from_slice(ADMISSION_TICKET_PREFIX);
    key.extend_from_slice(proposal.as_bytes());
    key
}

// ---------------------------------------------------------------------------
// Record shape helpers
// ---------------------------------------------------------------------------

/// True when this record's provenance says ONE-1448's job drafted it.
fn born_on_optimize_road(record: &SkillRecord) -> bool {
    provenance_str(record, PROVENANCE_BIRTH_KEY).as_deref() == Some(SKILL_OPTIMIZE_BIRTH_PATH)
}

/// Every shape question the gate and the admission door ask of a proposal
/// BEFORE they will rule on it — including the birth cycle.
///
/// The cycle stamp is required here, at both doors, rather than only where the
/// label is read from the record: the cap is counted against a cycle, and a
/// proposal that can show no birth cycle has no provable place in any wake's
/// budget. Naming a cycle explicitly does not rescue it — a caller-named label
/// on an unstamped proposal was exactly the free cap the stamp exists to
/// prevent. Prerelease, so no unstamped corpus is accommodated.
pub(super) fn require_open_optimizer_proposal(record: &SkillRecord) -> Result<()> {
    if !born_on_optimize_road(record) {
        return Err(invalid("this gate rules on optimizer-born proposals only"));
    }
    if record.lifecycle_status != SkillLifecycle::Candidate
        || record.approval_status != ClaimApprovalStatus::Proposed
    {
        return Err(invalid(
            "an optimizer-born proposal is gated while it is an open candidate",
        ));
    }
    SkillEditCycle::of_record(record)?;
    Ok(())
}

pub(super) fn target_of(proposal: &SkillRecord) -> Result<EntityId> {
    provenance_str(proposal, PROVENANCE_OPTIMIZE_OF_ENTITY_KEY)
        .and_then(|hex| EntityId::from_hex(&hex).ok())
        .ok_or(invalid(
            "an optimizer-born proposal names the entity it revises",
        ))
}

/// Whether the predecessor is still the revision this proposal was drafted
/// against — active, same `skillId`, same version.
pub(super) fn target_is_current(proposal: &SkillRecord, target: &SkillRecord) -> bool {
    target.lifecycle_status == SkillLifecycle::Active
        && target.skill_id == proposal.skill_id
        && provenance_str(proposal, PROVENANCE_OPTIMIZE_OF_VERSION_KEY).as_deref()
            == Some(target.version.as_str())
}

pub(super) fn provenance_str(record: &SkillRecord, key: &str) -> Option<String> {
    let Value::Map(entries) = &record.provenance else {
        return None;
    };
    entries
        .iter()
        .find(|(entry, _)| entry.as_str() == Some(key))
        .and_then(|(_, value)| value.as_str())
        .map(str::to_owned)
}

/// Keeps the most recent [`SKILL_OPTIMIZE_MAX_BRIEF_EVIDENCE`] receipts, for
/// DISPLAY.
///
/// The ledger is mint-ordered, so dropping from the front drops the oldest —
/// the citation-cap choice the reliability claim and the optimize brief both
/// already make. A verdict cites the evidence it rested on; it is not a copy of
/// the evidence ledger.
///
/// What makes the cap honest rather than a quiet lie is that it is no longer
/// the only record of the basis: the row also carries the exact COUNT, the
/// canonical DIGEST of the whole scored set and a truncation marker
/// ([`HeldOutVerdict::held_out_digest`]), and every comparison this module
/// makes — accept-time, commit-time and admission-time — runs against those,
/// never against this list.
pub(super) fn bounded_receipts(mut receipts: Vec<String>) -> Vec<String> {
    if receipts.len() > SKILL_OPTIMIZE_MAX_BRIEF_EVIDENCE {
        receipts.drain(..receipts.len() - SKILL_OPTIMIZE_MAX_BRIEF_EVIDENCE);
    }
    receipts
}
