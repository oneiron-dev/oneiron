//! Pre-materialized author seam and durable maintenance execution. No delivery here.
use super::super::applied::{MaintenanceInverse, MaintenanceRevert};
use super::super::proposals;
use super::approval::ApprovalOwner;
use super::context::{
    reach_out_stands, reach_out_stands_in_txn, validate_citations, validate_packet,
};
use super::{
    PREDICATE, Packet, REPRESENTATION_FACET, ReachOutPin, RepresentationCitation,
    RepresentationContext, RepresentationRequest, RepresentationSource, invalid,
};
use crate::dreamer_runner::{
    DreamerAdmittedAttempt, DreamerRunnerStore, EnqueueDreamerAttemptOutcome,
};
use crate::limit_ask::EngineLimit;
use crate::provenance::birth::RowBirth;
use crate::provenance::made_by::MadeByClass;
use crate::side_table::{self, LegacyJson, SideTable};
use crate::{
    ClaimApprovalStatus, ClaimCandidate, ClaimLifecycleStatus, ClaimSource, ClaimSubject, EntityId,
    Result, TimeRange, Vault, WriteActor,
};
use rmpv::Value;
use serde::{Deserialize, Serialize};

/// Evidence-citing user-voice representation proposal record, keyed by
/// proposal claim id.
const PROPOSAL: SideTable<EntityId, StoredProposal, LegacyJson> =
    SideTable::new(&side_table::DREAMER_REPRESENTATION_PROPOSAL);

/// The host chooses the wording. The engine verifies every citation, stores
/// the immutable UTF-8 bytes, and keeps source quotes beside the review.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RepresentationDraft {
    pub text: String,
    pub evidence: Vec<RepresentationCitation>,
    pub voice: Vec<RepresentationCitation>,
}
/// Synchronous, deterministic author seam, like CommitmentWakeProposalPlanner.
/// Model hosts must pre-materialize the answer (with their budgeted call seam)
/// and return it here. Queue replay never invokes a model or charges again.
pub trait RepresentationPlanner {
    fn plan(&mut self, context: &RepresentationContext) -> Result<RepresentationDraft>;
}
/// Characters of a source's own text one citation quotes.
const QUOTE_CHARS: usize = 200;
/// A host's model answer, cited deterministically: every evidence and voice
/// source is cited by a bounded prefix of its own text, and an evidence
/// marker the answer left out is appended on a closing line. The host makes
/// its budgeted call before scheduling; planning never calls a model.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PrematerializedDraft {
    pub text: String,
}
impl RepresentationPlanner for PrematerializedDraft {
    fn plan(&mut self, context: &RepresentationContext) -> Result<RepresentationDraft> {
        if self.text.trim().is_empty() {
            return Err(invalid());
        }
        let quote = |source: &RepresentationSource| {
            let text = source.text.trim();
            let end = text
                .char_indices()
                .nth(QUOTE_CHARS)
                .map_or(text.len(), |(at, _)| at);
            source.cite(&text[..end])
        };
        let evidence: Vec<RepresentationCitation> = context.evidence.iter().map(quote).collect();
        let mut text = self.text.trim().to_owned();
        let missing: Vec<String> = evidence
            .iter()
            .map(RepresentationCitation::marker)
            .filter(|marker| !text.contains(marker.as_str()))
            .collect();
        if !missing.is_empty() {
            text.push_str("\n\n");
            text.push_str(&missing.join(" "));
        }
        Ok(RepresentationDraft {
            text,
            evidence,
            voice: context.voice.iter().map(quote).collect(),
        })
    }
}
/// A plan's row, written when it is queued: its packet, the owner it is
/// for, and its landing once it lands.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct StoredProposal {
    packet: Packet,
    /// Outside the hashed packet, so an erase forgets them while the
    /// packet's id and content ref stand (FIX 4512).
    owner: ApprovalOwner,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    landed: Option<LandedProposal>,
}
/// The run a plan landed in and its reviewed revision.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct LandedProposal {
    run: String,
    revision: [u8; 32],
}
/// A landed plan as a review reads it, for its live owner: the request is
/// rebuilt from the packet and the envelope, never stored with the owner.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct LiveProposal {
    pub(super) packet: Packet,
    pub(super) request: RepresentationRequest,
    pub(super) run: String,
    pub(super) revision: [u8; 32],
}
impl Vault {
    /// Reads real context, verifies the pre-materialized draft, stores it below
    /// the claim graph, then queues the maintenance facet that saves the plan
    /// for the owner's send review. Nothing is sent.
    pub fn schedule_representation(
        &self,
        request: &RepresentationRequest,
        planner: &mut dyn RepresentationPlanner,
        now: u64,
    ) -> Result<EnqueueDreamerAttemptOutcome> {
        self.schedule_plan(request, None, planner, now)
    }

    /// [`Self::schedule_representation`] for a stewardship follow-up: the plan
    /// carries the reach-out it drafts, at `revision`, and lands only while
    /// that reach-out still stands there.
    pub(in crate::dreamer_runner::maintenance) fn schedule_follow_up(
        &self,
        request: &RepresentationRequest,
        reach_out: EntityId,
        revision: [u8; 32],
        planner: &mut dyn RepresentationPlanner,
        now: u64,
    ) -> Result<EnqueueDreamerAttemptOutcome> {
        let pin = ReachOutPin {
            claim: reach_out,
            revision,
        };
        self.schedule_plan(request, Some(pin), planner, now)
    }

    fn schedule_plan(
        &self,
        request: &RepresentationRequest,
        reach_out: Option<ReachOutPin>,
        planner: &mut dyn RepresentationPlanner,
        now: u64,
    ) -> Result<EnqueueDreamerAttemptOutcome> {
        let context = self.representation_context(request)?;
        let draft = planner.plan(&context)?;
        if draft.text.trim().is_empty() {
            return Err(invalid());
        }
        validate_citations(&context.evidence, &draft.evidence, Some(&draft.text))?;
        validate_citations(&context.voice, &draft.voice, None)?;
        measure_plan(self, &context, &draft.text);
        let packet = Packet {
            request: request.packet(),
            content: crate::compaction::output::store_output(self, draft.text.as_bytes())?,
            evidence: draft.evidence,
            voice: draft.voice,
            reach_out,
        };
        // Re-read after the host callback. A source edited while authoring is
        // not the source the model saw, even when its old quote still exists.
        validate_packet(self, &packet, request.owner)?;
        let id = packet.id()?;
        // The owner waits in the plan's envelope, not in the queue (FIX 4512).
        // A plan queued or landed for them keeps its row; one whose owner was
        // erased never takes a live owner again.
        self.with_write_txn_grouped(|txn| {
            let held = PROPOSAL.get(&self.store, &*txn, &id)?;
            match held {
                Some(held) if held.owner.is(request.owner) => Ok(()),
                Some(_) => Err(invalid()),
                None => {
                    let envelope = StoredProposal {
                        packet: packet.clone(),
                        owner: ApprovalOwner::Actor(request.owner),
                        landed: None,
                    };
                    PROPOSAL.put(&self.store, txn, &id, &envelope)
                }
            }
        })?;
        let input = String::from_utf8(packet.bytes()?).map_err(|_| invalid())?;
        DreamerRunnerStore::new(self).enqueue_maintenance(
            REPRESENTATION_FACET,
            Value::from(input),
            format!("representation:{}", id.to_hex()),
            now,
        )
    }
}
/// Measures a plan where it is written against the `[limits]` rows (OF-520):
/// its evidence and voice sources, and its longest route, source text or
/// draft. Past one the vault's port asks, and the plan is kept whole.
fn measure_plan(vault: &Vault, context: &RepresentationContext, text: &str) {
    let request = &context.request;
    for items in [request.evidence.len(), request.voice.len()] {
        let _ = vault.measure_limit(EngineLimit::MaintenanceRowItems, items as u64);
    }
    let mut longest = text.len();
    for route in [&request.verb, &request.channel, &request.target] {
        longest = longest.max(route.len());
    }
    for source in context.evidence.iter().chain(&context.voice) {
        longest = longest.max(source.text.len());
    }
    let _ = vault.measure_limit(EngineLimit::MaintenanceTextBytes, longest as u64);
}
/// Saves one queued plan for the owner's send review. The Dreamer applies it
/// at once (OF-023): it lands Auto with a receipt the owner reverts, and the
/// inbox's finding notice tells them; a plan the Gate parks waits Proposed
/// in the run tray as before. Saving arms no send. A follow-up whose
/// reach-out no longer stands lands nothing.
pub(in crate::dreamer_runner::maintenance) fn run(
    vault: &Vault,
    attempt: &DreamerAdmittedAttempt,
    now: u64,
) -> Result<Option<EntityId>> {
    let packet: Packet =
        serde_json::from_str(attempt.status.payload.input.as_str().ok_or_else(invalid)?)
            .map_err(|_| invalid())?;
    let id = packet.id()?;
    // The owner is the envelope's, written when the plan was queued. A plan
    // whose owner was erased since lands nothing (FIX 4512).
    let held = {
        let txn = vault.store.env.read_txn()?;
        PROPOSAL.get(&vault.store, &txn, &id)?.ok_or_else(invalid)?
    };
    if held.packet != packet {
        return Err(invalid());
    }
    let ApprovalOwner::Actor(owner) = held.owner else {
        return Ok(None);
    };
    if let Some(pin) = &packet.reach_out
        && !reach_out_stands(vault, pin.claim, pin.revision)?
    {
        return Ok(None);
    }
    validate_packet(vault, &packet, owner)?;
    let authority = vault.dreamer_authority()?.entity_ref();
    let run = crate::entity_id::bytes_to_hex_lower(attempt.status.attempt.id.as_bytes());
    let value = String::from_utf8(packet.bytes()?).map_err(|_| invalid())?;
    let evidence = crate::dreamer_consolidation::encode_consolidation_evidence(
        &crate::dreamer_consolidation::ConsolidationEvidenceEnvelope {
            refs: packet
                .evidence
                .iter()
                .chain(&packet.voice)
                .map(|c| c.claim)
                .collect(),
            chain: Vec::new(),
            source_meet: ClaimSource::Generated,
        },
    );
    // The Dreamer's own claim, about no person: the owner stays in the
    // envelope alone (FIX 4512).
    let candidate = ClaimCandidate::new(
        PREDICATE,
        ClaimSubject::Entity(authority),
        Value::from(value),
        1.0,
    )
    .with_evidence(evidence);
    // Rule A: the draft is concluded from every claim it cites, over their
    // validated quotes.
    let cited: Vec<_> = packet.evidence.iter().chain(&packet.voice).collect();
    let _ = vault.measure_limit(EngineLimit::MaintenanceRowItems, cited.len() as u64);
    let inputs: Vec<EntityId> = cited.iter().map(|citation| citation.claim).collect();
    let quotes: Vec<&[u8]> = cited
        .iter()
        .map(|citation| citation.quote.as_bytes())
        .collect();
    // The landing's envelope keeps the shared authority stamp and the Gate's
    // run-tray keys, not another policy or another Dreamer actor.
    proposals::land(
        vault,
        REPRESENTATION_FACET,
        attempt.status.attempt.id,
        |landing| {
            vault.with_write_txn_grouped(|txn| {
                let held = PROPOSAL
                    .get(&vault.store, &*txn, &id)?
                    .ok_or_else(invalid)?;
                if held.packet != packet {
                    return Err(invalid());
                }
                if held.landed.is_some() {
                    if vault.get_claim_in_txn(&*txn, &id)?.is_none() {
                        return Err(invalid());
                    }
                    // The owner's review and revert are terminal, never reset
                    // by replay.
                    return Ok(Some(id));
                }
                if !held.owner.is(owner) {
                    return Ok(None);
                }
                if let Some(pin) = &packet.reach_out
                    && !reach_out_stands_in_txn(vault, &*txn, authority, pin.claim, pin.revision)?
                {
                    return Ok(None);
                }
                if vault.get_claim_in_txn(&*txn, &id)?.is_some() {
                    return Err(invalid());
                }
                let mut envelope = landing.envelope().clone();
                vault.sign_retained_machine_claim_in_txn(&*txn, &id, &candidate, &mut envelope)?;
                let birth = RowBirth::written(
                    envelope.actor(),
                    MadeByClass::Concluded,
                    "dreamer.representation",
                    &inputs,
                    &quotes,
                    now,
                );
                vault
                    .batch_in()
                    .claim_candidate(
                        &id,
                        candidate.clone(),
                        &envelope,
                        TimeRange {
                            start: now,
                            end: now,
                        },
                        now,
                    )
                    .made_by(&id, birth)
                    .apply_recording_gate_decisions(txn)?;
                let landed = vault.get_claim_in_txn(&*txn, &id)?.ok_or_else(invalid)?;
                if landed.approval != landing.envelope().approval() {
                    return Err(invalid());
                }
                let record = StoredProposal {
                    packet: packet.clone(),
                    owner: held.owner,
                    landed: Some(LandedProposal {
                        run: run.clone(),
                        revision: review_revision(&landed)?,
                    }),
                };
                PROPOSAL.put(&vault.store, txn, &id, &record)?;
                if landing.record_in_txn(
                    vault,
                    txn,
                    id,
                    MaintenanceInverse::RepresentationPlan,
                    now,
                )? {
                    vault.record_finding_notification_in_txn(txn, id, owner, now)?;
                }
                Ok(Some(id))
            })
        },
    )
}

/// Withdraws, as `owner`, each live plan drafted from `reach_out`, for the
/// owner's revert of that reach-out, and lists it as closed. The plan's
/// content and receipts stay as history; one already sent stays sent.
pub(in crate::dreamer_runner::maintenance) fn withdraw_follow_ups_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    reach_out: EntityId,
    owner: WriteActor,
    now: u64,
    out: &mut MaintenanceRevert,
) -> Result<()> {
    let mut drafted = Vec::new();
    for row in PROPOSAL.iter_from(&vault.store, &*txn, &[])? {
        let (id, record) = row?;
        if record
            .packet
            .reach_out
            .is_some_and(|pin| pin.claim == reach_out)
        {
            drafted.push(id);
        }
    }
    for id in drafted {
        if vault
            .get_claim_in_txn(&*txn, &id)?
            .is_some_and(|body| body.lifecycle == ClaimLifecycleStatus::Active)
        {
            vault.retract_claim_in_txn_as(txn, &id, now, Some(owner))?;
            out.closed.push(id);
        }
    }
    Ok(())
}
/// A plan's (or a pinned reach-out's) body hashed with its approval set
/// aside, so a review or an approval moves nothing while any rewrite does.
pub(in crate::dreamer_runner::maintenance) fn review_revision(
    body: &crate::ClaimBody,
) -> Result<[u8; 32]> {
    let mut normalized = body.clone();
    normalized.approval = ClaimApprovalStatus::Proposed;
    Ok(*blake3::hash(&crate::claim::encode_claim_body(&normalized)?).as_bytes())
}
/// A landed plan for its live owner. One whose owner was erased reads as
/// stale: it no longer reviews, arms or sends (FIX 4512).
pub(super) fn read_proposal(
    vault: &Vault,
    id: &EntityId,
) -> Result<(LiveProposal, crate::ClaimBody)> {
    let record: StoredProposal = {
        let txn = vault.store.env.read_txn()?;
        PROPOSAL.get(&vault.store, &txn, id)?.ok_or_else(invalid)?
    };
    let (ApprovalOwner::Actor(owner), Some(landed)) = (record.owner, record.landed) else {
        return Err(invalid());
    };
    let body = vault.get_claim(id)?.ok_or_else(invalid)?;
    let authority = vault.dreamer_authority()?.entity_ref();
    if record.packet.id()? != *id
        || body.predicate != PREDICATE
        || body.subject != ClaimSubject::Entity(authority)
        || body.source != Some(ClaimSource::Generated)
        || body.lifecycle != crate::ClaimLifecycleStatus::Active
        || body.stale
        || review_revision(&body)? != landed.revision
        || crate::claim::session_claim_producer(&body) != Some(authority)
        || body.value.as_str() != std::str::from_utf8(&record.packet.bytes()?).ok()
    {
        return Err(invalid());
    }
    let proposal = LiveProposal {
        request: record.packet.request.with_owner(owner),
        packet: record.packet,
        run: landed.run,
        revision: landed.revision,
    };
    Ok((proposal, body))
}

/// Erasing `actor` from the plans' envelopes (FIX 4512): a plan for them
/// keeps its packet, id, content ref and landing and names no one, so it no
/// longer reviews, arms or sends, and a queued one lands nothing. The packet
/// and the claim it landed as never named them. One-way, in the erase's own
/// transaction. An id whose entity is no actor scans nothing.
///
/// # Errors
///
/// Storage errors, or a plan row that cannot be read.
pub(crate) fn erase_proposal_actor_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    actor: &EntityId,
) -> Result<()> {
    if crate::typed_body::names_no_actor(vault, wtxn, actor)? {
        return Ok(());
    }
    let mut plans = Vec::new();
    for (id, mut record) in PROPOSAL.scan(&vault.store, wtxn)? {
        if record.owner.is(*actor) {
            record.owner = ApprovalOwner::Erased;
            plans.push((id, record));
        }
    }
    for (id, record) in plans {
        PROPOSAL.put(&vault.store, wtxn, &id, &record)?;
    }
    Ok(())
}
