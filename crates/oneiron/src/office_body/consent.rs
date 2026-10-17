//! Office proposals (DEC-0006, "A content proposal is a set of forks that
//! share its id"; ARCH-0035's embedded header): a DOCX or XLSX fork joins a
//! proposal when its writer opens it, never by author or time, and one
//! settlement closes the set.
//!
//! A member lands on an answer. A person's word answers when that person is
//! outside the opener's lineage. Otherwise a standing grant answers: one that
//! lets the member's opener edit the artifact, minted by someone outside that
//! lineage. A grant never answers a block both sides edited; a person edited
//! it, so it asks a holder (ARCH-0075). A member with no answer waits. A
//! settlement selects the waiting members its approve scope covers and its
//! review pinned, so a fork that joins later never inherits an answer. A
//! proposal keeps to one artifact, so the artifact's read admission covers
//! every member (CALLS "OF-505 slice D"). The members a settlement leaves
//! waiting are asked of their holders (`holder_ask`); the proposal records
//! each ask.

use std::collections::{BTreeMap, BTreeSet};

use heed::{RoTxn, RwTxn};
use loro::ExportMode;
use oneiron_docedit::live::ApproveScope;
use serde::{Deserialize, Serialize};

use super::{ConflictKind, OfficeBodyDiff, invalid, loro_kind, open_fork, three_way, validate};
use crate::Vault;
use crate::consent::{
    ActionClass, ActionEnvelope, ActorBound, ComposedEffect, ConsentDecision, EffectFacts,
    GrantBound, StandingConsentGrant, evaluate_consent, load_active_standing_grants,
};
use crate::edge::EdgeActorClass;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::side_table::{self, Named, SideTable};
use crate::store::Store;
use crate::typed_body::{
    TypedBodyFork, discard_typed_body_fork_in_txn, merge_admitted_typed_body_fork_in_txn,
};
use crate::write_envelope::WriteActor;

/// The action class a standing grant names to land an actor's office fork on
/// an artifact without a person's word.
pub const OFFICE_BODY_EDIT_CLASS: &str = "entity.office.edit";
const OFFICE_MERGE_OPERATION: &str = "office.body.merge";
const MAX_PROPOSAL_MEMBERS: usize = 64;
const MAX_REASON_BYTES: usize = 1024;

/// Each proposal, by artifact and proposal id.
const PROPOSALS: SideTable<(EntityId, EntityId), OfficeBodyProposal, Named> =
    SideTable::new(&side_table::OFFICE_BODY_PROPOSAL);
/// The proposal each DOCX or XLSX fork joined when it was opened, by artifact
/// and fork.
const MEMBERSHIP: SideTable<(EntityId, EntityId), EntityId, Named> =
    SideTable::new(&side_table::OFFICE_BODY_FORK_PROPOSAL);

/// Who opened a proposal, in which run, and when. A proposal opened by a
/// fork with no named proposal takes that fork's id.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProposalHeader {
    pub proposal: EntityId,
    pub artifact: EntityId,
    pub opener: EntityId,
    pub run_root: Option<EntityId>,
    pub opened_at: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MemberVerdict {
    Waiting,
    Landed,
    Rejected,
    /// Its opener discarded it unsettled.
    LetGo,
}

/// What answered one member: a person's word, or a standing grant with the
/// gate decision that recorded its use.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum AnsweringAuthority {
    Word { person: EntityId },
    Grant { grant_ref: String, decision: String },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MemberAnswer {
    pub by: AnsweringAuthority,
    /// Who called the settlement; under a grant, possibly the opener.
    pub caller: EntityId,
    /// The live head and the fork head the review read.
    pub head: Vec<u8>,
    pub fork_head: Vec<u8>,
    /// The body head the landing left; `None` for a rejection.
    pub landed: Option<Vec<u8>>,
    pub at: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProposalMember {
    pub fork: EntityId,
    pub opener: EntityId,
    /// The run the fork was opened in, which a run-and-children scope names.
    pub run_root: Option<EntityId>,
    pub verdict: MemberVerdict,
    pub answer: Option<MemberAnswer>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BundleVerdict {
    Landed,
    Rejected,
    Mixed,
    LetGo,
}

/// The holder ask raised for the members a settlement left waiting.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProposalAsk {
    /// The ask group its TASKs share.
    pub ask: EntityId,
    /// The waiting forks it asks about, in member order.
    pub forks: Vec<EntityId>,
    pub at: u64,
}

/// The one receipt that closes a proposal once no member waits.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProposalSettlement {
    pub verdict: BundleVerdict,
    pub at: u64,
    pub reason: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OfficeBodyProposal {
    pub header: ProposalHeader,
    pub members: Vec<ProposalMember>,
    pub settlement: Option<ProposalSettlement>,
    /// The holder asks raised while members waited, oldest first.
    #[serde(default)]
    pub asks: Vec<ProposalAsk>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum SettleVerdict {
    Accept,
    Reject,
}

/// One member fork as the review read it: the diff's `fork_head`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReviewedFork {
    pub fork: EntityId,
    pub fork_head: Vec<u8>,
}

pub struct ProposalSettleRequest<'a> {
    pub verdict: SettleVerdict,
    /// The members the answer covers; `None` covers the whole proposal.
    pub scope: Option<ApproveScope>,
    /// The live head every pinned diff was read at.
    pub head: &'a [u8],
    pub reviewed: &'a [ReviewedFork],
    pub reason: Option<&'a str>,
}

/// One answered member's landing: what only a settlement constructs, and what
/// [`merge_admitted_typed_body_fork_in_txn`] takes in place of its opener
/// check.
pub(crate) struct MergeAdmission {
    fork: EntityId,
}

impl MergeAdmission {
    pub(crate) const fn fork(&self) -> &EntityId {
        &self.fork
    }
}

impl Vault {
    /// One office proposal on `artifact`.
    pub fn office_body_proposal(
        &self,
        artifact: &EntityId,
        proposal: &EntityId,
    ) -> Result<Option<OfficeBodyProposal>> {
        let txn = self.store.env.read_txn()?;
        PROPOSALS.get(&self.store, &txn, &(*artifact, *proposal))
    }

    /// Answer the members of `proposal` that `request` selects, in one
    /// transaction. Accept lands each answered member through its pins; a
    /// member nothing answers stays waiting. Reject is a person's, outside the
    /// opener's lineage, and discards the member's fork. Any refusal refuses
    /// the whole call.
    pub fn settle_office_body_proposal(
        &self,
        artifact: &EntityId,
        proposal: &EntityId,
        request: &ProposalSettleRequest<'_>,
        actor: WriteActor,
    ) -> Result<OfficeBodyProposal> {
        self.with_write_txn_grouped(|wtxn| {
            settle_in_txn(self, wtxn, artifact, proposal, request, actor).map(|(record, _)| record)
        })
    }

    /// Record a holder ask on an unsettled proposal, once per ask group.
    pub(super) fn record_office_proposal_ask(
        &self,
        artifact: &EntityId,
        proposal: &EntityId,
        ask: ProposalAsk,
    ) -> Result<()> {
        self.with_write_txn_grouped(|wtxn| {
            let key = (*artifact, *proposal);
            let Some(mut record) = PROPOSALS.get(&self.store, wtxn, &key)? else {
                return Ok(());
            };
            if record.settlement.is_some() || record.asks.iter().any(|held| held.ask == ask.ask) {
                return Ok(());
            }
            record.asks.push(ask);
            PROPOSALS.put(&self.store, wtxn, &key, &record)
        })
    }
}

/// Registers a just-opened DOCX or XLSX fork in `proposal`, or in a proposal
/// of its own under its id.
pub(super) fn join_in_txn(
    store: &Store,
    wtxn: &mut RwTxn<'_>,
    fork: &TypedBodyFork,
    run_root: Option<&EntityId>,
    proposal: Option<&EntityId>,
) -> Result<()> {
    let member = ProposalMember {
        fork: fork.fork,
        opener: fork.opener,
        run_root: run_root.copied(),
        verdict: MemberVerdict::Waiting,
        answer: None,
    };
    let record = match proposal {
        None => OfficeBodyProposal {
            header: ProposalHeader {
                proposal: fork.fork,
                artifact: fork.entity,
                opener: fork.opener,
                run_root: run_root.copied(),
                opened_at: fork.opened_at,
            },
            members: vec![member],
            settlement: None,
            asks: Vec::new(),
        },
        Some(proposal) => {
            let mut record = PROPOSALS
                .get(store, wtxn, &(fork.entity, *proposal))?
                .ok_or_else(|| invalid("no such proposal on this artifact"))?;
            if record.settlement.is_some() {
                return Err(invalid("the proposal is settled; open a new one"));
            }
            if record.members.len() >= MAX_PROPOSAL_MEMBERS {
                return Err(invalid("a proposal holds at most 64 forks"));
            }
            record.members.push(member);
            record
        }
    };
    let key = (fork.entity, record.header.proposal);
    PROPOSALS.put(store, wtxn, &key, &record)?;
    MEMBERSHIP.put(
        store,
        wtxn,
        &(fork.entity, fork.fork),
        &record.header.proposal,
    )
}

/// The proposal a DOCX or XLSX fork joined.
pub(super) fn proposal_of(
    store: &Store,
    txn: &RoTxn<'_>,
    artifact: &EntityId,
    fork: &EntityId,
) -> Result<EntityId> {
    MEMBERSHIP
        .get(store, txn, &(*artifact, *fork))?
        .ok_or(Error::EntityNotFound)
}

/// The run a DOCX or XLSX fork was opened in.
pub(super) fn member_run_root(
    store: &Store,
    txn: &RoTxn<'_>,
    artifact: &EntityId,
    fork: &EntityId,
) -> Result<Option<EntityId>> {
    let Some(proposal) = MEMBERSHIP.get(store, txn, &(*artifact, *fork))? else {
        return Ok(None);
    };
    Ok(PROPOSALS
        .get(store, txn, &(*artifact, proposal))?
        .and_then(|record| {
            record
                .members
                .into_iter()
                .find(|member| member.fork == *fork)
        })
        .and_then(|member| member.run_root))
}

/// A discarded fork lets its member go; the proposal closes once no member
/// waits.
pub(super) fn let_go_in_txn(
    store: &Store,
    wtxn: &mut RwTxn<'_>,
    artifact: &EntityId,
    fork: &EntityId,
    at: u64,
) -> Result<()> {
    let Some(proposal) = MEMBERSHIP.get(store, wtxn, &(*artifact, *fork))? else {
        return Ok(());
    };
    let key = (*artifact, proposal);
    let mut record = PROPOSALS
        .get(store, wtxn, &key)?
        .ok_or(Error::CorruptedIndex("office proposal missing"))?;
    for member in &mut record.members {
        if member.fork == *fork && member.verdict == MemberVerdict::Waiting {
            member.verdict = MemberVerdict::LetGo;
        }
    }
    close_if_done(&mut record, at, None);
    PROPOSALS.put(store, wtxn, &key, &record)
}

/// Removes `artifact`'s proposals and memberships, with its office rows.
pub(super) fn erase_in_txn(store: &Store, txn: &mut RwTxn<'_>, artifact: &EntityId) -> Result<()> {
    PROPOSALS.delete_from(store, txn, artifact.as_bytes())?;
    MEMBERSHIP.delete_from(store, txn, artifact.as_bytes())?;
    Ok(())
}

/// [`Vault::settle_office_body_proposal`] in the caller's transaction, with
/// the diff of each member it landed, in member order.
pub(super) fn settle_in_txn(
    vault: &Vault,
    wtxn: &mut RwTxn<'_>,
    artifact: &EntityId,
    proposal: &EntityId,
    request: &ProposalSettleRequest<'_>,
    actor: WriteActor,
) -> Result<(OfficeBodyProposal, Vec<(EntityId, OfficeBodyDiff)>)> {
    let kind = loro_kind(&vault.store, wtxn, artifact)?;
    let key = (*artifact, *proposal);
    let mut record = PROPOSALS
        .get(&vault.store, wtxn, &key)?
        .ok_or(Error::EntityNotFound)?;
    if record.settlement.is_some() {
        return Err(invalid("the proposal is settled"));
    }
    if request.reviewed.len() > MAX_PROPOSAL_MEMBERS {
        return Err(invalid("a proposal holds at most 64 forks"));
    }
    let reason = match request.reason.map(str::trim) {
        Some(reason) if reason.is_empty() || reason.len() > MAX_REASON_BYTES => {
            return Err(invalid("a settlement reason is 1 to 1024 bytes"));
        }
        reason => reason.map(str::to_owned),
    };
    let mut pins = BTreeMap::new();
    for pin in request.reviewed {
        let Some(member) = record.members.iter().find(|member| member.fork == pin.fork) else {
            return Err(invalid("a reviewed fork is not a member of this proposal"));
        };
        if member.verdict != MemberVerdict::Waiting {
            return Err(invalid("a reviewed fork is already settled"));
        }
        if pins.insert(pin.fork, pin.fork_head.as_slice()).is_some() {
            return Err(invalid("a fork is reviewed twice"));
        }
    }
    let scope = request
        .scope
        .clone()
        .unwrap_or_else(|| ApproveScope::OneItem(proposal.to_hex()));
    let selected: Vec<usize> = (0..record.members.len())
        .filter(|&index| {
            let member = &record.members[index];
            pins.contains_key(&member.fork) && covers(&scope, &record.header, member)
        })
        .collect();
    if selected.is_empty() {
        return Err(invalid(
            "the scope covers no reviewed fork that waits in this proposal",
        ));
    }
    let caller = actor.entity_ref();
    let person = actor.actor_class() == EdgeActorClass::Human;
    let at = vault.now_recorded_at();
    let mut landed = Vec::new();
    match request.verdict {
        SettleVerdict::Reject => {
            for index in selected {
                let member = &record.members[index];
                if !person || lineage(&record.header, member).contains(&caller) {
                    return Err(invalid(
                        "a person outside the opener's lineage rejects a proposal; its opener discards the fork",
                    ));
                }
                let (_, fork_doc) = open_fork(&vault.store, wtxn, artifact, &member.fork)?;
                let fork_head = fork_doc.oplog_frontiers().encode();
                if fork_head != pins[&member.fork] {
                    return Err(invalid(
                        "the fork changed since the review; read the diff again",
                    ));
                }
                let fork = member.fork;
                discard_typed_body_fork_in_txn(vault, wtxn, artifact, &fork, actor)?;
                let member = &mut record.members[index];
                member.verdict = MemberVerdict::Rejected;
                member.answer = Some(MemberAnswer {
                    by: AnsweringAuthority::Word { person: caller },
                    caller,
                    head: request.head.to_vec(),
                    fork_head,
                    landed: None,
                    at,
                });
            }
        }
        SettleVerdict::Accept => {
            let (head, _) = vault.loro_body(wtxn, artifact, kind, None)?;
            if head.frontier != request.head {
                return Err(invalid(
                    "the body moved since the review; read the diff again",
                ));
            }
            let grants = issued_grants(vault, wtxn)?;
            for index in selected {
                let member = record.members[index].clone();
                let (fork_record, fork_doc) =
                    open_fork(&vault.store, wtxn, artifact, &member.fork)?;
                let fork_head = fork_doc.oplog_frontiers().encode();
                if fork_head != pins[&member.fork] {
                    return Err(invalid(
                        "the fork changed since the review; read the diff again",
                    ));
                }
                // The head moves only by this settlement's own landings.
                let (head, live) = vault.loro_body(wtxn, artifact, kind, None)?;
                let diff = three_way(kind, &live, &fork_doc, &fork_record.base, &head.frontier)?;
                if diff.blocking() {
                    return Err(invalid("a reviewed fork conflicts with the live body"));
                }
                let excluded = lineage(&record.header, &member);
                let by = if person && !excluded.contains(&caller) {
                    AnsweringAuthority::Word { person: caller }
                } else if diff
                    .conflicts
                    .iter()
                    .any(|conflict| conflict.kind == ConflictKind::BothEdited)
                {
                    continue;
                } else {
                    let Some(grant_ref) =
                        covering_grant(&grants, &excluded, artifact, &member.opener)?
                    else {
                        continue;
                    };
                    let effect = office_effect(artifact, &member.opener)?;
                    let used = vault.record_standing_grant_use_in_txn(
                        wtxn,
                        &grant_ref,
                        effect.digest(),
                    )?;
                    AnsweringAuthority::Grant {
                        grant_ref,
                        decision: used.decision_id().to_hex(),
                    }
                };
                let updates = fork_doc
                    .export(ExportMode::updates(&live.oplog_vv()))
                    .map_err(|_| invalid("office body fork export"))?;
                let scratch = live.fork();
                scratch
                    .import(&updates)
                    .map_err(|_| invalid("office body fork import"))?;
                validate(kind, &scratch)?;
                let admission = MergeAdmission { fork: member.fork };
                let after = merge_admitted_typed_body_fork_in_txn(
                    vault,
                    wtxn,
                    artifact,
                    &member.fork,
                    &head.frontier,
                    actor,
                    &admission,
                )?;
                let member = &mut record.members[index];
                member.verdict = MemberVerdict::Landed;
                member.answer = Some(MemberAnswer {
                    by,
                    caller,
                    head: request.head.to_vec(),
                    fork_head,
                    landed: Some(after.frontier),
                    at,
                });
                landed.push((member.fork, diff));
            }
        }
    }
    close_if_done(&mut record, at, reason);
    PROPOSALS.put(&vault.store, wtxn, &key, &record)?;
    Ok((record, landed))
}

/// Everyone whose answer on `member` would be the opener's own: the
/// proposal's opener and the member's. No agent or run lineage resolver
/// exists yet, so each is exactly itself (FIX-LIST).
fn lineage(header: &ProposalHeader, member: &ProposalMember) -> BTreeSet<EntityId> {
    BTreeSet::from([header.opener, member.opener])
}

fn covers(scope: &ApproveScope, header: &ProposalHeader, member: &ProposalMember) -> bool {
    let named = |id: &EntityId, reference: &str| id.to_hex().eq_ignore_ascii_case(reference.trim());
    match scope {
        ApproveScope::ThisActor(actor) => named(&member.opener, actor),
        ApproveScope::ThisRunAndChildren(run) => {
            member.run_root.is_some_and(|root| named(&root, run))
        }
        ApproveScope::OneItem(proposal) => named(&header.proposal, proposal),
    }
}

/// Every active standing grant with the person who minted it.
fn issued_grants(
    vault: &Vault,
    txn: &RoTxn<'_>,
) -> Result<Vec<(StandingConsentGrant, Option<EntityId>)>> {
    let mut issued = Vec::new();
    for grant in load_active_standing_grants(&vault.store, txn)? {
        let issuer = vault
            .consent_grant_in_txn(txn, &grant.bound().digest().to_hex())?
            .map(|row| row.owner_stamp.actor);
        issued.push((grant, issuer));
    }
    Ok(issued)
}

/// The landing of `opener`'s work on `artifact` as the one consent evaluator
/// reads it: `opener` editing the artifact under the office edit class.
fn office_effect(artifact: &EntityId, opener: &EntityId) -> Result<ComposedEffect> {
    ComposedEffect::new(EffectFacts::new(OFFICE_MERGE_OPERATION)?)
        .with_action_requirement(office_bound(artifact, opener)?)
}

fn office_bound(artifact: &EntityId, opener: &EntityId) -> Result<GrantBound> {
    let (class, envelope) = office_scope(artifact)?;
    GrantBound::action(ActorBound::new(opener.to_hex())?, class, envelope)
}

/// The scope of office edits to `artifact`: what a standing grant names to
/// land a fork there, and whose holders a waiting member is asked of.
pub(super) fn office_scope(artifact: &EntityId) -> Result<(ActionClass, ActionEnvelope)> {
    let target = format!("entity:{}", artifact.to_hex());
    Ok((
        ActionClass::new(OFFICE_BODY_EDIT_CLASS)?,
        ActionEnvelope::new([target.clone()])?.with_target(target)?,
    ))
}

/// The ref of a standing grant that lands `opener`'s work on `artifact`,
/// minted by someone outside `excluded`; `None` when none does.
fn covering_grant(
    grants: &[(StandingConsentGrant, Option<EntityId>)],
    excluded: &BTreeSet<EntityId>,
    artifact: &EntityId,
    opener: &EntityId,
) -> Result<Option<String>> {
    let eligible: Vec<StandingConsentGrant> = grants
        .iter()
        .filter(|(_, issuer)| issuer.is_some_and(|issuer| !excluded.contains(&issuer)))
        .map(|(grant, _)| grant.clone())
        .collect();
    let bound = office_bound(artifact, opener)?;
    if evaluate_consent(&office_effect(artifact, opener)?, None, &eligible) != ConsentDecision::Auto
    {
        return Ok(None);
    }
    Ok(eligible
        .iter()
        .find(|grant| grant.bound().contains(&bound))
        .map(|grant| grant.bound().digest().to_hex()))
}

/// Writes the settlement once no member waits.
fn close_if_done(record: &mut OfficeBodyProposal, at: u64, reason: Option<String>) {
    if record.settlement.is_some()
        || record
            .members
            .iter()
            .any(|member| member.verdict == MemberVerdict::Waiting)
    {
        return;
    }
    let all = |verdict: MemberVerdict| {
        record
            .members
            .iter()
            .all(|member| member.verdict == verdict)
    };
    let verdict = if all(MemberVerdict::Landed) {
        BundleVerdict::Landed
    } else if all(MemberVerdict::Rejected) {
        BundleVerdict::Rejected
    } else if all(MemberVerdict::LetGo) {
        BundleVerdict::LetGo
    } else {
        BundleVerdict::Mixed
    };
    record.settlement = Some(ProposalSettlement {
        verdict,
        at,
        reason,
    });
}
