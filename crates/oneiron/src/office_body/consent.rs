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
//! proposal's members may span artifacts. Its header's artifact is the home
//! its read and settle doors name; every member carries its own artifact, so
//! admission, review pins, landing and lifted-key masking stay member-local
//! (CALLS "OF-505 slice D"). The members a settlement leaves waiting are
//! asked of their own artifacts' holders (`holder_ask`); the proposal records
//! each ask.

use std::collections::{BTreeMap, BTreeSet};

use heed::{RoTxn, RwTxn};
use loro::ExportMode;
use oneiron_docedit::live::ApproveScope;
use serde::{Deserialize, Serialize};

use super::{
    ConflictKind, OfficeBodyDiff, OfficeBodyKind, invalid, land_moved_xlsx, loro_kind, open_fork,
    three_way, validate,
};
use crate::Vault;
use crate::attempt_queue::AttemptId;
use crate::consent::{
    ActionClass, ActionEnvelope, ActorBound, AuthenticatedOwner, ComposedEffect, ConsentDecision,
    EffectFacts, GrantBound, StandingConsentGrant, evaluate_consent, load_active_standing_grants,
};
use crate::edge::EdgeActorClass;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::side_table::{self, Named, SideTable};
use crate::store::{ManifestDbs, Store};
use crate::typed_body::{
    BodyActor, TypedBodyFork, discard_admitted_typed_body_fork_in_txn,
    merge_admitted_typed_body_fork_in_txn,
};
use crate::write_envelope::WriteActor;

mod live_edit;
pub(crate) use live_edit::LiveEditAdmission;
pub(super) use live_edit::revoke_office_edit_grants_naming_in_txn;
pub(super) use live_edit::{
    admit_live_edit_in_txn, covering_live_grant, identical_live_edit_grant_active_in_txn,
    live_edit_admission_in_txn, live_edit_effect, mint_live_edit_grant_in_txn, office_bound,
    office_effect_for, office_scope,
};

/// The action class a standing grant names to land an actor's office fork on
/// an artifact without a person's word.
pub const OFFICE_BODY_EDIT_CLASS: &str = "entity.office.edit";
const OFFICE_MERGE_OPERATION: &str = "office.body.merge";

/// Each proposal by its id. The header's artifact is its home, not its key.
pub(super) const PROPOSALS: SideTable<EntityId, OfficeBodyProposal, Named> =
    SideTable::new(&side_table::OFFICE_BODY_PROPOSAL);
/// The proposal each DOCX or XLSX fork joined when it was opened, by artifact
/// and fork.
pub(super) const MEMBERSHIP: SideTable<(EntityId, EntityId), EntityId, Named> =
    SideTable::new(&side_table::OFFICE_BODY_FORK_PROPOSAL);

/// Who opened a proposal, in which run, and when. A proposal opened by a
/// fork with no named proposal takes that fork's id.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProposalHeader {
    pub proposal: EntityId,
    pub artifact: EntityId,
    pub opener: BodyActor,
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
    Word { person: BodyActor },
    Grant { grant_ref: String, decision: String },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MemberAnswer {
    pub by: AnsweringAuthority,
    /// Who called the settlement; under a grant, possibly the opener.
    pub caller: BodyActor,
    /// The live head and the fork head the review read.
    pub head: Vec<u8>,
    pub fork_head: Vec<u8>,
    /// The body head the landing left; `None` for a rejection.
    pub landed: Option<Vec<u8>>,
    pub at: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProposalMember {
    /// The artifact this fork edits; the proposal's home need not be its own.
    pub artifact: EntityId,
    pub fork: EntityId,
    pub opener: BodyActor,
    /// The run its opener named when it opened the fork: a label, never
    /// what a scope matches (FIX 3551).
    pub run_root: Option<EntityId>,
    /// The try the fork was opened from, which the host bound the opening
    /// surface to and the opening transaction proved live (FIX 3551): what a
    /// run-and-children scope names. `None` for an owner's or a direct
    /// opening, which belongs to no run.
    #[serde(default)]
    pub origin: Option<AttemptId>,
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
    /// The member artifact whose holders were asked.
    pub artifact: EntityId,
    /// The ask group its TASKs share.
    pub ask: EntityId,
    /// The waiting forks it asks about, in member order.
    pub forks: Vec<EntityId>,
    pub at: u64,
}

/// A holder ask the ask admission refused, kept until an ask is raised.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProposalAskRefusal {
    /// The member artifact whose ask admission refused.
    pub artifact: EntityId,
    /// The waiting forks no holder was asked about, in member order.
    pub forks: Vec<EntityId>,
    /// The ask admission's refusal.
    pub reason: String,
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
    /// The latest holder-ask refusal for each member artifact, cleared for
    /// that artifact once an ask is raised.
    #[serde(default)]
    pub ask_refused: Vec<ProposalAskRefusal>,
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
    pub artifact: EntityId,
    pub fork: EntityId,
    /// The live head on this member's artifact that its diff read.
    pub head: Vec<u8>,
    pub fork_head: Vec<u8>,
}

pub struct ProposalSettleRequest<'a> {
    pub verdict: SettleVerdict,
    /// The members the answer covers; `None` covers the whole proposal.
    pub scope: Option<ApproveScope>,
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

/// One rejected member's letting go: what only a settlement constructs,
/// after a person outside the opener's lineage answered it and its reviewed
/// head held, and what [`discard_admitted_typed_body_fork_in_txn`] takes in
/// place of its opener check (FIX 10016).
pub(crate) struct DiscardAdmission {
    artifact: EntityId,
    fork: EntityId,
    caller: EntityId,
}

impl DiscardAdmission {
    pub(crate) const fn artifact(&self) -> &EntityId {
        &self.artifact
    }

    pub(crate) const fn fork(&self) -> &EntityId {
        &self.fork
    }

    pub(crate) const fn caller(&self) -> &EntityId {
        &self.caller
    }
}

impl Vault {
    /// One office proposal by its id. The caller's door checks its home.
    pub fn office_body_proposal(&self, proposal: &EntityId) -> Result<Option<OfficeBodyProposal>> {
        let txn = self.store.env.read_txn()?;
        PROPOSALS.get(&self.store, &txn, proposal)
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
            settle_in_txn(self, wtxn, proposal, Some(artifact), request, actor)
                .map(|(record, _)| record)
        })
    }

    /// Record a holder ask on an unsettled proposal, once per ask group.
    pub(super) fn record_office_proposal_ask(
        &self,
        proposal: &EntityId,
        ask: ProposalAsk,
    ) -> Result<()> {
        self.with_write_txn_grouped(|wtxn| {
            self.record_office_proposal_ask_in_txn(wtxn, proposal, ask)
        })
    }

    /// Keep a proposal's ask link in the ask admission's transaction.
    pub(super) fn record_office_proposal_ask_in_txn(
        &self,
        wtxn: &mut RwTxn<'_>,
        proposal: &EntityId,
        ask: ProposalAsk,
    ) -> Result<()> {
        let Some(mut record) = PROPOSALS.get(&self.store, wtxn, proposal)? else {
            return Ok(());
        };
        if record.settlement.is_some() {
            return Ok(());
        }
        let repeated = record.asks.iter().any(|held| held.ask == ask.ask);
        let refused = record.ask_refused.len();
        record
            .ask_refused
            .retain(|held| held.artifact != ask.artifact);
        if repeated && record.ask_refused.len() == refused {
            return Ok(());
        }
        if !repeated {
            record.asks.push(ask);
        }
        PROPOSALS.put(&self.store, wtxn, proposal, &record)
    }

    /// Record that ask admission refused one member artifact's holder ask.
    pub(super) fn record_office_proposal_ask_refused(
        &self,
        proposal: &EntityId,
        artifact: &EntityId,
        reason: &str,
    ) -> Result<()> {
        let at = self.now_recorded_at();
        self.with_write_txn_grouped(|wtxn| {
            let Some(mut record) = PROPOSALS.get(&self.store, wtxn, proposal)? else {
                return Ok(());
            };
            if record.settlement.is_some() {
                return Ok(());
            }
            let forks = record
                .members
                .iter()
                .filter(|member| {
                    member.artifact == *artifact && member.verdict == MemberVerdict::Waiting
                })
                .map(|member| member.fork)
                .collect();
            record.ask_refused.retain(|held| held.artifact != *artifact);
            record.ask_refused.push(ProposalAskRefusal {
                artifact: *artifact,
                forks,
                reason: reason.to_owned(),
                at,
            });
            PROPOSALS.put(&self.store, wtxn, proposal, &record)
        })
    }
}

/// Registers a just-opened DOCX or XLSX fork in `proposal`, or in a proposal
/// of its own under its id, with `origin`, the try its opening transaction
/// proved. A proposal holds every fork that joins it (FIX 9991).
pub(super) fn join_in_txn(
    store: &Store,
    wtxn: &mut RwTxn<'_>,
    fork: &TypedBodyFork,
    run_root: Option<&EntityId>,
    origin: Option<AttemptId>,
    proposal: Option<&EntityId>,
) -> Result<()> {
    let member = ProposalMember {
        artifact: fork.entity,
        fork: fork.fork,
        opener: fork.opener,
        run_root: run_root.copied(),
        origin,
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
            ask_refused: Vec::new(),
        },
        Some(proposal) => {
            let mut record = PROPOSALS
                .get(store, wtxn, proposal)?
                .ok_or(Error::EntityNotFound)?;
            if record.settlement.is_some() {
                return Err(invalid("the proposal is settled; open a new one"));
            }
            record.members.push(member);
            record
        }
    };
    PROPOSALS.put(store, wtxn, &record.header.proposal, &record)?;
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

/// The member a DOCX or XLSX fork is in its proposal: the run its opener
/// named and the try it was opened from.
pub(super) fn member_of(
    store: &Store,
    txn: &RoTxn<'_>,
    artifact: &EntityId,
    fork: &EntityId,
) -> Result<Option<ProposalMember>> {
    let Some(proposal) = MEMBERSHIP.get(store, txn, &(*artifact, *fork))? else {
        return Ok(None);
    };
    Ok(PROPOSALS.get(store, txn, &proposal)?.and_then(|record| {
        record
            .members
            .into_iter()
            .find(|member| member.artifact == *artifact && member.fork == *fork)
    }))
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
    let mut record = PROPOSALS
        .get(store, wtxn, &proposal)?
        .ok_or(Error::CorruptedIndex("office proposal missing"))?;
    for member in &mut record.members {
        if member.artifact == *artifact
            && member.fork == *fork
            && member.verdict == MemberVerdict::Waiting
        {
            member.verdict = MemberVerdict::LetGo;
        }
    }
    close_if_done(&mut record, at, None);
    PROPOSALS.put(store, wtxn, &proposal, &record)
}

/// Removes `artifact`'s memberships and its members from every proposal. A
/// surviving proposal's home moves to its first remaining member's artifact.
pub(super) fn erase_in_txn(store: &Store, txn: &mut RwTxn<'_>, artifact: &EntityId) -> Result<()> {
    let at = store.clock().now_recorded_at();
    let mut changed = Vec::new();
    for (proposal, mut record) in PROPOSALS.scan(store, txn)? {
        let members = record.members.len();
        let asks = record.asks.len();
        let refusals = record.ask_refused.len();
        record.members.retain(|member| member.artifact != *artifact);
        record.asks.retain(|ask| ask.artifact != *artifact);
        record.ask_refused.retain(|held| held.artifact != *artifact);
        if record.header.artifact != *artifact
            && record.members.len() == members
            && record.asks.len() == asks
            && record.ask_refused.len() == refusals
        {
            continue;
        }
        if record.members.is_empty() {
            changed.push((proposal, None));
            continue;
        }
        if record.header.artifact == *artifact {
            record.header.artifact = record.members[0].artifact;
        }
        close_if_done(&mut record, at, None);
        changed.push((proposal, Some(record)));
    }
    for (proposal, record) in changed {
        match record {
            Some(record) => PROPOSALS.put(store, txn, &proposal, &record)?,
            None => {
                PROPOSALS.delete(store, txn, &proposal)?;
            }
        }
    }
    MEMBERSHIP.delete_from(store, txn, artifact.as_bytes())?;
    Ok(())
}

/// [`Vault::settle_office_body_proposal`] in the caller's transaction, with
/// the diff of each member it landed, in member order.
pub(super) fn settle_in_txn(
    vault: &Vault,
    wtxn: &mut RwTxn<'_>,
    proposal: &EntityId,
    home: Option<&EntityId>,
    request: &ProposalSettleRequest<'_>,
    actor: WriteActor,
) -> Result<(OfficeBodyProposal, Vec<(EntityId, OfficeBodyDiff)>)> {
    let mut record = PROPOSALS
        .get(&vault.store, wtxn, proposal)?
        .ok_or(Error::EntityNotFound)?;
    if home.is_some_and(|home| record.header.artifact != *home) {
        return Err(Error::EntityNotFound);
    }
    if record.settlement.is_some() {
        return Err(invalid("the proposal is settled"));
    }
    let reason = match request.reason.map(str::trim) {
        Some(reason) if reason.is_empty() => {
            return Err(invalid("a settlement reason is not empty"));
        }
        reason => reason.map(str::to_owned),
    };
    let mut pins = BTreeMap::new();
    for pin in request.reviewed {
        let Some(member) = record
            .members
            .iter()
            .find(|member| member.artifact == pin.artifact && member.fork == pin.fork)
        else {
            return Err(invalid("a reviewed fork is not a member of this proposal"));
        };
        if member.verdict != MemberVerdict::Waiting {
            return Err(invalid("a reviewed fork is already settled"));
        }
        if pins.insert((pin.artifact, pin.fork), pin).is_some() {
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
            pins.contains_key(&(member.artifact, member.fork))
                && covers(&scope, &record.header, member)
        })
        .collect();
    if selected.is_empty() {
        return Err(invalid(
            "the scope covers no reviewed fork that waits in this proposal",
        ));
    }
    let caller = actor.entity_ref();
    let answerer = BodyActor::Actor(caller);
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
                let pin = pins[&(member.artifact, member.fork)];
                let (_, fork_doc) = open_fork(&vault.store, wtxn, &member.artifact, &member.fork)?;
                let fork_head = fork_doc.oplog_frontiers().encode();
                if fork_head.as_slice() != pin.fork_head.as_slice() {
                    return Err(invalid(
                        "the fork changed since the review; read the diff again",
                    ));
                }
                let fork = member.fork;
                let admission = DiscardAdmission {
                    artifact: member.artifact,
                    fork,
                    caller,
                };
                discard_admitted_typed_body_fork_in_txn(
                    vault,
                    wtxn,
                    &member.artifact,
                    &fork,
                    actor,
                    &admission,
                )?;
                let member = &mut record.members[index];
                member.verdict = MemberVerdict::Rejected;
                member.answer = Some(MemberAnswer {
                    by: AnsweringAuthority::Word { person: answerer },
                    caller: answerer,
                    head: pin.head.clone(),
                    fork_head,
                    landed: None,
                    at,
                });
            }
        }
        SettleVerdict::Accept => {
            // Check every reviewed live head before this settlement's first
            // landing moves any of them. Several pins on one artifact all
            // name its pre-settlement head; later landings use the new head.
            for &index in &selected {
                let member = &record.members[index];
                let pin = pins[&(member.artifact, member.fork)];
                let kind = loro_kind(&vault.store, wtxn, &member.artifact)?;
                let (head, _) = vault.loro_body(wtxn, &member.artifact, kind, None)?;
                if head.frontier.as_slice() != pin.head.as_slice() {
                    return Err(invalid(
                        "the body moved since the review; read the diff again",
                    ));
                }
            }
            let grants = issued_grants(vault, wtxn)?;
            for index in selected {
                let member = record.members[index].clone();
                let pin = pins[&(member.artifact, member.fork)];
                let kind = loro_kind(&vault.store, wtxn, &member.artifact)?;
                let (fork_record, fork_doc) =
                    open_fork(&vault.store, wtxn, &member.artifact, &member.fork)?;
                let fork_head = fork_doc.oplog_frontiers().encode();
                if fork_head.as_slice() != pin.fork_head.as_slice() {
                    return Err(invalid(
                        "the fork changed since the review; read the diff again",
                    ));
                }
                // The head moves only by this settlement's own landings.
                let (head, live) = vault.loro_body(wtxn, &member.artifact, kind, None)?;
                let diff = three_way(kind, &live, &fork_doc, &fork_record.base, &head.frontier)?;
                if diff.blocking() {
                    return Err(invalid("a reviewed fork conflicts with the live body"));
                }
                let excluded = lineage(&record.header, &member);
                let by = if person && !excluded.contains(&caller) {
                    AnsweringAuthority::Word { person: answerer }
                } else if diff
                    .conflicts
                    .iter()
                    .any(|conflict| conflict.kind == ConflictKind::BothEdited)
                {
                    continue;
                } else {
                    // A member whose opener was erased left its proposal.
                    let Some(opener) = member.opener.id() else {
                        continue;
                    };
                    let Some(grant_ref) =
                        covering_grant(&grants, &excluded, &member.artifact, &opener)?
                    else {
                        continue;
                    };
                    let effect = office_effect(&member.artifact, &opener)?;
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
                let mut after = merge_admitted_typed_body_fork_in_txn(
                    vault,
                    wtxn,
                    &member.artifact,
                    &member.fork,
                    &head.frontier,
                    actor,
                    &admission,
                )?;
                // Writes made beside a row or column edit move with it.
                if kind == OfficeBodyKind::Xlsx
                    && let Some(frontier) = land_moved_xlsx(
                        vault,
                        wtxn,
                        &member.artifact,
                        (&fork_record.base, &head.frontier),
                        &fork_doc,
                        actor,
                    )?
                {
                    after.frontier = frontier;
                }
                let member = &mut record.members[index];
                member.verdict = MemberVerdict::Landed;
                member.answer = Some(MemberAnswer {
                    by,
                    caller: answerer,
                    head: pin.head.clone(),
                    fork_head,
                    landed: Some(after.frontier),
                    at,
                });
                landed.push((member.fork, diff));
            }
        }
    }
    close_if_done(&mut record, at, reason);
    PROPOSALS.put(&vault.store, wtxn, proposal, &record)?;
    Ok((record, landed))
}

/// Everyone whose answer on `member` would be the opener's own: the
/// proposal's opener and the member's. No agent or run lineage resolver
/// exists yet, so each is exactly itself (FIX-LIST).
pub(super) fn lineage(header: &ProposalHeader, member: &ProposalMember) -> BTreeSet<EntityId> {
    [header.opener, member.opener]
        .into_iter()
        .filter_map(BodyActor::id)
        .collect()
}

fn covers(scope: &ApproveScope, header: &ProposalHeader, member: &ProposalMember) -> bool {
    let named = |id: &EntityId, reference: &str| id.to_hex().eq_ignore_ascii_case(reference.trim());
    match scope {
        ApproveScope::ThisActor(actor) => member.opener.id().is_some_and(|id| named(&id, actor)),
        // The stamped try, never a run a caller named (FIX 3551).
        ApproveScope::ThisRunAndChildren(run) => member.origin.is_some_and(|origin| {
            crate::entity_id::bytes_to_hex_lower(origin.as_bytes()).eq_ignore_ascii_case(run.trim())
        }),
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
    office_effect_for(OFFICE_MERGE_OPERATION, artifact, opener)
}

/// The ref of a standing grant that lands `opener`'s work on `artifact`,
/// minted by someone outside `excluded`; `None` when none does.
fn covering_grant(
    grants: &[(StandingConsentGrant, Option<EntityId>)],
    excluded: &BTreeSet<EntityId>,
    artifact: &EntityId,
    opener: &EntityId,
) -> Result<Option<String>> {
    covering_grant_for(OFFICE_MERGE_OPERATION, grants, excluded, artifact, opener)
}

fn covering_grant_for(
    operation: &str,
    grants: &[(StandingConsentGrant, Option<EntityId>)],
    excluded: &BTreeSet<EntityId>,
    artifact: &EntityId,
    subject: &EntityId,
) -> Result<Option<String>> {
    let eligible: Vec<StandingConsentGrant> = grants
        .iter()
        .filter(|(_, issuer)| issuer.is_some_and(|issuer| !excluded.contains(&issuer)))
        .map(|(grant, _)| grant.clone())
        .collect();
    let bound = office_bound(artifact, subject)?;
    if evaluate_consent(
        &office_effect_for(operation, artifact, subject)?,
        None,
        &eligible,
    ) != ConsentDecision::Auto
    {
        return Ok(None);
    }
    Ok(eligible
        .iter()
        .find(|grant| grant.bound().contains(&bound))
        .map(|grant| grant.bound().digest().to_hex()))
}

/// Writes the settlement once no member waits.
pub(super) fn close_if_done(record: &mut OfficeBodyProposal, at: u64, reason: Option<String>) {
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
