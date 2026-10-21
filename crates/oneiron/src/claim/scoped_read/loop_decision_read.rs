//! An authorised read of loop admissions and rejections for the weave
//! (OF-499 A2): the gate decisions a Dreamer or Coach loop, a resident's
//! dreaming or a turn program left, admitted and refused alike, each one
//! the reader may see. The weave's own adapter builds its items over this
//! read; no existing row, section, policy or route changes with it. A row,
//! a floor or a project read that does not answer withholds only the item
//! it stands under, and the read returns what it admitted: it never fails
//! a report and never widens one.

use std::collections::{BTreeMap, BTreeSet};

use super::{ScopedRead, WeaveReader};
use crate::EntityId;
use crate::claim::{ClaimSubject, decode_claim_body};
use crate::error::Result;
use crate::gate::{PolicyManifestResolution, ResolvedRetrievalFilter};
use crate::ports::EntityStoreRead;
use crate::registry::ENTITY_TYPE_CLAIM;
use crate::scan_check::{DEFAULT_SCAN_CHECK_THRESHOLD, EngineScan, ScanCount};
use crate::store::{GateDecisionId, GateDecisionRecord};

/// Which part of a loop a stored decision is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) enum LoopDecisionFamily {
    /// A loop's run admitted or refused: a base agent's or a resident's
    /// dreaming attempt, or a turn program.
    Admission,
    /// A loop's action or the feedback on it: an applied maintenance write,
    /// an identity kept provisional or settled, a strength archive, or the
    /// revert of one.
    Action,
}

#[allow(
    dead_code,
    reason = "L07-A's weave adapter (OF-499 A2) is its first caller"
)]
impl LoopDecisionFamily {
    /// The family's name, as a served view spells it.
    pub(crate) const fn name(self) -> &'static str {
        match self {
            Self::Admission => "admission",
            Self::Action => "action",
        }
    }
}

/// The stored tags that are loop decisions, each with its family (CALLS
/// "OF-499 A2 loop families"): the direct tags, base agents' and residents'
/// alike. A generic claim, repair or settlement tag joins only once its row
/// links back to one of these decisions durably; none does today
/// (FIX-LIST), so none is here.
pub(crate) const LOOP_DECISION_FAMILIES: &[(&str, LoopDecisionFamily)] = &[
    ("dreamer_authority", LoopDecisionFamily::Admission),
    ("dreamer_turn_program", LoopDecisionFamily::Admission),
    ("dreamer_maintenance_apply", LoopDecisionFamily::Action),
    ("dreamer_maintenance_revert", LoopDecisionFamily::Action),
    ("dreamer_identity_provisional", LoopDecisionFamily::Action),
    ("dreamer_identity_settle", LoopDecisionFamily::Action),
    ("dreamer_strength_archive", LoopDecisionFamily::Action),
    ("dreamer_change_revert", LoopDecisionFamily::Action),
];

/// The family a tag outside [`LOOP_DECISION_FAMILIES`] reads as (CALLS
/// "OF-499 A2 unknown family"): none, so its decision is withheld. A tag is
/// never guessed into a family by its name's prefix.
const LOOP_DECISION_UNKNOWN_FAMILY: Option<LoopDecisionFamily> = None;

/// Whether a subject's own event, its actor the bound reader, is theirs to
/// see (CALLS "OF-499 A2 self receipt"). Its read scope is still proven:
/// an actor's text alone never overrides a narrowed credential.
const LOOP_DECISION_SELF_RECEIPT: bool = true;

/// What a subject's event withholds when its read context is missing: no
/// entity named, or one the reader's own floor refuses (CALLS "OF-499 A2
/// missing context"). The whole item: a retention sidecar, an actor's text
/// or a candidate that never landed proves no scope.
const LOOP_DECISION_MISSING_CONTEXT: Withhold = Withhold::Item;

/// Whether a pending decision is shown, its outcome kept exactly as stored
/// beside allow/approved and deny/rejected (CALLS "OF-499 A2 pending").
const LOOP_DECISION_PENDING: bool = true;

/// Whether a reader learns how many decisions were withheld from it (CALLS
/// "OF-499 A2 withheld counts"): no, since a count leaks other readers'
/// events. The read returns its items alone, so a flip needs a carrier for
/// the count first.
const LOOP_DECISION_WITHHELD_COUNTS: bool = false;
const _: () = assert!(!LOOP_DECISION_WITHHELD_COUNTS);

/// What an actor the reader's own floor refuses withholds (CALLS "OF-499
/// A2 actor visibility"): only the actor ref; the event, its outcome and
/// its reasons stay.
const LOOP_DECISION_ACTOR_VISIBILITY: Withhold = Withhold::Field;

/// What a row or a check that does not answer withholds (CALLS "OF-499 A2
/// error policy"): its one item. The rest of the read stands, a source that
/// does not read adds nothing, and no error reaches the caller.
const LOOP_DECISION_ERROR_POLICY: Withhold = Withhold::Item;

/// The outcome a held decision is stored with.
const PENDING_OUTCOME: &str = "pending";

/// What one rule above withholds when it does not admit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Withhold {
    /// The one optional field; the item stays.
    Field,
    /// The one item; the rest of the read stays.
    Item,
}

/// One loop decision a reader may see: its event's own metadata, admitted
/// before any field, and each optional ref under its own floor. Never the
/// stored record: no diff handle, frontier hash, grant, receipt reason or
/// notice.
#[allow(
    dead_code,
    reason = "L07-A's weave adapter (OF-499 A2) is its first caller"
)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ReadableLoopDecision {
    pub(crate) decision_id: GateDecisionId,
    pub(crate) created_at: u64,
    pub(crate) family: LoopDecisionFamily,
    /// The stored tag, exactly.
    pub(crate) kind: String,
    /// The stored outcome, exactly: allow, pending, deny, approved or
    /// rejected, none collapsed into another.
    pub(crate) outcome: String,
    /// The stored reason codes, shown only past the event's admission. An
    /// erasure skeleton keeps none, and none is made up for it.
    pub(crate) reason_codes: Vec<String>,
    /// Whether the row is an erasure skeleton: its outcome, tag and claim
    /// kept, its reasons and actor scrubbed.
    pub(crate) redacted: bool,
    /// The entity the decision names, when the reader's own floor admits it
    /// (an edge claim's pair too).
    pub(crate) claim_ref: Option<EntityId>,
    /// The decision's actor, when it is the reader or the reader's own floor
    /// admits its row; never read from an actor's text as a name.
    pub(crate) actor_ref: Option<EntityId>,
    /// The vault rows this item's admission stood on, each once: its shown
    /// claim and actor and, for a subject, the project that made the event
    /// theirs. A saved item rechecks whole through
    /// [`ScopedRead::authorised_loop_decision_in_txn`].
    pub(crate) dependencies: Vec<EntityId>,
}

/// The family a stored tag reads as, from [`LOOP_DECISION_FAMILIES`] alone.
pub(crate) fn loop_decision_family(kind: &str) -> Option<LoopDecisionFamily> {
    LOOP_DECISION_FAMILIES
        .iter()
        .find(|(tag, _)| *tag == kind)
        .map(|&(_, family)| family)
        .or(LOOP_DECISION_UNKNOWN_FAMILY)
}

/// A reader bound in the read's own transaction.
#[derive(Debug, Clone, Copy)]
enum LoopReader {
    /// A live vault Owner, co-Owners included: every classified event.
    Owner(EntityId),
    /// A person or an agent bound to the scoped actor: its own events and
    /// those about it or its projects, each with its scope proven.
    Subject(EntityId),
}

impl LoopReader {
    const fn id(self) -> EntityId {
        match self {
            Self::Owner(id) | Self::Subject(id) => id,
        }
    }
}

/// One read's admission state: the lane's policy and floor, resolved once,
/// and the answers it already has.
struct LoopRead {
    reader: LoopReader,
    policy: PolicyManifestResolution,
    filter: ResolvedRetrievalFilter,
    /// Each actor row's floor answer; `None` did not answer.
    floor: BTreeMap<EntityId, Option<bool>>,
    /// The subject's projects, read once on first need.
    projects: Option<BTreeSet<EntityId>>,
}

/// One check's answer under [`LOOP_DECISION_ERROR_POLICY`]: `None` withholds
/// the item; a check that did not answer otherwise admits nothing.
fn answered<T>(check: Result<Option<T>>, what: &'static str) -> Option<Option<T>> {
    match check {
        Ok(answer) => Some(answer),
        Err(error) => {
            tracing::warn!(
                error_kind = ?error.kind(),
                check = what,
                "a loop decision's check did not answer"
            );
            match LOOP_DECISION_ERROR_POLICY {
                Withhold::Item => None,
                Withhold::Field => Some(None),
            }
        }
    }
}

#[allow(
    dead_code,
    reason = "L07-A's weave adapter (OF-499 A2) is its first caller"
)]
impl ScopedRead<'_> {
    /// Every loop decision `reader` may see, admitted and refused alike, in
    /// ledger order (OF-499 A2). The reader binds in `txn` as the live weave
    /// report binds it: a person or an agent to this lane's actor, an owner
    /// to its proof revalidated here. An owner sees every classified event;
    /// a subject sees an event whose named entity passes its own floor and
    /// that is its own or about it or its projects. Outcome and reasons come
    /// only past that admission, and each optional ref only past its own
    /// floor. A rejected event reads though its candidate never landed.
    ///
    /// Every ledger row is read (rule 5: past its threshold the walk raises
    /// one scan check and reads on). A row or check that does not answer
    /// withholds its own item; a reader that does not bind, or a ledger that
    /// does not open, adds nothing. Nothing here refuses.
    pub(crate) fn authorised_loop_decisions_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        reader: WeaveReader<'_>,
    ) -> Vec<ReadableLoopDecision> {
        let Some(mut read) = self.loop_read_in(txn, reader) else {
            return Vec::new();
        };
        let mut count = ScanCount::start(&self.vault.store, txn, EngineScan::GateDecisionRows, &[])
            .unwrap_or_else(|_| {
                ScanCount::start_at(
                    EngineScan::GateDecisionRows,
                    &[],
                    DEFAULT_SCAN_CHECK_THRESHOLD,
                )
            });
        let mut items = Vec::new();
        let walked = self
            .vault
            .store
            .for_each_gate_decision_item_in_txn(txn, |row| {
                count.row();
                match row {
                    Ok(record) => items.extend(self.admit_loop_decision_in(txn, &mut read, record)),
                    Err(error) => tracing::warn!(
                        error_kind = ?error.kind(),
                        "a gate decision row did not read; its loop decision is withheld"
                    ),
                }
            });
        if let Err(error) = walked {
            tracing::warn!(
                error_kind = ?error.kind(),
                "the gate decision ledger did not read to its end; the loop decisions before it stand"
            );
        }
        count.finish(self.vault);
        items
    }

    /// The one decision `decision`, admitted again exactly as
    /// [`Self::authorised_loop_decisions_in_txn`] admits each: `None` when
    /// the reader may not see it now, it is gone, or it did not read. A
    /// saved item rechecks against this alone, so its failure moves no other.
    pub(crate) fn authorised_loop_decision_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        reader: WeaveReader<'_>,
        decision: GateDecisionId,
    ) -> Option<ReadableLoopDecision> {
        let mut read = self.loop_read_in(txn, reader)?;
        let record = match self.vault.store.gate_decision_in_txn(txn, decision) {
            Ok(record) => record?,
            Err(error) => {
                tracing::warn!(
                    error_kind = ?error.kind(),
                    "a gate decision row did not read; its loop decision is withheld"
                );
                return None;
            }
        };
        self.admit_loop_decision_in(txn, &mut read, record)
    }

    /// Binds `reader` in `txn` and resolves this lane's policy and floor:
    /// `None` when the reader is not this lane's actor, its proof is not
    /// current, or the lane reads no row at all.
    fn loop_read_in(&self, txn: &heed::RoTxn<'_>, reader: WeaveReader<'_>) -> Option<LoopRead> {
        let bound = match reader {
            WeaveReader::Person(id) | WeaveReader::Agent(id) => {
                (self.actor_key.actor_ref() == id.to_hex()).then_some(LoopReader::Subject(id))
            }
            WeaveReader::Owner(owner) => match self.loop_owner_in(txn, owner) {
                Ok(bound) => bound,
                Err(error) => {
                    tracing::warn!(
                        error_kind = ?error.kind(),
                        "an owner's proof did not revalidate; no loop decisions"
                    );
                    None
                }
            },
        }?;
        let (filter, policy) = match self.resolve_retrieval_filter_in(txn, None) {
            Ok(resolved) => resolved,
            Err(error) => {
                tracing::warn!(
                    error_kind = ?error.kind(),
                    "the lane's read floor did not resolve; no loop decisions"
                );
                return None;
            }
        };
        if filter.deny_all {
            return None;
        }
        Some(LoopRead {
            reader: bound,
            policy,
            filter,
            floor: BTreeMap::new(),
            projects: None,
        })
    }

    /// The live Owner behind `owner`, revalidated in `txn` (a co-Owner as
    /// well as the first), when it is this lane's actor or principal.
    fn loop_owner_in(
        &self,
        txn: &heed::RoTxn<'_>,
        owner: &crate::consent::AuthenticatedOwner,
    ) -> Result<Option<LoopReader>> {
        let actor = owner.revalidate_in_txn(self.vault, txn)?;
        let lane = self.actor_key.actor_ref();
        Ok(
            (lane == actor.to_hex() || lane == owner.principal_ref_in_txn(self.vault, txn)?)
                .then_some(LoopReader::Owner(actor)),
        )
    }

    /// One decision through the reader's admission: its family, then its
    /// event, then each optional ref under its own floor.
    fn admit_loop_decision_in(
        &self,
        txn: &heed::RoTxn<'_>,
        read: &mut LoopRead,
        record: GateDecisionRecord,
    ) -> Option<ReadableLoopDecision> {
        let family = loop_decision_family(&record.content_kind)?;
        if record.outcome == PENDING_OUTCOME && !LOOP_DECISION_PENDING {
            return None;
        }
        let named = match record
            .claim_id
            .and_then(|bytes| EntityId::from_bytes(bytes).ok())
        {
            Some(id) => answered(self.loop_entity_in(txn, read, id), "entity floor")?
                .map(|about| (id, about)),
            None => None,
        };
        let actor = record
            .actor_ref
            .as_deref()
            .and_then(|text| EntityId::from_hex(text).ok());
        let mut dependencies = BTreeSet::new();
        if let LoopReader::Subject(subject) = read.reader {
            dependencies.extend(self.loop_subject_admits_in(
                txn,
                read,
                subject,
                actor,
                named.as_ref(),
            )?);
        }
        let actor_ref = self.loop_actor_ref_in(txn, read, actor)?;
        let claim_ref = named.map(|(id, _)| id);
        dependencies.extend(claim_ref);
        dependencies.extend(actor_ref);
        Some(ReadableLoopDecision {
            decision_id: record.decision_id,
            created_at: record.created_at,
            family,
            kind: record.content_kind,
            outcome: record.outcome,
            reason_codes: record.reason_codes,
            redacted: record.redacted_at.is_some(),
            claim_ref,
            actor_ref,
            dependencies: dependencies.into_iter().collect(),
        })
    }

    /// The rows the entity a decision names is about, when the reader's own
    /// floor admits it: a claim's subject (an edge claim's two ends, its
    /// pair admitted as a Links row's is), else the entity itself. `None`
    /// when the floor refuses it or it is gone.
    fn loop_entity_in(
        &self,
        txn: &heed::RoTxn<'_>,
        read: &LoopRead,
        id: EntityId,
    ) -> Result<Option<Vec<EntityId>>> {
        if !self.is_entity_retrievable_with_policy_in(txn, &read.policy, &read.filter, &id)? {
            return Ok(None);
        }
        let Some(record) = self.entity_record_in(txn, &id)? else {
            return Ok(None);
        };
        if record.entity_type != ENTITY_TYPE_CLAIM {
            return Ok(Some(vec![id]));
        }
        let body = decode_claim_body(&record.body, true)?;
        if !self.weave_claim_edge_admitted_in(txn, &read.policy, &read.filter, &body)? {
            return Ok(None);
        }
        Ok(Some(match body.subject {
            ClaimSubject::Entity(subject) => vec![subject],
            ClaimSubject::Edge { source, target, .. } => vec![source, target],
        }))
    }

    /// Whether a subject may see a decision, and the project row that made
    /// it theirs when one did; `None` withholds it. The event's scope is the
    /// entity it names passing the subject's own floor; it is theirs when
    /// they are its actor or it is about them or one of their projects, the
    /// live weave report's own relevance.
    fn loop_subject_admits_in(
        &self,
        txn: &heed::RoTxn<'_>,
        read: &mut LoopRead,
        subject: EntityId,
        actor: Option<EntityId>,
        named: Option<&(EntityId, Vec<EntityId>)>,
    ) -> Option<Option<EntityId>> {
        let own = LOOP_DECISION_SELF_RECEIPT && actor == Some(subject);
        let Some((_, about)) = named else {
            return match LOOP_DECISION_MISSING_CONTEXT {
                Withhold::Item => None,
                Withhold::Field => own.then_some(None),
            };
        };
        if own || about.contains(&subject) {
            return Some(None);
        }
        if read.projects.is_none() {
            read.projects =
                Some(self.loop_subject_projects_in(txn, &read.policy, &read.filter, subject));
        }
        let projects = read.projects.get_or_insert_default();
        about
            .iter()
            .copied()
            .find(|row| projects.contains(row))
            .map(Some)
    }

    /// The decision's actor, shown when it is the reader (already bound) or
    /// the reader's own floor admits its row; `None` withholds the item.
    fn loop_actor_ref_in(
        &self,
        txn: &heed::RoTxn<'_>,
        read: &mut LoopRead,
        actor: Option<EntityId>,
    ) -> Option<Option<EntityId>> {
        let Some(actor) = actor else {
            return Some(None);
        };
        if actor == read.reader.id() {
            return Some(Some(actor));
        }
        let answer = match read.floor.get(&actor) {
            Some(answer) => *answer,
            None => {
                let answer = answered(
                    self.is_entity_retrievable_with_policy_in(
                        txn,
                        &read.policy,
                        &read.filter,
                        &actor,
                    )
                    .map(|admitted| admitted.then_some(())),
                    "actor floor",
                )
                .map(|admitted| admitted.is_some());
                read.floor.insert(actor, answer);
                answer
            }
        };
        if answer? {
            return Some(Some(actor));
        }
        match LOOP_DECISION_ACTOR_VISIBILITY {
            Withhold::Field => Some(None),
            Withhold::Item => None,
        }
    }

    /// The projects `subject` leads, sits on or boards that this lane's floor
    /// admits, folded as the live weave report folds them. A project row
    /// that does not answer is left out, so only an event it alone would
    /// have made theirs is withheld; a read that does not open leaves none.
    fn loop_subject_projects_in(
        &self,
        txn: &heed::RoTxn<'_>,
        policy: &PolicyManifestResolution,
        filter: &ResolvedRetrievalFilter,
        subject: EntityId,
    ) -> BTreeSet<EntityId> {
        let mut projects = BTreeSet::new();
        let Ok(kind) = self.vault.project_type_byte() else {
            return projects;
        };
        let opened = crate::workspace_roster::ProjectReader::new(
            &self.vault.store,
            txn,
            self.vault.privacy_posture(),
        )
        .and_then(|fold| {
            let rows = match self.session_view {
                Some(view) => view.port_entity_ids_by_type(txn, kind, None)?,
                None => self.vault.port_entity_ids_by_type(txn, kind, None)?,
            };
            Ok(fold.map(|fold| (fold, rows)))
        });
        let (fold, rows) = match opened {
            Ok(Some(opened)) => opened,
            Ok(None) => return projects,
            Err(error) => {
                tracing::warn!(
                    error_kind = ?error.kind(),
                    "the project rows did not read; no loop decision is theirs by a project"
                );
                return projects;
            }
        };
        let who = subject.to_hex();
        let mut count =
            ScanCount::start(&self.vault.store, txn, EngineScan::TypeIndexRows, &[kind])
                .unwrap_or_else(|_| {
                    ScanCount::start_at(
                        EngineScan::TypeIndexRows,
                        &[kind],
                        DEFAULT_SCAN_CHECK_THRESHOLD,
                    )
                });
        for row in rows {
            count.row();
            let member = row.and_then(|id| {
                if !self.is_entity_retrievable_with_policy_in(txn, policy, filter, &id)? {
                    return Ok(None);
                }
                let Some(record) = self.entity_record_in(txn, &id)? else {
                    return Ok(None);
                };
                if record.entity_type != kind {
                    return Ok(None);
                }
                Ok(fold
                    .visible_body(id, &record.body)?
                    .filter(|(_, effective)| {
                        effective.leader == who
                            || effective.seats.contains(&who)
                            || effective.board.contains(&who)
                    })
                    .map(|_| id))
            });
            match member {
                Ok(found) => projects.extend(found),
                Err(error) => tracing::warn!(
                    error_kind = ?error.kind(),
                    "a project row did not read; no loop decision is theirs by it"
                ),
            }
        }
        count.finish(self.vault);
        projects
    }
}
