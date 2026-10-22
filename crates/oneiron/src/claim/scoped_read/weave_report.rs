//! Live weave data for a reader, not a saved digest or a rendered section recipe.
//! The host/resident supplies predicates and ordering; the engine enforces which
//! sections and subjects a reader may see in one scoped-read snapshot.
use super::{ScopedRead, ScopedReadResult};
use crate::claim::{ClaimBody, ClaimSubject, decode_claim_body};
use crate::dreamer_runner::maintenance::agent_health::{AgentHealthCard, AgentHealthPadRead};
use crate::error::{Error, Result};
use crate::ports::{EdgeDirection, EdgeStoreRead, EntityStoreRead};
use crate::registry::ENTITY_TYPE_CLAIM;
use crate::scan_check::{EngineScan, ScanCount};
use crate::{EdgeKind, EntityId, Vault};
use std::collections::{BTreeMap, BTreeSet};

// The Admissions section's loop decisions (OF-499 A2).
pub(super) mod admissions;
// The SieveScore section's sampled sieve audits (OF-499).
pub(super) mod sieve_score;
// The live projection core, a due Owner schedule's binding too (FIX 1259).
mod projection;

/// Reader role is a constraint on the projection, never a claim of new read authority.
#[derive(Clone, Copy)]
pub enum WeaveReader<'a> {
    Person(EntityId),
    Owner(&'a crate::consent::AuthenticatedOwner),
    Agent(EntityId),
}

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize, schemars::JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum WeaveSectionKind {
    Changes,
    Projects,
    OpenAsks,
    Links,
    Conflicts,
    Exceptions,
    Admissions,
    Budgets,
    SieveScore,
    Digest,
}

/// A resident-authored recipe uses exact predicate names; no prose or
/// per-deployment ontology is compiled into the engine. Projects and budgets
/// read the typed project records and need no predicate list.
#[derive(Debug, Clone)]
pub struct WeaveSectionSpec {
    pub kind: WeaveSectionKind,
    pub predicates: Vec<String>,
    /// Direct graph kinds to project in a Links section. Empty for claim-only
    /// sections; the recipe, not the engine, decides which links belong here.
    pub edge_kinds: Vec<EdgeKind>,
}

#[derive(Debug, Clone, PartialEq)]
pub enum WeaveItem {
    /// A claim's reference is the correction target for a host-mediated wrong
    /// action. Its body comes through the same authority gate as normal reads.
    Claim {
        id: EntityId,
        body: Box<ClaimBody>,
    },
    Project {
        id: EntityId,
        goal: Option<String>,
    },
    Budget {
        project: EntityId,
        budget_ref: EntityId,
    },
    Link {
        source: EntityId,
        kind: EdgeKind,
        target: EntityId,
    },
    /// A resident's own dreaming, in its own Digest section only: when it
    /// last dreamed and how many entries its dreaming has written. Never
    /// an entry's id or text, and never in another reader's report.
    DreamProgress {
        resident: EntityId,
        dreamed_at: u64,
        entries: u64,
    },
    /// One of the Coach's open agent-health cards (OF-568), in a Digest
    /// section read by one of its recipients or a live owner.
    /// `draft_erased`: a saved copy's Coach draft lost its diagnosis and
    /// proposal because a row they were drafted from was erased (FIX 8672).
    AgentHealth {
        card: AgentHealthCard,
        draft_erased: bool,
    },
    /// One sampled sieve audit (OF-499), in a SieveScore section after its
    /// predicate rows: the attempt that wrote it, and the rule's reading
    /// beside the expensive path's label, or an unflagged window's finding
    /// (OF-498f). Its turn, source and the entities it names each passed
    /// the reader's own floor. A served copy's decisions keep only the
    /// candidate refs that floor admits; `redacted` marks each decision it
    /// left a ref out of (FIX 8322). A stored row keeps its decisions whole.
    SieveAudit {
        attempt: crate::attempt_queue::AttemptId,
        audit: crate::dreamer_wake::SieveAuditRecord,
        redacted: Vec<sieve_score::RedactedSieveDecision>,
    },
    /// One loop decision (OF-499 A2), in an Admissions section after its
    /// predicate rows: a loop's run or action admitted, held or refused, as
    /// the authorised loop-decision read admitted it for this reader. Its
    /// `outcome` and `kind` are exactly as stored (`pending` is its own),
    /// `family` names admission or action, and a `redacted` skeleton keeps
    /// no reasons and no actor. Each ref is shown only past the reader's
    /// own floor; `evidence_refs` are the rows its admission stood on,
    /// evidence only, never a correction target or a read grant.
    LoopDecision {
        decision_id: crate::store::GateDecisionId,
        created_at: u64,
        family: String,
        kind: String,
        outcome: String,
        reason_codes: Vec<String>,
        redacted: bool,
        claim_ref: Option<EntityId>,
        actor_ref: Option<EntityId>,
        evidence_refs: Vec<EntityId>,
    },
}

#[derive(Debug, Clone, PartialEq)]
pub struct WeaveSection {
    pub kind: WeaveSectionKind,
    pub items: Vec<WeaveItem>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct WeaveReport {
    pub sections: Vec<WeaveSection>,
}

impl WeaveReport {
    /// The rows the read that selected this report's items read them from
    /// (DEC-0005): each claim, project, goal, budget and link endpoint, a
    /// dreaming's resident, what an agent-health card is built from, the
    /// rows a sieve audit stands on, and a loop decision's evidence refs.
    #[must_use]
    pub fn source_rows(&self) -> Vec<EntityId> {
        let mut rows = Vec::new();
        for item in self.sections.iter().flat_map(|section| &section.items) {
            match item {
                WeaveItem::Claim { id, .. } => rows.push(*id),
                WeaveItem::Project { id, goal } => {
                    rows.push(*id);
                    rows.extend(
                        goal.as_deref()
                            .and_then(|goal| EntityId::from_hex(goal).ok()),
                    );
                }
                WeaveItem::Budget {
                    project,
                    budget_ref,
                } => rows.extend([*project, *budget_ref]),
                WeaveItem::Link { source, target, .. } => rows.extend([*source, *target]),
                WeaveItem::DreamProgress { resident, .. } => rows.push(*resident),
                WeaveItem::AgentHealth { card, .. } => rows.extend(card_rows(card)),
                WeaveItem::SieveAudit { audit, .. } => {
                    rows.extend(sieve_score::sieve_audit_rows(audit));
                }
                // The rows a loop decision's admission stood on, as evidence.
                WeaveItem::LoopDecision { evidence_refs, .. } => {
                    rows.extend(evidence_refs.iter().copied());
                }
            }
        }
        rows
    }
}

/// The rows an agent-health card is built from, as the card keeps them:
/// its agent, TASK, attempts (the newest and every one it witnessed),
/// diagnostics and evidence, and the Coach's ask on it (the diagnostic it was
/// asked on, the attempt that answers and, for a pad read that was granted,
/// its read-log row and the pads it returned). A pad count is never an id.
fn card_rows(card: &AgentHealthCard) -> Vec<EntityId> {
    let mut rows = vec![card.subject];
    rows.extend(
        card.task
            .into_iter()
            .chain(card.attempt)
            .chain(card.confession),
    );
    rows.extend(card.witnessed_attempts.iter().copied());
    rows.extend(card.diagnostics.iter().chain(&card.evidence).copied());
    if let Some(ask) = &card.coach {
        rows.extend(ask.diagnostic);
        rows.extend(EntityId::from_hex(&ask.attempt).ok());
        if let Some(answer) = &ask.answer
            && let AgentHealthPadRead::Read { read, pad_ids, .. } = &answer.pads
        {
            rows.extend(*read);
            rows.extend(pad_ids.iter().copied());
        }
    }
    rows
}

impl ScopedRead<'_> {
    /// Project live vault rows for one bound reader, with a mandatory scoped
    /// receipt. The recipe cannot elevate a role or expand the actor's floor.
    /// Past the policy's `max_rows` a scan raises one scan check and reads on
    /// (rule 5). Each sampled audit's decisions serve past the reader's own
    /// floor (FIX 8322).
    pub fn weave_report(
        &self,
        reader: WeaveReader<'_>,
        recipe: &[WeaveSectionSpec],
    ) -> Result<ScopedReadResult<WeaveReport>> {
        let txn = self.grant_read_txn()?;
        let mut report = self.weave_report_in_txn(&txn, reader, recipe)?;
        let (filter, policy) = self.resolve_retrieval_filter_in(&txn, None)?;
        self.redact_sieve_decisions_in(&txn, &policy, &filter, &mut report.value);
        Ok(report)
    }

    /// The live report as a period publishes it: [`Self::weave_report`]'s
    /// rows with each audit's decisions whole, as the publication recheck
    /// reads them and the saved period stores them. Never served as is.
    pub(super) fn weave_report_snapshot(
        &self,
        reader: WeaveReader<'_>,
        recipe: &[WeaveSectionSpec],
    ) -> Result<ScopedReadResult<WeaveReport>> {
        let txn = self.grant_read_txn()?;
        self.weave_report_in_txn(&txn, reader, recipe)
    }
}

/// Whether `reader` may see `card` in a weave: one of its recipients or a
/// live owner, never the agent it is about. This is the concern door's own
/// audience, so a row's one-tap "wrong" never shows a card its door refuses.
pub(super) fn weave_card_admitted(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    card: &AgentHealthCard,
    reader: EntityId,
) -> Result<bool> {
    if reader == card.subject {
        return Ok(false);
    }
    Ok(card.recipients.contains(&reader)
        || crate::policy_model::is_live_vault_owner_in_txn(vault, txn, &reader)?)
}

impl ScopedRead<'_> {
    /// The base predicate index is not part of a session's write overlay.
    /// A composed type scan sees overlay-only, shadowed and removed rows under
    /// the same snapshot as hydration. Either read runs to its end: past
    /// `threshold` claim rows it raises one scan check and reads on (rule 5).
    fn weave_claim_ids_in(
        &self,
        txn: &heed::RoTxn<'_>,
        predicate: &str,
        threshold: u64,
    ) -> Result<Vec<EntityId>> {
        let Some(view) = self.session_view else {
            // The whole posting list, one page of this snapshot.
            let mut count = ScanCount::start_at(
                EngineScan::PredicateClaimRows,
                predicate.as_bytes(),
                threshold,
            );
            let ids = crate::claim::claim_ids_for_predicate_page_in_txn(
                &self.vault.store,
                txn,
                predicate,
                None,
                usize::MAX,
            )?;
            count.rows(ids.len());
            count.finish(self.vault);
            return Ok(ids);
        };
        let mut count =
            ScanCount::start_at(EngineScan::TypeIndexRows, &[ENTITY_TYPE_CLAIM], threshold);
        let mut matches = Vec::new();
        for row in view.port_entity_ids_by_type(txn, ENTITY_TYPE_CLAIM, None)? {
            let id = row?;
            count.row();
            let Some(record) = self.entity_record_in(txn, &id)? else {
                continue;
            };
            if record.entity_type != ENTITY_TYPE_CLAIM || record.body.is_empty() {
                continue;
            }
            let body = decode_claim_body(&record.body, true)?;
            if body.predicate == predicate {
                matches.push(id);
            }
        }
        count.finish(self.vault);
        Ok(matches)
    }

    fn weave_links_in(
        &self,
        txn: &heed::RoTxn<'_>,
        policy: &crate::gate::PolicyManifestResolution,
        filter: &crate::gate::ResolvedRetrievalFilter,
        anchors: (Option<EntityId>, &BTreeSet<EntityId>),
        kinds: &[EdgeKind],
        threshold: u64,
    ) -> Result<Vec<WeaveItem>> {
        let (subject, project_ids) = anchors;
        let mut links = BTreeMap::new();
        if let Some(person) = subject {
            for anchor in std::iter::once(&person).chain(project_ids.iter()) {
                for direction in [EdgeDirection::Out, EdgeDirection::In] {
                    for (index, &kind) in kinds.iter().enumerate() {
                        if kinds[..index].contains(&kind) {
                            continue;
                        }
                        // Every admitted row is read: past the policy's row
                        // count the anchor's link read raises one scan check
                        // and reads on (rule 5). Hidden pairs are never counted.
                        let admitted = self.admitted_edges_in(
                            txn,
                            policy,
                            filter,
                            anchor,
                            direction,
                            Some(kind),
                            usize::MAX,
                            usize::MAX,
                            false,
                        )?;
                        let scope =
                            [&[direction as u8][..], anchor.as_bytes(), &[kind as u8][..]].concat();
                        let mut count =
                            ScanCount::start_at(EngineScan::EdgePeerRows, &scope, threshold);
                        for edge in admitted.edges {
                            let edge = edge.info();
                            if !weave_edge_live(edge.provenance) {
                                continue;
                            }
                            count.row();
                            let (source, target) = if direction == EdgeDirection::Out {
                                (*anchor, edge.target)
                            } else {
                                (edge.target, *anchor)
                            };
                            links.insert(
                                (source, edge.kind as u8, target),
                                WeaveItem::Link {
                                    source,
                                    kind: edge.kind,
                                    target,
                                },
                            );
                        }
                        count.finish(self.vault);
                    }
                }
            }
        } else {
            // Owner-global view reads the canonical cursor whole: past the
            // policy's row count its walk raises one scan check and reads on
            // (rule 5). Hidden relations still never reach the report.
            if self.session_view.is_some() {
                return Err(Error::InvalidConfig(
                    "owner weave links need a canonical read".into(),
                ));
            }
            let mut count = ScanCount::start_at(EngineScan::VaultEdgeRows, &[], threshold);
            for row in crate::ports::EdgeStoreInventory::port_edge_rows_raw(&self.vault.store, txn)?
            {
                count.row();
                let (key, value) = row?;
                let edge = crate::edge::parse_strict_edge_record(&key, &value)?;
                if !kinds.contains(&edge.kind) || !weave_edge_live(edge.decoded.provenance) {
                    continue;
                }
                let (source, kind, target) = (edge.source, edge.kind, edge.target);
                if !self
                    .admit_stored_edge_in(txn, policy, filter, source, edge.into_edge_info())?
                    .visible()
                {
                    continue;
                }
                links.insert(
                    (source, kind as u8, target),
                    WeaveItem::Link {
                        source,
                        kind,
                        target,
                    },
                );
            }
            count.finish(self.vault);
        }
        Ok(links.into_values().collect())
    }

    /// An edge-subject claim is admitted only while its exact edge is live and
    /// passes the same pair admission as a Links row; endpoint readability
    /// alone is not pair authority. Entity-subject claims pass through.
    pub(super) fn weave_claim_edge_admitted_in(
        &self,
        txn: &heed::RoTxn<'_>,
        policy: &crate::gate::PolicyManifestResolution,
        filter: &crate::gate::ResolvedRetrievalFilter,
        body: &ClaimBody,
    ) -> Result<bool> {
        let ClaimSubject::Edge {
            source,
            kind,
            target,
        } = body.subject
        else {
            return Ok(true);
        };
        let Some(edge) = self.live_weave_edge_in(txn, source, kind, target)? else {
            return Ok(false);
        };
        Ok(self
            .admit_stored_edge_in(txn, policy, filter, source, edge)?
            .visible())
    }

    /// Exact edge-key lookup: a known relation never scans its source's
    /// adjacency, so no compiled scan ceiling stands in for policy.
    pub(super) fn live_weave_edge_in(
        &self,
        txn: &heed::RoTxn<'_>,
        source: EntityId,
        kind: crate::EdgeKind,
        target: EntityId,
    ) -> Result<Option<crate::EdgeInfo>> {
        let edge = match self.session_view {
            Some(view) => view.port_edge_get(txn, &source, kind, &target)?,
            None => self.vault.port_edge_get(txn, &source, kind, &target)?,
        };
        Ok(edge.filter(|edge| weave_edge_live(edge.provenance)))
    }
}

fn weave_edge_live(flags: Option<crate::edge::EdgeProvenanceFlags>) -> bool {
    !flags.is_some_and(|flags| {
        flags.confirmation_status == crate::edge::EdgeConfirmationStatus::Retracted
    })
}

impl WeaveReader<'_> {
    pub(super) fn role(&self) -> &'static str {
        match self {
            Self::Person(_) => "person",
            Self::Owner(_) => "owner",
            Self::Agent(_) => "agent",
        }
    }
    /// The reader's id, which selects the policy row that bounds a report
    /// and a digest schedule: an owner's proof is revalidated in `txn`.
    pub(super) fn id(&self, vault: &Vault, txn: &heed::RoTxn<'_>) -> Result<EntityId> {
        match self {
            Self::Person(id) | Self::Agent(id) => Ok(*id),
            Self::Owner(owner) => owner.revalidate_in_txn(vault, txn),
        }
    }
}
impl WeaveSectionKind {
    pub(super) fn policy_name(self) -> &'static str {
        match self {
            Self::Changes => "changes",
            Self::Projects => "projects",
            Self::OpenAsks => "open_asks",
            Self::Links => "links",
            Self::Conflicts => "conflicts",
            Self::Exceptions => "exceptions",
            Self::Admissions => "admissions",
            Self::Budgets => "budgets",
            Self::SieveScore => "sieve_score",
            Self::Digest => "digest",
        }
    }
}

pub(super) fn validate_weave_recipe(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    policy: &crate::gate::PolicyManifestResolution,
    reader: &WeaveReader<'_>,
    recipe: &[WeaveSectionSpec],
) -> Result<()> {
    projection::validate_weave_recipe_for(policy, reader.role(), reader.id(vault, txn)?, recipe)
}

#[cfg(test)]
mod tests;
