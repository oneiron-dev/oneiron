//! The live weave projection (OF-499; FIX 1259): the one core every weave
//! report runs, a reader's live read, a correction's snapshot and a due
//! Owner schedule's alike. A reader binds at its own door, in the read's own
//! transaction: a person or an agent to this lane's actor, an Owner to his
//! proof revalidated here. A due Owner schedule binds as its recorded Owner
//! ([`ScheduledOwner`]): the schedule row as its owner-authorized writer
//! left it and the live-owner census, both read again in each projection's
//! transaction. Either way the projection is the same: the role's policy
//! row, the recipe's sections, the lane's own floor on every row, an
//! Owner's vault-global shape. Nothing here is a new read authority.
use std::collections::BTreeSet;

use super::super::weave_digest::scheduled_owner::ScheduledOwner;
use super::super::{ScopedRead, ScopedReadResult};
use super::admissions::loop_decision_item;
use super::{
    WeaveItem, WeaveReader, WeaveReport, WeaveSection, WeaveSectionKind, WeaveSectionSpec,
    weave_card_admitted,
};
use crate::EntityId;
use crate::batch::{ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader};
use crate::claim::{ClaimSubject, decode_claim_body};
use crate::dreamer_runner::maintenance::agent_health::{
    AgentHealthOutcome, agent_health_cards_in_txn,
};
use crate::error::{Error, Result};
use crate::ports::EntityStoreRead;
use crate::registry::ENTITY_TYPE_CLAIM;
use crate::scan_check::{EngineScan, ScanCount};

/// The policy row a due Owner schedule's report reads under: the Owner's
/// own, as his open reads it.
const SCHEDULED_OWNER_ROLE: &str = "owner";

/// Who one projection reads for.
#[derive(Clone, Copy)]
enum Projector<'a> {
    /// A reader at its own door.
    Reader(WeaveReader<'a>),
    /// A due Owner schedule's recorded Owner (FIX 1259).
    ScheduledOwner(&'a ScheduledOwner),
}

/// A projector bound in its projection's transaction.
struct Bound<'a> {
    projector: Projector<'a>,
    /// Its policy row's role.
    role: &'static str,
    /// Its own id: the row's holder, its cards' reader.
    id: EntityId,
    /// The person or agent a report is about; `None` for an Owner's
    /// vault-global shape.
    subject: Option<EntityId>,
}

impl ScopedRead<'_> {
    /// Run the same live report admission against a caller-owned transaction.
    /// Correction writes and receipt reads need admission and effects in one snapshot.
    pub(in crate::claim::scoped_read) fn weave_report_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        reader: WeaveReader<'_>,
        recipe: &[WeaveSectionSpec],
    ) -> Result<ScopedReadResult<WeaveReport>> {
        let subject = match reader {
            WeaveReader::Person(id) | WeaveReader::Agent(id) => {
                if self.actor_key.actor_ref() != id.to_hex() {
                    return Err(Error::InvalidConfig(
                        "weave reader is not the scoped actor".into(),
                    ));
                }
                Some(id)
            }
            WeaveReader::Owner(owner) => {
                let actor = owner.revalidate_in_txn(self.vault, txn)?;
                if self.actor_key.actor_ref() != actor.to_hex()
                    && self.actor_key.actor_ref() != owner.principal_ref_in_txn(self.vault, txn)?
                {
                    return Err(Error::InvalidConfig(
                        "weave owner is not the scoped actor".into(),
                    ));
                }
                None
            }
        };
        let id = reader.id(self.vault, txn)?;
        let bound = Bound {
            projector: Projector::Reader(reader),
            role: reader.role(),
            id,
            subject,
        };
        self.project_weave_report_in(txn, bound, recipe)
    }

    /// A due Owner schedule's report in `txn` (FIX 1259): the projection an
    /// Owner's open runs, bound to the schedule's recorded Owner while
    /// `owner` still holds here, never to an Owner proof. Every live
    /// co-Owner's own schedule reads the same way.
    pub(in crate::claim::scoped_read) fn weave_report_for_scheduled_owner_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        owner: &ScheduledOwner,
        recipe: &[WeaveSectionSpec],
    ) -> Result<ScopedReadResult<WeaveReport>> {
        let id = owner.current_in(self, txn)?;
        let bound = Bound {
            projector: Projector::ScheduledOwner(owner),
            role: SCHEDULED_OWNER_ROLE,
            id,
            subject: None,
        };
        self.project_weave_report_in(txn, bound, recipe)
    }

    /// The projection core for one bound projector. The recipe cannot
    /// elevate a role or expand the lane's floor.
    fn project_weave_report_in(
        &self,
        txn: &heed::RoTxn<'_>,
        bound: Bound<'_>,
        recipe: &[WeaveSectionSpec],
    ) -> Result<ScopedReadResult<WeaveReport>> {
        let subject = bound.subject;
        let (filter, policy) = self.resolve_retrieval_filter_in(txn, None)?;
        validate_weave_recipe_for(&policy, bound.role, bound.id, recipe)?;
        let max_rows = crate::gate::weave_policy::effective_resolved(&policy, bound.role, bound.id)
            .ok_or_else(|| Error::InvalidConfig("missing weave report policy".into()))?
            .max_rows;
        let threshold = u64::try_from(max_rows).unwrap_or(u64::MAX);
        let mut project_ids = BTreeSet::new();
        let mut projects = Vec::new();
        if (recipe.iter().any(|s| {
            matches!(
                s.kind,
                WeaveSectionKind::Projects | WeaveSectionKind::Budgets
            )
        }) || subject.is_some())
            && let Ok(kind) = self.vault.project_type_byte()
        {
            let mut count = ScanCount::start_at(EngineScan::TypeIndexRows, &[kind], threshold);
            let project_fold = crate::workspace_roster::ProjectReader::new(
                &self.vault.store,
                txn,
                self.vault.privacy_posture(),
            )?;
            let project_rows = match self.session_view {
                Some(view) => view.port_entity_ids_by_type(txn, kind, None)?,
                None => self.vault.port_entity_ids_by_type(txn, kind, None)?,
            };
            for row in project_rows {
                let id = row?;
                count.row();
                // A project id must be readable before its body or membership
                // becomes available to the projection.
                if !self.is_entity_retrievable_with_policy_in(txn, &policy, &filter, &id)? {
                    continue;
                }
                let raw = self
                    .entity_record_in(txn, &id)?
                    .ok_or(Error::CorruptedIndex("weave project index"))?
                    .encode();
                let header = EntityMetadataHeader::parse(&raw)
                    .ok_or(Error::CorruptedIndex("weave project header"))?;
                if header.entity_type != kind {
                    return Err(Error::CorruptedIndex("weave project kind"));
                }
                // A row the project read fold hides never reaches a report,
                // and a subject's role is the one its signed history folds to.
                let Some((record, effective)) = project_fold
                    .as_ref()
                    .map(|fold| fold.visible_body(id, &raw[ENTITY_METADATA_HEADER_LEN..]))
                    .transpose()?
                    .flatten()
                else {
                    continue;
                };
                if subject.is_none_or(|id| {
                    let who = id.to_hex();
                    effective.leader == who
                        || effective.seats.contains(&who)
                        || effective.board.contains(&who)
                }) {
                    project_ids.insert(id);
                    projects.push((id, record));
                }
            }
            count.finish(self.vault);
        }
        let mut sections = Vec::with_capacity(recipe.len());
        for spec in recipe {
            let mut items = Vec::new();
            if spec.kind == WeaveSectionKind::Projects {
                for (id, row) in &projects {
                    let goal = match &row.goal {
                        Some(value) => {
                            let goal_id = EntityId::from_hex(value)?;
                            self.is_entity_retrievable_with_policy_in(
                                txn, &policy, &filter, &goal_id,
                            )?
                            .then(|| value.clone())
                        }
                        None => None,
                    };
                    items.push(WeaveItem::Project { id: *id, goal });
                }
            } else if spec.kind == WeaveSectionKind::Budgets {
                for (id, row) in &projects {
                    if let Some(budget) = &row.budget {
                        let budget_ref = EntityId::from_hex(budget)?;
                        if self.is_entity_retrievable_with_policy_in(
                            txn,
                            &policy,
                            &filter,
                            &budget_ref,
                        )? {
                            items.push(WeaveItem::Budget {
                                project: *id,
                                budget_ref,
                            });
                        }
                    }
                }
            } else {
                let mut seen = BTreeSet::new();
                for predicate in &spec.predicates {
                    for id in self.weave_claim_ids_in(txn, predicate, threshold)? {
                        if !seen.insert(id) {
                            continue;
                        }
                        if !self.is_entity_retrievable_with_policy_in(txn, &policy, &filter, &id)? {
                            continue;
                        }
                        let raw = self
                            .entity_record_in(txn, &id)?
                            .ok_or(Error::CorruptedIndex("weave claim index"))?
                            .encode();
                        let header = EntityMetadataHeader::parse(&raw)
                            .ok_or(Error::CorruptedIndex("weave claim header"))?;
                        if header.entity_type != ENTITY_TYPE_CLAIM {
                            return Err(Error::CorruptedIndex("weave claim kind"));
                        }
                        let body = decode_claim_body(&raw[ENTITY_METADATA_HEADER_LEN..], true)?;
                        if body.predicate != *predicate {
                            return Err(Error::CorruptedIndex("weave predicate index"));
                        }
                        let relevant = match (subject, body.subject) {
                            (None, _) => true,
                            (Some(person), ClaimSubject::Entity(id)) => {
                                id == person || project_ids.contains(&id)
                            }
                            (Some(person), ClaimSubject::Edge { source, target, .. }) => {
                                source == person
                                    || target == person
                                    || project_ids.contains(&source)
                                    || project_ids.contains(&target)
                            }
                        };
                        if !relevant {
                            continue;
                        }
                        // An edge claim must not launder an unreadable endpoint
                        // (or a deleted edge) into a report about the reader.
                        if !self.weave_claim_edge_admitted_in(txn, &policy, &filter, &body)? {
                            continue;
                        }
                        items.push(WeaveItem::Claim {
                            id,
                            body: Box::new(body),
                        });
                    }
                }
            }
            // A SieveScore section shows the sampled sieve audits after its
            // predicate rows (OF-499), each one this reader's floor admits.
            if spec.kind == WeaveSectionKind::SieveScore {
                items.extend(self.weave_sieve_audits_in(txn, &policy, &filter));
            }
            // An Admissions section shows the loop decisions this reader may
            // see after its predicate rows (OF-499 A2), in ledger order.
            if spec.kind == WeaveSectionKind::Admissions {
                items.extend(self.projected_loop_decisions_in(txn, &bound));
            }
            // Each resident gets its own digest through its dreaming
            // (ARCH-0063 §6): its progress leads its own Digest section.
            if spec.kind == WeaveSectionKind::Digest
                && let Projector::Reader(WeaveReader::Agent(resident)) = bound.projector
            {
                let progress = crate::dreamer_consolidation::resident_dream_progress_in_txn(
                    self.vault, txn, resident,
                )?;
                if progress.entries > 0 {
                    items.insert(
                        0,
                        WeaveItem::DreamProgress {
                            resident,
                            dreamed_at: progress.dreamed_at,
                            entries: progress.entries,
                        },
                    );
                }
            }
            // The Coach's open agent-health cards follow, concern first, for
            // a reader the concern door would answer (OF-568).
            if spec.kind == WeaveSectionKind::Digest && !filter.deny_all {
                let id = bound.id;
                for card in agent_health_cards_in_txn(self.vault, txn)? {
                    if card.outcome == AgentHealthOutcome::Open
                        && weave_card_admitted(self.vault, txn, &card, id)?
                    {
                        items.push(WeaveItem::AgentHealth {
                            card,
                            draft_erased: false,
                        });
                    }
                }
            }
            if spec.kind == WeaveSectionKind::Links && !spec.edge_kinds.is_empty() {
                items.extend(self.weave_links_in(
                    txn,
                    &policy,
                    &filter,
                    (subject, &project_ids),
                    &spec.edge_kinds,
                    threshold,
                )?);
            }
            sections.push(WeaveSection {
                kind: spec.kind,
                items,
            });
        }
        Ok(ScopedReadResult {
            value: WeaveReport { sections },
            receipt: self.receipt_for(None, &policy, &filter, 0),
        })
    }

    /// The loop decisions an Admissions section shows the projector (OF-499
    /// A2): a reader's own authorised read, or the recorded Owner's
    /// current-owner read (FIX 7597).
    fn projected_loop_decisions_in(
        &self,
        txn: &heed::RoTxn<'_>,
        bound: &Bound<'_>,
    ) -> Vec<WeaveItem> {
        match bound.projector {
            Projector::Reader(reader) => self.weave_loop_decisions_in_txn(txn, reader),
            Projector::ScheduledOwner(owner) => self
                .authorised_loop_decisions_for_recorded_owner_in_txn(txn, owner.owner())
                .into_iter()
                .map(loop_decision_item)
                .collect(),
        }
    }
}

/// Whether `recipe` fits the policy row of `role` held by `id`: every
/// section one the row allows, each predicate a token, edge kinds only on a
/// Links section.
pub(super) fn validate_weave_recipe_for(
    policy: &crate::gate::PolicyManifestResolution,
    role: &str,
    id: EntityId,
    recipe: &[WeaveSectionSpec],
) -> Result<()> {
    let row = crate::gate::weave_policy::effective_resolved(policy, role, id)
        .ok_or_else(|| Error::InvalidConfig("missing weave report policy".into()))?;
    // A recipe holds however many sections, predicates and edge kinds (rule
    // 5); the 128-byte bound is the predicate token grammar's own.
    if recipe.iter().any(|section| {
        (!section.edge_kinds.is_empty() && section.kind != WeaveSectionKind::Links)
            || section
                .predicates
                .iter()
                .any(|p| p.is_empty() || p.len() > 128)
            || !row.sections.contains(section.kind.policy_name())
    }) {
        return Err(Error::InvalidConfig("invalid weave report recipe".into()));
    }
    Ok(())
}
