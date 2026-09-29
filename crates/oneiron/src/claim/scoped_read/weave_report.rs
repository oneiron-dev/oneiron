//! Live weave data for a reader, not a saved digest or a rendered section recipe.
//! The host/resident supplies predicates and ordering; the engine enforces which
//! sections and subjects a reader may see in one scoped-read snapshot.
use super::{ScopedRead, ScopedReadResult};
use crate::batch::{ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader};
use crate::claim::{ClaimBody, ClaimSubject, decode_claim_body};
use crate::error::{Error, Result};
use crate::ports::{EdgeDirection, EdgeStoreRead, EntityStoreRead};
use crate::registry::ENTITY_TYPE_CLAIM;
use crate::{EdgeKind, EntityId};
use std::collections::{BTreeMap, BTreeSet};

/// Reader role is a constraint on the projection, never a claim of new read authority.
#[derive(Clone, Copy)]
pub enum WeaveReader<'a> {
    Person(EntityId),
    Owner(&'a crate::consent::AuthenticatedOwner),
    Agent(EntityId),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
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

impl ScopedRead<'_> {
    /// Project live vault rows for one bound reader, with a mandatory scoped
    /// receipt. The recipe cannot elevate a role or expand the actor's floor.
    /// A bounded scan refuses rather than silently dropping a lower-ranked row.
    pub fn weave_report(
        &self,
        reader: WeaveReader<'_>,
        recipe: &[WeaveSectionSpec],
    ) -> Result<ScopedReadResult<WeaveReport>> {
        let txn = self.grant_read_txn()?;
        self.weave_report_in_txn(&txn, reader, recipe)
    }

    /// Run the same live report admission against a caller-owned transaction.
    /// Correction writes and receipt reads need admission and effects in one snapshot.
    pub(super) fn weave_report_in_txn(
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
                owner.revalidate_in_txn(self.vault, txn)?;
                if self.actor_key.actor_ref() != owner.actor().to_hex()
                    && self.actor_key.actor_ref() != owner.principal_ref()
                {
                    return Err(Error::InvalidConfig(
                        "weave owner is not the scoped actor".into(),
                    ));
                }
                None
            }
        };
        let (filter, policy) = self.resolve_retrieval_filter_in(txn, None)?;
        validate_weave_recipe(&policy, &reader, recipe)?;
        let max_rows =
            crate::gate::weave_policy::effective_resolved(&policy, reader.role(), reader.id())
                .ok_or_else(|| Error::InvalidConfig("missing weave report policy".into()))?
                .max_rows;
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
            let mut scanned = 0;
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
                scanned += 1;
                if scanned > max_rows {
                    return Err(Error::IndexOverflow("weave projects"));
                }
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
                // A row the project read fold hides never reaches a report.
                let Some(record) = project_fold
                    .as_ref()
                    .map(|fold| fold.visible_body(id, &raw[ENTITY_METADATA_HEADER_LEN..]))
                    .transpose()?
                    .flatten()
                else {
                    continue;
                };
                if subject.is_none_or(|id| {
                    let who = id.to_hex();
                    record.leader == who
                        || record.roster.contains(&who)
                        || record.board.contains(&who)
                }) {
                    project_ids.insert(id);
                    projects.push((id, record));
                }
            }
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
                    for id in self.weave_claim_ids_in(txn, predicate, max_rows)? {
                        if !seen.insert(id) {
                            continue;
                        }
                        if seen.len() > max_rows {
                            return Err(Error::IndexOverflow("weave claim rows"));
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
            if spec.kind == WeaveSectionKind::Links && !spec.edge_kinds.is_empty() {
                items.extend(self.weave_links_in(
                    txn,
                    &policy,
                    &filter,
                    (subject, &project_ids),
                    &spec.edge_kinds,
                    max_rows,
                )?);
            }
            if items.len()
                > crate::gate::weave_policy::effective_resolved(&policy, reader.role(), reader.id())
                    .ok_or_else(|| Error::InvalidConfig("missing weave report policy".into()))?
                    .max_rows
            {
                return Err(Error::IndexOverflow("weave policy rows"));
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
}

impl ScopedRead<'_> {
    /// The base predicate index is not part of a session's write overlay.
    /// A composed type scan sees overlay-only, shadowed and removed rows under
    /// the same snapshot as hydration. Refuse an oversized scan, never page it.
    fn weave_claim_ids_in(
        &self,
        txn: &heed::RoTxn<'_>,
        predicate: &str,
        max_rows: usize,
    ) -> Result<Vec<EntityId>> {
        let Some(view) = self.session_view else {
            return crate::claim::claim_ids_for_predicate_bounded_in_txn(
                &self.vault.store,
                txn,
                predicate,
                max_rows,
            );
        };
        let mut matches = Vec::new();
        let mut scanned = 0;
        for row in view.port_entity_ids_by_type(txn, ENTITY_TYPE_CLAIM, None)? {
            let id = row?;
            scanned += 1;
            if scanned > max_rows {
                return Err(Error::IndexOverflow("weave session claims"));
            }
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
        Ok(matches)
    }

    fn weave_links_in(
        &self,
        txn: &heed::RoTxn<'_>,
        policy: &crate::gate::PolicyManifestResolution,
        filter: &crate::gate::ResolvedRetrievalFilter,
        anchors: (Option<EntityId>, &BTreeSet<EntityId>),
        kinds: &[EdgeKind],
        max_rows: usize,
    ) -> Result<Vec<WeaveItem>> {
        let (subject, project_ids) = anchors;
        let mut links = BTreeMap::new();
        let mut scanned = 0;
        if let Some(person) = subject {
            for anchor in std::iter::once(&person).chain(project_ids.iter()) {
                for direction in [EdgeDirection::Out, EdgeDirection::In] {
                    for (index, &kind) in kinds.iter().enumerate() {
                        if kinds[..index].contains(&kind) {
                            continue;
                        }
                        // One extra eligible row proves completeness at the cap.
                        // Hidden pairs never consume a visible row slot.
                        let admitted = self.admitted_edges_in(
                            txn,
                            policy,
                            filter,
                            anchor,
                            direction,
                            Some(kind),
                            max_rows.saturating_add(1),
                            max_rows.saturating_add(1),
                            false,
                        )?;
                        for edge in admitted.edges {
                            let edge = edge.info();
                            if !weave_edge_live(edge.provenance) {
                                continue;
                            }
                            scanned += 1;
                            if scanned > max_rows {
                                return Err(Error::IndexOverflow("weave link rows"));
                            }
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
                    }
                }
            }
        } else {
            // Owner-global view still uses the canonical cursor, but hidden
            // relations cannot consume its visible scan budget either.
            if self.session_view.is_some() {
                return Err(Error::InvalidConfig(
                    "owner weave links need a canonical read".into(),
                ));
            }
            for row in crate::ports::EdgeStoreInventory::port_edge_rows_raw(&self.vault.store, txn)?
            {
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
                scanned += 1;
                if scanned > max_rows {
                    return Err(Error::IndexOverflow("weave link rows"));
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
    pub(super) fn id(&self) -> EntityId {
        match self {
            Self::Person(id) | Self::Agent(id) => *id,
            Self::Owner(owner) => owner.actor(),
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
    policy: &crate::gate::PolicyManifestResolution,
    reader: &WeaveReader<'_>,
    recipe: &[WeaveSectionSpec],
) -> Result<()> {
    let row = crate::gate::weave_policy::effective_resolved(policy, reader.role(), reader.id())
        .ok_or_else(|| Error::InvalidConfig("missing weave report policy".into()))?;
    if recipe.len() > row.max_sections
        || recipe.iter().any(|section| {
            section.predicates.len() > row.max_predicates
                || section.edge_kinds.len() > row.max_edge_kinds
                || (!section.edge_kinds.is_empty() && section.kind != WeaveSectionKind::Links)
                || section
                    .predicates
                    .iter()
                    .any(|p| p.is_empty() || p.len() > 128)
                || !row.sections.contains(section.kind.policy_name())
        })
    {
        return Err(Error::InvalidConfig("invalid weave report recipe".into()));
    }
    Ok(())
}

#[cfg(test)]
mod tests;
