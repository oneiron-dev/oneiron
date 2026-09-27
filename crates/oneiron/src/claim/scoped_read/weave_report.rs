//! Live weave data for a reader, not a saved digest or a rendered section recipe.
//! The host/resident supplies predicates and ordering; the engine enforces which
//! sections and subjects a reader may see in one scoped-read snapshot.
use super::{ScopedRead, ScopedReadResult};
use crate::batch::{ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader};
use crate::claim::{ClaimBody, ClaimSubject, decode_claim_body};
use crate::error::{Error, Result};
use crate::ports::{EdgeDirection, EdgeStoreRead, EntityStoreRead};
use crate::registry::ENTITY_TYPE_CLAIM;
use crate::workspace_roster::ProjectRecord;
use crate::{EdgeKind, EntityId};
use std::collections::{BTreeMap, BTreeSet};

const MAX_SECTIONS: usize = 16;
const MAX_PREDICATES: usize = 32;
const MAX_ROWS: usize = 10_000;

/// Reader role is a constraint on the projection, never a claim of new read authority.
pub enum WeaveReader<'a> {
    Person(EntityId),
    Owner(&'a crate::consent::AuthenticatedOwner),
    Agent(EntityId),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
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
        if recipe.len() > MAX_SECTIONS
            || recipe.iter().any(|section| {
                section.predicates.len() > MAX_PREDICATES
                    || section.edge_kinds.len() > MAX_PREDICATES
                    || (!section.edge_kinds.is_empty() && section.kind != WeaveSectionKind::Links)
                    || section
                        .predicates
                        .iter()
                        .any(|p| p.is_empty() || p.len() > 128)
                    || !section.kind.allowed_for(&reader)
            })
        {
            return Err(Error::InvalidConfig("invalid weave report recipe".into()));
        }
        let txn = self.vault.store.env.read_txn()?;
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
                owner.revalidate_in_txn(self.vault, &txn)?;
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
        let (filter, policy) = self.resolve_retrieval_filter_in(&txn, None)?;
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
            let project_rows = match self.session_view {
                Some(view) => view.port_entity_ids_by_type(&txn, kind, None)?,
                None => self.vault.port_entity_ids_by_type(&txn, kind, None)?,
            };
            for row in project_rows {
                let id = row?;
                scanned += 1;
                if scanned > MAX_ROWS {
                    return Err(Error::IndexOverflow("weave projects"));
                }
                // A project id must be readable before its body or membership
                // becomes available to the projection.
                if !self.is_entity_retrievable_with_policy_in(&txn, &policy, &filter, &id)? {
                    continue;
                }
                let raw = self
                    .entity_record_in(&txn, &id)?
                    .ok_or(Error::CorruptedIndex("weave project index"))?
                    .encode();
                let header = EntityMetadataHeader::parse(&raw)
                    .ok_or(Error::CorruptedIndex("weave project header"))?;
                if header.entity_type != kind {
                    return Err(Error::CorruptedIndex("weave project kind"));
                }
                let record: ProjectRecord =
                    rmp_serde::from_slice(&raw[ENTITY_METADATA_HEADER_LEN..])
                        .map_err(|_| Error::CorruptedIndex("weave project body"))?;
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
                                &txn, &policy, &filter, &goal_id,
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
                            &txn,
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
                    for id in self.weave_claim_ids_in(&txn, predicate)? {
                        if !seen.insert(id) {
                            continue;
                        }
                        if seen.len() > MAX_ROWS {
                            return Err(Error::IndexOverflow("weave claim rows"));
                        }
                        if !self
                            .is_entity_retrievable_with_policy_in(&txn, &policy, &filter, &id)?
                        {
                            continue;
                        }
                        let raw = self
                            .entity_record_in(&txn, &id)?
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
                        if let ClaimSubject::Edge {
                            source,
                            kind,
                            target,
                        } = body.subject
                            && (!self.is_entity_retrievable_with_policy_in(
                                &txn, &policy, &filter, &source,
                            )? || !self.is_entity_retrievable_with_policy_in(
                                &txn, &policy, &filter, &target,
                            )? || !self.live_weave_edge_in(&txn, source, kind, target)?)
                        {
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
                    &txn,
                    &policy,
                    &filter,
                    subject,
                    &project_ids,
                    &spec.edge_kinds,
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
}

impl ScopedRead<'_> {
    /// The base predicate index is not part of a session's write overlay.
    /// A composed type scan sees overlay-only, shadowed and removed rows under
    /// the same snapshot as hydration. Refuse an oversized scan, never page it.
    fn weave_claim_ids_in(&self, txn: &heed::RoTxn<'_>, predicate: &str) -> Result<Vec<EntityId>> {
        let Some(view) = self.session_view else {
            return crate::claim::claim_ids_for_predicate_in_txn(&self.vault.store, txn, predicate);
        };
        let mut matches = Vec::new();
        let mut scanned = 0;
        for row in view.port_entity_ids_by_type(txn, ENTITY_TYPE_CLAIM, None)? {
            let id = row?;
            scanned += 1;
            if scanned > MAX_ROWS {
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
        subject: Option<EntityId>,
        project_ids: &BTreeSet<EntityId>,
        kinds: &[EdgeKind],
    ) -> Result<Vec<WeaveItem>> {
        let mut links = BTreeMap::new();
        let mut add = |source: EntityId, kind: EdgeKind, target: EntityId| -> Result<()> {
            if self.is_entity_retrievable_with_policy_in(txn, policy, filter, &source)?
                && self.is_entity_retrievable_with_policy_in(txn, policy, filter, &target)?
            {
                links.insert(
                    (source, kind as u8, target),
                    WeaveItem::Link {
                        source,
                        kind,
                        target,
                    },
                );
            }
            Ok(())
        };
        let mut scanned = 0;
        if let Some(person) = subject {
            for anchor in std::iter::once(&person).chain(project_ids.iter()) {
                for direction in [EdgeDirection::Out, EdgeDirection::In] {
                    let rows = match self.session_view {
                        Some(view) => view.port_edges(txn, anchor, direction, None, None)?,
                        None => self.vault.port_edges(txn, anchor, direction, None, None)?,
                    };
                    for row in rows {
                        let edge = row?;
                        scanned += 1;
                        if scanned > MAX_ROWS {
                            return Err(Error::IndexOverflow("weave link rows"));
                        }
                        if !kinds.contains(&edge.kind) || !weave_edge_live(edge.provenance) {
                            continue;
                        }
                        let (source, target) = match direction {
                            EdgeDirection::Out => (*anchor, edge.target),
                            EdgeDirection::In => (edge.target, *anchor),
                            EdgeDirection::Both => unreachable!("only directed scans"),
                        };
                        add(source, edge.kind, target)?;
                    }
                }
            }
        } else {
            // Owner-only global view. A canonical edge cursor, bounded before
            // filtering, prevents a truncated report from claiming completeness.
            // Session overlays have no global edge cursor; refuse instead of
            // silently showing edges that the overlay removed.
            if self.session_view.is_some() {
                return Err(Error::InvalidConfig(
                    "owner weave links need a canonical read".into(),
                ));
            }
            for row in self.vault.store.edges_out.iter(txn)? {
                let (key, value) = row?;
                scanned += 1;
                if scanned > MAX_ROWS {
                    return Err(Error::IndexOverflow("weave link rows"));
                }
                let edge = crate::edge::parse_strict_edge_record(&key, &value)?;
                if kinds.contains(&edge.kind) && weave_edge_live(edge.decoded.provenance) {
                    add(edge.source, edge.kind, edge.target)?;
                }
            }
        }
        Ok(links.into_values().collect())
    }

    fn live_weave_edge_in(
        &self,
        txn: &heed::RoTxn<'_>,
        source: EntityId,
        kind: crate::EdgeKind,
        target: EntityId,
    ) -> Result<bool> {
        let mut count = 0;
        for edge in self.out_edges_in(txn, &source, Some(kind))? {
            count += 1;
            if count > crate::vault::MAX_EDGE_QUERY_RESULTS {
                return Err(Error::IndexOverflow("weave link edges"));
            }
            let edge = edge?;
            if edge.target == target {
                return Ok(weave_edge_live(edge.provenance));
            }
        }
        Ok(false)
    }
}

fn weave_edge_live(flags: Option<crate::edge::EdgeProvenanceFlags>) -> bool {
    !flags.is_some_and(|flags| {
        flags.confirmation_status == crate::edge::EdgeConfirmationStatus::Retracted
    })
}

impl WeaveSectionKind {
    fn allowed_for(self, reader: &WeaveReader<'_>) -> bool {
        match reader {
            WeaveReader::Person(_) => matches!(
                self,
                Self::Changes | Self::Projects | Self::OpenAsks | Self::Links
            ),
            WeaveReader::Owner(_) => matches!(
                self,
                Self::Links
                    | Self::Conflicts
                    | Self::Exceptions
                    | Self::Admissions
                    | Self::Budgets
                    | Self::SieveScore
            ),
            WeaveReader::Agent(_) => self == Self::Digest,
        }
    }
}

#[cfg(test)]
mod tests;
