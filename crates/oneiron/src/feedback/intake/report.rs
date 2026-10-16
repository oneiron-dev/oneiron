//! T2 for universal reports, sharing the bundle intake's cosine normalization.
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

use super::{FeedbackDedup, normalized};
use crate::feedback::{IssueCategory, ReportIssue, ReportKind, ReportRoute, ReportStatus};
use crate::side_table::{self, Named, SideTable};
use crate::{EntityId, Error, Result, Vault};

const CLUSTERS: SideTable<EntityId, ReportCluster, Named> =
    SideTable::new(&side_table::FEEDBACK_REPORT_CLUSTER);

/// Membership is evidence, not a report counter. The centroid is recomputed
/// from the retained host vectors, so it is never the only copy of a summary.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ReportCluster {
    category: IssueCategory,
    kind: ReportKind,
    route: ReportRoute,
    members: BTreeMap<String, Vec<f32>>,
    centroid: Vec<f32>,
}

impl Vault {
    pub(crate) fn ingest_report_feedback_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        issue: &ReportIssue,
        embedding: &[f32],
        dedup: FeedbackDedup,
    ) -> Result<Option<EntityId>> {
        let vector = normalized(embedding)?;
        if vector.len() != self.config.dimensions {
            return Err(Error::InvalidConfig("report embedding dimensions".into()));
        }
        let mut best: Option<(f32, EntityId, ReportCluster)> = None;
        for (id, cluster) in CLUSTERS.scan(&self.store, txn)? {
            if cluster.category != issue.request.category
                || cluster.kind != issue.request.kind
                || cluster.route != issue.route
                || cluster.centroid.len() != vector.len()
            {
                continue;
            }
            let Some(root) = self.report_issue_in_txn(txn, &id)? else {
                continue;
            };
            if matches!(
                root.review.status,
                ReportStatus::Rejected | ReportStatus::Duplicate
            ) {
                continue;
            }
            let center = normalized(&cluster.centroid)?;
            let similarity = vector.iter().zip(&center).map(|(a, b)| a * b).sum::<f32>();
            if similarity >= dedup.min_similarity
                && best
                    .as_ref()
                    .is_none_or(|(score, _, _)| similarity > *score)
            {
                best = Some((similarity, id, cluster));
            }
        }
        let duplicate = best.as_ref().map(|(_, id, _)| *id);
        let id = duplicate.unwrap_or(EntityId::from_hex(&issue.issue_ref)?);
        let mut cluster = best
            .map(|(_, _, cluster)| cluster)
            .unwrap_or_else(|| ReportCluster {
                category: issue.request.category,
                kind: issue.request.kind,
                route: issue.route.clone(),
                members: BTreeMap::new(),
                centroid: Vec::new(),
            });
        cluster
            .members
            .insert(issue.issue_ref.clone(), vector.clone());
        let mut centroid = vec![0.0; vector.len()];
        for vector in cluster.members.values() {
            if vector.len() != centroid.len() {
                return Err(Error::CorruptedIndex("report cluster dimensions"));
            }
            for (sum, value) in centroid.iter_mut().zip(vector) {
                *sum += value;
            }
        }
        cluster.centroid = normalized(&centroid)?;
        CLUSTERS.put(&self.store, txn, &id, &cluster)?;
        Ok(duplicate)
    }
}
