//! Durable issue identity, entity-local review, and the arrival index.
use std::sync::atomic::Ordering;

use super::{ReportIssue, ReportReceipt, ReportRequest, ReportReview, ReportStatus, invalid};
use crate::batch::{BatchOp, apply_ops};
use crate::feedback::intake::FeedbackDedup;
use crate::registry::ENTITY_TYPE_ISSUE;
use crate::side_table::{self, Named, SideTable};
use crate::{EntityId, Error, Result, TimeRange, Vault};

const ARRIVALS: SideTable<(u64, EntityId), (), Named> =
    SideTable::new(&side_table::FEEDBACK_REPORT_ARRIVAL);

fn issue_id(actor: EntityId, request: &ReportRequest) -> Result<EntityId> {
    let mut hash = blake3::Hasher::new();
    hash.update(b"oneiron.report.v1\0");
    hash.update(actor.as_bytes());
    for value in [
        request.subject_ref.as_bytes(),
        request.category.as_str().as_bytes(),
    ] {
        hash.update(&(value.len() as u64).to_be_bytes());
        hash.update(value);
    }
    EntityId::from_bytes(
        hash.finalize().as_bytes()[..16]
            .try_into()
            .expect("hash prefix"),
    )
}

pub(super) fn read(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    id: &EntityId,
) -> Result<Option<ReportIssue>> {
    let Some(raw) = crate::vault::entity_revision::read_entity_revision_in_txn(
        vault,
        txn,
        id,
        crate::vault::entity_revision::ReadMode::Live,
    )?
    else {
        return Ok(None);
    };
    let header = crate::batch::EntityMetadataHeader::parse(&raw)
        .ok_or(Error::CorruptedIndex("report issue header"))?;
    if header.entity_type != ENTITY_TYPE_ISSUE {
        return Err(invalid("report reference is not an ISSUE"));
    }
    let issue: ReportIssue =
        rmp_serde::from_slice(&raw[crate::batch::ENTITY_METADATA_HEADER_LEN..])
            .map_err(|_| Error::CorruptedIndex("report issue body"))?;
    if issue.issue_ref != id.to_hex() {
        return Err(Error::CorruptedIndex("report issue identity"));
    }
    Ok(Some(issue))
}

fn write(vault: &Vault, txn: &mut heed::RwTxn<'_>, issue: &ReportIssue) -> Result<()> {
    let id = EntityId::from_hex(&issue.issue_ref)?;
    let data = rmp_serde::to_vec_named(issue).map_err(|_| invalid("report issue encoding"))?;
    apply_ops(
        &vault.store,
        &vault.config,
        &vault.analyzer,
        txn,
        vec![BatchOp::Put {
            id,
            entity_type: ENTITY_TYPE_ISSUE,
            occurred: TimeRange {
                start: issue.received_at,
                end: u64::MAX,
            },
            learned_at: vault.store.clock.now_recorded_at(),
            data,
            allow_maintenance: true,
            allow_reserved_predicate: false,
            hub_sync_imported: false,
        }],
        vault.text_index_trusted.load(Ordering::Acquire),
        false,
        true,
    )
}

impl Vault {
    pub(crate) fn submit_report(
        &self,
        actor: EntityId,
        request: ReportRequest,
        embedding: Option<&[f32]>,
        dedup: FeedbackDedup,
    ) -> Result<ReportReceipt> {
        request.validate()?;
        let id = issue_id(actor, &request)?;
        // Routing uses installed publisher provenance, not a caller-chosen destination.
        let artifact_route = self.report_artifact_route(&request.subject_ref)?;
        let now = self.store.clock.now_recorded_at();
        self.with_write_txn_grouped(|txn| {
            if let Some(issue) = read(self, txn, &id)? {
                if issue.actor_ref != actor.to_hex()
                    || issue.request.subject_ref != request.subject_ref
                    || issue.request.category != request.category
                {
                    return Err(Error::CorruptedIndex("report identity collision"));
                }
                return Ok(ReportReceipt::from_issue(&issue, true));
            }
            let route =
                self.report_route_in_txn(txn, &request.subject_ref, artifact_route.clone())?;
            let disclosure = self.report_disclosure_in_txn(txn, &route, request.carries_text())?;
            let mut issue = ReportIssue {
                issue_ref: id.to_hex(),
                actor_ref: actor.to_hex(),
                request,
                received_at: now,
                route,
                review: ReportReview::default(),
                disclosure,
            };
            if let Some(vector) = embedding {
                if let Some(root) =
                    self.ingest_report_feedback_in_txn(txn, &issue, vector, dedup)?
                {
                    issue.review.status = ReportStatus::Duplicate;
                    issue.review.duplicate_of = Some(root.to_hex());
                }
            }
            write(self, txn, &issue)?;
            ARRIVALS.put(&self.store, txn, &(now, id), &())?;
            Ok(ReportReceipt::from_issue(&issue, false))
        })
    }

    pub(crate) fn report_issue_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        id: &EntityId,
    ) -> Result<Option<ReportIssue>> {
        read(self, txn, id)
    }

    /// A local issue read for host-authorized triage, not a public vault read grant.
    pub fn report_issue(&self, id: &EntityId) -> Result<Option<ReportIssue>> {
        let txn = self.store.env.read_txn()?;
        read(self, &txn, id)
    }

    /// Receipt-backed arrivals, oldest first. Each accepted actor/subject/category appears once.
    pub fn report_inbox(
        &self,
        after: Option<(u64, EntityId)>,
        limit: usize,
    ) -> Result<Vec<ReportIssue>> {
        use std::ops::Bound;
        let txn = self.store.env.read_txn()?;
        let start = after.map_or(Bound::Unbounded, Bound::Excluded);
        let mut issues = Vec::new();
        for row in ARRIVALS.iter_range(&self.store, &txn, start.as_ref(), Bound::Unbounded)? {
            let ((_, id), ()) = row?;
            if let Some(issue) = read(self, &txn, &id)? {
                if issues.len() == limit {
                    break;
                }
                issues.push(issue);
            }
        }
        Ok(issues)
    }

    /// The owner reviews the ISSUE itself. Reports do not create a TASK or grant authority.
    pub fn review_report(
        &self,
        owner: &crate::consent::AuthenticatedOwner,
        id: &EntityId,
        review: ReportReview,
    ) -> Result<ReportIssue> {
        if review
            .quality_score
            .is_some_and(|score| !score.is_finite() || !(0.0..=1.0).contains(&score))
        {
            return Err(invalid("invalid report quality score"));
        }
        let duplicate = review
            .duplicate_of
            .as_deref()
            .map(EntityId::from_hex)
            .transpose()?;
        if (review.status == ReportStatus::Duplicate) != duplicate.is_some()
            || duplicate == Some(*id)
        {
            return Err(invalid("duplicate review must name another issue"));
        }
        self.with_write_txn_grouped(|txn| {
            owner.revalidate_in_txn(self, txn)?;
            if let Some(duplicate) = duplicate {
                read(self, txn, &duplicate)?.ok_or(Error::EntityNotFound)?;
            }
            let mut issue = read(self, txn, id)?.ok_or(Error::EntityNotFound)?;
            issue.review = review;
            write(self, txn, &issue)?;
            Ok(issue)
        })
    }

    pub(super) fn write_report_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        issue: &ReportIssue,
    ) -> Result<()> {
        write(self, txn, issue)
    }
}
