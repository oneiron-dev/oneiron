//! Durable issue identity, entity-local review, and the arrival index.
use std::sync::atomic::Ordering;

use super::{
    ReportDisclosure, ReportIssue, ReportIssueOrigin, ReportReceipt, ReportRequest, ReportReview,
    ReportRoute, ReportStatus, invalid,
};
use crate::batch::{BatchOp, apply_ops};
use crate::consent::StandingConsentGrant;
use crate::feedback::intake::FeedbackDedup;
use crate::limit_ask::EngineLimit;
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

/// One issue as `txn` reads it, its disclosure the effective view its basis
/// and the live consent registry give (FIX 8747).
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
    let mut issue: ReportIssue =
        rmp_serde::from_slice(&raw[crate::batch::ENTITY_METADATA_HEADER_LEN..])
            .map_err(|_| Error::CorruptedIndex("report issue body"))?;
    if issue.issue_ref != id.to_hex() {
        return Err(Error::CorruptedIndex("report issue identity"));
    }
    vault.project_report_disclosure_in_txn(txn, &mut issue)?;
    Ok(Some(issue))
}

/// One issue as `txn` reads it, its disclosure the effective view its basis
/// and the already-loaded `grants` give (FIX 9366, one load per pass). Same
/// output as [`read`] when `grants` holds the active set on `txn`; pure of
/// grant IO.
pub(super) fn read_with_grants(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    id: &EntityId,
    grants: &[StandingConsentGrant],
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
    let mut issue: ReportIssue =
        rmp_serde::from_slice(&raw[crate::batch::ENTITY_METADATA_HEADER_LEN..])
            .map_err(|_| Error::CorruptedIndex("report issue body"))?;
    if issue.issue_ref != id.to_hex() {
        return Err(Error::CorruptedIndex("report issue identity"));
    }
    vault.project_report_disclosure_with_grants_in_txn(&mut issue, grants)?;
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
            row_version: None,
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

/// What the owner's archive restore did with one archived ISSUE.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ReportRestoreOutcome {
    /// The report was absent here and is now written, with its arrival.
    Inserted,
    /// This vault already holds the same report; nothing was written.
    Unchanged,
}

/// Review shape is shared; only the live review door requires its target to exist.
fn validate_review(id: &EntityId, review: &ReportReview) -> Result<Option<EntityId>> {
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
    if (review.status == ReportStatus::Duplicate) != duplicate.is_some() || duplicate == Some(*id) {
        return Err(invalid("duplicate review must name another issue"));
    }
    Ok(duplicate)
}

/// The report an archived ISSUE `body` holds, when it decodes as a report
/// filed under `id` with a valid request and review; `None` for any other
/// body. An export without secrets nulls credential-shaped text, so a
/// required text field (a proposal's problem or fix) no longer decodes. The
/// owner's restore leaves such a row omitted, as every ISSUE was before that
/// restore existed, and restores the rest of the archive.
pub(crate) fn restorable_archived_report(id: EntityId, body: &[u8]) -> Option<ReportIssue> {
    let issue: ReportIssue = rmp_serde::from_slice(body).ok()?;
    let actor = EntityId::from_hex(&issue.actor_ref).ok()?;
    if EntityId::from_hex(&issue.issue_ref).ok()? != id
        || issue_id(actor, &issue.request).ok()? != id
    {
        return None;
    }
    issue.request.validate().ok()?;
    validate_review(&id, &issue.review).ok()?;
    Some(issue)
}

impl Vault {
    /// The filing resolver, called before the archive import opens its writer.
    pub(crate) fn archived_report_artifact_route(
        &self,
        subject: &str,
    ) -> Result<Option<ReportRoute>> {
        self.report_artifact_route(subject)
    }

    /// Restores one archived ISSUE under `id` for the owner's whole-vault
    /// restore; `issue` is the report [`restorable_archived_report`] read from
    /// its body. The actor, request, filing time, review and disclosure round
    /// come from the archive; the route is computed here from `artifact_route`
    /// (resolved before the writer opened) and this vault's route policy, and
    /// the disclosure from that route and this vault's live grants, keeping an
    /// archived `Denied` only on the same route. The archived disclosure basis
    /// is dropped: a source owner's approve-once is no consent on this vault,
    /// so its text waits on this owner (REVIEW-7706/7771). The row is marked
    /// [`ReportIssueOrigin::OwnerArchiveRestore`], so no signature is offered
    /// for it. A row already here with the same actor, request, filing time and
    /// review is `Unchanged`; any other row under `id` is a collision.
    pub(crate) fn restore_archived_report_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        id: EntityId,
        mut issue: ReportIssue,
        artifact_route: Option<ReportRoute>,
    ) -> Result<ReportRestoreOutcome> {
        if let Some(raw) = crate::ports::EntityStoreRead::port_entity_raw(&self.store, txn, &id)? {
            let header = crate::batch::EntityMetadataHeader::parse(&raw)
                .ok_or(Error::CorruptedIndex("report issue header"))?;
            if header.entity_type == ENTITY_TYPE_ISSUE
                && let Some(existing) = read(self, txn, &id)?
                && existing.actor_ref == issue.actor_ref
                && existing.request == issue.request
                && existing.received_at == issue.received_at
                && existing.review == issue.review
            {
                return Ok(ReportRestoreOutcome::Unchanged);
            }
            return Err(Error::InvalidConfig(
                "whole-vault import: import ID collides with different entity data".into(),
            ));
        }
        let route = self.report_route_in_txn(txn, &issue.request.subject_ref, artifact_route)?;
        let keep_denial = issue.disclosure == ReportDisclosure::Denied && route == issue.route;
        issue.disclosure = if keep_denial {
            ReportDisclosure::Denied
        } else {
            super::routing::report_disclosure(&route, issue.request.carries_text())
        };
        issue.route = route;
        issue.disclosure_basis = None;
        self.project_report_disclosure_in_txn(txn, &mut issue)?;
        issue.origin = ReportIssueOrigin::OwnerArchiveRestore;
        write(self, txn, &issue)?;
        ARRIVALS.put(&self.store, txn, &(issue.received_at, id), &())?;
        Ok(ReportRestoreOutcome::Inserted)
    }

    pub(crate) fn submit_report(
        &self,
        actor: EntityId,
        request: ReportRequest,
        embedding: Option<&[f32]>,
        dedup: FeedbackDedup,
    ) -> Result<ReportReceipt> {
        request.validate()?;
        let _ = self.measure_limit(
            EngineLimit::MaintenanceTextBytes,
            request.longest_text() as u64,
        );
        // Every evidence reference is kept; how many is measured (FIX 8746).
        let _ = self.measure_limit(
            EngineLimit::MaintenanceRowItems,
            request.evidence_refs.len() as u64,
        );
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
            let disclosure = super::routing::report_disclosure(&route, request.carries_text());
            let mut issue = ReportIssue {
                issue_ref: id.to_hex(),
                actor_ref: actor.to_hex(),
                request,
                received_at: now,
                route,
                review: ReportReview::default(),
                disclosure,
                disclosure_basis: None,
                disclosure_round: 0,
                origin: ReportIssueOrigin::Filed,
            };
            // A standing grant live for this publisher approves its text now.
            self.project_report_disclosure_in_txn(txn, &mut issue)?;
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
    /// Loads the active standing grants once on the page txn and reuses the
    /// set for every arrival (FIX 9366): at most N scans become 1; empty/no-text pages pay 1.
    pub fn report_inbox(
        &self,
        after: Option<(u64, EntityId)>,
        limit: usize,
    ) -> Result<Vec<ReportIssue>> {
        let (issues, _) = self.report_inbox_page_and_grants(after, limit)?;
        Ok(issues)
    }

    /// [`Self::report_inbox`] with its pass-local grant set (FIX 9366, one
    /// load per pass): the page and the grants share one txn snapshot, so the
    /// projection is output-identical to per-issue loads. The delivery pass
    /// reuses the returned set for its sends (0 fresh loads); the set is
    /// dropped at pass end, never memoized across passes/pages.
    pub(super) fn report_inbox_page_and_grants(
        &self,
        after: Option<(u64, EntityId)>,
        limit: usize,
    ) -> Result<(Vec<ReportIssue>, Vec<StandingConsentGrant>)> {
        use std::ops::Bound;
        let txn = self.store.env.read_txn()?;
        let grants = self.active_standing_consent_grants_in_txn(&txn)?;
        let start = after.map_or(Bound::Unbounded, Bound::Excluded);
        let mut issues = Vec::new();
        for row in ARRIVALS.iter_range(&self.store, &txn, start.as_ref(), Bound::Unbounded)? {
            let ((_, id), ()) = row?;
            if let Some(issue) = read_with_grants(self, &txn, &id, &grants)? {
                if issues.len() == limit {
                    break;
                }
                issues.push(issue);
            }
        }
        Ok((issues, grants))
    }

    /// The owner reviews the ISSUE itself. Reports do not create a TASK or grant authority.
    pub fn review_report(
        &self,
        owner: &crate::consent::AuthenticatedOwner,
        id: &EntityId,
        review: ReportReview,
    ) -> Result<ReportIssue> {
        let duplicate = validate_review(id, &review)?;
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
