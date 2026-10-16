//! Maker routing and disclosure. Text never enters the content-free publisher payload.
use serde::{Deserialize, Serialize};

use super::{
    IssueCategory, ReportDisclosure, ReportIssue, ReportKind, ReportRequest, ReportStatus, invalid,
    validate_ref,
};
use crate::consent::AuthenticatedOwner;
use crate::side_table::{self, LegacyJson, Named, SideTable};
use crate::skill_hub::HubImportReceipt;
use crate::{EntityId, Error, Result, Vault};

// Read the canonical source receipts directly: the owner-facing recent-install
// projection is deliberately bounded and cannot resolve an older subject.
const IMPORTS: SideTable<(EntityId, EntityId, [u8; 32]), HubImportReceipt, LegacyJson> =
    SideTable::new(&side_table::SKILL_HUB_IMPORT_RECEIPT);

const ROUTES: SideTable<String, ReportRoute, Named> =
    SideTable::new(&side_table::FEEDBACK_REPORT_ROUTE);
const DISCLOSURES: SideTable<String, bool, Named> =
    SideTable::new(&side_table::FEEDBACK_REPORT_DISCLOSURE);

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "destination", rename_all = "snake_case", deny_unknown_fields)]
pub enum ReportRoute {
    #[default]
    OwnerInbox,
    Publisher {
        publisher_ref: String,
    },
}

/// The three DEC-0006 choices, scoped to this issue or its already-resolved publisher.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReportDisclosureChoice {
    ApproveOnce,
    StopAskingForPublisher,
    Deny,
}

/// Fixed-shape content-free evidence. No caller-authored reference or prose crosses here.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReportSignature {
    pub issue_ref: String,
    pub subject_hash: [u8; 32],
    pub category: IssueCategory,
    pub kind: ReportKind,
}

/// The transport consumes this only after resolving the stored maker route.
/// `disclosed` is absent unless the owner approved this publisher's text.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReportRoutedPayload {
    pub route: ReportRoute,
    pub signature: ReportSignature,
    pub disclosed: Option<ReportRequest>,
}

impl Vault {
    /// Host-trusted receipt provenance: the wire-receipt minter can bind its
    /// lasting reference to the artifact's maker. The reporting caller cannot.
    /// An existing binding is retained; the owner changes policy explicitly.
    pub fn bind_report_subject(&self, subject_ref: &str, route: ReportRoute) -> Result<()> {
        validate_ref(subject_ref)?;
        validate_route(&route)?;
        self.with_write_txn_grouped(|txn| {
            let key = subject_ref.to_owned();
            if ROUTES.get(&self.store, txn, &key)?.is_none() {
                ROUTES.put(&self.store, txn, &key, &route)?;
            }
            Ok(())
        })
    }

    /// An owner-authored subject's default route is the owner inbox. Owners
    /// may replace a subject's route without changing any reporter's authority.
    pub fn set_report_route(
        &self,
        owner: &AuthenticatedOwner,
        subject_ref: &str,
        route: ReportRoute,
    ) -> Result<()> {
        validate_ref(subject_ref)?;
        validate_route(&route)?;
        self.with_write_txn_grouped(|txn| {
            owner.revalidate_in_txn(self, txn)?;
            ROUTES.put(&self.store, txn, &subject_ref.to_owned(), &route)
        })
    }

    pub(super) fn report_route_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        subject: &str,
        artifact_route: Option<ReportRoute>,
    ) -> Result<ReportRoute> {
        Ok(ROUTES
            .get(&self.store, txn, &subject.to_owned())?
            .or(artifact_route)
            .unwrap_or_default())
    }

    pub(super) fn report_artifact_route(&self, subject: &str) -> Result<Option<ReportRoute>> {
        let subject = subject.strip_prefix("skill:").unwrap_or(subject);
        let mut publishers = std::collections::BTreeSet::new();
        let txn = self.store.env.read_txn()?;
        for row in IMPORTS.iter_from(&self.store, &txn, &[])? {
            let (_, receipt) = row?;
            if receipt.entity == subject
                || receipt.content_hash == subject
                || receipt.ref_string == subject
            {
                publishers.extend(receipt.publisher);
            }
        }
        for pack in self.installed_packs()? {
            if pack.source_id == subject
                || pack.content_hash == subject
                || pack.hub_ref == subject
                || pack.skills.iter().any(|skill| skill == subject)
            {
                if pack.publisher != "vault" {
                    publishers.insert(pack.publisher);
                }
            }
        }
        // Multiple source aliases must not silently pick a different maker.
        Ok((publishers.len() == 1).then(|| ReportRoute::Publisher {
            publisher_ref: publishers.into_iter().next().expect("one publisher"),
        }))
    }

    pub(super) fn report_disclosure_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        route: &ReportRoute,
        carries_text: bool,
    ) -> Result<ReportDisclosure> {
        if matches!(route, ReportRoute::OwnerInbox) {
            return Ok(ReportDisclosure::Local);
        }
        if !carries_text {
            return Ok(ReportDisclosure::ContentFree);
        }
        let ReportRoute::Publisher { publisher_ref } = route else {
            unreachable!()
        };
        Ok(
            if DISCLOSURES
                .get(&self.store, txn, publisher_ref)?
                .unwrap_or(false)
            {
                ReportDisclosure::Approved
            } else {
                ReportDisclosure::NeedsApproval
            },
        )
    }

    /// No transport runs here. The owner decides whether the report's exact
    /// text may cross the maker's boundary, once or for that publisher.
    pub fn decide_report_disclosure(
        &self,
        owner: &AuthenticatedOwner,
        id: &EntityId,
        choice: ReportDisclosureChoice,
    ) -> Result<ReportIssue> {
        self.with_write_txn_grouped(|txn| {
            owner.revalidate_in_txn(self, txn)?;
            let mut issue = super::store::read(self, txn, id)?.ok_or(Error::EntityNotFound)?;
            let ReportRoute::Publisher { publisher_ref } = &issue.route else {
                return Err(invalid("a local report needs no publisher disclosure"));
            };
            issue.disclosure = match choice {
                ReportDisclosureChoice::ApproveOnce => ReportDisclosure::Approved,
                ReportDisclosureChoice::StopAskingForPublisher => {
                    DISCLOSURES.put(&self.store, txn, publisher_ref, &true)?;
                    ReportDisclosure::Approved
                }
                ReportDisclosureChoice::Deny => ReportDisclosure::Denied,
            };
            self.write_report_in_txn(txn, &issue)?;
            Ok(issue)
        })
    }

    /// The outbound view of an ISSUE. The host uses the existing publisher
    /// channel; this door cannot run repairs, open tasks or send unapproved text.
    pub fn report_routed_payload(&self, id: &EntityId) -> Result<Option<ReportRoutedPayload>> {
        let txn = self.store.env.read_txn()?;
        let Some(issue) = super::store::read(self, &txn, id)? else {
            return Ok(None);
        };
        if matches!(issue.route, ReportRoute::OwnerInbox)
            || matches!(
                issue.review.status,
                ReportStatus::Duplicate | ReportStatus::Rejected
            )
            || issue.disclosure == ReportDisclosure::Denied
        {
            return Ok(None);
        }
        let standing = match &issue.route {
            ReportRoute::Publisher { publisher_ref } => DISCLOSURES
                .get(&self.store, &txn, publisher_ref)?
                .unwrap_or(false),
            ReportRoute::OwnerInbox => false,
        };
        let approved = issue.disclosure == ReportDisclosure::Approved
            || (issue.disclosure == ReportDisclosure::NeedsApproval && standing);
        if issue.request.carries_text() && !approved {
            return Ok(None);
        }
        Ok(Some(ReportRoutedPayload {
            signature: ReportSignature {
                issue_ref: issue.issue_ref,
                subject_hash: *blake3::hash(issue.request.subject_ref.as_bytes()).as_bytes(),
                category: issue.request.category,
                kind: issue.request.kind,
            },
            route: issue.route,
            disclosed: approved.then_some(issue.request),
        }))
    }
}

fn validate_route(route: &ReportRoute) -> Result<()> {
    if let ReportRoute::Publisher { publisher_ref } = route {
        validate_ref(publisher_ref)?;
    }
    Ok(())
}
