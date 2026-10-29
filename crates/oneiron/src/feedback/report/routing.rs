//! Maker routing and disclosure. Text never enters the content-free publisher payload.
//! A remembered publisher is a standing grant in the consent registry, never a
//! stored flag (FIX 8747, the `disclosure` child).
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
pub(super) const IMPORTS: SideTable<(EntityId, EntityId, [u8; 32]), HubImportReceipt, LegacyJson> =
    SideTable::new(&side_table::SKILL_HUB_IMPORT_RECEIPT);

const ROUTES: SideTable<String, ReportRoute, Named> =
    SideTable::new(&side_table::FEEDBACK_REPORT_ROUTE);

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(tag = "destination", rename_all = "snake_case", deny_unknown_fields)]
pub enum ReportRoute {
    #[default]
    OwnerInbox,
    Publisher {
        publisher_ref: String,
    },
}

/// The three DEC-0006 choices, scoped to this issue or its already-resolved publisher.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
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
/// `disclosed` is absent unless the owner's disclosure of this report's text
/// stands now: approved once, or by a standing grant still live.
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
            // Stop-asking mints the publisher's standing grant in this writer.
            let round = issue.disclosure_round;
            let (disclosure, basis) = self.report_disclosure_choice_in_txn(
                txn,
                owner,
                (&issue.issue_ref, publisher_ref),
                &issue.request,
                round,
                choice,
            )?;
            issue.disclosure = disclosure;
            issue.disclosure_basis = basis;
            // A successful Deny burns this round: the next choice mints under a fresh bound (FIX 9368).
            if choice == ReportDisclosureChoice::Deny {
                issue.disclosure_round = round.saturating_add(1);
            }
            self.write_report_in_txn(txn, &issue)?;
            Ok(issue)
        })
    }

    /// The outbound view of an ISSUE. The host uses the existing publisher
    /// channel; this door cannot run repairs, open tasks or send unapproved text.
    /// A report whose text still waits on the owner's disclosure answers its
    /// content-free signature with no `disclosed` request (FIX 4630). The text
    /// it shows is the owner's live disclosure; text that leaves is checked
    /// again, and receipted, where a send hands it to the transport.
    pub fn report_routed_payload(&self, id: &EntityId) -> Result<Option<ReportRoutedPayload>> {
        self.routed_payload(id, true)
    }

    /// [`Self::report_routed_payload`] with no text: the content-free
    /// signature lane's projection, which never carries a report's text and
    /// spends no disclosure receipt.
    pub(super) fn report_signature_payload(
        &self,
        id: &EntityId,
    ) -> Result<Option<ReportRoutedPayload>> {
        self.routed_payload(id, false)
    }

    fn routed_payload(
        &self,
        id: &EntityId,
        with_text: bool,
    ) -> Result<Option<ReportRoutedPayload>> {
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
        // The read gave the live view: an issue-once approval, or a standing
        // grant live now.
        let approved = with_text && issue.disclosure == ReportDisclosure::Approved;
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

/// A new report's disclosure before the owner's choices are read: local, a
/// content-free signature, or text that waits on the owner.
pub(super) fn report_disclosure(route: &ReportRoute, carries_text: bool) -> ReportDisclosure {
    match route {
        ReportRoute::OwnerInbox => ReportDisclosure::Local,
        ReportRoute::Publisher { .. } if !carries_text => ReportDisclosure::ContentFree,
        ReportRoute::Publisher { .. } => ReportDisclosure::NeedsApproval,
    }
}

fn validate_route(route: &ReportRoute) -> Result<()> {
    if let ReportRoute::Publisher { publisher_ref } = route {
        validate_ref(publisher_ref)?;
    }
    Ok(())
}
