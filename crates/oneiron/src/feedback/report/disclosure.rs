//! A report's text and its publisher (FIX 8747; DEC-0006). The owner's
//! "stop asking for this publisher" is a revocable DEC-0006 disclosure
//! standing grant, minted in the writer that records the decision: for
//! exactly this publisher and the report text its reporters write, listed in
//! the one consent registry, where one tap revokes it. An approve-once is
//! the owner's act on one issue's exact request, kept on the issue as its
//! own basis: a grant's revoke never ends it, and an explicit deny wins over
//! both.
//!
//! An issue's `disclosure` is the effective view, read from its basis and
//! the live registry every time the issue is read; it is never authority of
//! its own. While the grant is live, every report to that publisher, current
//! or future, stays quietly approved, as before. Each send that hands a
//! report's text to the transport checks the owner's live disclosure once
//! more, in the writer just before the bytes leave, and a standing reuse
//! writes its quiet use receipt there: a revoke before that writer wins,
//! and text that already left is recorded as sent. The content-free
//! signature lane never reads text through here.
use serde::{Deserialize, Serialize};

use super::{
    ReportDisclosure, ReportDisclosureChoice, ReportIssue, ReportRequest, ReportRoute, ReportStatus,
};
use crate::consent::{
    AudienceBound, AuthenticatedOwner, ComposedEffect, ConsentDecision, DisclosureClass,
    DisclosureEnvelope, EffectFacts, GrantBound, StandingConsentGrant, UndoFidelity,
    evaluate_consent, load_active_standing_grants,
};
use crate::entity_id::bytes_to_hex_lower;
use crate::error::GateError;
use crate::{EntityId, Error, Result, Vault};

/// The data class a publisher's standing disclosure covers: the text a
/// reporter wrote, never text loaded from the vault rows a report cites.
const REPORT_TEXT_CLASS: &str = "feedback.report_text";
/// The domain a report request's digest is taken under.
const REQUEST_DIGEST_DOMAIN: &[u8] = b"oneiron.report.request_digest.v1\0";

/// What lets one report's text reach its publisher (FIX 8747). The issue's
/// `disclosure` is the view this basis and the live consent registry give.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(tag = "basis", rename_all = "snake_case", deny_unknown_fields)]
pub enum ReportDisclosureBasis {
    /// The owner approved this issue's exact text once, for its publisher.
    /// Revoking a standing grant does not end it.
    IssueOnce {
        /// The publisher the issue routes to.
        publisher_ref: String,
        /// 64 lower hex: the digest of the exact report request approved.
        request_digest: String,
        /// Vault seconds the owner decided.
        decided_at: u64,
    },
    /// The owner's standing disclosure grant for this publisher, live in the
    /// consent registry, where one tap revokes it.
    StandingGrant {
        /// The grant's registry reference.
        grant_ref: String,
    },
}

/// One text send's tie to the report it quotes: the issue, its publisher
/// and the digest of its exact request, taken when the send was asked for.
/// The send's last check, in the writer before its bytes reach the
/// transport, holds it against the live issue and the owner's live
/// disclosure; a retained preview is bytes, never continuing authority.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReportTextSendBinding {
    issue: EntityId,
    publisher_ref: String,
    request_digest: [u8; 32],
}

impl ReportTextSendBinding {
    /// The binding a send of `issue`'s quoted text carries; `None` for a
    /// report that routes to no publisher or carries no text.
    ///
    /// # Errors
    ///
    /// An issue reference that is not an id; a request that does not encode.
    pub fn for_issue(issue: &ReportIssue) -> Result<Option<Self>> {
        let ReportRoute::Publisher { publisher_ref } = &issue.route else {
            return Ok(None);
        };
        if !issue.request.carries_text() {
            return Ok(None);
        }
        Ok(Some(Self {
            issue: EntityId::from_hex(&issue.issue_ref)?,
            publisher_ref: publisher_ref.clone(),
            request_digest: request_digest(&issue.request)?,
        }))
    }
}

/// The digest of a report's exact request, in its canonical encoding.
fn request_digest(request: &ReportRequest) -> Result<[u8; 32]> {
    let bytes =
        rmp_serde::to_vec_named(request).map_err(|_| super::invalid("report request encoding"))?;
    let mut hasher = blake3::Hasher::new();
    hasher.update(REQUEST_DIGEST_DOMAIN);
    hasher.update(&bytes);
    Ok(*hasher.finalize().as_bytes())
}

/// The standing disclosure bound for one publisher's report text in one
/// disclosure round, all engine-derived: audience `publisher:<publisher>`,
/// class `feedback.report_text`, envelope
/// `report_text:publisher:<publisher>:round:<round>` (FIX 9368).
fn publisher_bound(publisher_ref: &str, round: u64) -> Result<GrantBound> {
    GrantBound::disclosure(
        AudienceBound::singleton(format!("publisher:{publisher_ref}"))?,
        DisclosureClass::new(REPORT_TEXT_CLASS)?,
        DisclosureEnvelope::new([format!(
            "report_text:publisher:{publisher_ref}:round:{round}"
        )])?,
    )
}

/// One issue's text reaching its publisher, as the one evaluator reads it:
/// seen outside this vault, with no undo, for that issue's exact request.
/// Its digest names the reuse receipt.
fn text_effect(issue_ref: &str, digest: &[u8; 32], bound: GrantBound) -> Result<ComposedEffect> {
    let facts = EffectFacts::new(format!(
        "{REPORT_TEXT_CLASS}:{issue_ref}:{}",
        bytes_to_hex_lower(digest)
    ))?
    .with_external_observers(true)
    .with_undo_fidelity(UndoFidelity::None);
    ComposedEffect::new(facts).with_disclosure_requirement(bound)
}

/// The registry reference of the standing grant in `grants` that covers one
/// issue's text to `publisher_ref`, by the one evaluator; `None` when none
/// does. Pure of IO: the caller supplies the already-loaded grant set
/// (FIX 9366, one load per pass).
fn covering_grant_with_grants(
    issue_ref: &str,
    publisher_ref: &str,
    digest: &[u8; 32],
    round: u64,
    grants: &[StandingConsentGrant],
) -> Result<Option<String>> {
    let bound = publisher_bound(publisher_ref, round)?;
    let effect = text_effect(issue_ref, digest, bound.clone())?;
    if evaluate_consent(&effect, None, grants) != ConsentDecision::Auto {
        return Ok(None);
    }
    Ok(grants
        .iter()
        .find(|grant| grant.bound().contains(&bound))
        .map(|grant| grant.bound().digest().to_hex()))
}

impl Vault {
    /// `issue`'s effective disclosure against the already-loaded `grants`
    /// (FIX 9366, one load per pass). Same view as
    /// [`Self::project_report_disclosure_in_txn`]: a publisher-routed report
    /// with text is approved by its own issue-once basis, else by a covering
    /// grant in `grants`, and otherwise waits on the owner. A denied, local
    /// or content-free report keeps its view; so does one with no text.
    /// Pure of grant IO: the caller loaded `grants` once on the pass txn.
    pub(super) fn project_report_disclosure_with_grants_in_txn(
        &self,
        _txn: &heed::RoTxn<'_>,
        issue: &mut ReportIssue,
        grants: &[StandingConsentGrant],
    ) -> Result<()> {
        let ReportRoute::Publisher { publisher_ref } = &issue.route else {
            return Ok(());
        };
        if !issue.request.carries_text()
            || !matches!(
                issue.disclosure,
                ReportDisclosure::NeedsApproval | ReportDisclosure::Approved
            )
        {
            return Ok(());
        }
        let digest = request_digest(&issue.request)?;
        if let Some(ReportDisclosureBasis::IssueOnce {
            publisher_ref: approved,
            request_digest,
            ..
        }) = &issue.disclosure_basis
            && approved == publisher_ref
            && *request_digest == bytes_to_hex_lower(&digest)
        {
            issue.disclosure = ReportDisclosure::Approved;
            return Ok(());
        }
        let grant = covering_grant_with_grants(
            &issue.issue_ref,
            publisher_ref,
            &digest,
            issue.disclosure_round,
            grants,
        )?;
        (issue.disclosure, issue.disclosure_basis) = match grant {
            Some(grant_ref) => (
                ReportDisclosure::Approved,
                Some(ReportDisclosureBasis::StandingGrant { grant_ref }),
            ),
            None => (ReportDisclosure::NeedsApproval, None),
        };
        Ok(())
    }

    /// `issue`'s effective disclosure as `txn` reads it. A publisher-routed
    /// report with text is approved by its own issue-once basis, else by a
    /// standing grant live now, and otherwise waits on the owner. A denied,
    /// local or content-free report keeps its view; so does one with no text.
    pub(super) fn project_report_disclosure_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        issue: &mut ReportIssue,
    ) -> Result<()> {
        // Cases that never touch grants return without a scan, as before;
        // only a text issue without a matching issue-once basis loads.
        let ReportRoute::Publisher { publisher_ref } = &issue.route else {
            return Ok(());
        };
        if !issue.request.carries_text()
            || !matches!(
                issue.disclosure,
                ReportDisclosure::NeedsApproval | ReportDisclosure::Approved
            )
        {
            return Ok(());
        }
        let digest = request_digest(&issue.request)?;
        if let Some(ReportDisclosureBasis::IssueOnce {
            publisher_ref: approved,
            request_digest,
            ..
        }) = &issue.disclosure_basis
            && approved == publisher_ref
            && *request_digest == bytes_to_hex_lower(&digest)
        {
            issue.disclosure = ReportDisclosure::Approved;
            return Ok(());
        }
        let grants = load_active_standing_grants(&self.store, txn)?;
        self.project_report_disclosure_with_grants_in_txn(txn, issue, &grants)
    }

    /// The owner's disclosure choice for one issue to `publisher_ref`, in the
    /// writer that records it. Approve-once appends its consent receipt for
    /// the issue's exact text effect (FIX 9368); stop-asking mints the
    /// publisher's standing grant. Both go through the consent registry's
    /// own doors, here.
    pub(super) fn report_disclosure_choice_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        owner: &AuthenticatedOwner,
        (issue_ref, publisher_ref): (&str, &str),
        request: &ReportRequest,
        round: u64,
        choice: ReportDisclosureChoice,
    ) -> Result<(ReportDisclosure, Option<ReportDisclosureBasis>)> {
        Ok(match choice {
            ReportDisclosureChoice::ApproveOnce => {
                let digest = request_digest(request)?;
                let effect =
                    text_effect(issue_ref, &digest, publisher_bound(publisher_ref, round)?)?;
                // The same approval asked again keeps its first receipt.
                match self.approve_once_in_txn(txn, owner, effect.digest()) {
                    Err(Error::Gate(GateError::ConsentApproveOnceSpent(_))) | Ok(_) => {}
                    Err(error) => return Err(error),
                }
                (
                    ReportDisclosure::Approved,
                    Some(ReportDisclosureBasis::IssueOnce {
                        publisher_ref: publisher_ref.to_owned(),
                        request_digest: bytes_to_hex_lower(&digest),
                        decided_at: self.now_recorded_at(),
                    }),
                )
            }
            ReportDisclosureChoice::StopAskingForPublisher => {
                let receipt = self.create_standing_grant_in_txn(
                    txn,
                    owner,
                    publisher_bound(publisher_ref, round)?,
                )?;
                let grant_ref = receipt.grant_ref().ok_or(Error::InvariantViolation(
                    "a standing grant's receipt names its grant",
                ))?;
                (
                    ReportDisclosure::Approved,
                    Some(ReportDisclosureBasis::StandingGrant { grant_ref }),
                )
            }
            ReportDisclosureChoice::Deny => {
                let digest = request_digest(request)?;
                let effect =
                    text_effect(issue_ref, &digest, publisher_bound(publisher_ref, round)?)?;
                self.deny_consent_in_txn(txn, owner, effect.digest())?;
                (ReportDisclosure::Denied, None)
            }
        })
    }

    /// The last check before a report's quoted text reaches the transport,
    /// in a write of its own: `true` while the live issue is the one
    /// `binding` names (same publisher, same exact request), not duplicate
    /// or rejected, and the owner's disclosure of it stands now, by its
    /// issue-once basis or by a standing grant live in this writer, whose
    /// quiet use receipt is written here. `false`, writing nothing, once the
    /// owner revoked, denied or changed it: the text does not leave. The
    /// send pipeline calls it, so it writes in a group of its own.
    pub(crate) fn admit_report_text_exposure(
        &self,
        binding: &ReportTextSendBinding,
    ) -> Result<bool> {
        self.with_write_txn(|txn| {
            let Some(issue) = super::store::read(self, txn, &binding.issue)? else {
                return Ok(false);
            };
            let same = matches!(
                &issue.route,
                ReportRoute::Publisher { publisher_ref }
                    if *publisher_ref == binding.publisher_ref
            ) && request_digest(&issue.request)? == binding.request_digest
                && !matches!(
                    issue.review.status,
                    ReportStatus::Duplicate | ReportStatus::Rejected
                )
                && issue.disclosure == ReportDisclosure::Approved;
            if !same {
                return Ok(false);
            }
            match &issue.disclosure_basis {
                Some(ReportDisclosureBasis::IssueOnce { .. }) => Ok(true),
                // The read above found this grant live and covering, by the
                // one evaluator, in this same writer.
                Some(ReportDisclosureBasis::StandingGrant { grant_ref }) => {
                    let effect = text_effect(
                        &issue.issue_ref,
                        &binding.request_digest,
                        publisher_bound(&binding.publisher_ref, issue.disclosure_round)?,
                    )?;
                    self.record_standing_grant_use_in_txn(txn, grant_ref, effect.digest())?;
                    Ok(true)
                }
                None => Ok(false),
            }
        })
    }
}
