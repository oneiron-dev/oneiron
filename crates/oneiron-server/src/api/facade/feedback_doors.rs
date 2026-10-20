//! The host doors of subject-bound feedback (OF-420/537): the owner's
//! report disclosure, route and outbound reads, and `feedback.preview` /
//! `feedback.send` over one report issue. `host_doors` re-exports them, so
//! the generated HTTP facade handler and the MCP dispatcher call them by
//! the name every host door has, and a tool call, a code-mode call and an
//! SDK call meet one admission: the vault owner's proof, as `/v1/owner`
//! and the owner report routes take it.
//!
//! Preview and send reuse the owner feedback door's shared path
//! (`owner::feedback::preview_view` / `send_previewed`): the preview
//! returns the exact bundle, its digest and its destination, and the
//! owner's send of that preview is the approve-once on those bytes to
//! that destination. The bundle here is built from the issue, so a
//! metadata send carries no vault text, and a text send carries the
//! report's quoted text — which may leave only while the issue's disclosure
//! stands approved for its publisher. When this server's on-device tagger
//! can filter, that text leaves as the in-vault filter returned it (OF-420,
//! `crate::feedback_redaction`); when it cannot, as written, as it did
//! before the filter. The send carries the bytes the preview kept and runs
//! no filter (FIX 5212); it rebuilds only the unfiltered bundle, to bind its
//! request to the issue, category and text choice the preview was made for.
use std::sync::Arc;

use oneiron::consent::AuthenticatedOwner;
use oneiron::feedback::{FeedbackPreview, ReportIssue, prepare_feedback_preview};
use oneiron::memory::{MEMORY_CODE_INVALID_STATE, MemoryError, MemoryResult};
use oneiron::task_verb::sdk::{
    self, FeedbackPreviewRequest, FeedbackSendSubjectRequest, FeedbackSubjectPreview,
    FeedbackSubjectSent, ReportDisclosureRequest, ReportOutboundRequest, ReportOutboundView,
    ReportRouteReceipt, ReportRouteRequest,
};

use super::host_doors::{Listed, hex_rows};
use super::legal_hold_doors::as_owner_naming;
use crate::auth::CoreAuth;
use crate::feedback_delivery::FeedbackHost;
use crate::feedback_redaction::{Unfiltered, feedback_redactor};
use crate::owner::{OwnerError, feedback as owner_feedback};
use crate::server::SyncServer;

/// `vault.reports.disclosure`: the owner decides whether this report's
/// exact text may cross to its already-resolved publisher.
pub(crate) async fn vault_reports_disclosure(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: ReportDisclosureRequest,
) -> Listed<ReportIssue> {
    as_owner_naming(
        server,
        auth,
        "vault.reports.disclosure",
        move |server, owner| sdk::decide_report_disclosure_as_owner(server.vault(), owner, input),
        |issue| hex_rows([&issue.issue_ref]),
    )
    .await
}

/// `vault.reports.route`: the owner replaces one subject's maker route.
pub(crate) async fn vault_reports_route(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: ReportRouteRequest,
) -> Listed<ReportRouteReceipt> {
    as_owner_naming(
        server,
        auth,
        "vault.reports.route",
        move |server, owner| sdk::set_report_route_as_owner(server.vault(), owner, input),
        |_| Vec::new(),
    )
    .await
}

/// `vault.reports.outbound`: the content-free payload a publisher delivery
/// would carry now; its disclosed text only when disclosure approved it.
pub(crate) async fn vault_reports_outbound(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: ReportOutboundRequest,
) -> Listed<ReportOutboundView> {
    as_owner_naming(
        server,
        auth,
        "vault.reports.outbound",
        move |server, owner| sdk::report_outbound_as_owner(server.vault(), owner, input),
        |view| hex_rows([&view.issue_ref]),
    )
    .await
}

/// `feedback.preview`: the subject-bound bundle as it would leave to this
/// server's feedback destination, shown before any approval.
pub(crate) async fn feedback_preview(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: FeedbackPreviewRequest,
) -> Listed<FeedbackSubjectPreview> {
    as_owner_naming(
        server,
        auth,
        "feedback.preview",
        move |server, owner| preview_subject(server, owner, &input),
        |preview| hex_rows([&preview.issue_ref]),
    )
    .await
}

/// `feedback.send`: send exactly the previewed bundle for this issue,
/// once, over this server's feedback transport.
pub(crate) async fn feedback_send(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: FeedbackSendSubjectRequest,
) -> Listed<FeedbackSubjectSent> {
    as_owner_naming(
        server,
        auth,
        "feedback.send",
        move |server, owner| send_subject(server, owner, &input),
        |sent| hex_rows([&sent.issue_ref]),
    )
    .await
}

fn feedback_host(server: &SyncServer) -> MemoryResult<Arc<FeedbackHost>> {
    server.feedback.clone().ok_or_else(|| {
        MemoryError::new(
            MEMORY_CODE_INVALID_STATE,
            "this server has no feedback destination",
            &["Set [feedback] destination and endpoint in the config, then restart `oneiron serve`."],
        )
    })
}

/// The issue's bundle as it would leave: every free text in it run through
/// this server's in-vault filter when it runs, and as built when it cannot;
/// beside it, the digest of the bundle as built, which binds a send to it.
fn bundle_preview(
    server: &SyncServer,
    issue: &ReportIssue,
    category: oneiron::feedback::FeedbackCategory,
    include_text: bool,
) -> MemoryResult<(FeedbackPreview, String)> {
    let built = sdk::subject_feedback_bundle(issue, category, include_text);
    let source = owner_feedback::source_digest(&built)
        .map_err(|error| MemoryError::bad_request(error.to_string()))?;
    let preview =
        prepare_feedback_preview(built, &feedback_redactor(server).door(Unfiltered::AsBuilt))
            .map_err(|error| MemoryError::bad_request(error.to_string()))?;
    Ok((preview, source))
}

fn preview_subject(
    server: &SyncServer,
    owner: &AuthenticatedOwner,
    input: &FeedbackPreviewRequest,
) -> MemoryResult<FeedbackSubjectPreview> {
    let host = feedback_host(server)?;
    let vault = server.vault();
    let issue = sdk::report_issue_as_owner(vault, owner, &input.issue_ref)?;
    let publisher_ref = sdk::subject_feedback_publisher(&issue)?;
    let (preview, source) = bundle_preview(server, &issue, input.category, input.include_text)?;
    let view = owner_feedback::preview_view(vault, &host, owner, &preview, &source)
        .map_err(owner_error)?;
    Ok(FeedbackSubjectPreview {
        includes_text: input.include_text && issue.request.carries_text(),
        digest: view.digest,
        encoding: view.encoding.to_owned(),
        bundle: view.bundle,
        destination: view.destination,
        approval: view.approval,
        previewed_at: view.previewed_at,
        subject_ref: issue.request.subject_ref.clone(),
        disclosure: issue.disclosure,
        issue_ref: issue.issue_ref,
        publisher_ref,
    })
}

fn send_subject(
    server: &SyncServer,
    owner: &AuthenticatedOwner,
    input: &FeedbackSendSubjectRequest,
) -> MemoryResult<FeedbackSubjectSent> {
    let host = feedback_host(server)?;
    let vault = server.vault();
    let issue = sdk::report_issue_as_owner(vault, owner, &input.issue_ref)?;
    let publisher_ref = sdk::subject_feedback_publisher(&issue)?;
    // Beside the bundle approval, quoted vault text crosses only while the
    // issue's own disclosure stands approved for its publisher.
    sdk::subject_feedback_send_allowed(vault, &issue, input.include_text)?;
    // FIX 5212: the bytes go as the preview kept them; only the unfiltered
    // bundle is rebuilt, so a request naming another issue, category or text
    // choice than the preview's is refused, and no filter runs.
    let built = sdk::subject_feedback_bundle(&issue, input.category, input.include_text);
    let source = owner_feedback::source_digest(&built)
        .map_err(|error| MemoryError::bad_request(error.to_string()))?;
    let sent = owner_feedback::send_previewed(
        vault,
        &host,
        owner,
        &source,
        &input.digest,
        &input.approval,
        input.previewed_at,
    )
    .map_err(owner_error)?;
    Ok(FeedbackSubjectSent {
        subject_ref: issue.request.subject_ref.clone(),
        issue_ref: issue.issue_ref,
        publisher_ref,
        digest: sent.digest,
        outcome: sent.outcome.to_owned(),
        gate_reasons: sent.gate_reasons,
        approval_receipt_ref: sent.approval_receipt_ref,
        logical_send_ref: sent.logical_send_ref,
        approval_digest: sent.approval_digest,
    })
}

/// The owner door's refusals as the facade's typed errors: an engine
/// refusal keeps its own code (a stopped-holding owner proof above all).
fn owner_error(error: OwnerError) -> MemoryError {
    match error {
        OwnerError::Engine(error) => MemoryError::from(*error),
        OwnerError::NotFound(..) => MemoryError::from(oneiron::Error::EntityNotFound),
        other => MemoryError::bad_request(other.to_string()),
    }
}
