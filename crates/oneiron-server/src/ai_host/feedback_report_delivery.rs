//! The Coach's publisher delivery on the host (OF-420, FIX 739; ARCH-0056
//! §9: "reports are background"). The run hands every report's content-free
//! issue signature to [`oneiron::Vault::run_coach_feedback_delivery`], which
//! keeps each issue's custody and holds. Only this server's configured
//! `[feedback]` destination carries a signature, with that destination's own
//! bearer token, and only to a publisher the owner bound to exactly that
//! destination. With no destination configured every bound publisher holds
//! as changed, and nothing is sent.
use oneiron::dreamer_runner::DreamerAdmittedAttempt;
use oneiron::feedback::{
    ReportPublisherEndpoint, ReportSignatureTransport, ReportSignatureTransportRequest,
};
use oneiron::outbound::OutboundExecutionOutcome;

use crate::feedback_delivery::HttpFeedbackTransport;
use crate::server::SyncServer;

/// Resolves a bound publisher endpoint to this host's feedback carrier: the
/// configured destination's HTTP transport, or none.
pub(super) struct ReportPublisherResolver {
    transport: Option<HttpFeedbackTransport>,
}

impl ReportPublisherResolver {
    /// The carrier for `server`'s feedback destination. A destination whose
    /// transport cannot be built resolves to none, so every send holds.
    pub(super) fn for_server(server: &SyncServer) -> Self {
        let transport = server.feedback.as_ref().and_then(|host| {
            HttpFeedbackTransport::new(host.config.clone(), host.bearer.clone()).ok()
        });
        Self { transport }
    }
}

impl ReportSignatureTransport for ReportPublisherResolver {
    fn destination(&self) -> Option<ReportPublisherEndpoint> {
        self.transport
            .as_ref()
            .and_then(ReportSignatureTransport::destination)
    }

    fn send_issue_signature(
        &mut self,
        request: &ReportSignatureTransportRequest<'_>,
    ) -> OutboundExecutionOutcome {
        match self.transport.as_mut() {
            Some(transport) => transport.send_issue_signature(request),
            None => OutboundExecutionOutcome::failed("feedback_destination_unset"),
        }
    }
}

/// One delivery run over every report.
pub(super) fn run(
    server: &SyncServer,
    admitted: &DreamerAdmittedAttempt,
    now: u64,
) -> oneiron::Result<()> {
    let mut resolver = ReportPublisherResolver::for_server(server);
    let pass = server
        .vault()
        .run_coach_feedback_delivery(admitted, &mut resolver, now)?;
    tracing::debug!(
        seen = pass.seen,
        delivered = pass.delivered,
        uncertain = pass.uncertain,
        held = pass.held,
        not_delivered = pass.not_delivered,
        errors = pass.errors,
        "the Coach delivered issue signatures"
    );
    Ok(())
}
