//! A run's receipt screenshots kept for the caller its guest call came from
//! (FIX 2150). Each receipt's masked pixels become a blob artifact version,
//! made by the run, and written on the caller's own surface, built as the
//! guest call's is. A caller that may not write keeps none, and its receipts
//! say so: nothing writes with more authority than the call had.
use std::sync::Arc;

use oneiron::EntityId;
use oneiron::claim::CallerLocality;
use oneiron::memory::{HostWriteOrigin, Memory};
use oneiron::runtime_hooks::InvocationId;
use oneiron_browser::{EffectReceipt, ReceiptEvidence, ReceiptEvidenceSink};

use super::VerdictAsker;
use crate::server::SyncServer;

/// One guest call's keeper of its receipt screenshots.
pub(super) struct ReceiptWriter {
    server: Arc<SyncServer>,
    caller: VerdictAsker,
    origin: HostWriteOrigin,
    invocation: Option<InvocationId>,
    run_id: EntityId,
}

impl ReceiptWriter {
    pub(super) fn new(
        server: &Arc<SyncServer>,
        caller: VerdictAsker,
        origin: &HostWriteOrigin,
        invocation: Option<InvocationId>,
        run_id: EntityId,
    ) -> Self {
        Self {
            server: Arc::clone(server),
            caller,
            origin: origin.clone(),
            invocation,
            run_id,
        }
    }

    /// The caller's surface, as its guest call's: the connector's credential,
    /// or the run's own agent on this device under the run's origin (as
    /// `run_host_door::agent_memory` builds it).
    fn memory(&self) -> Memory<'_> {
        let memory = match &self.caller {
            VerdictAsker::Connector(actor) => crate::api::mcp_credential_memory(
                &self.server.vault,
                actor.auth.as_ref(),
                actor.actor_ref,
                actor.actor_class,
            ),
            VerdictAsker::Agent(actor) => self
                .server
                .vault
                .memory(actor.entity_ref(), actor.actor_class())
                .at(CallerLocality::OnDevice)
                .with_host_origin(self.origin.clone()),
        };
        match self.invocation {
            Some(invocation) => memory.with_invocation(invocation),
            None => memory,
        }
    }
}

impl ReceiptEvidenceSink for ReceiptWriter {
    fn keep(&mut self, receipt: &EffectReceipt, png: &[u8]) -> ReceiptEvidence {
        let kept = crate::decision_verdict::keep_screenshot(
            &self.memory(),
            &self.run_id.to_hex(),
            format!("effect receipt {} {}", receipt.seq, receipt.verb),
            "image/png".to_owned(),
            png,
        );
        match kept {
            Ok(version) => ReceiptEvidence::Kept {
                artifact_ref: version.artifact_ref,
                version: version.version,
                content_hash: version.content_hash_hex,
            },
            Err(error) => {
                tracing::warn!(%error, seq = receipt.seq, "an effect receipt's screenshot stays on its session");
                ReceiptEvidence::NotKept { code: error.code }
            }
        }
    }
}
