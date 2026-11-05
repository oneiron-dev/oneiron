//! Native source half of an order-scoped legal clone. The HOST owns independent
//! key custody, persistence, legal access audit and destruction. No clone is a
//! Vault, and no ordinary owner/member/agent surface routes to this channel.

mod auth;
mod collector;
mod live;
mod messages;
mod outbox;

pub use auth::{HostLegalChannel, HostLegalConnection};
pub(crate) use live::HostLegalCaptures;

use std::io::{self, Write};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use oneiron_crypto::HybridPublicKey;
use oneiron_crypto::legal_clone::SourceComponent;
use oneiron_vault_contract::host_legal::{
    CaptureExtent, CaptureRequest, CaptureScope, CaptureSource, HostLegalRequest, SourceHello,
};

use crate::error::Result;
use crate::store::GateCloneComponent;
use crate::{EntityId, Vault};

use collector::Collector;

impl HostLegalConnection {
    /// Run on the managed blocking executor. At its stop trigger teardown
    /// cancels the private live registry and shuts every accepted stream but
    /// a prospective order's; after every writer stopped it runs the final
    /// prospective drain, then shuts the rest and joins ALL workers before
    /// Vault close. A successful stream ACK covers only its declared source
    /// extent.
    pub fn run(mut self, vault: &Vault, cancelled: &AtomicBool) -> Result<()> {
        self.stream.set_nonblocking(false)?;
        SourceHello {
            source_vault: *vault.vault_id().as_bytes(),
        }
        .write_to(&mut self.stream)?;
        self.stream.flush()?;
        let request = match HostLegalRequest::read_from(&mut self.stream)? {
            HostLegalRequest::ReleaseLiveOrder(release) => {
                return self.release_live(vault, release);
            }
            HostLegalRequest::Capture(request) => request,
        };
        EntityId::from_bytes(request.order)?;
        EntityId::from_bytes(request.capture)?;
        if request.source_vault != *vault.vault_id().as_bytes() {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "legal capture source identity",
            )
            .into());
        }
        let public = HybridPublicKey::from_bytes(&request.recipient)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "legal capture recipient"))?;
        check(vault, &request, cancelled)?;
        // The actual order term, not an invented service timeout. Managed
        // teardown separately interrupts accepted sockets and queued waiters.
        let remaining = request
            .ends_at
            .saturating_sub(vault.store.clock.now_recorded_at());
        if remaining == 0 {
            check(vault, &request, cancelled)?;
        }
        let deadline = Some(Duration::from_secs(remaining));
        self.stream.set_read_timeout(deadline)?;
        self.stream.set_write_timeout(deadline)?;
        if matches!(&request.scope, CaptureScope::LiveSession(_)) {
            return self.run_live(vault, request, public);
        }
        if matches!(&request.scope, CaptureScope::ProspectiveMessages(_)) {
            // Teardown's stop trigger leaves this stream open; the final
            // drain, a release or the order's term ends it.
            self.prospective.store(true, Ordering::Release);
            return self.run_prospective(vault, request, public);
        }
        if let CaptureScope::Messages(ids) = &request.scope {
            return messages::capture(&mut self.stream, vault, &request, &public, ids, || {
                check(vault, &request, cancelled)
            });
        }
        let check = || check(vault, &request, cancelled);
        // Gate custody BEFORE its source writer. Neither guard is reused for
        // LIVE: K lends its final overlay/spill source at the close boundary.
        let _custody = vault.store.gate_custody_read_guard()?;
        let txn = vault.store.env.write_txn()?;
        check()?;
        let mut collector = Collector::pinned(&mut self.stream, &public, &request)?;
        let mut stored_revision = [0; 32];
        let decisions = vault.store.for_each_gate_clone_component_in_txn(
            &txn,
            matches!(&request.scope, CaptureScope::GateDecisions(_)),
            |decision| request.scope.includes(&decision.as_bytes()),
            check,
            |decision, component, key, value| {
                check()?;
                let fingerprint = *blake3::hash(value).as_bytes();
                let revision = match component {
                    GateCloneComponent::StoredPrimary => {
                        stored_revision = fingerprint;
                        fingerprint
                    }
                    GateCloneComponent::OpenedPrimary => stored_revision,
                    _ => fingerprint,
                };
                collector.component(
                    source_component(component),
                    CaptureSource::GateDecision(decision.as_bytes()),
                    component.label(),
                    key,
                    revision,
                    value.len() as u64,
                    fingerprint,
                    &mut &value[..],
                    check,
                )
            },
        )?;
        check()?;
        if let CaptureScope::GateDecisions(ids) = &request.scope
            && decisions as u128 != ids.len() as u128
        {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                "legal capture selected decision unavailable",
            )
            .into());
        }
        collector.finish(decisions, 0, 0, 0, CaptureExtent::GateDecisions, check)?;
        // Read-only abort, after the exact durable HOST acknowledgement.
        drop(txn);
        Ok(())
    }
}

fn check(vault: &Vault, request: &CaptureRequest, cancelled: &AtomicBool) -> Result<()> {
    if cancelled.load(Ordering::Acquire) {
        return Err(io::Error::new(io::ErrorKind::Interrupted, "legal capture stopped").into());
    }
    if vault.store.clock.now_recorded_at() >= request.ends_at {
        return Err(io::Error::new(io::ErrorKind::TimedOut, "legal order term ended").into());
    }
    Ok(())
}

fn source_component(component: GateCloneComponent) -> SourceComponent {
    match component {
        GateCloneComponent::StoredPrimary => SourceComponent::StoredLedger,
        GateCloneComponent::OpenedPrimary => SourceComponent::OpenedMessagePack,
        GateCloneComponent::RetentionScope => SourceComponent::RetentionContext,
        GateCloneComponent::ClaimRefs => SourceComponent::BundleRefs,
        GateCloneComponent::PendingScrub => SourceComponent::PendingScrub,
    }
}
