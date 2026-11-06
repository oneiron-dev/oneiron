//! Request-owned private Human asks and their live socket recipients.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex, Weak};

use oneiron::llm::decision::{
    AskConsent, AskRole, AskRoleResolver, HolderKind, HumanDecisionQueue, HumanDecisionRequest,
    ResolvedRole,
};
use oneiron::{EntityId, Error, Result as VaultResult};
use tokio::sync::mpsc::{UnboundedReceiver, UnboundedSender, unbounded_channel};

use crate::auth::{CoreAuth, CoreScope};
use crate::server::SyncServer;

#[derive(Default)]
pub(crate) struct Recipients {
    sockets: Mutex<BTreeMap<u32, Socket>>,
}

#[derive(Clone)]
struct Socket {
    auth: CoreAuth,
    sender: UnboundedSender<PendingAsk>,
}

/// Only the live socket owns its registration. The registry retains no ask.
pub(crate) struct Registration {
    recipients: Arc<Recipients>,
    conn: u32,
    sender: UnboundedSender<PendingAsk>,
}

impl Recipients {
    pub(crate) fn register(
        self: &Arc<Self>,
        conn: u32,
    ) -> (Registration, UnboundedReceiver<PendingAsk>) {
        let (sender, receiver) = unbounded_channel();
        (
            Registration {
                recipients: Arc::clone(self),
                conn,
                sender,
            },
            receiver,
        )
    }
}

impl Registration {
    /// Called by the socket owner after binding and before its next event.
    pub(crate) fn bind(&self, auth: Option<&CoreAuth>) {
        let mut sockets = self
            .recipients
            .sockets
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        match auth {
            Some(auth) => {
                sockets.insert(
                    self.conn,
                    Socket {
                        auth: auth.clone(),
                        sender: self.sender.clone(),
                    },
                );
            }
            None => {
                sockets.remove(&self.conn);
            }
        }
    }
}

impl Drop for Registration {
    fn drop(&mut self) {
        let mut sockets = self
            .recipients
            .sockets
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if sockets
            .get(&self.conn)
            .is_some_and(|socket| socket.sender.same_channel(&self.sender))
        {
            sockets.remove(&self.conn);
        }
    }
}

/// Each accepted recipient queue owns the ask until its send or disconnect.
/// Closing the producing HTTP call cannot drop its sole pending payload.
pub(crate) struct PendingAsk {
    ask: Arc<PrivateAsk>,
    producer: CoreAuth,
    recipient: CoreAuth,
}

struct PrivateAsk {
    request: HumanDecisionRequest,
    state: Option<serde_json::Value>,
    consent: Option<AskConsent>,
}

impl PrivateAsk {
    fn refs(&self) -> Vec<EntityId> {
        self.request
            .evidence
            .iter()
            .copied()
            .chain(self.request.correlation)
            .collect()
    }

    fn recipient(&self, server: &SyncServer, auth: &CoreAuth) -> Option<ResolvedRole> {
        if auth.require(CoreScope::Read).is_err() || !auth.credential_is_live(server.vault()) {
            return None;
        }
        let role = server.vault().next_role(&self.request.to, None).ok()??;
        let holds =
            if role.role == AskRole::Owner && super::owner_routes::owner(auth, server).is_ok() {
                true
            } else {
                let actor = EntityId::from_hex(auth.principal_ref()?).ok()?;
                let kind = match auth.actor_class()? {
                    "human" => HolderKind::Person,
                    "agent" => HolderKind::Agent,
                    _ => return None,
                };
                role.holders
                    .iter()
                    .any(|holder| holder.actor == actor && holder.kind == kind)
            };
        if !holds {
            return None;
        }
        let admitted =
            super::scoped_auth::lane_reads_each(server.vault(), auth, vec![()], |_| self.refs())
                .ok()?;
        (!admitted.is_empty()).then_some(role)
    }

    fn encode(&self, tag: u8) -> Option<Vec<u8>> {
        let request = &self.request;
        let payload = serde_json::json!({
            "kind": "private.human.ask",
            "no_record": true,
            "question": request.question,
            "principal": request.principal.to_hex(),
            "evidence": request.evidence.iter().map(|id| id.to_hex()).collect::<Vec<_>>(),
            "reason": request.reason,
            "prior": request.prior,
            "prior_provider": request.prior_provider,
            "queue_pin": request.queue_pin,
            "to": request.to,
            "correlation": request.correlation.map(|id| id.to_hex()),
            "state": self.state,
            "consent": self.consent,
        });
        let mut frame = vec![tag];
        serde_json::to_writer(&mut frame, &payload).ok()?;
        Some(frame)
    }
}

impl PendingAsk {
    /// The socket's actual current credential, not the publisher's snapshot,
    /// resolves the role and source lane again before this body is encoded.
    pub(crate) fn release(
        &self,
        server: &SyncServer,
        auth: &CoreAuth,
        locality: oneiron::claim::CallerLocality,
        peer: oneiron::authority::PeerMachine,
        tag: u8,
    ) -> Option<Vec<u8>> {
        if !auth.same_authority(&self.recipient)
            || !self.producer.credential_is_live(server.vault())
        {
            return None;
        }
        self.ask.recipient(server, auth)?;
        let frame = self.ask.encode(tag)?;
        self.permits(server, auth, locality, peer, &frame)
            .then_some(frame)
    }

    pub(crate) fn permits(
        &self,
        server: &SyncServer,
        auth: &CoreAuth,
        locality: oneiron::claim::CallerLocality,
        peer: oneiron::authority::PeerMachine,
        frame: &[u8],
    ) -> bool {
        auth.same_authority(&self.recipient)
            && self.producer.credential_is_live(server.vault())
            && self.ask.recipient(server, auth).is_some()
            && (locality == oneiron::claim::CallerLocality::OnDevice
                || !crate::device_local::replay_withheld(
                    server.vault(),
                    oneiron::settings::ReadDestination::at(locality, peer),
                    &frame[1..],
                    &self.ask.refs(),
                ))
    }
}

/// One producing request's queue. It keeps no durable ask or answer waiter.
pub(crate) struct RequestHumanQueue {
    server: Weak<SyncServer>,
    producer: CoreAuth,
    recipients: Arc<Recipients>,
}

impl RequestHumanQueue {
    pub(crate) fn new(
        server: &Arc<SyncServer>,
        producer: &CoreAuth,
        recipients: Arc<Recipients>,
    ) -> Self {
        Self {
            server: Arc::downgrade(server),
            producer: producer.clone(),
            recipients,
        }
    }

    fn publish(
        &self,
        request: HumanDecisionRequest,
        state: Option<&serde_json::Value>,
        consent: Option<&AskConsent>,
    ) -> VaultResult<()> {
        let unavailable = || Error::InvalidConfig("private Human recipient unavailable".into());
        let server = self.server.upgrade().ok_or_else(unavailable)?;
        if self.producer.require(CoreScope::Read).is_err()
            || !self.producer.credential_is_live(server.vault())
        {
            return Err(unavailable());
        }
        let ask = Arc::new(PrivateAsk {
            request,
            state: state.cloned(),
            consent: consent.cloned(),
        });
        let sockets: Vec<Socket> = self
            .recipients
            .sockets
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .values()
            .cloned()
            .collect();
        let mut queued = false;
        for socket in sockets {
            if ask.recipient(&server, &socket.auth).is_some() {
                queued |= socket
                    .sender
                    .send(PendingAsk {
                        ask: Arc::clone(&ask),
                        producer: self.producer.clone(),
                        recipient: socket.auth,
                    })
                    .is_ok();
            }
        }
        if queued { Ok(()) } else { Err(unavailable()) }
    }
}

impl HumanDecisionQueue for RequestHumanQueue {
    fn queue(&self, request: HumanDecisionRequest) -> VaultResult<()> {
        self.publish(request, None, None)
    }

    fn queue_with_state(
        &self,
        request: HumanDecisionRequest,
        state: &serde_json::Value,
    ) -> VaultResult<Option<u64>> {
        self.publish(request, Some(state), None).map(|()| None)
    }

    fn queue_with_consent(
        &self,
        request: HumanDecisionRequest,
        state: Option<&serde_json::Value>,
        consent: &AskConsent,
    ) -> VaultResult<Option<u64>> {
        self.publish(request, state, Some(consent)).map(|()| None)
    }
}
