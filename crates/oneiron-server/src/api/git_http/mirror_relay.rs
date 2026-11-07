//! An exact publish's mirror git through the credential broker on a served
//! host (ARCH-0069 OSH-3, ARCH-0068 RC4, FIX 19083).
//!
//! Serve installs this transport on its vault where it attaches the broker
//! ([`install_origin_git_transport`]). It holds the vault and the broker
//! weakly, since the broker's custody door holds the vault, and for each
//! authenticated read of the mirror's branch and for the one push it starts
//! a mirror relay of that call alone:
//!
//! - **Relay.** Stock Git lists or pushes, with no credential, to a loopback
//!   listener on an OS-assigned port under a fresh random path, which serves
//!   the advertisement and the RPC of one service of the one destination
//!   repository: `git-upload-pack` for the read, `git-receive-pack` for the
//!   push. Its URL rides Git's argv, which other local users can read, so it
//!   is no capability: each request must carry the relay's random ticket in
//!   a header Git's environment holds, and anything else is not found.
//! - **Exchange.** Each request is judged again (for the push, the mirror
//!   still the destination the request recorded, as the dispatch judged it
//!   before its claim), its body spooled to a private unnamed file on the
//!   vault's disk, each write first asking for room above the disk reserve
//!   (`limits.disk_reserve_bytes`), decoded from any gzip, and its digest
//!   taken. The broker gets the exchange and its body and acknowledges both;
//!   only then is the mirror's credential released at the custody door
//!   (`origin:mirror-push`), the same basic-auth value the direct path
//!   builds, copied once and handed to the broker, which installs it and
//!   sends. The reply streams back to Git exactly as the mirror sent it; a
//!   reply the broker cut ends Git's read broken, never clean.
//! - **Outcome.** Git's own porcelain still decides: applied, rejected or
//!   unknown. An unknown push's detail names the first refusal any exchange
//!   met and whether the push's RPC reached the broker: `not sent` before,
//!   `unproven` after. Once Git returns the relay stops, and no exchange
//!   hands the broker the credential after, so a `not sent` holds. The
//!   publish settles an unknown push by an authenticated reread and never
//!   sends it again. The broker's isolation goes on the request.
//!
//! No pack size or call time is bounded here: each step waits at most the
//! host's transfer idle limit without progress, a write at the disk reserve
//! is refused, and Git's exit ends the relay. No host allowlist applies: a
//! relay serves the one repository its request names.

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, OnceLock, Weak};
use std::time::Duration;

use axum::Router;
use axum::body::Body;
use axum::extract::{RawQuery, State};
use axum::http::StatusCode;
use axum::http::header::CONTENT_TYPE;
use axum::http::request::Parts;
use axum::response::Response;
use axum::routing::{get, post};
use oneiron::git_wire::{GitPublishPushOutcome, GitRefName, GitRemoteTip, GitWire, GitWireRepo};
use oneiron::llm::BrokerIsolation;
use oneiron::origin::git_transport::{
    OriginGitPublishPush, OriginGitPushReport, OriginGitTransport,
};
use oneiron::origin::publish::OriginPublishDestination;
use oneiron::{EntityId, Vault};
use oneiron_broker::{
    GitCallHeader, GitExchange, GitReply, GitRepository, GitTarget, Isolation, MAX_SECRET,
};
use tokio::io::AsyncRead;
use tokio::sync::oneshot;
use zeroize::Zeroizing;

use super::broker_relay::{
    RelayNotes, answer, broker_code, digest_body, serve_loopback, spool_request,
};
use super::gate::{advertised_service, header_value, text_response};
use super::import_source_relay::{carries_relay_ticket, mint_relay_ticket};
use super::routes::GitService;
use crate::machine::DiskFloor;
use crate::models::{BrokerContext, WeakBrokerContext};

/// The served name every mirror relay path carries; it serves one repo.
const MIRROR_REPO_SEGMENT: &str = "mirror.git";

/// The prefix of every refusal code a mirror relay notes.
const MIRROR_CODE_PREFIX: &str = "mirror";

/// Installs on `vault` the transport its exact publishes send their mirror
/// git through: `broker`, each step waiting at most the transfer idle limit
/// `idle`, each spool write keeping the vault disk's floor `disk`. Both the
/// vault and the broker are held weakly.
pub(crate) fn install_origin_git_transport(
    vault: &Arc<Vault>,
    broker: &BrokerContext,
    idle: Duration,
    disk: DiskFloor,
) {
    vault.install_origin_git_transport(Arc::new(BrokeredOriginGitTransport {
        vault: Arc::downgrade(vault),
        broker: broker.downgrade(),
        idle,
        disk,
    }));
}

/// The served host's transport for an exact publish's mirror git.
struct BrokeredOriginGitTransport {
    vault: Weak<Vault>,
    broker: WeakBrokerContext,
    /// The host's transfer idle limit.
    idle: Duration,
    /// The vault disk's floor, which each spool write keeps.
    disk: DiskFloor,
}

impl BrokeredOriginGitTransport {
    /// Starts one call's mirror relay, serving `service` of `destination`'s
    /// repository; a push names its repository's id in `push_of`, so the
    /// destination is judged again before each exchange. A relay that cannot
    /// start answers its refusal code: nothing was sent.
    fn relay(
        &self,
        service: oneiron_broker::GitService,
        destination: &OriginPublishDestination,
        push_of: Option<EntityId>,
    ) -> Result<MirrorRelay, String> {
        let (Some(vault), Some(broker)) = (self.vault.upgrade(), self.broker.upgrade()) else {
            return Err(format!("{MIRROR_CODE_PREFIX}_broker_unavailable"));
        };
        let repository = GitRepository::parse(&destination.url)
            .map_err(|_| format!("{MIRROR_CODE_PREFIX}_url_malformed"))?;
        let mut id = [0_u8; 16];
        rand_core::RngCore::fill_bytes(&mut rand_core::OsRng, &mut id);
        let leg = Arc::new(MirrorLeg {
            vault,
            broker,
            destination: destination.clone(),
            push_of,
            service,
            idle: self.idle,
            disk: self.disk.clone(),
            id: id.iter().map(|byte| format!("{byte:02x}")).collect(),
            sequence: AtomicU64::new(0),
            notes: Arc::new(RelayNotes::new(MIRROR_CODE_PREFIX)),
            isolation: OnceLock::new(),
            rpc_opened: AtomicBool::new(false),
            stopped: AtomicBool::new(false),
        });
        MirrorRelay::start(leg, repository).map_err(|error| {
            tracing::warn!(%error, "an exact publish's mirror relay did not start");
            format!("{MIRROR_CODE_PREFIX}_relay_unavailable")
        })
    }
}

impl OriginGitTransport for BrokeredOriginGitTransport {
    fn read_remote_branch(
        &self,
        wire: &GitWire<'_>,
        repo: &GitWireRepo,
        destination: &OriginPublishDestination,
        name: &GitRefName,
    ) -> oneiron::Result<GitRemoteTip> {
        let relay = self
            .relay(oneiron_broker::GitService::UploadPack, destination, None)
            .map_err(read_refused)?;
        let read = wire.read_remote_branch_via_relay(repo, &relay.url, &relay.ticket, name);
        let end = relay.stop();
        match (read, end.noted) {
            (Err(_), Some(code)) => Err(read_refused(code)),
            (read, _) => read,
        }
    }

    fn push_publish(
        &self,
        wire: &GitWire<'_>,
        repo: &GitWireRepo,
        push: &OriginGitPublishPush<'_>,
    ) -> OriginGitPushReport {
        let service = oneiron_broker::GitService::ReceivePack;
        let relay = match self.relay(service, push.destination, Some(push.repo_id)) {
            Ok(relay) => relay,
            Err(code) => {
                return OriginGitPushReport {
                    outcome: Ok(GitPublishPushOutcome::Unknown(format!("{code}, not sent"))),
                    broker_isolation: None,
                };
            }
        };
        let pushed = wire.push_publish_via_relay(
            repo,
            &relay.url,
            &relay.ticket,
            push.name,
            push.commit,
            push.expected,
            push.hold,
        );
        let end = relay.stop();
        OriginGitPushReport {
            outcome: Ok(pushed_outcome(pushed, &end)),
            broker_isolation: end.isolation,
        }
    }
}

/// A read's failure through the relay, naming its refusal code.
fn read_refused(code: String) -> oneiron::Error {
    oneiron::Error::Refused(format!(
        "{code}: the mirror's branch was not read through the credential broker"
    ))
}

/// The push's outcome as its child reported it. An unknown one names the
/// first refusal its exchanges met and whether its RPC reached the broker:
/// `not sent` before, `unproven` after. Applied and rejected stand as Git
/// reported them.
fn pushed_outcome(
    pushed: oneiron::Result<GitPublishPushOutcome>,
    end: &RelayEnd,
) -> GitPublishPushOutcome {
    let stage = if end.rpc_opened {
        "unproven"
    } else {
        "not sent"
    };
    let named = |detail: String| match &end.noted {
        Some(code) => format!("{code}, {stage}; {detail}"),
        None => format!("{stage}; {detail}"),
    };
    match pushed {
        Ok(GitPublishPushOutcome::Unknown(detail)) => GitPublishPushOutcome::Unknown(named(detail)),
        Err(error) => GitPublishPushOutcome::Unknown(named(error.to_string())),
        Ok(reported) => reported,
    }
}

/// The receipt spelling of the broker's isolation.
const fn broker_isolation(isolation: Isolation) -> BrokerIsolation {
    match isolation {
        Isolation::SeparateUser => BrokerIsolation::SeparateUser,
        Isolation::SameUser => BrokerIsolation::SameUser,
    }
}

/// One call's broker leg: what each exchange is judged and sent under, the
/// first refusal any exchange met, and what reached the broker.
struct MirrorLeg {
    vault: Arc<Vault>,
    broker: BrokerContext,
    /// The destination the request recorded.
    destination: OriginPublishDestination,
    /// A push's repository id, whose mirror is judged again before each
    /// exchange; `None` for a read, which the custody door alone judges, as
    /// the direct read is.
    push_of: Option<EntityId>,
    service: oneiron_broker::GitService,
    /// The host's transfer idle limit.
    idle: Duration,
    /// The vault disk's floor, which each spool write keeps.
    disk: DiskFloor,
    /// This call's random id, which each exchange's call id carries.
    id: String,
    sequence: AtomicU64,
    notes: Arc<RelayNotes>,
    /// The broker's isolation, once an exchange handed it the credential.
    isolation: OnceLock<Isolation>,
    /// Whether an RPC exchange handed the broker its credential: from then
    /// on its request may have left.
    rpc_opened: AtomicBool,
    /// Whether the call's Git child returned and the relay stopped: no
    /// exchange hands the broker its credential after.
    stopped: AtomicBool,
}

impl MirrorLeg {
    /// A push's mirror, still the destination its request recorded, judged
    /// again now. A read is judged by the custody door alone.
    fn admitted(&self) -> Result<(), String> {
        let Some(repo_id) = self.push_of else {
            return Ok(());
        };
        self.vault
            .check_origin_publish_destination(repo_id, &self.destination)
            .map_err(|error| match error {
                oneiron::Error::Refused(reason) => reason
                    .split(':')
                    .next()
                    .unwrap_or("destination_changed")
                    .to_owned(),
                _ => "destination_unreadable".to_owned(),
            })
    }

    /// The mirror's basic-auth value, released at the custody door for the
    /// recorded destination and copied once into a buffer wiped on drop.
    fn credential(&self) -> Result<Zeroizing<Vec<u8>>, String> {
        let mut secret = Zeroizing::new(Vec::new());
        let mut oversized = false;
        self.vault
            .with_publish_credential(&self.destination, &mut |header: &str| {
                if header.len() > MAX_SECRET {
                    oversized = true;
                    return;
                }
                // Sized once, so no reallocation leaves a copy behind.
                secret.reserve_exact(header.len());
                secret.extend_from_slice(header.as_bytes());
            })
            .map_err(|error| match error {
                oneiron::Error::Refused(reason) => reason
                    .split(':')
                    .next()
                    .unwrap_or("credential_refused")
                    .to_owned(),
                _ => format!("{MIRROR_CODE_PREFIX}_credential_refused_at_door"),
            })?;
        if oversized || secret.is_empty() {
            return Err(format!("{MIRROR_CODE_PREFIX}_credential_not_a_header"));
        }
        Ok(secret)
    }

    /// Sends one exchange of this leg's service with `repository` through
    /// the broker: judged again, its body (`body`, spooled and rewound)
    /// digested, the broker reached and its acknowledgement taken, then the
    /// credential released and handed over. Answers the reply, its body
    /// still to come, or the refusal's code.
    async fn send(
        &self,
        repository: &GitRepository,
        exchange: GitExchange,
        git_protocol: Option<String>,
        body: Option<std::fs::File>,
    ) -> Result<GitReply, String> {
        self.admitted()?;
        let target = GitTarget {
            repository: repository.clone(),
            service: self.service,
            exchange,
        };
        let headers: Vec<(String, String)> = git_protocol
            .map(|value| ("git-protocol".to_owned(), value))
            .into_iter()
            .collect();
        let (digest, len, body) =
            digest_body(&target, &headers, body).map_err(|fault| fault.code(MIRROR_CODE_PREFIX))?;
        let call = format!(
            "origin-mirror/{}/{}",
            self.id,
            self.sequence.fetch_add(1, Ordering::Relaxed)
        );
        let header = GitCallHeader::new(call, target, headers, len, digest, self.idle);
        let (connection, isolation) =
            self.broker
                .git_connection(self.idle)
                .await
                .map_err(|error| {
                    tracing::warn!(%error, "no credential broker for an exact publish's mirror");
                    format!("{MIRROR_CODE_PREFIX}_broker_unavailable")
                })?;
        let mut body: Box<dyn AsyncRead + Unpin + Send> = match body {
            Some(file) => Box::new(tokio::fs::File::from_std(file)),
            None => Box::new(tokio::io::empty()),
        };
        let prepared = connection
            .prepare_git(&header, &mut body)
            .await
            .map_err(|error| broker_code(MIRROR_CODE_PREFIX, error))?;
        let secret = self.credential()?;
        // From here the request may leave. The open is marked before the
        // stop is read, and the stop is marked before the open is read
        // (`MirrorRelay::stop`): a stop that saw no open RPC is never
        // followed by one, so its `not sent` holds.
        if exchange == GitExchange::Rpc {
            self.rpc_opened.store(true, Ordering::SeqCst);
        }
        if self.stopped.load(Ordering::SeqCst) {
            return Err(format!("{MIRROR_CODE_PREFIX}_relay_stopped"));
        }
        let _ = self.isolation.set(isolation);
        let reply = prepared
            .open(secret)
            .await
            .map_err(|error| broker_code(MIRROR_CODE_PREFIX, error))?;
        tracing::info!(
            service = self.service.as_str(),
            exchange = ?exchange,
            digest = %header.digest,
            isolation = isolation.as_str(),
            "an exact publish's mirror exchange went through the credential broker"
        );
        Ok(reply)
    }
}

/// What one mirror relay serves: its leg, the one destination repository,
/// and the ticket each request must carry.
struct MirrorRelayState {
    leg: Arc<MirrorLeg>,
    repository: GitRepository,
    ticket: Zeroizing<String>,
}

impl MirrorRelayState {
    /// Sends Git's request through the broker and answers with the reply.
    async fn forward(
        &self,
        exchange: GitExchange,
        parts: &Parts,
        body: Option<std::fs::File>,
    ) -> Response {
        let git_protocol = header_value(&parts.headers, "git-protocol");
        match self
            .leg
            .send(&self.repository, exchange, git_protocol, body)
            .await
        {
            Ok(reply) => answer(reply, &self.leg.notes),
            Err(code) => self.leg.notes.refuse(StatusCode::BAD_GATEWAY, &code),
        }
    }
}

/// `GET <relay>/info/refs?service=<service>`: the advertisement, of the
/// relay's one service only.
async fn mirror_info_refs(
    State(relay): State<Arc<MirrorRelayState>>,
    RawQuery(query): RawQuery,
    parts: Parts,
) -> Response {
    // Before anything else, and never noted: a request without the ticket
    // is not this call's Git child.
    if !carries_relay_ticket(&parts, &relay.ticket) {
        return text_response(StatusCode::NOT_FOUND, "not found");
    }
    let asked = match advertised_service(&query.unwrap_or_default()) {
        Ok(GitService::UploadPack) => oneiron_broker::GitService::UploadPack,
        Ok(GitService::ReceivePack) => oneiron_broker::GitService::ReceivePack,
        Err(refusal) => return refusal.response(),
    };
    if asked != relay.leg.service {
        return relay
            .leg
            .notes
            .refuse(StatusCode::FORBIDDEN, "mirror_relay_serves_another_service");
    }
    relay
        .forward(GitExchange::Advertisement, &parts, None)
        .await
}

/// `POST <relay>/<service>`: the RPC, its body spooled above the disk
/// reserve, its reply streamed.
async fn mirror_rpc(
    State(relay): State<Arc<MirrorRelayState>>,
    parts: Parts,
    body: Body,
) -> Response {
    if !carries_relay_ticket(&parts, &relay.ticket) {
        return text_response(StatusCode::NOT_FOUND, "not found");
    }
    let expected = GitTarget {
        repository: relay.repository.clone(),
        service: relay.leg.service,
        exchange: GitExchange::Rpc,
    }
    .request_content_type();
    if header_value(&parts.headers, CONTENT_TYPE.as_str()) != expected {
        return relay.leg.notes.refuse(
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            "mirror_request_content_type_mismatch",
        );
    }
    let spool = match spool_request(&parts, body, relay.leg.idle, Some(&relay.leg.disk)).await {
        Ok(spool) => spool,
        Err(fault) => {
            return relay
                .leg
                .notes
                .refuse(fault.status(), &fault.code(MIRROR_CODE_PREFIX));
        }
    };
    relay.forward(GitExchange::Rpc, &parts, Some(spool)).await
}

/// What one call's relay exchanges met, once it stopped.
struct RelayEnd {
    /// The first refusal code any exchange met.
    noted: Option<String>,
    /// The isolation of the broker an exchange handed the credential to.
    isolation: Option<BrokerIsolation>,
    /// Whether an RPC exchange handed the broker its credential.
    rpc_opened: bool,
}

/// One call's loopback mirror relay.
struct MirrorRelay {
    url: String,
    /// The ticket Git presents in the relay ticket header.
    ticket: Zeroizing<String>,
    stop: Option<oneshot::Sender<()>>,
    leg: Arc<MirrorLeg>,
}

impl MirrorRelay {
    /// Serves `repository`'s advertisement and RPC of `leg`'s service through
    /// `leg` on an OS-assigned loopback port under a fresh random path, to
    /// requests carrying a fresh random ticket drawn apart from it.
    fn start(leg: Arc<MirrorLeg>, repository: GitRepository) -> oneiron::Result<Self> {
        let path = mint_relay_ticket();
        let ticket = mint_relay_ticket();
        let state = Arc::new(MirrorRelayState {
            leg: Arc::clone(&leg),
            repository,
            ticket: ticket.clone(),
        });
        let base = format!("/{}/{MIRROR_REPO_SEGMENT}", path.as_str());
        let app = Router::new()
            .route(&format!("{base}/info/refs"), get(mirror_info_refs))
            .route(
                &format!("{base}/{}", leg.service.as_str()),
                post(mirror_rpc),
            )
            .with_state(state);
        let (port, stop) =
            serve_loopback(leg.broker.runtime(), app, "an exact publish's mirror relay")?;
        Ok(Self {
            url: format!("http://127.0.0.1:{port}{base}"),
            ticket,
            stop: Some(stop),
            leg,
        })
    }

    /// Stops the relay and answers what its exchanges met. No exchange
    /// hands the broker its credential after.
    fn stop(mut self) -> RelayEnd {
        self.leg.stopped.store(true, Ordering::SeqCst);
        if let Some(stop) = self.stop.take() {
            let _ = stop.send(());
        }
        RelayEnd {
            noted: self.leg.notes.first(),
            isolation: self.leg.isolation.get().copied().map(broker_isolation),
            rpc_opened: self.leg.rpc_opened.load(Ordering::SeqCst),
        }
    }
}

impl Drop for MirrorRelay {
    fn drop(&mut self) {
        self.leg.stopped.store(true, Ordering::SeqCst);
        if let Some(stop) = self.stop.take() {
            let _ = stop.send(());
        }
    }
}
