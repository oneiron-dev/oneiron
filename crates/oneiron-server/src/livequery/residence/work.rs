//! Socket-owned drivers for durable sealed-bundle work. Only a live caller
//! starts a phase; socket and host stop join the phase already admitted.

use oneiron::authority::PeerMachine;
use oneiron::sync::residence::{
    SealedBundleWorkOutcome, SealedBundleWorkStatus, sealed_bundle_work_memory_bytes,
    sealed_bundle_work_memory_room, step_sealed_bundle_work_in_turn,
};
use serde_json::json;
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};
use tokio::sync::{Notify, mpsc::UnboundedSender};
use tokio::task::JoinSet;

use super::super::{RpcCall, RpcReply, RpcRequest};
use super::bundle_commit::{Operation, operation, start, status_value};
use crate::auth::{CoreAuth, CoreScope};
use crate::byte_line::HeldBytes;
use crate::protocol::ProtocolError;
use crate::server::SyncServer;

#[derive(Clone)]
pub(crate) struct ResidenceWorkAttachment {
    closed: Arc<AtomicBool>,
    changed: Arc<Notify>,
}

impl ResidenceWorkAttachment {
    fn live(&self, server: &SyncServer, auth: &CoreAuth) -> bool {
        !self.closed.load(Ordering::Acquire)
            && !server.residence_work_stopping()
            && auth.credential_is_live(server.vault())
            && auth.require(CoreScope::Read).is_ok()
            && auth.require(CoreScope::Write).is_ok()
    }

    async fn stopped(&self) {
        loop {
            let changed = self.changed.notified();
            tokio::pin!(changed);
            changed.as_mut().enable();
            if self.closed.load(Ordering::Acquire) {
                return;
            }
            changed.await;
        }
    }
}

/// This connection's transient attachments, not a second durable ledger.
pub(crate) struct ResidenceWorkState {
    attachment: ResidenceWorkAttachment,
    running: JoinSet<Result<(), ProtocolError>>,
}

impl Default for ResidenceWorkState {
    fn default() -> Self {
        Self {
            attachment: ResidenceWorkAttachment {
                closed: Arc::new(AtomicBool::new(false)),
                changed: Arc::new(Notify::new()),
            },
            running: JoinSet::new(),
        }
    }
}

impl ResidenceWorkState {
    pub(crate) fn attachment(&self) -> ResidenceWorkAttachment {
        self.attachment.clone()
    }
    pub(crate) fn is_empty(&self) -> bool {
        self.running.is_empty()
    }
    pub(crate) fn spawn(
        &mut self,
        call: ResidenceWorkCall,
        server: Arc<SyncServer>,
        direct: UnboundedSender<Vec<u8>>,
    ) {
        self.running.spawn(call.answer(server, direct));
    }
    pub(crate) async fn join_next(
        &mut self,
    ) -> Option<Result<Result<(), ProtocolError>, tokio::task::JoinError>> {
        self.running.join_next().await
    }
    pub(crate) fn detach(&self) {
        self.attachment.closed.store(true, Ordering::Release);
        self.attachment.changed.notify_waiters();
    }
    pub(crate) async fn drain(&mut self) {
        self.detach();
        while self.running.join_next().await.is_some() {}
    }
}

/// A parsed, fixed-size operation. The original unbounded JSON tree is not
/// kept behind a pending work attachment.
pub(crate) struct ResidenceWorkCall {
    auth: CoreAuth,
    peer: PeerMachine,
    operation: Result<Operation, super::AppError>,
    call: RpcCall,
    request_id: u64,
    conn: u32,
    attachment: ResidenceWorkAttachment,
    _held: HeldBytes,
}

impl ResidenceWorkCall {
    pub(crate) fn new(
        server: &SyncServer,
        auth: CoreAuth,
        peer: PeerMachine,
        request: RpcRequest,
        conn: u32,
        attachment: ResidenceWorkAttachment,
    ) -> Self {
        let call = RpcCall::of(&request);
        let operation = operation(&request.method, request.params);
        let mut held = server.retained.empty();
        // The operation's strings have already become fixed-size ids; the
        // saved call holds its method, digest and credential metadata only.
        let bytes = std::mem::size_of::<Self>()
            .saturating_add(auth.principal().len())
            .saturating_add(auth.principal_ref().map_or(0, str::len))
            .saturating_add(auth.jti().map_or(0, str::len));
        server
            .retained
            .charge(&mut held, bytes, &server.transfers.questions);
        Self {
            auth,
            peer,
            operation,
            call,
            request_id: request.request_id,
            conn,
            attachment,
            _held: held,
        }
    }

    pub(crate) async fn answer(
        self,
        server: Arc<SyncServer>,
        direct: UnboundedSender<Vec<u8>>,
    ) -> Result<(), ProtocolError> {
        let Self {
            auth,
            peer,
            operation,
            call,
            request_id,
            conn,
            attachment,
            _held,
        } = self;
        let result = match operation {
            Err(error) => Err(error),
            Ok(operation) => {
                let worker = Arc::clone(&server);
                let caller = auth.clone();
                let attached = attachment.clone();
                tokio::task::spawn_blocking(move || {
                    if !attached.live(&worker, &caller) {
                        return Err(super::AppError::unauthorized());
                    }
                    worker.transfers.sealed_stage_change(worker.vault(), || {
                        start(&worker, &caller, peer, operation)
                    })
                })
                .await
                .unwrap_or_else(|_| {
                    Err(super::AppError::internal_server_error(
                        "bundle work phase ended",
                    ))
                })
            }
        };
        let mut status = match result {
            Ok(mut status) => {
                // Fitting ready work can still finish in its original reply;
                // larger work acknowledges durable acceptance immediately.
                if let Some(current) = status.as_mut()
                    && current.total <= oneiron::sync::residence::SEALED_BUNDLE_WORK_PART_BYTES
                {
                    while matches!(current.outcome, SealedBundleWorkOutcome::Pending) {
                        let Some(next) = advance(&server, &auth, peer, current, &attachment).await
                        else {
                            break;
                        };
                        if next.phase == current.phase && next.prepared == current.prepared {
                            break;
                        }
                        *current = next;
                    }
                }
                let reply = RpcReply::answer(
                    &server,
                    &auth,
                    call,
                    request_id,
                    Ok((
                        json!({"work": status.as_ref().map(status_value)}),
                        Some(Vec::new()),
                    )),
                )?;
                for frame in reply.queued(conn) {
                    direct
                        .send(frame)
                        .map_err(|_| ProtocolError::InvalidPayload("reply channel closed"))?;
                }
                status
            }
            Err(error) => {
                let reply = RpcReply::answer(&server, &auth, call, request_id, Err(error))?;
                for frame in reply.queued(conn) {
                    direct
                        .send(frame)
                        .map_err(|_| ProtocolError::InvalidPayload("reply channel closed"))?;
                }
                return Ok(());
            }
        };
        while let Some(current) = status.as_mut() {
            if !matches!(current.outcome, SealedBundleWorkOutcome::Pending) {
                break;
            }
            // Register before the slice. Another work's terminal cleanup may
            // release this generation's reservation while the slice runs.
            let changed = server.residence_work_changed.notified();
            tokio::pin!(changed);
            changed.as_mut().enable();
            let Some(next) = advance(&server, &auth, peer, current, &attachment).await else {
                break;
            };
            let progressed = next.phase != current.phase || next.prepared != current.prepared;
            *current = next;
            if progressed {
                server.residence_work_changed.notify_waiters();
            } else {
                tokio::select! { () = attachment.stopped() => break, () = changed => {} }
            }
        }
        Ok(())
    }
}

async fn advance(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    peer: PeerMachine,
    status: &SealedBundleWorkStatus,
    attachment: &ResidenceWorkAttachment,
) -> Option<SealedBundleWorkStatus> {
    if !attachment.live(server, auth) {
        return None;
    }
    let PeerMachine::Proven { machine, .. } = peer else {
        return None;
    };
    let id = status.work_id;
    let held = server.retained.empty();
    let turn = tokio::select! {
        () = attachment.stopped() => return None,
        turn = server.admit_task_work(machine) => turn,
    };
    if !attachment.live(server, auth) {
        return None;
    }
    let worker = Arc::clone(server);
    let caller = auth.clone();
    let attached = attachment.clone();
    // Join this handle even after detach. Its memory and disk holds live on
    // the worker, and are not released merely because the socket closed.
    let result = tokio::task::spawn_blocking(move || {
        let mut held = held;
        let until = std::time::Instant::now() + worker.transfers.wait;
        let stopped =
            || attached.closed.load(Ordering::Acquire) || worker.residence_work_stopping();
        let scan_bytes = sealed_bundle_work_memory_bytes(0);
        worker.retained.charge(
            &mut held,
            usize::try_from(scan_bytes).unwrap_or(usize::MAX),
            &worker.transfers.questions,
        );
        let scan_memory = worker
            .memory
            .lease_until(scan_bytes, until, &stopped)
            .ok()?;
        let bytes = sealed_bundle_work_memory_room(worker.vault(), peer, id).ok()?;
        drop(scan_memory);
        worker.retained.charge(
            &mut held,
            usize::try_from(bytes).unwrap_or(usize::MAX),
            &worker.transfers.questions,
        );
        let _memory = worker.memory.lease_until(bytes, until, &stopped).ok()?;
        let _held = held;
        if !attached.live(&worker, &caller) {
            return None;
        }
        let _disk = worker.transfers.hold_sealed_work(worker.vault(), id)?;
        let admitted = |txn: Option<&heed::RwTxn<'_>>| {
            !attached.closed.load(Ordering::Acquire)
                && !worker.residence_work_stopping()
                && match txn {
                    Some(txn) => caller.credential_is_live_in_write_txn(worker.vault(), txn),
                    None => caller.credential_is_live(worker.vault()),
                }
        };
        let status =
            step_sealed_bundle_work_in_turn(worker.vault(), peer, id, &turn, &admitted).ok()?;
        worker.transfers.reconcile_sealed_stages(worker.vault());
        Some(status)
    })
    .await
    .ok()
    .flatten();
    result
}
