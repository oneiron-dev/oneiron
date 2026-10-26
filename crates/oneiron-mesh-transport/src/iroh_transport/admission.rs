//! Fair dispatch of authenticated inbound admissions (FIX 8620), and the one
//! receipt each leaves however it ends (FIX 8621).
//!
//! A connection the live gate proved waits here for the transport's accept.
//! Waiting admissions queue per caller, keyed by the MACHINE the gate proved:
//! first in, first out for one caller, and round-robin across callers, so one
//! machine's burst never holds another's turn. Each carries its arrival and
//! its deadline ([`ADMISSION_DEADLINE`]); no count refuses one. An accept
//! hands the next caller in turn its grant, one grant at a time; the
//! admission then rechecks its grant, sends the acknowledgement its dialer
//! waits for, and only then is admitted. With nothing else waiting, an
//! admission is granted as soon as an accept asks.
//!
//! Every exit after the gate's proof leaves one path receipt through the
//! admission's guard: admitted once its acknowledgement is sent, or failed
//! with its stage (the deadline, the queue's close, the acknowledgement's
//! open, write or finish, or the admission's own end). A grant revoked
//! before dispatch leaves the gate's refusal receipt instead. TLS, pre-gate
//! and policy failures keep the receipts the gate already leaves.

use std::collections::VecDeque;

use tokio::sync::{Notify, oneshot};

use super::*;

/// How long an authenticated admission may take, from the gate's proof to
/// its acknowledgement sent, before it fails and its connection closes
/// (CALLS ADMISSION_DEADLINE).
const ADMISSION_DEADLINE: Duration = Duration::from_secs(30);

/// An admitted connection for the next accept: its MACHINE, its ALPN and the
/// connection.
pub(super) type Admitted = (MachineId, Vec<u8>, Connection);

/// The authenticated admissions waiting for an accept, shared by the gates
/// and the transport.
#[derive(Debug, Default)]
pub(super) struct Admissions {
    queue: StdMutex<Queue>,
    changed: Notify,
}

#[derive(Debug, Default)]
struct Queue {
    /// Each caller's waiting admissions, oldest first.
    waiting: BTreeMap<MachineId, VecDeque<Waiting>>,
    /// The callers with an admission waiting, in turn order.
    turns: VecDeque<MachineId>,
    /// The admission whose grant is under way: its acknowledgement has not
    /// ended yet.
    granting: Option<u64>,
    /// Admitted connections for the next accepts, oldest first.
    ready: VecDeque<Admitted>,
    /// The id the next waiting admission takes.
    next_id: u64,
    /// The transport takes no more admissions.
    closed: bool,
}

/// One waiting admission.
#[derive(Debug)]
struct Waiting {
    id: u64,
    /// When it fails if no grant reached it.
    deadline: Instant,
    /// Its grant, sent when its turn comes.
    grant: oneshot::Sender<()>,
}

/// Where a waiting admission stood when it was withdrawn.
#[derive(Debug, PartialEq, Eq)]
enum Withdrawal {
    /// It waited, and is off the queue now.
    Withdrawn,
    /// Its grant was sent: it holds the grant under way.
    Granted,
    /// It was gone: passed over at its deadline, or dropped as the queue
    /// closed.
    Gone,
}

impl Admissions {
    fn queue(&self) -> std::sync::MutexGuard<'_, Queue> {
        self.queue.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Queues an admission of `machine`'s that fails at `deadline`: its id
    /// and the receiver of its grant, or `None` once the queue is closed.
    fn enqueue(
        &self,
        machine: MachineId,
        deadline: Instant,
    ) -> Option<(u64, oneshot::Receiver<()>)> {
        let (grant, granted) = oneshot::channel();
        let id = {
            let mut queue = self.queue();
            if queue.closed {
                return None;
            }
            let id = queue.next_id;
            queue.next_id += 1;
            let waiting = queue.waiting.entry(machine).or_default();
            let first = waiting.is_empty();
            waiting.push_back(Waiting {
                id,
                deadline,
                grant,
            });
            if first {
                queue.turns.push_back(machine);
            }
            id
        };
        self.changed.notify_waiters();
        Some((id, granted))
    }

    /// Takes `machine`'s waiting admission `id` off the queue, and says where
    /// it stood.
    fn withdraw(&self, machine: MachineId, id: u64) -> Withdrawal {
        let mut queue = self.queue();
        if queue.granting == Some(id) {
            return Withdrawal::Granted;
        }
        let Some(waiting) = queue.waiting.get_mut(&machine) else {
            return Withdrawal::Gone;
        };
        let Some(at) = waiting.iter().position(|entry| entry.id == id) else {
            return Withdrawal::Gone;
        };
        waiting.remove(at);
        if waiting.is_empty() {
            queue.waiting.remove(&machine);
            queue.turns.retain(|caller| *caller != machine);
        }
        Withdrawal::Withdrawn
    }

    /// Ends grant `id`: `admitted`, when it was admitted, joins the
    /// connections the next accepts take, and the next turn may be granted.
    fn grant_ended(&self, id: u64, admitted: Option<Admitted>) {
        {
            let mut queue = self.queue();
            if queue.granting == Some(id) {
                queue.granting = None;
            }
            queue.ready.extend(admitted);
        }
        self.changed.notify_waiters();
    }

    /// Takes no more admissions: each waiting one fails as the queue closes,
    /// and accepts end once the admitted ones are taken.
    pub(super) fn close(&self) {
        {
            let mut queue = self.queue();
            queue.closed = true;
            queue.waiting.clear();
            queue.turns.clear();
        }
        self.changed.notify_waiters();
    }

    /// The next admitted connection, granting the next caller in turn while
    /// none is ready. Cancel-safe: a grant it handed out lands with the next
    /// call. `Unavailable` once the queue is closed and nothing admitted
    /// waits.
    pub(super) async fn next(&self) -> Result<Admitted, MeshError> {
        loop {
            let changed = self.changed.notified();
            tokio::pin!(changed);
            changed.as_mut().enable();
            {
                let mut queue = self.queue();
                if let Some(admitted) = queue.ready.pop_front() {
                    return Ok(admitted);
                }
                if queue.granting.is_none() {
                    if queue.closed {
                        return Err(MeshError::Unavailable);
                    }
                    queue.grant_next();
                }
            }
            changed.await;
        }
    }
}

impl Queue {
    /// Sends the next caller in turn the grant of its oldest admission:
    /// round-robin across callers, first in first out for each. One past its
    /// deadline, or whose admission already ended, is passed over.
    fn grant_next(&mut self) {
        let now = Instant::now();
        while let Some(machine) = self.turns.pop_front() {
            let Some(waiting) = self.waiting.get_mut(&machine) else {
                continue;
            };
            let entry = waiting.pop_front();
            if waiting.is_empty() {
                self.waiting.remove(&machine);
            } else {
                self.turns.push_back(machine);
            }
            if let Some(entry) = entry
                && entry.deadline > now
                && entry.grant.send(()).is_ok()
            {
                self.granting = Some(entry.id);
                return;
            }
        }
    }
}

/// Closes the queue when dropped: the accept loop holds it, so the queue
/// closes when that loop ends or the transport stops it.
#[derive(Debug)]
pub(super) struct Closing(pub(super) Arc<Admissions>);

impl Drop for Closing {
    fn drop(&mut self) {
        self.0.close();
    }
}

/// Why an authenticated admission ended unadmitted: the stage its receipt
/// names (FIX 8621).
#[derive(Debug)]
enum AdmissionExit {
    /// The transport took no more admissions before its turn.
    QueueClosed,
    /// Its deadline passed first.
    DeadlineExpired,
    /// The acknowledgement stream did not open.
    AcknowledgementOpen(String),
    /// The acknowledgement was not written.
    AcknowledgementWrite(String),
    /// The acknowledgement stream did not finish.
    AcknowledgementFinish(String),
    /// Its task ended first: cancelled, or the transport stopped.
    Cancelled,
}

impl AdmissionExit {
    /// The stage and, where one failed, its error, as the receipt says them.
    fn detail(&self) -> String {
        match self {
            Self::QueueClosed => "queue closed".to_owned(),
            Self::DeadlineExpired => "deadline expired".to_owned(),
            Self::AcknowledgementOpen(error) => format!("acknowledgement open: {error}"),
            Self::AcknowledgementWrite(error) => format!("acknowledgement write: {error}"),
            Self::AcknowledgementFinish(error) => format!("acknowledgement finish: {error}"),
            Self::Cancelled => "cancelled".to_owned(),
        }
    }
}

/// Where an admission stands in its guard.
#[derive(Debug, Clone, Copy)]
enum Stage {
    /// Proved, and not on the queue.
    Proved,
    /// Waiting for its turn as admission `id`.
    Waiting(u64),
    /// Granted as admission `id`: its acknowledgement is under way.
    Granted(u64),
    /// Its receipt is left.
    Ended,
}

/// One authenticated admission, from the gate's proof to its end: the guard
/// that leaves its receipt on every exit (FIX 8621).
struct Admission<'a> {
    gate: &'a GateHandler,
    connection: Connection,
    machine: MachineId,
    key: [u8; 32],
    /// When it began to wait.
    arrived: Instant,
    /// When it fails if it is not admitted by then.
    deadline: Instant,
    stage: Stage,
}

impl GateHandler {
    /// Admits `connection`, which the gate proved, once an accept grants its
    /// turn: its grant is rechecked as it arrives and again just before its
    /// acknowledgement. Every exit leaves its receipt.
    pub(super) async fn admit(&self, connection: Connection) {
        // Recheck: revocation can race the completed handshake before dispatch.
        let key = *connection.remote_id().as_bytes();
        let machine = match self.policy.inbound(key, &self.alpn) {
            Ok(machine) => machine,
            Err(error) => return self.refused(&connection, key, &error),
        };
        let arrived = Instant::now();
        let admission = Admission {
            gate: self,
            connection,
            machine,
            key,
            arrived,
            deadline: arrived + ADMISSION_DEADLINE,
            stage: Stage::Proved,
        };
        admission.run().await;
    }
}

impl Admission<'_> {
    async fn run(mut self) {
        let admissions = Arc::clone(&self.gate.admissions);
        let Some((id, mut turn)) = admissions.enqueue(self.machine, self.deadline) else {
            return self.exit(AdmissionExit::QueueClosed);
        };
        self.stage = Stage::Waiting(id);
        let deadline = tokio::time::Instant::from_std(self.deadline);
        let granted = tokio::select! {
            granted = &mut turn => granted.is_ok(),
            () = tokio::time::sleep_until(deadline) => {
                admissions.withdraw(self.machine, id) == Withdrawal::Granted
            }
        };
        if !granted {
            // Off the queue: passed over, withdrawn, or dropped as it closed.
            self.stage = Stage::Proved;
            let exit = if Instant::now() >= self.deadline {
                AdmissionExit::DeadlineExpired
            } else {
                AdmissionExit::QueueClosed
            };
            return self.exit(exit);
        }
        self.stage = Stage::Granted(id);
        // The grant once more, just before dispatch: a refusal leaves the
        // gate's own receipt.
        let machine = match self.gate.policy.inbound(self.key, &self.gate.alpn) {
            Ok(machine) => machine,
            Err(error) => {
                self.gate.refused(&self.connection, self.key, &error);
                return self.release(None);
            }
        };
        let acknowledged = tokio::time::timeout_at(deadline, acknowledge(&self.connection)).await;
        match acknowledged {
            Ok(Ok(())) => self.admitted(machine),
            Ok(Err(exit)) => self.exit(exit),
            Err(_) => self.exit(AdmissionExit::DeadlineExpired),
        }
    }

    /// Leaves the admitted receipt, sent its acknowledgement, and hands the
    /// connection to the next accept.
    fn admitted(mut self, machine: MachineId) {
        if let Some(receipts) = &self.gate.receipts {
            let receipt = admission(
                MeshPathDirection::Inbound,
                &self.gate.alpn,
                machine,
                self.key,
            );
            receipts.admitted(receipt, &self.connection);
        }
        let admitted = (machine, self.gate.alpn.clone(), self.connection.clone());
        self.release(Some(admitted));
    }

    /// Ends unadmitted for `exit`: its receipt, and its connection closed.
    fn exit(mut self, exit: AdmissionExit) {
        self.end(&exit);
    }

    fn end(&mut self, exit: &AdmissionExit) {
        self.release(None);
        if let Some(receipts) = &self.gate.receipts {
            let mut receipt = MeshPathReceipt::new(
                MeshPathDirection::Inbound,
                MeshPathOutcome::Failed,
                &self.gate.alpn,
            );
            receipt.endpoint_key = Some(key_hex(self.key));
            receipt.detail = Some(format!(
                "admission {} after {} ms",
                exit.detail(),
                self.arrived.elapsed().as_millis()
            ));
            receipts.refused(receipt, Some(self.machine), Some(&self.connection));
        }
        self.connection.close(0u32.into(), b"admission ended");
    }

    /// Gives up its place: off the queue while it waits, or the grant it
    /// holds, with `admitted` for the next accept.
    fn release(&mut self, admitted: Option<Admitted>) {
        let admissions = &self.gate.admissions;
        match std::mem::replace(&mut self.stage, Stage::Ended) {
            Stage::Waiting(id) => {
                if admissions.withdraw(self.machine, id) == Withdrawal::Granted {
                    admissions.grant_ended(id, None);
                }
            }
            Stage::Granted(id) => admissions.grant_ended(id, admitted),
            Stage::Proved | Stage::Ended => {}
        }
    }
}

impl Drop for Admission<'_> {
    /// An admission whose task ended first: cancelled, or the transport
    /// stopped. Its receipt is left while a runtime can write it.
    fn drop(&mut self) {
        if matches!(self.stage, Stage::Ended) {
            return;
        }
        if tokio::runtime::Handle::try_current().is_ok() {
            self.end(&AdmissionExit::Cancelled);
        } else {
            self.release(None);
        }
    }
}

/// Sends `connection` the acknowledgement its dialer waits for: each stage
/// that fails is its own exit.
async fn acknowledge(connection: &Connection) -> Result<(), AdmissionExit> {
    let mut acknowledgement = connection
        .open_uni()
        .await
        .map_err(|error| AdmissionExit::AcknowledgementOpen(error.to_string()))?;
    acknowledgement
        .write_all(dial::ADMISSION)
        .await
        .map_err(|error| AdmissionExit::AcknowledgementWrite(error.to_string()))?;
    acknowledgement
        .finish()
        .map_err(|error| AdmissionExit::AcknowledgementFinish(error.to_string()))
}
