//! A live stream's reader while its round waits for an answer (FIX 9286).
//!
//! A worker idle on its answers alone reads nothing, so a remote stream
//! that ends meanwhile went unseen and a kept owner ask stood until an
//! answer or teardown. The pump reads the stream on its own thread, one
//! event per credit, and posts what it reads to the worker's mailbox
//! beside the answers, which a forwarder posts there from the registry's
//! channel. A quiet stream is not an ended one: a read that times out
//! reads on while the worker waits. What the stream says while the round
//! waits is handled as the read after an answer handles it: a request this
//! client does not serve is refused, the call's issuer binding read again
//! before the kept header goes out (FIX 9303), and the next question or the
//! call's reply is kept for the read after the answer, the pump holding on
//! meanwhile. A stream that ends or fails while the round waits ends the
//! exchange: nothing is left to send an answer to. Each event comes with the
//! stream's last event id as it was read, which a round's resume state keeps
//! (FIX 9157).

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::RecvTimeoutError;

use zeroize::Zeroizing;

use super::live_exchange::{AnswerReceipts, Next};
use super::reply_read::{EventStream, terminal};
use super::*;

/// What a pumped worker's mailbox carries.
enum Mail {
    Answer(AnswerCommand),
    /// The answers' channel closed: no one is left to answer.
    Closed,
    Stream(Said),
}

/// One event the stream said, and its last event id once that event was
/// read (FIX 9157): what a reattachment after a restart reads on from.
struct Said {
    event: Result<StreamEvent, ()>,
    last_event_id: Option<Zeroizing<String>>,
}

/// What a pumped worker's wait for its round's answer came to.
pub(super) enum Waited {
    Answer(AnswerCommand),
    /// No one is left to answer.
    Closed,
    /// The stream ended, or failed, while the round waited.
    Ended,
}

/// A live stream's reader, on its own thread, and the worker's mailbox.
pub(super) struct Pump {
    mail: mpsc::Receiver<Mail>,
    /// One credit, one event read: what the pump reads ahead stays one.
    credit: mpsc::Sender<()>,
    /// Whether a credit is out that the pump has not answered yet.
    outstanding: bool,
    /// Whether the worker still waits on the stream; the pump reads through
    /// a quiet stream only while it does.
    waiting: Arc<AtomicBool>,
    /// An event read while the round waited, kept for the read after its
    /// answer.
    early: Option<Said>,
    /// The answers' channel closed while a round was read.
    closed: bool,
}

impl Drop for Pump {
    fn drop(&mut self) {
        self.waiting.store(false, Ordering::Release);
    }
}

impl Pump {
    /// Starts reading `stream` beside the answers `commands` carries; `None`
    /// when a thread could not start.
    pub(super) fn start(
        stream: EventStream,
        commands: mpsc::Receiver<AnswerCommand>,
    ) -> Option<Self> {
        let (post, mail) = mpsc::channel();
        let (credit, credits) = mpsc::channel();
        let waiting = Arc::new(AtomicBool::new(true));
        let (reader_post, reader_waiting) = (post.clone(), Arc::clone(&waiting));
        std::thread::Builder::new()
            .name("connector-stream".to_owned())
            .spawn(move || read_stream(stream, &reader_post, &credits, &reader_waiting))
            .ok()?;
        std::thread::Builder::new()
            .name("connector-answers".to_owned())
            .spawn(move || forward_answers(&commands, &post))
            .ok()?;
        Some(Self {
            mail,
            credit,
            outstanding: false,
            waiting,
            early: None,
            closed: false,
        })
    }

    /// Lets the pump read one more event, unless one is out already.
    fn grant(&mut self) {
        if !self.outstanding {
            self.outstanding = self.credit.send(()).is_ok();
        }
    }

    /// Waits for the round's answer while the stream is read on.
    pub(super) fn wait_answer(
        &mut self,
        session: &LiveSession,
        receipts: &AnswerReceipts,
    ) -> Waited {
        if self.closed {
            return Waited::Closed;
        }
        loop {
            if self.early.is_none() {
                self.grant();
            }
            match self.mail.recv() {
                Ok(Mail::Answer(command)) => return Waited::Answer(command),
                Ok(Mail::Closed) | Err(_) => return Waited::Closed,
                Ok(Mail::Stream(Said {
                    event,
                    last_event_id,
                })) => {
                    self.outstanding = false;
                    match event {
                        Ok(StreamEvent::Request(request))
                            if stream_question(&request).is_none() =>
                        {
                            session.refuse_unheld(&request, receipts);
                        }
                        event @ Ok(StreamEvent::Request(_) | StreamEvent::Answer(..)) => {
                            self.early = Some(Said {
                                event,
                                last_event_id,
                            });
                        }
                        Ok(StreamEvent::End) | Err(()) => return Waited::Ended,
                    }
                }
            }
        }
    }

    /// Reads the stream on after an answer, within `timeout` of it: the
    /// call's reply ends it, another form `elicitation/create` opens the
    /// next round under its own request id and the stream's last event id
    /// as that request was read (FIX 9157), and any other server request is
    /// refused once the call's issuer binding is read again (FIX 9303).
    pub(super) fn read_round(
        &mut self,
        session: &LiveSession,
        receipts: &AnswerReceipts,
        request_id: &mut KeptWire,
        last_event_id: &mut Option<Zeroizing<String>>,
        timeout: Duration,
    ) -> Next {
        let deadline = Instant::now() + timeout;
        loop {
            let said = match self.early.take() {
                Some(said) => said,
                None => {
                    self.grant();
                    self.next_event(deadline)
                }
            };
            match said.event {
                Ok(StreamEvent::Answer(message, _)) => return Next::Over(terminal(&message)),
                Ok(StreamEvent::Request(request)) => match stream_question(&request) {
                    Some(question) => {
                        *request_id = KeptWire::keep(request.get("id").unwrap_or(&Value::Null));
                        *last_event_id = said.last_event_id;
                        return Next::Asked(vec![question]);
                    }
                    None => session.refuse_unheld(&request, receipts),
                },
                Ok(StreamEvent::End) | Err(()) => {
                    return Next::Over(WorkerEvent::Failed {
                        sent: true,
                        reason: "connector_reply_unreadable",
                    });
                }
            }
        }
    }

    /// The stream's next event, read by `deadline`; past it, unreadable. No
    /// answer is taken while a round is read: one that comes finds its
    /// round gone.
    fn next_event(&mut self, deadline: Instant) -> Said {
        loop {
            let left = deadline.saturating_duration_since(Instant::now());
            match self.mail.recv_timeout(left) {
                Ok(Mail::Stream(said)) => {
                    self.outstanding = false;
                    return said;
                }
                Ok(Mail::Answer(command)) => {
                    let _ = command.reply.send(WorkerEvent::Failed {
                        sent: false,
                        reason: "connector_question_gone",
                    });
                }
                Ok(Mail::Closed) => self.closed = true,
                Err(RecvTimeoutError::Timeout | RecvTimeoutError::Disconnected) => {
                    return Said {
                        event: Err(()),
                        last_event_id: None,
                    };
                }
            }
        }
    }
}

/// The pump's thread: one event per credit, until the stream ends or the
/// worker is gone.
fn read_stream(
    mut stream: EventStream,
    post: &mpsc::Sender<Mail>,
    credits: &mpsc::Receiver<()>,
    waiting: &AtomicBool,
) {
    stream.read_on();
    while credits.recv().is_ok() {
        let event = stream.next_while(CALL_ID, waiting);
        let more = matches!(event, Ok(StreamEvent::Answer(..) | StreamEvent::Request(_)));
        let last_event_id = stream
            .last_event_id()
            .map(|id| Zeroizing::new(id.to_owned()));
        let said = Said {
            event,
            last_event_id,
        };
        if post.send(Mail::Stream(said)).is_err() || !more {
            return;
        }
    }
}

/// The forwarder's thread: each answer from the registry's channel into
/// the worker's mailbox, then its close.
fn forward_answers(commands: &mpsc::Receiver<AnswerCommand>, post: &mpsc::Sender<Mail>) {
    while let Ok(command) = commands.recv() {
        if post.send(Mail::Answer(command)).is_err() {
            return;
        }
    }
    let _ = post.send(Mail::Closed);
}
