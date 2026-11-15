//! What every vendor's sandbox client keeps the same way (L8-43): the
//! owner's key, read at the custody door bound to the vendor's effector and
//! wiped when the client drops; an HTTP client that follows no redirect and
//! no proxy, so a secret goes only to the base it was sent to; the step's
//! deadline and cancellation on every call; and error texts that never show
//! a secret.
//!
//! Each call runs on a thread of its own, and the step's thread only waits
//! for its answer ([`Answer`]), so the step's cancellation ends that wait
//! soon after it fires, even while a vendor holds its answer back. A call
//! given up on ends on its own thread at its request timeout, which is the
//! step's deadline.

use std::io::{self, Read, Write};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError, SyncSender};
use std::sync::{Mutex, Weak};
use std::time::{Duration, Instant};

use oneiron::Vault;
use oneiron::code_sandbox::SandboxVendor;
use oneiron::code_sandbox::microvm::backend_error;
use oneiron::engine_executor::{CANCEL_POLL_SLICE, StepCancellation};
use oneiron_agent_runtime::code_sandbox::microvm::VendorCallBound;
use reqwest::StatusCode;
use reqwest::blocking::{Client, RequestBuilder};
use serde::de::DeserializeOwned;
use zeroize::Zeroizing;

/// The longest wait for a connection to a vendor's API.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
/// A delete's own bound: it runs after the step's deadline or cancellation
/// too, so it never takes theirs.
pub(super) const DELETE_TIMEOUT: Duration = Duration::from_secs(60);
/// The most characters of a vendor's text an error quotes.
const ERROR_BODY_CHARS: usize = 300;
/// The most bytes of a vendor's error answer an error reads.
const ERROR_BODY_BYTES: usize = 4096;
/// The longest JSON answer a client reads.
const MAX_JSON_ANSWER_BYTES: usize = 1024 * 1024;
/// The bytes one read of an answer's body takes.
const ANSWER_CHUNK: usize = 64 * 1024;
/// The chunks of an answer its call's thread reads ahead of the step's.
const ANSWER_CHUNKS_AHEAD: usize = 4;

/// The calls of one vendor's client: each error names the vendor's backend.
#[derive(Clone, Copy, Debug)]
pub(super) struct VendorHttp(pub(super) SandboxVendor);

impl VendorHttp {
    pub(super) fn failed(self, detail: impl Into<String>) -> oneiron::Error {
        backend_error(self.0.backend_name(), detail)
    }

    /// The time left before `deadline`.
    pub(super) fn remaining(self, deadline: Instant) -> oneiron::Result<Duration> {
        deadline
            .checked_duration_since(Instant::now())
            .filter(|left| !left.is_zero())
            .ok_or_else(|| self.failed("the step's deadline passed"))
    }

    /// The step's pause before the next poll: at most `wait`, never past the
    /// deadline, and refused once the step is cancelled.
    pub(super) fn pause(self, wait: Duration, bound: VendorCallBound<'_>) -> oneiron::Result<()> {
        std::thread::sleep(wait.min(self.remaining(bound.deadline)?));
        bound.cancel.check()
    }

    /// A URL segment from an id an answer named: anything but a plain name
    /// could reshape the URL it goes into.
    pub(super) fn segment(self, id: &str) -> oneiron::Result<&str> {
        let plain = !id.is_empty()
            && id.len() <= 128
            && id
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_');
        if plain {
            Ok(id)
        } else {
            Err(self.failed(format!(
                "{} answered an id that is not a plain name",
                self.0.as_str()
            )))
        }
    }

    /// The vendor's name for its copy of a digest-pinned guest image (a
    /// Daytona snapshot, an E2B template), built once from the image:
    /// `oneiron-guest-<first 12 hex of its digest>`.
    pub(super) fn guest_image_name(self, guest_image: &str) -> oneiron::Result<String> {
        let digest = guest_image
            .rsplit_once("@sha256:")
            .map(|(_, digest)| digest)
            .filter(|digest| digest.len() == 64 && digest.bytes().all(|b| b.is_ascii_hexdigit()))
            .ok_or_else(|| self.failed("a vendor run needs a digest-pinned guest image"))?;
        Ok(format!("oneiron-guest-{}", &digest[..12]))
    }

    /// An HTTP client for one call: no redirect, no proxy, so a secret goes
    /// to the base it was sent to and nowhere else.
    pub(super) fn client(self) -> oneiron::Result<Client> {
        Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .no_proxy()
            .connect_timeout(CONNECT_TIMEOUT)
            .build()
            .map_err(|_| {
                self.failed(format!(
                    "the {} HTTP client could not be built",
                    self.0.as_str()
                ))
            })
    }

    /// A failed call, without its URL and without any of `secrets`.
    pub(super) fn http_failed(self, error: reqwest::Error, secrets: &[&str]) -> oneiron::Error {
        self.failed(format!(
            "{} call failed: {}",
            self.0.as_str(),
            scrubbed(&error.without_url().to_string(), secrets)
        ))
    }

    /// Sends `request` inside the step's bound, and keeps only an answer of
    /// success. Its errors show none of `secrets`.
    pub(super) fn send(
        self,
        request: RequestBuilder,
        secrets: &[&str],
        bound: VendorCallBound<'_>,
    ) -> oneiron::Result<Answer> {
        bound.cancel.check()?;
        let request = request.timeout(self.remaining(bound.deadline)?);
        self.exchange(request, secrets, bound.deadline, Some(bound.cancel.clone()))?
            .checked()
    }

    /// Sends a delete inside its own [`DELETE_TIMEOUT`], which neither the
    /// step's deadline nor its cancellation shortens, and keeps only an
    /// answer of success.
    pub(super) fn send_delete(
        self,
        request: RequestBuilder,
        secrets: &[&str],
    ) -> oneiron::Result<Answer> {
        let deadline = Instant::now() + DELETE_TIMEOUT;
        self.exchange(request.timeout(DELETE_TIMEOUT), secrets, deadline, None)?
            .checked()
    }

    /// Starts `request` on a thread of its own, and waits for its status
    /// until `deadline` or `cancel`.
    fn exchange(
        self,
        request: RequestBuilder,
        secrets: &[&str],
        deadline: Instant,
        cancel: Option<StepCancellation>,
    ) -> oneiron::Result<Answer> {
        let (to, from) = mpsc::sync_channel(ANSWER_CHUNKS_AHEAD);
        std::thread::Builder::new()
            .name(format!("{}-call", self.0.as_str()))
            .spawn(move || deliver(request, &to))
            .map_err(|_| self.failed(format!("a {} call could not start", self.0.as_str())))?;
        let mut answer = Answer {
            http: self,
            status: StatusCode::OK,
            from,
            deadline,
            cancel,
            secrets: secrets
                .iter()
                .map(|secret| Zeroizing::new((*secret).to_owned()))
                .collect(),
            ended: false,
            buffer: Vec::new(),
            buffered: 0,
        };
        answer.status = match answer.next()? {
            Delivery::Status(status) => status,
            Delivery::Refused(error) => return Err(self.http_failed(error, secrets)),
            Delivery::Chunk(_) | Delivery::End | Delivery::Broken(_) => {
                return Err(answer.out_of_order());
            }
        };
        Ok(answer)
    }
}

/// What the thread of one call hands the step's thread, in this order: the
/// answer's status, then its body's chunks, then its end. A call that fails
/// hands over its failure instead.
enum Delivery {
    Status(StatusCode),
    Chunk(Vec<u8>),
    End,
    /// The call got no answer.
    Refused(reqwest::Error),
    /// The answer's body broke off.
    Broken(io::Error),
}

/// Runs one call on its own thread and hands its answer over a chunk at a
/// time. It stops once the step's thread no longer waits for it.
fn deliver(request: RequestBuilder, to: &SyncSender<Delivery>) {
    let mut response = match request.send() {
        Ok(response) => response,
        Err(error) => {
            let _ = to.send(Delivery::Refused(error));
            return;
        }
    };
    if to.send(Delivery::Status(response.status())).is_err() {
        return;
    }
    let mut chunk = vec![0; ANSWER_CHUNK];
    loop {
        let delivery = match response.read(&mut chunk) {
            Ok(0) => Delivery::End,
            Ok(read) => Delivery::Chunk(chunk[..read].to_vec()),
            Err(error) => Delivery::Broken(error),
        };
        let more = matches!(delivery, Delivery::Chunk(_));
        if to.send(delivery).is_err() || !more {
            return;
        }
    }
}

/// A vendor's answer to one call, read by the call's own thread. Every wait
/// for its next bytes ends at the step's deadline or cancellation (a
/// delete's: at its own bound). Read it as JSON ([`Self::json`]), copy it
/// into a sink ([`Self::copy_to`]), or read it as a stream ([`Read`]).
pub(super) struct Answer {
    http: VendorHttp,
    status: StatusCode,
    from: Receiver<Delivery>,
    deadline: Instant,
    cancel: Option<StepCancellation>,
    /// What its error texts scrub.
    secrets: Vec<Zeroizing<String>>,
    ended: bool,
    /// The chunk a [`Read`] of it is in, and the bytes of it already read.
    buffer: Vec<u8>,
    buffered: usize,
}

impl Answer {
    /// The answer, when it is a success; else an error quoting the start of
    /// its body, without any secret.
    fn checked(mut self) -> oneiron::Result<Self> {
        if self.status.is_success() {
            return Ok(self);
        }
        let mut head = Vec::new();
        while head.len() < ERROR_BODY_BYTES {
            match self.chunk() {
                Ok(Some(bytes)) => head.extend_from_slice(&bytes),
                Ok(None) | Err(_) => break,
            }
        }
        head.truncate(ERROR_BODY_BYTES);
        Err(self.http.failed(format!(
            "{} answered {}: {}",
            self.http.0.as_str(),
            self.status.as_u16(),
            quoted(&String::from_utf8_lossy(&head), &self.secret_texts())
        )))
    }

    /// The body as JSON.
    pub(super) fn json<T: DeserializeOwned>(mut self) -> oneiron::Result<T> {
        let mut body = Vec::new();
        while let Some(bytes) = self.chunk()? {
            if body.len() + bytes.len() > MAX_JSON_ANSWER_BYTES {
                return Err(self.http.failed(format!(
                    "a {} answer is over {MAX_JSON_ANSWER_BYTES} bytes",
                    self.http.0.as_str()
                )));
            }
            body.extend_from_slice(&bytes);
        }
        serde_json::from_slice(&body).map_err(|_| {
            self.http.failed(format!(
                "{} answered JSON this client cannot read",
                self.http.0.as_str()
            ))
        })
    }

    /// Copies a download's body into `sink`, and stops at the first write
    /// `sink` refuses. Only a whole file (200) is a download: no call asks
    /// for a part of one.
    pub(super) fn copy_to(mut self, sink: &mut dyn Write) -> oneiron::Result<()> {
        if self.status != StatusCode::OK {
            return Err(self.http.failed(format!(
                "{} answered {} to a download, not 200",
                self.http.0.as_str(),
                self.status.as_u16()
            )));
        }
        while let Some(bytes) = self.chunk()? {
            sink.write_all(&bytes)?;
        }
        Ok(())
    }

    /// The body's next bytes, or none at its end.
    fn chunk(&mut self) -> oneiron::Result<Option<Vec<u8>>> {
        if self.ended {
            return Ok(None);
        }
        match self.next()? {
            Delivery::Chunk(bytes) => Ok(Some(bytes)),
            Delivery::End => {
                self.ended = true;
                Ok(None)
            }
            Delivery::Broken(error) => Err(self.http.failed(format!(
                "{} answer broke off: {}",
                self.http.0.as_str(),
                scrubbed(&error.to_string(), &self.secret_texts())
            ))),
            Delivery::Status(_) | Delivery::Refused(_) => Err(self.out_of_order()),
        }
    }

    /// The call's next delivery, waited for in slices, so the deadline or
    /// the cancellation ends the wait.
    fn next(&mut self) -> oneiron::Result<Delivery> {
        loop {
            if let Some(cancel) = &self.cancel {
                cancel.check()?;
            }
            let left = self.http.remaining(self.deadline)?;
            match self.from.recv_timeout(left.min(CANCEL_POLL_SLICE)) {
                Ok(delivery) => return Ok(delivery),
                Err(RecvTimeoutError::Timeout) => {}
                Err(RecvTimeoutError::Disconnected) => {
                    return Err(self.http.failed(format!(
                        "a {} call ended without its answer",
                        self.http.0.as_str()
                    )));
                }
            }
        }
    }

    fn out_of_order(&self) -> oneiron::Error {
        self.http
            .failed(format!("a {} call answered out of order", self.http.0.as_str()))
    }

    fn secret_texts(&self) -> Vec<&str> {
        self.secrets.iter().map(|secret| secret.as_str()).collect()
    }
}

/// The body as a stream. A wait the deadline or the cancellation ends is an
/// error of the stream, so a reader checks the step's cancellation before it
/// reports one.
impl Read for Answer {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        while self.buffered == self.buffer.len() {
            match self
                .chunk()
                .map_err(|error| io::Error::other(error.to_string()))?
            {
                Some(bytes) => {
                    self.buffer = bytes;
                    self.buffered = 0;
                }
                None => return Ok(0),
            }
        }
        let read = buf.len().min(self.buffer.len() - self.buffered);
        buf[..read].copy_from_slice(&self.buffer[self.buffered..self.buffered + read]);
        self.buffered += read;
        Ok(read)
    }
}

/// The start of a vendor's `text` an error quotes: without any of
/// `secrets`, without control characters, and at most [`ERROR_BODY_CHARS`]
/// characters long.
pub(super) fn quoted(text: &str, secrets: &[&str]) -> String {
    scrubbed(text, secrets)
        .chars()
        .filter(|c| !c.is_control())
        .take(ERROR_BODY_CHARS)
        .collect()
}

/// `text` with every copy of each of `secrets` replaced.
pub(super) fn scrubbed(text: &str, secrets: &[&str]) -> String {
    secrets
        .iter()
        .filter(|secret| !secret.is_empty())
        .fold(text.to_owned(), |text, secret| {
            text.replace(secret, "<key>")
        })
}

/// The owner's key for one vendor, named by the switch: read at the custody
/// door bound to the vendor's effector at the run's first call, and held in
/// memory that is wiped when the client drops.
pub(super) struct OwnerVendorKey {
    vault: Weak<Vault>,
    http: VendorHttp,
    name: String,
    held: Mutex<Option<Zeroizing<String>>>,
}

impl OwnerVendorKey {
    pub(super) fn new(vault: Weak<Vault>, vendor: SandboxVendor, name: String) -> Self {
        Self {
            vault,
            http: VendorHttp(vendor),
            name,
            held: Mutex::new(None),
        }
    }

    /// The key, from the custody door at the first call and from memory
    /// after it.
    pub(super) fn read(&self) -> oneiron::Result<Zeroizing<String>> {
        let vendor = self.http.0;
        let mut held = self
            .held
            .lock()
            .map_err(|_| self.http.failed("the vendor key state is poisoned"))?;
        if let Some(key) = held.as_ref() {
            return Ok(Zeroizing::new(key.as_str().to_owned()));
        }
        let vault = self
            .vault
            .upgrade()
            .ok_or_else(|| self.http.failed("the vault closed before its vendor run"))?;
        let mut bytes = Zeroizing::new(Vec::new());
        vault
            .inject_secret_at_door(&self.name, vendor.effector(), &mut |value: &[u8]| {
                // Sized once, so no reallocation leaves an unwiped copy.
                bytes.reserve_exact(value.len());
                bytes.extend_from_slice(value);
                Ok(())
            })
            .map_err(|error| {
                tracing::warn!(%error, secret = %self.name, vendor = vendor.as_str(), "vendor key not read at the custody door");
                self.http.failed(format!(
                    "the owner's {} key is not readable at the custody door: {error}",
                    vendor.as_str()
                ))
            })?;
        let key = std::str::from_utf8(&bytes)
            .map_err(|_| {
                self.http
                    .failed(format!("the owner's {} key is not text", vendor.as_str()))
            })?
            .trim();
        if key.is_empty() {
            return Err(self
                .http
                .failed(format!("the owner's {} key is empty", vendor.as_str())));
        }
        let key = Zeroizing::new(key.to_owned());
        *held = Some(Zeroizing::new(key.as_str().to_owned()));
        Ok(key)
    }
}

/// A body reader that stops at the step's cancellation, so an upload ends
/// soon after it.
pub(super) struct CancellableReader<R> {
    pub(super) inner: R,
    pub(super) cancel: StepCancellation,
}

impl<R: Read> Read for CancellableReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if self.cancel.is_cancelled() {
            return Err(io::Error::other("the step was cancelled"));
        }
        self.inner.read(buf)
    }
}
