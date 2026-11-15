//! What every vendor's sandbox client keeps the same way (L8-43): the
//! owner's key, read at the custody door bound to the vendor's effector and
//! wiped when the client drops; an HTTP client that follows no redirect and
//! no proxy, so a secret goes only to the base it was sent to; the step's
//! deadline and cancellation on every call; and error texts that never show
//! a secret.

use std::io::{self, Read, Write};
use std::sync::{Mutex, Weak};
use std::time::{Duration, Instant};

use oneiron::Vault;
use oneiron::code_sandbox::SandboxVendor;
use oneiron::code_sandbox::microvm::backend_error;
use oneiron::engine_executor::StepCancellation;
use oneiron_agent_runtime::code_sandbox::microvm::VendorCallBound;
use reqwest::blocking::{Client, Response};
use zeroize::Zeroizing;

/// The longest wait for a connection to a vendor's API.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
/// A delete's own bound: it runs after the step's deadline or cancellation
/// too, so it never takes theirs.
pub(super) const DELETE_TIMEOUT: Duration = Duration::from_secs(60);
/// The most characters of a vendor's text an error quotes.
const ERROR_BODY_CHARS: usize = 300;
/// The bytes one read of a download takes.
const DOWNLOAD_CHUNK: usize = 64 * 1024;

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

    /// The answer, when it is a success; else an error quoting the start of
    /// its body, without any of `secrets`.
    pub(super) fn checked(self, response: Response, secrets: &[&str]) -> oneiron::Result<Response> {
        let status = response.status();
        if status.is_success() {
            return Ok(response);
        }
        let mut body = Vec::new();
        let _ = response.take(4096).read_to_end(&mut body);
        Err(self.failed(format!(
            "{} answered {}: {}",
            self.0.as_str(),
            status.as_u16(),
            quoted(&String::from_utf8_lossy(&body), secrets)
        )))
    }

    /// Copies a download's body into `sink`, and stops at the first write
    /// `sink` refuses or at the step's cancellation.
    pub(super) fn copy_body(
        self,
        mut response: Response,
        sink: &mut dyn Write,
        secrets: &[&str],
        bound: VendorCallBound<'_>,
    ) -> oneiron::Result<()> {
        let mut chunk = vec![0; DOWNLOAD_CHUNK];
        loop {
            bound.cancel.check()?;
            let read = response.read(&mut chunk).map_err(|error| {
                self.failed(format!(
                    "{} download failed: {}",
                    self.0.as_str(),
                    scrubbed(&error.to_string(), secrets)
                ))
            })?;
            if read == 0 {
                return Ok(());
            }
            sink.write_all(&chunk[..read])?;
        }
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
