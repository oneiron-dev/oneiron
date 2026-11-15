//! A vendor's sandbox as the backend of a finite Foreign or Untrusted run
//! (L8-43, VENDOR-BOUNDARY = A: a batch boundary).
//!
//! A vendor's machine has no live channel to this host, so a run is one
//! batch. The host's exchange runs unchanged on one end of a socket pair. On
//! the other end a relay answers the exchange's wait for the guest's hello,
//! and records the host's opening (start, component, the staged workspace
//! files, ready) as a transcript. A fresh sandbox of the vendor's, one per
//! run, gets that transcript and runs `oneiron-guest --batch`, which answers
//! its own receipt waits and appends every frame it sends to a second
//! transcript. The relay downloads that one, deletes the sandbox, and replays
//! the guest's frames to the exchange one at a time. So every check the host
//! makes on a container guest's frames (paths, sizes, JSON, proposals,
//! outputs, the spool floor) is made on the vendor's, by the same code.
//!
//! Each receipt the host sends back must be the one the guest gave itself.
//! A transcript that diverges from the host's answers, that ends before its
//! finish, or that runs past it, refuses the whole run.
//!
//! No credential broker is reachable from a vendor's machine: every
//! credential read is refused on both sides, and the host records each one
//! as transport-unavailable. The guest has no egress of ours, and its
//! isolation is the vendor's, which this host cannot prove: the session
//! manifest records the run as unproven.

use std::{
    collections::BTreeMap,
    io::{self, Read, Write},
    os::unix::net::UnixStream,
    path::PathBuf,
    sync::{Arc, Mutex, mpsc},
    time::{Duration, Instant},
};

use oneiron_container::{GuestSeccomp, SessionManifest, image_release::ImageReleaseObservation};
use oneiron_sandbox_contract::{GUEST_PROTOCOL_VERSION, MAX_COMPONENT_BYTES, MAX_FRAME_BYTES};
use serde::Deserialize;
use serde_json::{Value, json};

use super::{
    CredentialEgressProxy, CredentialResolver, ExecutionBudget, GuestImage, MicroVmBackend,
    MicroVmExit, MicroVmHandle, MicroVmOutputSink, backend_error, prepare_overlay_handle,
};
use crate::Result;
use crate::code_sandbox::{
    ProposalSpoolFloor, SandboxBoundaryContract, SandboxMountTable, SandboxProposalBody,
    SandboxProposalBodyWriter, SandboxProposalWrite, SandboxVendor,
};
use crate::engine_executor::{CANCEL_POLL_SLICE, StepCancellation};

/// The guest binary in the guest image
/// (`crates/oneiron-container/images/packages.toml`).
pub const VENDOR_GUEST_BIN: &str = "/usr/local/bin/oneiron-guest";

/// The private directory of one batch run on the vendor's sandbox.
pub const VENDOR_BATCH_DIR: &str = "/tmp/oneiron-batch";

/// The host's opening, as the guest reads it.
const HOST_FRAMES: &str = "/tmp/oneiron-batch/host-frames";
/// The guest's frames, in a file the guest makes.
const GUEST_FRAMES: &str = "/tmp/oneiron-batch/guest-frames";
/// The empty directory the guest copies the staged files into.
const WORKSPACE: &str = "/tmp/oneiron-batch/workspace";

/// Makes the batch directory and its empty workspace, both private; a
/// sandbox that already has either is not a fresh one.
const MAKE_BATCH_DIR: [&str; 5] = ["mkdir", "-m", "0700", VENDOR_BATCH_DIR, WORKSPACE];

/// Runs the guest over the two transcripts.
const BATCH_COMMAND: [&str; 5] = [
    VENDOR_GUEST_BIN,
    "--batch",
    HOST_FRAMES,
    GUEST_FRAMES,
    WORKSPACE,
];

/// The most bytes either transcript of one run may hold. The opening is at
/// most the component (64 MiB) and the workspace (16 MiB), each byte sent as
/// a JSON number of at most four characters; the guest's frames are bounded
/// by the same workspace and the step's output.
pub const MAX_VENDOR_TRANSCRIPT_BYTES: u64 = 512 * 1024 * 1024;

/// The vendor's id of one sandbox it made for one run.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VendorSandboxId(String);

impl VendorSandboxId {
    /// An id the vendor answered.
    ///
    /// # Errors
    ///
    /// [`crate::error::CodeError::MicroVmBackendError`] for an empty id, one
    /// longer than 256 bytes, or one with a control character.
    pub fn new(id: impl Into<String>) -> Result<Self> {
        let id = id.into();
        if id.is_empty() || id.len() > 256 || id.chars().any(char::is_control) {
            return Err(backend_error("vendor-sandbox", "vendor sandbox id refused"));
        }
        Ok(Self(id))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// What one batch run asks of the vendor's sandbox.
#[derive(Clone, Copy, Debug)]
pub struct VendorSandboxSpec<'a> {
    /// The pinned guest image the step names (`ONEIRON_CODE_GUEST_IMAGE`),
    /// whose [`VENDOR_GUEST_BIN`] the run starts.
    pub guest_image: &'a str,
    /// The step's budget: the sandbox gets no more memory or processes.
    pub budget: ExecutionBudget,
}

/// The bound every vendor call stays inside: the step's deadline and its
/// cancellation.
#[derive(Clone, Copy, Debug)]
pub struct VendorCallBound<'a> {
    pub deadline: Instant,
    pub cancel: &'a StepCancellation,
}

/// One vendor's sandbox API, as a batch run needs it. An implementation
/// holds the owner's key for its vendor and never shows it. Each call
/// returns by its bound's deadline, and soon after its cancellation fires.
pub trait VendorSandboxClient: Send + Sync {
    /// The vendor this client reaches.
    fn vendor(&self) -> SandboxVendor;

    /// Makes one fresh sandbox for one run, and waits until it runs.
    ///
    /// # Errors
    ///
    /// The vendor refused, or the sandbox did not start inside `bound`.
    fn create(
        &self,
        spec: &VendorSandboxSpec<'_>,
        bound: VendorCallBound<'_>,
    ) -> Result<VendorSandboxId>;

    /// Writes the `len` bytes `body` yields to the file `path` on `sandbox`.
    ///
    /// # Errors
    ///
    /// The vendor refused the upload, or it did not end inside `bound`.
    fn upload(
        &self,
        sandbox: &VendorSandboxId,
        path: &str,
        body: &mut dyn Read,
        len: u64,
        bound: VendorCallBound<'_>,
    ) -> Result<()>;

    /// Runs `argv` on `sandbox`, with no shell, and answers its exit status.
    ///
    /// # Errors
    ///
    /// The vendor refused the command, or it did not end inside `bound`.
    fn execute(
        &self,
        sandbox: &VendorSandboxId,
        argv: &[&str],
        bound: VendorCallBound<'_>,
    ) -> Result<i32>;

    /// Copies the file `path` on `sandbox` into `sink`, and stops at the
    /// first write `sink` refuses.
    ///
    /// # Errors
    ///
    /// The vendor refused the download, `sink` refused a write, or it did
    /// not end inside `bound`.
    fn download(
        &self,
        sandbox: &VendorSandboxId,
        path: &str,
        sink: &mut dyn Write,
        bound: VendorCallBound<'_>,
    ) -> Result<()>;

    /// Deletes `sandbox`. Called once for each sandbox [`Self::create`]
    /// made, whatever the run's outcome.
    ///
    /// # Errors
    ///
    /// The vendor refused the delete.
    fn delete(&self, sandbox: &VendorSandboxId) -> Result<()>;
}

/// The finite-run backend of one vendor's sandbox (module doc). It ignores
/// a read transport it is lent: no broker is reachable from the vendor's
/// machine, so the host answers every credential read as unavailable. It
/// serves no long-lived session.
pub struct VendorBatchBackend {
    client: Arc<dyn VendorSandboxClient>,
    root: PathBuf,
    states: Mutex<BTreeMap<String, State>>,
    /// The host's measured disk floor the transcripts and the guest's
    /// proposed files spool on (FIX 7650); none spools them as before.
    spool: Option<Arc<dyn ProposalSpoolFloor>>,
}

struct State {
    handle: MicroVmHandle,
    armed: bool,
    proposals: Option<Vec<SandboxProposalWrite>>,
    manifest: Option<SessionManifest>,
}

impl VendorBatchBackend {
    /// A backend whose runs go to `client`'s vendor. Each run's private
    /// scratch lives under `scratch_root`.
    #[must_use]
    pub fn new(client: Arc<dyn VendorSandboxClient>, scratch_root: impl Into<PathBuf>) -> Self {
        Self {
            client,
            root: scratch_root.into(),
            states: Mutex::new(BTreeMap::new()),
            spool: None,
        }
    }

    fn failed(&self, detail: impl Into<String>) -> crate::Error {
        backend_error(self.name(), detail)
    }

    fn diverged(&self, detail: &str) -> crate::Error {
        self.failed(format!(
            "vendor transcript diverges from the host's exchange: {detail}"
        ))
    }

    fn state<'a>(
        &'a self,
        vm: &MicroVmHandle,
    ) -> Result<std::sync::MutexGuard<'a, BTreeMap<String, State>>> {
        let state = self
            .states
            .lock()
            .map_err(|_| self.failed("vendor sandbox state poisoned"))?;
        if state.get(vm.id()).is_none_or(|s| s.handle != *vm) {
            return Err(self.failed("unknown vendor sandbox handle"));
        }
        Ok(state)
    }

    /// What this run's session is, as far as this host can tell: the
    /// vendor's own isolation, with no fence or egress of ours.
    fn manifest(&self, vm: &MicroVmHandle, guest_image: &str) -> Result<SessionManifest> {
        let argv = serde_json::to_vec(&BATCH_COMMAND)
            .map_err(|_| self.failed("vendor command encoding"))?;
        Ok(SessionManifest {
            backend: self.name().into(),
            runtime: self.client.vendor().as_str().into(),
            image: guest_image.into(),
            argv_digest: blake3::hash(&argv).to_hex().to_string(),
            network: "vendor; no engine egress".into(),
            seccomp: GuestSeccomp::Unfiltered,
            generation: vm.id().into(),
            fence_proof: None,
            fence_unproven: true,
            image_release: ImageReleaseObservation::default(),
        })
    }

    fn component(&self, image: &GuestImage) -> Result<Vec<u8>> {
        let mut component = Vec::new();
        std::fs::File::open(&image.component)
            .map_err(|_| self.failed("guest component unavailable"))?
            .take(MAX_COMPONENT_BYTES as u64 + 1)
            .read_to_end(&mut component)?;
        if component.is_empty() || component.len() > MAX_COMPONENT_BYTES {
            return Err(self.failed("component size"));
        }
        Ok(component)
    }

    /// The relay end of one run: the hello, the opening, the vendor's run
    /// and the replay. A socket the host ended answers no more, and the
    /// host's own outcome stands.
    fn relay(
        &self,
        mut peer: UnixStream,
        spec: &VendorSandboxSpec<'_>,
        bound: VendorCallBound<'_>,
    ) -> Result<()> {
        let Some(opening) = self.record_opening(&mut peer)? else {
            return Ok(());
        };
        bound.cancel.check()?;
        let transcript = self.run_on_vendor(&opening, spec, bound)?;
        drop(opening);
        bound.cancel.check()?;
        self.replay(&mut peer, &transcript, bound.cancel)
    }

    /// Answers the exchange's wait for a hello, and spools the host's frames
    /// up to its ready. `None` when the host ended the exchange first.
    fn record_opening(&self, peer: &mut UnixStream) -> Result<Option<SandboxProposalBody>> {
        let hello = encode(&json!({ "type": "hello", "version": GUEST_PROTOCOL_VERSION }))
            .map_err(|_| self.failed("hello encoding"))?;
        if peer.write_all(&hello).is_err() {
            return Ok(None);
        }
        let mut opening = TranscriptSpool::new(self.name(), self.spool.as_deref())?;
        loop {
            let Ok(Some(frame)) = read_frame(&mut *peer) else {
                return Ok(None);
            };
            opening.append(&frame.bytes)?;
            if frame.kind == "ready" {
                return opening.finish().map(Some);
            }
        }
    }

    /// Runs the opening on a fresh sandbox of the vendor's and answers the
    /// guest's frames. The sandbox is deleted on every path out.
    fn run_on_vendor(
        &self,
        opening: &SandboxProposalBody,
        spec: &VendorSandboxSpec<'_>,
        bound: VendorCallBound<'_>,
    ) -> Result<SandboxProposalBody> {
        let client = &*self.client;
        let sandbox = CreatedSandbox {
            client,
            backend: self.name(),
            id: client.create(spec, bound)?,
        };
        bound.cancel.check()?;
        let made = client.execute(&sandbox.id, &MAKE_BATCH_DIR, bound)?;
        if made != 0 {
            return Err(self.failed(format!(
                "vendor sandbox could not make its batch directory (exit {made})"
            )));
        }
        bound.cancel.check()?;
        client.upload(
            &sandbox.id,
            HOST_FRAMES,
            &mut opening.reader(),
            opening.len(),
            bound,
        )?;
        bound.cancel.check()?;
        // The transcript, not the guest's exit status, carries the run's
        // outcome: a failed program still ends it with its error and finish.
        let status = client.execute(&sandbox.id, &BATCH_COMMAND, bound)?;
        bound.cancel.check()?;
        let mut transcript = TranscriptSpool::new(self.name(), self.spool.as_deref())?;
        let downloaded = client.download(&sandbox.id, GUEST_FRAMES, &mut transcript, bound);
        if let Some(refused) = transcript.refused.take() {
            return Err(refused);
        }
        downloaded.map_err(|error| {
            self.failed(format!(
                "vendor guest frames unavailable (guest exit {status}): {error}"
            ))
        })?;
        drop(sandbox);
        transcript.finish()
    }

    /// Feeds the guest's frames to the exchange one at a time, and checks
    /// each receipt the host sends back against the one the guest gave
    /// itself.
    fn replay(
        &self,
        peer: &mut UnixStream,
        transcript: &SandboxProposalBody,
        cancel: &StepCancellation,
    ) -> Result<()> {
        let mut frames = transcript.reader();
        let unreadable = |_: io::Error| self.diverged("an unreadable frame");
        let hello = read_frame(&mut frames)
            .map_err(unreadable)?
            .ok_or_else(|| self.diverged("no hello"))?;
        if frame_value(&hello)
            != Some(json!({ "type": "hello", "version": GUEST_PROTOCOL_VERSION }))
        {
            return Err(self.diverged("guest protocol version"));
        }
        loop {
            cancel.check()?;
            let Some(frame) = read_frame(&mut frames).map_err(unreadable)? else {
                return Err(self.diverged("it ends before its finish"));
            };
            if peer.write_all(&frame.bytes).is_err() {
                return Ok(());
            }
            if frame.kind == "finish" {
                return match read_frame(&mut frames).map_err(unreadable)? {
                    None => Ok(()),
                    Some(_) => Err(self.diverged("frames after its finish")),
                };
            }
            let Some(accepted) = receipt_for(&frame.kind) else {
                continue;
            };
            let Ok(Some(answer)) = read_frame(&mut *peer) else {
                return Ok(());
            };
            let answer = frame_value(&answer);
            if answer
                .as_ref()
                .and_then(|answer| answer.get("type"))
                .and_then(Value::as_str)
                == Some("failure")
            {
                return Ok(());
            }
            if answer != Some(json!({ "type": "receipt", "accepted": accepted })) {
                return Err(self.diverged("the host answered a frame otherwise than its guest"));
            }
        }
    }
}

impl MicroVmBackend for VendorBatchBackend {
    fn name(&self) -> &'static str {
        self.client.vendor().backend_name()
    }

    fn prepare(
        &self,
        contract: &SandboxBoundaryContract,
        mounts: &SandboxMountTable,
    ) -> Result<MicroVmHandle> {
        let handle = prepare_overlay_handle(&self.root, self.name(), contract, mounts)?;
        self.states
            .lock()
            .map_err(|_| self.failed("vendor sandbox state poisoned"))?
            .insert(
                handle.id().into(),
                State {
                    handle: handle.clone(),
                    armed: false,
                    proposals: None,
                    manifest: None,
                },
            );
        Ok(handle)
    }

    fn proxy_credentials(&self, vm: &MicroVmHandle, _: &dyn CredentialResolver) -> Result<()> {
        let mut states = self.state(vm)?;
        let state = states
            .get_mut(vm.id())
            .ok_or_else(|| self.failed("unknown vendor sandbox handle"))?;
        if state.armed {
            return Err(self.failed("vendor sandbox already armed"));
        }
        state.armed = true;
        Ok(())
    }

    fn set_proposal_spool(&mut self, spool: Arc<dyn ProposalSpoolFloor>) {
        self.spool = Some(spool);
    }

    fn session_manifest(&self, vm: &MicroVmHandle) -> Option<SessionManifest> {
        self.states.lock().ok()?.get(vm.id())?.manifest.clone()
    }

    fn run(&self, _: &MicroVmHandle, _: &GuestImage, _: ExecutionBudget) -> Result<MicroVmExit> {
        Err(self.failed("vendor sandbox requires its host-bound proxy"))
    }

    fn run_with_proxy(
        &self,
        vm: &MicroVmHandle,
        image: &GuestImage,
        budget: ExecutionBudget,
        proxy: &CredentialEgressProxy,
        output: &mut dyn MicroVmOutputSink,
    ) -> Result<MicroVmExit> {
        self.run_with_proxy_cancellable(
            vm,
            image,
            budget,
            proxy,
            &StepCancellation::never(),
            output,
        )
    }

    /// Runs one guest on the vendor's sandbox under its step's token
    /// (FIX 600). Once `cancel` fires a watcher cuts the exchange's socket,
    /// and the relay stops at its next vendor call, which deletes the
    /// sandbox; the cancel wins over the run's result and proposals.
    fn run_with_proxy_cancellable(
        &self,
        vm: &MicroVmHandle,
        image: &GuestImage,
        budget: ExecutionBudget,
        proxy: &CredentialEgressProxy,
        cancel: &StepCancellation,
        output: &mut dyn MicroVmOutputSink,
    ) -> Result<MicroVmExit> {
        cancel.check()?;
        if !budget.is_bounded() || !proxy.is_armed() {
            return Err(self.failed("unbounded or unarmed vendor sandbox"));
        }
        if self
            .state(vm)?
            .get(vm.id())
            .is_none_or(|s| !s.armed || s.manifest.is_some())
        {
            return Err(self.failed("vendor run already consumed or unarmed"));
        }
        let guest_image = image
            .oci
            .as_ref()
            .map(|oci| oci.image.as_str())
            .ok_or_else(|| self.failed("a vendor run needs the step's pinned guest image"))?;
        let component = self.component(image)?;
        let manifest = self.manifest(vm, guest_image)?;
        self.state(vm)?
            .get_mut(vm.id())
            .ok_or_else(|| self.failed("unknown vendor sandbox handle"))?
            .manifest = Some(manifest);
        cancel.check()?;
        let deadline = Instant::now() + Duration::from_secs(budget.wall_clock_secs);
        let (stream, peer) = UnixStream::pair()?;
        let watched = stream.try_clone()?;
        let spec = VendorSandboxSpec {
            guest_image,
            budget,
        };
        let bound = VendorCallBound { deadline, cancel };
        let (finish, finished) = mpsc::channel();
        let (result, relayed) = std::thread::scope(|scope| {
            let relay = scope.spawn(move || self.relay(peer, &spec, bound));
            let watcher = scope.spawn(move || watch_run(&watched, &finished, cancel));
            let result = super::protocol::exchange_cancellable(
                stream,
                vm,
                super::protocol::GuestProgram {
                    component: &component,
                    source: &image.source,
                },
                budget,
                deadline,
                proxy,
                None,
                self.spool.as_deref(),
                cancel,
                output,
            );
            // The watcher cuts the socket, so a relay waiting on a frame
            // the ended exchange never sends wakes.
            let _ = finish.send(());
            let relayed = relay
                .join()
                .unwrap_or_else(|_| Err(self.failed("vendor relay panicked")));
            let _ = watcher.join();
            (result, relayed)
        });
        cancel.check()?;
        // A vendor that failed, or a transcript that diverged, is why the
        // exchange lost its guest.
        relayed?;
        let (exit, proposals) = result?;
        // A failed guest keeps its program error and leaves nothing to
        // collect (FIX 9209).
        if exit.status == 0 {
            self.state(vm)?
                .get_mut(vm.id())
                .ok_or_else(|| self.failed("unknown vendor sandbox handle"))?
                .proposals = Some(proposals);
        }
        Ok(exit)
    }

    fn collect_overlay_delta(&self, vm: &MicroVmHandle) -> Result<Vec<SandboxProposalWrite>> {
        self.state(vm)?
            .get_mut(vm.id())
            .and_then(|s| s.proposals.take())
            .ok_or_else(|| self.failed("no completed vendor proposals"))
    }

    fn cleanup(&self, vm: &MicroVmHandle) {
        if let Ok(mut states) = self.states.lock() {
            states.remove(vm.id());
        }
    }
}

/// A sandbox the vendor made for this run, deleted when it drops.
struct CreatedSandbox<'a> {
    client: &'a dyn VendorSandboxClient,
    backend: &'static str,
    id: VendorSandboxId,
}

impl Drop for CreatedSandbox<'_> {
    fn drop(&mut self) {
        if let Err(error) = self.client.delete(&self.id) {
            tracing::warn!(
                backend = self.backend,
                sandbox = self.id.as_str(),
                %error,
                "vendor sandbox delete failed"
            );
        }
    }
}

/// One transcript, spooled on the host's disk floor when one was lent, and
/// refused past [`MAX_VENDOR_TRANSCRIPT_BYTES`].
struct TranscriptSpool {
    backend: &'static str,
    writer: SandboxProposalBodyWriter,
    /// Why a write was refused, kept with its type (a floor refusal stays
    /// one).
    refused: Option<crate::Error>,
}

impl TranscriptSpool {
    fn new(backend: &'static str, floor: Option<&dyn ProposalSpoolFloor>) -> Result<Self> {
        Ok(Self {
            backend,
            writer: match floor {
                Some(floor) => SandboxProposalBody::spool_floored(floor)?,
                None => SandboxProposalBody::spool()?,
            },
            refused: None,
        })
    }

    fn append(&mut self, bytes: &[u8]) -> Result<()> {
        if self.writer.len().saturating_add(bytes.len() as u64) > MAX_VENDOR_TRANSCRIPT_BYTES {
            return Err(backend_error(
                self.backend,
                "vendor transcript exceeds its cap",
            ));
        }
        self.writer.append(bytes)
    }

    fn finish(self) -> Result<SandboxProposalBody> {
        self.writer.finish()
    }
}

impl Write for TranscriptSpool {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        match self.append(bytes) {
            Ok(()) => Ok(bytes.len()),
            Err(error) => {
                self.refused = Some(error);
                Err(io::Error::other("vendor transcript refused"))
            }
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// One whole frame of either transcript, as it was sent: its length header,
/// then its JSON.
struct RawFrame {
    bytes: Vec<u8>,
    kind: String,
}

#[derive(Deserialize)]
struct FrameKind {
    #[serde(rename = "type")]
    kind: String,
}

/// Reads one frame; `None` at a clean end between frames.
fn read_frame(reader: &mut impl Read) -> io::Result<Option<RawFrame>> {
    let mut header = [0; 4];
    let mut filled = 0;
    while filled < header.len() {
        match reader.read(&mut header[filled..]) {
            Ok(0) if filled == 0 => return Ok(None),
            Ok(0) => return Err(io::ErrorKind::UnexpectedEof.into()),
            Ok(read) => filled += read,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error) => return Err(error),
        }
    }
    let len = u32::from_be_bytes(header) as usize;
    if len == 0 || len > MAX_FRAME_BYTES {
        return Err(io::Error::other("frame size refused"));
    }
    let mut bytes = header.to_vec();
    bytes.resize(4 + len, 0);
    reader.read_exact(&mut bytes[4..])?;
    let kind = serde_json::from_slice::<FrameKind>(&bytes[4..])
        .map_err(io::Error::other)?
        .kind;
    Ok(Some(RawFrame { bytes, kind }))
}

fn frame_value(frame: &RawFrame) -> Option<Value> {
    serde_json::from_slice(&frame.bytes[4..]).ok()
}

fn encode(value: &Value) -> io::Result<Vec<u8>> {
    let body = serde_json::to_vec(value).map_err(io::Error::other)?;
    let len = u32::try_from(body.len()).map_err(io::Error::other)?;
    let mut frame = len.to_be_bytes().to_vec();
    frame.extend_from_slice(&body);
    Ok(frame)
}

/// The receipt the guest's batch channel gives itself for each frame that
/// waits on one (`crates/oneiron-guest/src/batch.rs`): the host's answer
/// when nothing is wrong. No broker answers a credential read on a vendor's
/// machine.
fn receipt_for(kind: &str) -> Option<bool> {
    match kind {
        "write_open" | "write_chunk" | "write_close" | "delete" | "rename" | "output_text"
        | "output_bytes" | "store_bytes" => Some(true),
        "credential_read" => Some(false),
        _ => None,
    }
}

/// Watches one run until its exchange ends, in slices of
/// [`CANCEL_POLL_SLICE`], then cuts the exchange's socket: at once when
/// `cancel` fires, which wakes the exchange, and after it ends, which wakes
/// a relay still waiting on it.
fn watch_run(stream: &UnixStream, finished: &mpsc::Receiver<()>, cancel: &StepCancellation) {
    while !cancel.is_cancelled() {
        match finished.recv_timeout(CANCEL_POLL_SLICE) {
            Err(mpsc::RecvTimeoutError::Timeout) => {}
            Ok(()) | Err(mpsc::RecvTimeoutError::Disconnected) => break,
        }
    }
    let _ = stream.shutdown(std::net::Shutdown::Both);
}
