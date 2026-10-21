//! The host's review renderer (ARCH-0077 "Review images"): LibreOffice
//! Impress headless exports the deck to PDF, and each asked page is
//! rasterized to PNG. Each conversion runs in a fresh private directory with
//! its own user profile and a timeout; a missing or empty output is a
//! failure, not an image, whatever the exit code. The renderer's name rides
//! each judgment as provisional evidence beside the PowerPoint oracle. A
//! proposer wake asks it for the changed slides of a held review.
//!
//! Every render is admitted work (FIX 7653), drawn through an
//! [`AdmittedRenderer`]. It takes a turn in the host's renderer line
//! (`limits.renderer_work`), round robin across the callers it is for, the
//! host's own wakes behind them, and runs to one deadline ([`RENDER_TIME`])
//! and a stop flag its caller sets on leaving. The memory it reads pages into
//! is leased from the machine's ([`MachineMemory`]) before it is read. Its
//! scratch lives in the vault disk's private spool, and each write claims
//! its room on that disk's floor first. A turn that does not come, memory
//! that does not fit, or a disk at its reserve answers typed:
//! [`RENDER_DEADLINE`], [`RENDER_MEMORY_FLOOR`], [`RENDER_DISK_FLOOR`].
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, OnceLock, PoisonError};
use std::time::{Duration, Instant};

use oneiron::edit_roundtrip::slides_review::SlideRenderer;
use oneiron::memory::{MemoryError, MemoryResult};
use oneiron::office_body::DeckPreview;
use oneiron::origin::smart_http::SpillFloor;
use oneiron::{EntityId, Error, Result};

use crate::admission::{Admission, Permit, WaitTimedOut};
use crate::machine::{DiskClaim, DiskFloor, MachineMemory, MemoryLease, MemoryRefusal};
use crate::server::SyncServer;

/// The whole deck's export to PDF, and one page's raster.
const CONVERT_TIMEOUT: Duration = Duration::from_secs(120);
const PAGE_TIMEOUT: Duration = Duration::from_secs(30);
/// How often a running child is looked at.
const POLL: Duration = Duration::from_millis(50);
/// One render's whole time, from its turn to its last page; each child runs
/// for the least of its own timeout and what is left of it (CALLS "FIX 7653
/// render deadline").
const RENDER_TIME: Duration = Duration::from_secs(300);
/// The disk a deck's export claims before LibreOffice writes it: four times
/// the deck's bytes and 128 MiB more, for its PDF, its private profile and
/// the temp files it writes to the scratch (CALLS "FIX 7653 render disk
/// estimates").
const CONVERT_DISK_FACTOR: u64 = 4;
const CONVERT_DISK_BYTES: u64 = 128 << 20;
/// The disk one page's raster claims before pdftoppm writes it (CALLS "FIX
/// 7653 render disk estimates"): a 96 dpi raster of a 13.33-inch slide is
/// 2.8 MB before compression.
const PAGE_DISK_BYTES: u64 = 16 << 20;
/// When a render that met its deadline or the disk floor may be asked
/// again, in seconds.
const RENDER_RETRY_AFTER: u64 = 30;
/// A page's raster density: a 13.33-inch 16:9 slide at 96 dpi is 1280×720.
const PAGE_DPI: u32 = 96;
/// Hidden slides are exported too, so page N is slide N.
const PDF_FILTER: &str =
    r#"pdf:impress_pdf_Export:{"ExportHiddenSlides":{"type":"boolean","value":"true"}}"#;
/// A judgment's renderer field holds at most this many bytes.
const MAX_NAME_BYTES: usize = 256;

/// A render that ran past its deadline: its turn in the renderer line, its
/// memory or a page did not come in time. Retryable.
pub(crate) const RENDER_DEADLINE: &str = "render_deadline";
/// A render whose memory does not fit past the machine's free-memory
/// reserve, even with no other work holding any.
pub(crate) const RENDER_MEMORY_FLOOR: &str = "render_memory_floor";
/// A render whose scratch the vault disk has no room for past its
/// free-space reserve. Retryable.
pub(crate) const RENDER_DISK_FLOOR: &str = "render_disk_floor";

/// `limits.renderer_work`'s default: a quarter of the machine's cores, at
/// least one (CALLS "FIX 7653 renderer turns"). A render is a LibreOffice
/// export and a raster per page, each a process that keeps a core busy; the
/// row schedules them and never refuses one.
pub(crate) fn default_turns() -> usize {
    (crate::machine::cores() / 4).max(1)
}

struct LibreOfficeSlides {
    soffice: PathBuf,
    pdftoppm: PathBuf,
    name: String,
}

/// The host's renderer, once looked for: `None` inside when `soffice` or
/// `pdftoppm` is not on PATH or LibreOffice names no version.
static RENDERER: OnceLock<Option<LibreOfficeSlides>> = OnceLock::new();

/// The host's renderer, looked for once, inside admitted work, its probe
/// run in a private directory under `spool`.
fn host_renderer(spool: &Path) -> Option<&'static LibreOfficeSlides> {
    RENDERER
        .get_or_init(|| LibreOfficeSlides::find(spool))
        .as_ref()
}

impl LibreOfficeSlides {
    fn find(spool: &Path) -> Option<Self> {
        let soffice = on_path("soffice")?;
        let pdftoppm = on_path("pdftoppm")?;
        let scratch = Scratch::new(spool).ok()?;
        let out = scratch.path.join("version");
        let mut version = Command::new(&soffice);
        version
            .arg(profile_arg(&scratch.path))
            .arg("--version")
            .env("TMPDIR", &scratch.path)
            .stdout(std::fs::File::create(&out).ok()?);
        // The one look keeps its own timeout: no caller's deadline or
        // leaving ends it, as its answer stands for every later render.
        let alone = AtomicBool::new(false);
        let under = Under {
            deadline: Instant::now() + CONVERT_TIMEOUT,
            stop: &alone,
        };
        if run(version, CONVERT_TIMEOUT, &under).ok()?.is_some() {
            return None;
        }
        let version = std::fs::read_to_string(&out).ok()?;
        let version = version.lines().next()?.trim();
        if version.is_empty() {
            return None;
        }
        let mut name = format!("{version}; pdftoppm {PAGE_DPI} dpi");
        while name.len() > MAX_NAME_BYTES {
            name.pop();
        }
        Some(Self {
            soffice,
            pdftoppm,
            name,
        })
    }
}

/// Why an admitted render stopped short of its pages.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum RenderRefusal {
    /// Its turn, its memory or a page did not come before its deadline, or
    /// its caller left.
    Deadline,
    /// `needed` bytes of memory do not fit even with no other work holding
    /// any: past its reserve the machine has `available` for work.
    MemoryFloor { needed: u64, available: u64 },
    /// The vault disk has no room past its reserve for what the render
    /// writes.
    DiskFloor,
}

impl RenderRefusal {
    fn message(self) -> String {
        match self {
            Self::Deadline => format!(
                "the deck render did not finish within its deadline: its turn in the host's renderer line, its memory or its pages did not come in time (at most {} s of rendering)",
                RENDER_TIME.as_secs()
            ),
            Self::MemoryFloor { needed, available } => format!(
                "the deck render needs {needed} bytes of memory, and past its free-memory reserve this machine holds {available} for work"
            ),
            Self::DiskFloor => "the vault's disk is at its free-space reserve (limits.disk_reserve_bytes), and the deck render writes its scratch there".to_owned(),
        }
    }

    /// The refusal as a door answers it: its typed code, with when to ask
    /// again where waiting can help.
    pub(crate) fn memory_error(self) -> MemoryError {
        let (code, suggestion) = match self {
            Self::Deadline => (
                RENDER_DEADLINE,
                "Ask again once retry_after seconds have passed; nothing of this render was kept.",
            ),
            Self::MemoryFloor { .. } => (
                RENDER_MEMORY_FLOOR,
                "This machine cannot hold the render's memory past its reserve; ask on a host with more memory.",
            ),
            Self::DiskFloor => (
                RENDER_DISK_FLOOR,
                "Ask again once the vault's disk has room past limits.disk_reserve_bytes.",
            ),
        };
        let mut error = MemoryError::new(code, self.message(), &[suggestion]);
        if !matches!(self, Self::MemoryFloor { .. }) {
            error.retry_after = Some(RENDER_RETRY_AFTER);
        }
        error
    }
}

/// One request's renderer (FIX 7653): the host's LibreOffice renderer under
/// that request's turn in the renderer line, its deadline and stop flag, the
/// memory it has leased and the vault disk's floor its scratch claims on.
/// Its lease lives as long as it does, and so does a turn taken before the
/// work began: its caller keeps it until what it admitted is gone, past the
/// encoding of a preview's answer.
pub(crate) struct AdmittedRenderer {
    host: &'static LibreOfficeSlides,
    turn: Turn,
    /// The deadline of a render whose turn was taken before the work, and of
    /// every memory admission the work asks for.
    deadline: Instant,
    stop: Arc<AtomicBool>,
    memory: MachineMemory,
    /// One lease, grown by each admission.
    lease: Mutex<Option<MemoryLease>>,
    disk: DiskFloor,
    /// The vault disk's private spool, the scratch's parent.
    spool: PathBuf,
    /// The refusal the work failed with, beside the message its error
    /// carries.
    refused: Mutex<Option<(RenderRefusal, String)>>,
}

/// Where a renderer's turn comes from.
enum Turn {
    /// Taken before the work began, and held as long as the renderer.
    Held { _permit: Permit },
    /// Taken by each render as it starts, at `caller`'s place in `line`, or
    /// the host's own behind every caller, and given back when it ends.
    AtRender {
        line: Admission<EntityId>,
        caller: Option<EntityId>,
    },
}

impl AdmittedRenderer {
    /// The renderer for work that took `turn` before it began, a deck
    /// preview, held as long as the renderer; finding the host's renderer,
    /// the first time, runs inside it. `None` where the host has no
    /// renderer; the typed disk floor where the vault disk keeps no spool to
    /// render in.
    pub(crate) fn held(
        server: &SyncServer,
        turn: Permit,
        stop: Arc<AtomicBool>,
    ) -> MemoryResult<Option<Self>> {
        let Some(spool) = server.transfers.disk.spool_dir() else {
            return Err(RenderRefusal::DiskFloor.memory_error());
        };
        let turn = Turn::Held { _permit: turn };
        Ok(host_renderer(&spool).map(|host| Self::new(server, host, turn, spool, stop)))
    }

    /// The renderer for work whose renders each take their turn as they
    /// start, at `caller`'s place in the line, or the host's own behind every
    /// caller when `None`, and give it back when they end: a slide review or
    /// a proposer wake, whose ladder calls after the render hold no turn
    /// (CALLS "FIX 7653 renderer turns"). Finding the host's renderer, the
    /// first time, takes a turn of its own. `None` where the host has no
    /// renderer, or that turn or the spool does not come: the work then reads
    /// as it does with no renderer.
    pub(crate) fn at_render(
        server: &SyncServer,
        caller: Option<EntityId>,
        stop: Arc<AtomicBool>,
    ) -> Option<Self> {
        let Some(spool) = server.transfers.disk.spool_dir() else {
            tracing::warn!(
                kind = RENDER_DISK_FLOOR,
                "the vault disk keeps no spool to render in; the work reads as with no renderer"
            );
            return None;
        };
        let line = server.renderer_turns.clone();
        let host = match RENDERER.get() {
            Some(found) => found.as_ref()?,
            None => {
                let Ok(_turn) = take(&line, caller) else {
                    tracing::warn!(
                        kind = RENDER_DEADLINE,
                        "no renderer turn came to find the host's renderer; the work reads as with no renderer"
                    );
                    return None;
                };
                host_renderer(&spool)?
            }
        };
        let turn = Turn::AtRender { line, caller };
        Some(Self::new(server, host, turn, spool, stop))
    }

    fn new(
        server: &SyncServer,
        host: &'static LibreOfficeSlides,
        turn: Turn,
        spool: PathBuf,
        stop: Arc<AtomicBool>,
    ) -> Self {
        Self {
            host,
            turn,
            deadline: Instant::now() + RENDER_TIME,
            stop,
            memory: server.memory.clone(),
            lease: Mutex::default(),
            disk: server.transfers.disk.clone(),
            spool,
            refused: Mutex::default(),
        }
    }

    /// This renderer, as the engine takes one.
    pub(crate) fn slides(&self) -> &dyn SlideRenderer {
        self
    }

    /// `error` as its caller hears it: the typed refusal this renderer failed
    /// the work with, when `error` is that refusal; else `error` itself.
    pub(crate) fn typed(&self, error: MemoryError) -> MemoryError {
        match &*lock(&self.refused) {
            Some((refusal, message)) if error.message == *message => refusal.memory_error(),
            _ => error,
        }
    }

    /// `refusal`, kept so [`Self::typed`] answers it typed, as the error the
    /// work fails with.
    fn refuse(&self, refusal: RenderRefusal) -> Error {
        let message = refusal.message();
        *lock(&self.refused) = Some((refusal, message.clone()));
        Error::Refused(message)
    }

    /// `bytes` more of the machine's memory, leased by `deadline` and held
    /// as long as the renderer.
    fn lease(&self, bytes: u64, deadline: Instant) -> Result<()> {
        if bytes == 0 {
            return Ok(());
        }
        let stopped = || self.stop.load(Ordering::Relaxed);
        let mut held = lock(&self.lease);
        let leased = match held.take() {
            Some(mut lease) => {
                let grown = lease.grow(bytes, deadline, &stopped);
                *held = Some(lease);
                grown
            }
            None => self
                .memory
                .lease_until(bytes, deadline, &stopped)
                .map(|lease| *held = Some(lease)),
        };
        drop(held);
        leased.map_err(|refused| {
            self.refuse(match refused {
                MemoryRefusal::Floor { needed, available } => {
                    RenderRefusal::MemoryFloor { needed, available }
                }
                MemoryRefusal::WaitedOut { .. } => RenderRefusal::Deadline,
            })
        })
    }

    /// Room for `bytes` the render is about to write, claimed on the vault
    /// disk's floor past its reserve and every other claim. Dropped once the
    /// bytes are written, when the disk itself shows them.
    fn claim(&self, bytes: u64) -> Result<Arc<DiskClaim>> {
        let claim = self.disk.claim();
        if self.disk.hold(&claim, bytes) {
            Ok(claim)
        } else {
            Err(self.refuse(RenderRefusal::DiskFloor))
        }
    }

    /// The floor checked again once a child wrote what it wrote: a child
    /// that took the disk past its reserve, counting every other claim, ends
    /// the render.
    fn floor_holds(&self) -> Result<()> {
        if self.disk.has_room_for(0) {
            Ok(())
        } else {
            Err(self.refuse(RenderRefusal::DiskFloor))
        }
    }

    /// A child's run as the render takes it: a cut at the deadline, or by
    /// its caller leaving, ends the render typed.
    fn ran(&self, cut: Option<RenderRefusal>) -> Result<()> {
        match cut {
            None => Ok(()),
            Some(refusal) => Err(self.refuse(refusal)),
        }
    }

    /// `slides` of `deck`, drawn by `deadline` in a private directory of the
    /// vault disk's spool: each write claims its room on that disk's floor
    /// first, the floor is checked again once a child wrote, and each page's
    /// bytes are leased before they are read and its file removed once they
    /// are.
    fn draw(&self, deck: &[u8], slides: &[u64], deadline: Instant) -> Result<Vec<Vec<u8>>> {
        let under = Under {
            deadline,
            stop: &self.stop,
        };
        let scratch = Scratch::new(&self.spool)?;
        let input = scratch.path.join("deck.pptx");
        let deck_bytes = u64::try_from(deck.len()).unwrap_or(u64::MAX);
        let writing = self.claim(deck_bytes)?;
        std::fs::write(&input, deck)?;
        drop(writing);
        let mut convert = Command::new(&self.host.soffice);
        convert
            .arg(profile_arg(&scratch.path))
            .args([
                "--headless",
                "--invisible",
                "--nologo",
                "--norestore",
                "--nodefault",
                "--nolockcheck",
                "--convert-to",
                PDF_FILTER,
                "--outdir",
            ])
            .arg(&scratch.path)
            .arg(&input)
            // LibreOffice's own temp files land in the scratch, on the
            // floored disk.
            .env("TMPDIR", &scratch.path)
            .stdout(Stdio::null());
        let exporting = self.claim(
            deck_bytes
                .saturating_mul(CONVERT_DISK_FACTOR)
                .saturating_add(CONVERT_DISK_BYTES),
        )?;
        let cut = run(convert, CONVERT_TIMEOUT, &under)?;
        drop(exporting);
        self.ran(cut)?;
        self.floor_holds()?;
        let pdf = scratch.path.join("deck.pdf");
        non_empty(&pdf)?;
        slides
            .iter()
            .map(|slide| {
                let stem = scratch.path.join(format!("slide-{slide}"));
                let page = slide.to_string();
                let mut raster = Command::new(&self.host.pdftoppm);
                raster
                    .args(["-png", "-singlefile", "-r"])
                    .arg(PAGE_DPI.to_string())
                    .args(["-f", &page, "-l", &page])
                    .arg(&pdf)
                    .arg(&stem)
                    .stdout(Stdio::null());
                let rasterizing = self.claim(PAGE_DISK_BYTES)?;
                let cut = run(raster, PAGE_TIMEOUT, &under)?;
                drop(rasterizing);
                self.ran(cut)?;
                self.floor_holds()?;
                let png = scratch.path.join(format!("slide-{slide}.png"));
                let size = std::fs::metadata(&png).map_or(0, |meta| meta.len());
                if size == 0 {
                    return Err(failed("the slide renderer wrote no output"));
                }
                // Its bytes are leased before they are read, and its file goes
                // once they are.
                self.lease(size, deadline)?;
                let image = std::fs::read(&png)?;
                let _ = std::fs::remove_file(&png);
                Ok(image)
            })
            .collect()
    }
}

impl SlideRenderer for AdmittedRenderer {
    fn name(&self) -> &str {
        &self.host.name
    }

    fn render(&self, deck: &[u8], slides: &[u64]) -> Result<Vec<Vec<u8>>> {
        match &self.turn {
            Turn::Held { .. } => self.draw(deck, slides, self.deadline),
            Turn::AtRender { line, caller } => {
                let _turn =
                    take(line, *caller).map_err(|_| self.refuse(RenderRefusal::Deadline))?;
                self.draw(deck, slides, Instant::now() + RENDER_TIME)
            }
        }
    }

    /// A lease on the machine's memory, grown by `bytes` by the renderer's
    /// deadline and held as long as the renderer; typed when it does not
    /// fit.
    fn admit(&self, bytes: u64) -> Result<()> {
        self.lease(bytes, self.deadline)
    }
}

/// A turn in `line` at `caller`'s place, or the host's own behind every
/// caller when `None`. Blocks its thread while it waits.
fn take(
    line: &Admission<EntityId>,
    caller: Option<EntityId>,
) -> std::result::Result<Permit, WaitTimedOut> {
    match caller {
        Some(caller) => line.admit_blocking(caller),
        None => line.admit_background_blocking(),
    }
}

/// Sets a render's stop flag when dropped: an async door holds it across
/// its wait, so a caller who leaves stops the render its worker runs.
pub(crate) struct StopOnDrop(Arc<AtomicBool>);

impl StopOnDrop {
    /// The guard, and the flag it sets, for the renderer.
    pub(crate) fn new() -> (Self, Arc<AtomicBool>) {
        let stop = Arc::new(AtomicBool::new(false));
        (Self(Arc::clone(&stop)), stop)
    }
}

impl Drop for StopOnDrop {
    fn drop(&mut self) {
        self.0.store(true, Ordering::Relaxed);
    }
}

/// A deck preview beside the renderer that drew it (FIX 7653): the
/// renderer's lease and turn cover the preview until it is encoded, and it
/// serializes as the preview alone.
pub(crate) struct RenderedPreview {
    preview: DeckPreview,
    _renderer: Option<AdmittedRenderer>,
}

impl serde::Serialize for RenderedPreview {
    fn serialize<S: serde::Serializer>(
        &self,
        serializer: S,
    ) -> std::result::Result<S::Ok, S::Error> {
        serde::Serialize::serialize(&self.preview, serializer)
    }
}

/// `preview` as `renderer` drew it: beside the renderer, kept until it is
/// encoded, or the refusal it failed with, typed.
pub(crate) fn rendered(
    preview: MemoryResult<DeckPreview>,
    renderer: Option<AdmittedRenderer>,
) -> MemoryResult<RenderedPreview> {
    match preview {
        Ok(preview) => Ok(RenderedPreview {
            preview,
            _renderer: renderer,
        }),
        Err(error) => Err(match &renderer {
            Some(renderer) => renderer.typed(error),
            None => error,
        }),
    }
}

/// A private directory removed with everything in it when dropped.
struct Scratch {
    path: PathBuf,
}

impl Scratch {
    /// A fresh private directory under `spool`.
    fn new(spool: &Path) -> Result<Self> {
        let path = spool.join(format!("oneiron-slides-{}", EntityId::now().to_hex()));
        let mut builder = std::fs::DirBuilder::new();
        #[cfg(unix)]
        std::os::unix::fs::DirBuilderExt::mode(&mut builder, 0o700);
        builder.create(&path)?;
        Ok(Self { path })
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.path);
    }
}

/// The conversion's own LibreOffice user profile, inside its directory.
fn profile_arg(dir: &Path) -> String {
    format!("-env:UserInstallation=file://{}/profile", dir.display())
}

fn on_path(program: &str) -> Option<PathBuf> {
    std::env::split_paths(&std::env::var_os("PATH")?)
        .map(|dir| dir.join(program))
        .find(|path| path.is_file())
}

fn non_empty(path: &Path) -> Result<()> {
    if std::fs::metadata(path).map_or(0, |meta| meta.len()) == 0 {
        return Err(failed("the slide renderer wrote no output"));
    }
    Ok(())
}

fn failed(message: &str) -> Error {
    Error::InvalidConfig(message.to_owned())
}

/// What one child runs under: its render's deadline, and the flag its
/// caller sets on leaving.
struct Under<'a> {
    deadline: Instant,
    stop: &'a AtomicBool,
}

/// Runs `command` in its own process group with no input and no error
/// output until it exits. Past `timeout` it fails, as it always has; past
/// the render's deadline, or once its caller left, it answers that cut
/// instead. However its run ends, an error or a panic among them, its group
/// is stopped ([`Group`]).
fn run(
    mut command: Command,
    timeout: Duration,
    under: &Under<'_>,
) -> Result<Option<RenderRefusal>> {
    command.stdin(Stdio::null()).stderr(Stdio::null());
    #[cfg(unix)]
    std::os::unix::process::CommandExt::process_group(&mut command, 0);
    let own = Instant::now() + timeout;
    let mut child = Group(command.spawn()?);
    loop {
        if let Some(status) = child.0.try_wait()? {
            return if status.success() {
                Ok(None)
            } else {
                Err(failed("the slide renderer failed"))
            };
        }
        let now = Instant::now();
        if under.stop.load(Ordering::Relaxed) || now >= under.deadline {
            return Ok(Some(RenderRefusal::Deadline));
        }
        if now >= own {
            return Err(failed("the slide renderer timed out"));
        }
        std::thread::sleep(POLL);
    }
}

/// A running child whose process group is stopped however its run ends.
struct Group(Child);

impl Drop for Group {
    fn drop(&mut self) {
        stop(&mut self.0);
    }
}

/// Kills whatever the run left in its process group, then reaps it.
fn stop(child: &mut Child) {
    #[cfg(unix)]
    if let Some(group) = i32::try_from(child.id())
        .ok()
        .and_then(rustix::process::Pid::from_raw)
    {
        let _ = rustix::process::kill_process_group(group, rustix::process::Signal::KILL);
    }
    let _ = child.kill();
    let _ = child.wait();
}

/// The renderer's own state changes in one step under each lock, so a
/// holder that panicked left it whole.
fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}
