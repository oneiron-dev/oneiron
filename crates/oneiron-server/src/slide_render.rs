//! The host's review renderer (ARCH-0077 "Review images"): LibreOffice
//! Impress headless exports the deck to PDF, and each asked page is
//! rasterized to PNG. Each conversion runs in a fresh private directory with
//! its own user profile and a timeout; a missing or empty output is a
//! failure, not an image, whatever the exit code. The renderer's name rides
//! each judgment as provisional evidence beside the PowerPoint oracle. A
//! proposer wake asks it for the changed slides of a held review.
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::OnceLock;
use std::time::{Duration, Instant};

use oneiron::edit_roundtrip::slides_review::SlideRenderer;
use oneiron::{EntityId, Error, Result};

/// The whole deck's export to PDF, and one page's raster.
const CONVERT_TIMEOUT: Duration = Duration::from_secs(120);
const PAGE_TIMEOUT: Duration = Duration::from_secs(30);
/// A page's raster density: a 13.33-inch 16:9 slide at 96 dpi is 1280×720.
const PAGE_DPI: u32 = 96;
/// Hidden slides are exported too, so page N is slide N.
const PDF_FILTER: &str =
    r#"pdf:impress_pdf_Export:{"ExportHiddenSlides":{"type":"boolean","value":"true"}}"#;
/// A judgment's renderer field holds at most this many bytes.
const MAX_NAME_BYTES: usize = 256;

pub(crate) struct LibreOfficeSlides {
    soffice: PathBuf,
    pdftoppm: PathBuf,
    name: String,
}

/// The host's renderer, when `soffice` and `pdftoppm` are both on PATH and
/// LibreOffice names its version; looked for once.
pub(crate) fn host_renderer() -> Option<&'static LibreOfficeSlides> {
    static RENDERER: OnceLock<Option<LibreOfficeSlides>> = OnceLock::new();
    RENDERER.get_or_init(LibreOfficeSlides::find).as_ref()
}

impl LibreOfficeSlides {
    fn find() -> Option<Self> {
        let soffice = on_path("soffice")?;
        let pdftoppm = on_path("pdftoppm")?;
        let scratch = Scratch::new().ok()?;
        let out = scratch.path.join("version");
        let mut version = Command::new(&soffice);
        version
            .arg(profile_arg(&scratch.path))
            .arg("--version")
            .stdout(std::fs::File::create(&out).ok()?);
        run(version, CONVERT_TIMEOUT).ok()?;
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

impl SlideRenderer for LibreOfficeSlides {
    fn name(&self) -> &str {
        &self.name
    }

    fn render(&self, deck: &[u8], slides: &[u64]) -> Result<Vec<Vec<u8>>> {
        let scratch = Scratch::new()?;
        let input = scratch.path.join("deck.pptx");
        std::fs::write(&input, deck)?;
        let mut convert = Command::new(&self.soffice);
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
            .stdout(Stdio::null());
        run(convert, CONVERT_TIMEOUT)?;
        let pdf = scratch.path.join("deck.pdf");
        non_empty(&pdf)?;
        slides
            .iter()
            .map(|slide| {
                let stem = scratch.path.join(format!("slide-{slide}"));
                let page = slide.to_string();
                let mut raster = Command::new(&self.pdftoppm);
                raster
                    .args(["-png", "-singlefile", "-r"])
                    .arg(PAGE_DPI.to_string())
                    .args(["-f", &page, "-l", &page])
                    .arg(&pdf)
                    .arg(&stem)
                    .stdout(Stdio::null());
                run(raster, PAGE_TIMEOUT)?;
                let png = scratch.path.join(format!("slide-{slide}.png"));
                non_empty(&png)?;
                Ok(std::fs::read(&png)?)
            })
            .collect()
    }
}

/// A private directory removed with everything in it when dropped.
struct Scratch {
    path: PathBuf,
}

impl Scratch {
    fn new() -> Result<Self> {
        let path =
            std::env::temp_dir().join(format!("oneiron-slides-{}", EntityId::now().to_hex()));
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

/// Runs `command` in its own process group with no input and no error
/// output, killing the group at `timeout`.
fn run(mut command: Command, timeout: Duration) -> Result<()> {
    command.stdin(Stdio::null()).stderr(Stdio::null());
    #[cfg(unix)]
    std::os::unix::process::CommandExt::process_group(&mut command, 0);
    let mut child = command.spawn()?;
    let deadline = Instant::now() + timeout;
    loop {
        if let Some(status) = child.try_wait()? {
            stop(&mut child);
            return if status.success() {
                Ok(())
            } else {
                Err(failed("the slide renderer failed"))
            };
        }
        if Instant::now() >= deadline {
            stop(&mut child);
            return Err(failed("the slide renderer timed out"));
        }
        std::thread::sleep(Duration::from_millis(50));
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
