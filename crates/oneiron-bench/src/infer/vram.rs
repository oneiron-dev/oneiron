//! GPU memory, sampled: one `nvidia-smi -lms` child streams
//! `memory.used, memory.total, name, uuid` for one GPU, and a reader thread
//! keeps the latest reading, the run's maximum and the open window's
//! maximum.
//!
//! These are sampled peaks at the poll interval, not an allocator's
//! high-water mark: a spike shorter than one interval can be missed. Without
//! `nvidia-smi` every reading is null and the run goes on.

use std::io::{BufRead as _, BufReader};
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex, PoisonError};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

#[derive(Default)]
struct Readings {
    latest: Option<u64>,
    total: Option<u64>,
    name: Option<String>,
    uuid: Option<String>,
    window: Option<u64>,
    run: Option<u64>,
    samples: u64,
}

/// The GPU the sampler reads, as `nvidia-smi` names it.
#[derive(Clone, Debug, Default)]
pub(super) struct Gpu {
    pub(super) name: Option<String>,
    pub(super) uuid: Option<String>,
    pub(super) total_mib: Option<u64>,
}

pub(super) struct Vram {
    readings: Arc<Mutex<Readings>>,
    child: Option<Child>,
    reader: Option<JoinHandle<()>>,
}

/// One CSV line: `used, total, name, uuid`, MiB without units.
fn parse(line: &str) -> Option<(u64, u64, String, String)> {
    let mut fields = line.splitn(3, ',');
    let used = fields.next()?.trim().parse().ok()?;
    let total = fields.next()?.trim().parse().ok()?;
    let (name, uuid) = fields.next()?.rsplit_once(',')?;
    Some((used, total, name.trim().to_owned(), uuid.trim().to_owned()))
}

impl Vram {
    pub(super) fn start(gpu_index: u32, poll_ms: u64) -> Self {
        let readings = Arc::new(Mutex::new(Readings::default()));
        let spawned = Command::new("nvidia-smi")
            .args([
                "--query-gpu=memory.used,memory.total,name,uuid",
                "--format=csv,noheader,nounits",
                "-i",
                &gpu_index.to_string(),
                "-lms",
                &poll_ms.to_string(),
            ])
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn();
        let mut child = match spawned {
            Ok(child) => child,
            Err(e) => {
                eprintln!("nvidia-smi unavailable ({e}); VRAM fields stay null");
                return Self {
                    readings,
                    child: None,
                    reader: None,
                };
            }
        };
        let reader = child.stdout.take().map(|stdout| {
            let readings = Arc::clone(&readings);
            std::thread::spawn(move || {
                for line in BufReader::new(stdout).lines() {
                    let Ok(line) = line else { break };
                    let Some((used, total, name, uuid)) = parse(&line) else {
                        continue;
                    };
                    let mut now = readings.lock().unwrap_or_else(PoisonError::into_inner);
                    now.latest = Some(used);
                    now.total = Some(total);
                    now.name = Some(name);
                    now.uuid = Some(uuid);
                    now.window = Some(now.window.map_or(used, |peak| peak.max(used)));
                    now.run = Some(now.run.map_or(used, |peak| peak.max(used)));
                    now.samples += 1;
                }
            })
        });
        Self {
            readings,
            child: Some(child),
            reader,
        }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Readings> {
        self.readings.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// The first reading taken after this call, waiting at most `wait`; the
    /// latest one if none comes, and `None` without a sampler.
    pub(super) fn fresh(&self, wait: Duration) -> Option<u64> {
        self.child.as_ref()?;
        let seen = self.lock().samples;
        let deadline = Instant::now() + wait;
        while Instant::now() < deadline && self.lock().samples == seen {
            std::thread::sleep(Duration::from_millis(10));
        }
        self.lock().latest
    }

    /// Starts a window: [`Self::close_window`] reports the highest reading
    /// from here.
    pub(super) fn open_window(&self) {
        self.lock().window = None;
    }

    /// The highest reading since [`Self::open_window`]; the latest reading
    /// when none came in between.
    pub(super) fn close_window(&self) -> Option<u64> {
        let now = self.lock();
        now.window.or(now.latest)
    }

    /// The highest reading since the sampler started.
    pub(super) fn run_peak(&self) -> Option<u64> {
        self.lock().run
    }

    pub(super) fn gpu(&self) -> Gpu {
        let now = self.lock();
        Gpu {
            name: now.name.clone(),
            uuid: now.uuid.clone(),
            total_mib: now.total,
        }
    }
}

impl Drop for Vram {
    fn drop(&mut self) {
        // The sampler is this bench's own child: stop it by its handle.
        if let Some(mut child) = self.child.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
        if let Some(reader) = self.reader.take() {
            let _ = reader.join();
        }
    }
}
