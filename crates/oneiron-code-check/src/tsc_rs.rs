//! tsc-rs in process: the pinned Wasm build of the checker
//! (`components/tsc-rs`), run on the engine's Wasmtime.
//!
//! The port keeps one program per process (`set_prog`), so a native library
//! could check one program per process. One Wasm instance stands in for that
//! process: each check instantiates the compiled module afresh, and the
//! check's memory goes with it. The instance sees a read-only, in-memory file
//! system holding only the check's files; its WASI calls get a fixed clock and
//! seeded random bytes, so a check depends on its files alone. A trap, an
//! exit, the deadline or a memory cap ends the check, never the engine.

use crate::{
    BackendId, CheckFailure, CheckInput, CheckReport, CodeCheck, DEFAULT_OUTPUT_BYTES,
    DEFAULT_WALL_TIME, Exited, TSC_ARGS, project_files,
};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::mpsc;
use std::time::{Duration, Instant};
use wasmtime::{
    Caller, Config, Engine, ExternType, InstancePre, Linker, Module, ResourceLimiter, Store,
    UpdateDeadline, Val,
};

const ARTIFACT: &[u8] = include_bytes!("../../../components/tsc-rs/artifacts/ts_rust.wasm");
const SHA256: &str = "0f384de62ca87bb609a6a5ce82fabc8b02ffa0f3f28519337c1d048c1cf056e7";
/// The tsc-rs commit the module is built from (`components/tsc-rs/build.py`).
pub const TSC_RS_COMMIT: &str = "80f9944aab296595c4c9aa4d9d1ad65d1e5f76f6";

/// The directory the check's files sit in, and tsc's working directory.
const ROOT: &str = "/check";
/// The request flags of `crates/ts_wasm`: text diagnostics on stdout, and a
/// case-sensitive file system.
const FLAGS: u32 = 0;
/// The checker recurses deeply. Its own shadow stack sits in linear memory;
/// this bounds the native stack its frames take on the check's thread.
const MAX_WASM_STACK: usize = 32 << 20;
const THREAD_STACK: usize = MAX_WASM_STACK + (8 << 20);
/// How often a check past its deadline is woken to end.
const EPOCH_TICK: Duration = Duration::from_millis(10);
/// Host calls that loop over guest memory check the deadline every this many
/// bytes or entries.
const HOST_WORK_BLOCK: usize = 1 << 16;

const ESUCCESS: i32 = 0;
const EBADF: i32 = 8;
const EFAULT: i32 = 21;
const ENOSYS: i32 = 52;

/// Bounds of the in-process checker.
#[derive(Debug, Clone, Copy)]
pub struct TscRsBudget {
    pub wall_time: Duration,
    pub memory_bytes: usize,
    pub output_bytes: usize,
    /// Checks that may run at once; another is refused as busy.
    pub concurrent: usize,
}

impl Default for TscRsBudget {
    fn default() -> Self {
        Self {
            wall_time: DEFAULT_WALL_TIME,
            memory_bytes: 1 << 30,
            output_bytes: DEFAULT_OUTPUT_BYTES,
            concurrent: 2,
        }
    }
}

/// tsc-rs, compiled once, checking each program in a fresh instance.
pub struct TscRsWasm {
    engine: Engine,
    pre: InstancePre<Host>,
    budget: TscRsBudget,
    running: AtomicUsize,
}

impl TscRsWasm {
    /// Verifies the pinned module and compiles it. Compiling takes seconds:
    /// load once, off any async runtime, and share the checker.
    ///
    /// # Errors
    ///
    /// [`CheckFailure::Unavailable`] when the module fails its pin or does
    /// not compile and link.
    pub fn load(budget: TscRsBudget) -> Result<Self, CheckFailure> {
        if format!("{:x}", Sha256::digest(ARTIFACT)) != SHA256 {
            tracing::warn!("the tsc-rs module fails its pin");
            return Err(CheckFailure::Unavailable);
        }
        let unavailable = |error: wasmtime::Error| {
            tracing::warn!(%error, "the tsc-rs module did not load");
            CheckFailure::Unavailable
        };
        let mut config = Config::new();
        // Wasmtime bounds the stack by the async stack size even when no
        // async call runs.
        config
            .epoch_interruption(true)
            .max_wasm_stack(MAX_WASM_STACK)
            .async_stack_size(MAX_WASM_STACK);
        let engine = Engine::new(&config).map_err(unavailable)?;
        let module = Module::new(&engine, ARTIFACT).map_err(unavailable)?;
        let mut linker = Linker::new(&engine);
        link(&mut linker, &module).map_err(unavailable)?;
        let pre = linker.instantiate_pre(&module).map_err(unavailable)?;
        Ok(Self {
            engine,
            pre,
            budget,
            running: AtomicUsize::new(0),
        })
    }

    /// Runs tsc once over `files` in a new instance: how it ended, and its
    /// peak linear memory.
    fn run(
        &self,
        files: BTreeMap<String, Vec<u8>>,
        deadline: Instant,
    ) -> Result<(Exited, u64), CheckFailure> {
        if Instant::now() >= deadline {
            return Err(CheckFailure::Timeout);
        }
        let mut store = Store::new(&self.engine, Host::new(files, self.budget, deadline));
        store.limiter(|host| host);
        store.set_epoch_deadline(1);
        // Epochs belong to the Engine: another check's timeout wakes this
        // store too, and it runs on until its own deadline.
        store.epoch_deadline_callback(move |_| {
            if Instant::now() >= deadline {
                Err(wasmtime::Error::new(Deadline))
            } else {
                Ok(UpdateDeadline::Continue(1))
            }
        });
        let ended = |error: &wasmtime::Error, host: &Host| {
            if error.is::<Deadline>() {
                CheckFailure::Timeout
            } else if host.over_budget {
                CheckFailure::OverBudget
            } else {
                CheckFailure::Crashed
            }
        };
        let instance = match self.pre.instantiate(&mut store) {
            Ok(instance) => instance,
            Err(error) => return Err(ended(&error, store.data())),
        };
        let memory = instance
            .get_memory(&mut store, "memory")
            .ok_or(CheckFailure::Crashed)?;
        let input = instance
            .get_typed_func::<u32, u32>(&mut store, "ts_input")
            .map_err(|_| CheckFailure::Crashed)?;
        let run = instance
            .get_typed_func::<(), i32>(&mut store, "ts_run")
            .map_err(|_| CheckFailure::Crashed)?;
        let request = [ROOT.to_owned(), FLAGS.to_string()]
            .into_iter()
            .chain(TSC_ARGS.map(str::to_owned))
            .collect::<Vec<_>>()
            .join("\0");
        let length = u32::try_from(request.len()).map_err(|_| CheckFailure::InvalidInput)?;
        let at = match input.call(&mut store, length) {
            Ok(at) => at,
            Err(error) => return Err(ended(&error, store.data())),
        };
        memory
            .write(&mut store, at as usize, request.as_bytes())
            .map_err(|_| CheckFailure::Crashed)?;
        // A panic leaves through WASI `proc_exit`, never as a return.
        let status = match run.call(&mut store, ()) {
            Ok(status) => status,
            Err(error) => return Err(ended(&error, store.data())),
        };
        let host = store.into_data();
        if host.over_budget {
            return Err(CheckFailure::OverBudget);
        }
        let exited = Exited {
            status,
            stdout: host.stdout,
            stderr: host.stderr,
        };
        Ok((exited, host.peak_memory))
    }
}

impl CodeCheck for TscRsWasm {
    fn backend(&self) -> BackendId {
        BackendId {
            name: "tsc-rs",
            pin: format!("{TSC_RS_COMMIT}+sha256:{SHA256}"),
        }
    }

    fn check(&self, input: &CheckInput<'_>) -> Result<CheckReport, CheckFailure> {
        let deadline = Instant::now() + self.budget.wall_time;
        let _slot = Slot::take(&self.running, self.budget.concurrent)?;
        let files = project_files(input)?
            .into_iter()
            .map(|(name, bytes)| (format!("{ROOT}/{name}"), bytes))
            .collect();
        let (exited, peak) = std::thread::scope(|scope| {
            let (sender, receiver) = mpsc::sync_channel(1);
            let thread = std::thread::Builder::new()
                .name("tsc-rs-check".into())
                .stack_size(THREAD_STACK)
                .spawn_scoped(scope, move || {
                    let _ = sender.send(self.run(files, deadline));
                })
                .map_err(|_| CheckFailure::Unavailable)?;
            // Past the deadline, the epoch ticks until the check returns: each
            // tick runs its deadline callback, which ends it, however late
            // its store began.
            let mut wait = deadline.saturating_duration_since(Instant::now());
            let result = loop {
                match receiver.recv_timeout(wait) {
                    Ok(result) => break result,
                    Err(mpsc::RecvTimeoutError::Timeout) => {
                        self.engine.increment_epoch();
                        wait = EPOCH_TICK;
                    }
                    Err(mpsc::RecvTimeoutError::Disconnected) => break Err(CheckFailure::Crashed),
                }
            };
            // Joined here, a panicked check is a crash: the scope would
            // otherwise re-raise it on the caller's thread.
            thread.join().map_err(|_| CheckFailure::Crashed)?;
            result
        })?;
        exited.report(self.backend(), Some(peak))
    }
}

/// One of the checker's concurrent slots, released on drop.
struct Slot<'a>(&'a AtomicUsize);

impl<'a> Slot<'a> {
    fn take(running: &'a AtomicUsize, limit: usize) -> Result<Self, CheckFailure> {
        if running.fetch_add(1, Ordering::AcqRel) >= limit {
            running.fetch_sub(1, Ordering::AcqRel);
            return Err(CheckFailure::Busy);
        }
        Ok(Self(running))
    }
}

impl Drop for Slot<'_> {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::AcqRel);
    }
}

#[derive(Debug)]
struct Deadline;

impl std::fmt::Display for Deadline {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("code_check_timeout")
    }
}

impl std::error::Error for Deadline {}

#[derive(Debug)]
struct Exit;

impl std::fmt::Display for Exit {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("code_check_exit")
    }
}

impl std::error::Error for Exit {}

/// One instance's view of the world.
struct Host {
    /// Absolute path to bytes. Every ancestor of a file is a directory.
    files: BTreeMap<String, Vec<u8>>,
    /// The result of the last `ts_host.fs` call, until `fs_take` copies it.
    staged: Vec<u8>,
    stdout: Vec<u8>,
    stderr: bool,
    output_bytes: usize,
    memory_bytes: usize,
    peak_memory: u64,
    over_budget: bool,
    clock_ns: u64,
    random: u64,
    /// Host work past it ends the check, as the epoch does guest work.
    deadline: Instant,
}

impl Host {
    fn new(files: BTreeMap<String, Vec<u8>>, budget: TscRsBudget, deadline: Instant) -> Self {
        Self {
            files,
            staged: Vec::new(),
            stdout: Vec::new(),
            stderr: false,
            output_bytes: budget.output_bytes,
            memory_bytes: budget.memory_bytes,
            peak_memory: 0,
            over_budget: false,
            // 2026-01-01T00:00:00Z; tsc reads the clock only for timings.
            clock_ns: 1_767_225_600_000_000_000,
            random: 0x9E37_79B9_7F4A_7C15,
            deadline,
        }
    }

    /// Ends long host work at the check's deadline.
    fn on_time(&self) -> wasmtime::Result<()> {
        if Instant::now() >= self.deadline {
            return Err(wasmtime::Error::new(Deadline));
        }
        Ok(())
    }

    /// splitmix64: the same bytes for every check.
    fn next_random(&mut self) -> u64 {
        self.random = self.random.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.random;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    fn is_dir(&self, path: &str) -> bool {
        let prefix = if path == "/" {
            "/".to_owned()
        } else {
            format!("{path}/")
        };
        self.files
            .range(prefix.clone()..)
            .next()
            .is_some_and(|(file, _)| file.starts_with(&prefix))
    }

    /// One file operation of `crates/ts_wasm/src/host.rs`, or `None` when it
    /// fails. The file system is read-only: tsc writes nothing under `noEmit`.
    fn fs(&self, op: i32, request: &[u8]) -> Option<Vec<u8>> {
        let path = std::str::from_utf8(request).ok()?;
        let path = match path.trim_end_matches('/') {
            "" => "/",
            trimmed => trimmed,
        };
        match op {
            // Read
            0 => self.files.get(path).cloned(),
            // Stat: `<kind> <size> <mtime ns>`
            1 => match self.files.get(path) {
                Some(bytes) => Some(format!("f {} 0", bytes.len()).into_bytes()),
                None => self.is_dir(path).then(|| b"d 0 0".to_vec()),
            },
            // ReadDir: `<kind><name>` entries, each ended by NUL
            2 => {
                if !self.is_dir(path) {
                    return None;
                }
                let prefix = if path == "/" {
                    "/".to_owned()
                } else {
                    format!("{path}/")
                };
                let mut entries = BTreeMap::new();
                for file in self.files.keys().filter(|file| file.starts_with(&prefix)) {
                    let rest = &file[prefix.len()..];
                    match rest.split_once('/') {
                        Some((dir, _)) => entries.insert(dir, 'd'),
                        None => entries.insert(rest, 'f'),
                    };
                }
                Some(
                    entries
                        .into_iter()
                        .map(|(name, kind)| format!("{kind}{name}\0"))
                        .collect::<String>()
                        .into_bytes(),
                )
            }
            // Realpath
            3 => (self.files.contains_key(path) || self.is_dir(path))
                .then(|| path.as_bytes().to_vec()),
            // Chtimes: accepted, and nothing has times to change
            7 => Some(Vec::new()),
            // Write, Append, Remove, and anything newer
            _ => None,
        }
    }
}

impl ResourceLimiter for Host {
    fn memory_growing(
        &mut self,
        _current: usize,
        desired: usize,
        _maximum: Option<usize>,
    ) -> wasmtime::Result<bool> {
        if desired > self.memory_bytes {
            self.over_budget = true;
            return Ok(false);
        }
        self.peak_memory = self.peak_memory.max(desired as u64);
        Ok(true)
    }

    fn table_growing(
        &mut self,
        _current: usize,
        desired: usize,
        _maximum: Option<usize>,
    ) -> wasmtime::Result<bool> {
        Ok(desired <= 1 << 20)
    }
}

fn memory(caller: &mut Caller<'_, Host>) -> wasmtime::Result<wasmtime::Memory> {
    caller
        .get_export("memory")
        .and_then(wasmtime::Extern::into_memory)
        .ok_or_else(|| wasmtime::Error::new(Exit))
}

fn write_bytes(caller: &mut Caller<'_, Host>, at: i32, bytes: &[u8]) -> wasmtime::Result<i32> {
    let memory = memory(caller)?;
    let Ok(at) = usize::try_from(at) else {
        return Ok(EFAULT);
    };
    Ok(match memory.write(caller, at, bytes) {
        Ok(()) => ESUCCESS,
        Err(_) => EFAULT,
    })
}

/// Links `ts_host` and every WASI call the module imports. The calls of
/// `npm/wasm/core.js` behave as there; any other WASI call is `ENOSYS`.
fn link(linker: &mut Linker<Host>, module: &Module) -> wasmtime::Result<()> {
    const WASI: &str = "wasi_snapshot_preview1";
    const ANSWERED: [&str; 9] = [
        "proc_exit",
        "sched_yield",
        "fd_write",
        "fd_fdstat_get",
        "fd_prestat_get",
        "environ_sizes_get",
        "environ_get",
        "clock_time_get",
        "random_get",
    ];
    linker.func_wrap(
        "ts_host",
        "fs",
        |mut caller: Caller<'_, Host>, op: i32, at: i32, length: i32| -> wasmtime::Result<i32> {
            let memory = memory(&mut caller)?;
            let (data, host) = memory.data_and_store_mut(&mut caller);
            let request = usize::try_from(at)
                .ok()
                .zip(usize::try_from(length).ok())
                .and_then(|(at, length)| data.get(at..at.checked_add(length)?))
                .ok_or_else(|| wasmtime::Error::new(Exit))?;
            Ok(match host.fs(op, request) {
                Some(result) => {
                    let length = i32::try_from(result.len())?;
                    host.staged = result;
                    length
                }
                None => -1,
            })
        },
    )?;
    linker.func_wrap(
        "ts_host",
        "fs_take",
        |mut caller: Caller<'_, Host>, at: i32| -> wasmtime::Result<()> {
            let staged = std::mem::take(&mut caller.data_mut().staged);
            if write_bytes(&mut caller, at, &staged)? == ESUCCESS {
                Ok(())
            } else {
                Err(wasmtime::Error::new(Exit))
            }
        },
    )?;
    linker.func_wrap(
        WASI,
        "proc_exit",
        |_: Caller<'_, Host>, _: i32| -> wasmtime::Result<()> { Err(wasmtime::Error::new(Exit)) },
    )?;
    linker.func_wrap(WASI, "sched_yield", || ESUCCESS)?;
    linker.func_wrap(
        WASI,
        "fd_write",
        |mut caller: Caller<'_, Host>,
         fd: i32,
         iovs: i32,
         count: i32,
         written: i32|
         -> wasmtime::Result<i32> {
            if fd != 1 && fd != 2 {
                return Ok(EBADF);
            }
            let memory = memory(&mut caller)?;
            let (data, host) = memory.data_and_store_mut(&mut caller);
            let word = |at: usize| -> Option<usize> {
                let bytes = data.get(at..at.checked_add(4)?)?;
                Some(u32::from_le_bytes(bytes.try_into().ok()?) as usize)
            };
            let (Ok(iovs), Ok(count)) = (usize::try_from(iovs), usize::try_from(count)) else {
                return Ok(EFAULT);
            };
            let mut total = 0_usize;
            for index in 0..count {
                if index % HOST_WORK_BLOCK == 0 {
                    host.on_time()?;
                }
                let entry = index
                    .checked_mul(8)
                    .and_then(|offset| iovs.checked_add(offset));
                let (Some(at), Some(length)) = (
                    entry.and_then(word),
                    entry.and_then(|entry| word(entry.checked_add(4)?)),
                ) else {
                    return Ok(EFAULT);
                };
                let Some(chunk) = data.get(at..at.saturating_add(length)) else {
                    return Ok(EFAULT);
                };
                // stdout carries the diagnostics; stderr only a crash's story.
                host.stderr |= fd == 2 && !chunk.is_empty();
                if fd == 1 {
                    if host.stdout.len() + chunk.len() > host.output_bytes {
                        host.over_budget = true;
                        return Err(wasmtime::Error::new(Exit));
                    }
                    host.stdout.extend_from_slice(chunk);
                }
                total += length;
            }
            let total = u32::try_from(total)?;
            write_bytes(&mut caller, written, &total.to_le_bytes())
        },
    )?;
    linker.func_wrap(
        WASI,
        "fd_fdstat_get",
        |mut caller: Caller<'_, Host>, fd: i32, at: i32| -> wasmtime::Result<i32> {
            // Not a terminal, so tsc never colors its output.
            if !(0..=2).contains(&fd) {
                return Ok(EBADF);
            }
            write_bytes(&mut caller, at, &[0; 24])
        },
    )?;
    linker.func_wrap(WASI, "fd_prestat_get", |_: i32, _: i32| EBADF)?;
    linker.func_wrap(
        WASI,
        "environ_sizes_get",
        |mut caller: Caller<'_, Host>, count: i32, size: i32| -> wasmtime::Result<i32> {
            let status = write_bytes(&mut caller, count, &0_u32.to_le_bytes())?;
            if status != ESUCCESS {
                return Ok(status);
            }
            write_bytes(&mut caller, size, &0_u32.to_le_bytes())
        },
    )?;
    linker.func_wrap(WASI, "environ_get", |_: i32, _: i32| ESUCCESS)?;
    linker.func_wrap(
        WASI,
        "clock_time_get",
        |mut caller: Caller<'_, Host>,
         _id: i32,
         _precision: i64,
         at: i32|
         -> wasmtime::Result<i32> {
            let host = caller.data_mut();
            let now = host.clock_ns;
            host.clock_ns += 1_000;
            write_bytes(&mut caller, at, &now.to_le_bytes())
        },
    )?;
    linker.func_wrap(
        WASI,
        "random_get",
        |mut caller: Caller<'_, Host>, at: i32, length: i32| -> wasmtime::Result<i32> {
            // Filled in place: the guest's own memory bounds the request.
            let memory = memory(&mut caller)?;
            let (data, host) = memory.data_and_store_mut(&mut caller);
            let Some(target) = usize::try_from(at)
                .ok()
                .zip(usize::try_from(length).ok())
                .and_then(|(at, length)| data.get_mut(at..at.checked_add(length)?))
            else {
                return Ok(EFAULT);
            };
            for block in target.chunks_mut(HOST_WORK_BLOCK) {
                host.on_time()?;
                for chunk in block.chunks_mut(8) {
                    chunk.copy_from_slice(&host.next_random().to_le_bytes()[..chunk.len()]);
                }
            }
            Ok(ESUCCESS)
        },
    )?;
    for import in module.imports() {
        let ExternType::Func(ty) = import.ty() else {
            continue;
        };
        if import.module() != WASI || ANSWERED.contains(&import.name()) {
            continue;
        }
        linker.func_new(WASI, import.name(), ty, |_, _, results: &mut [Val]| {
            if let Some(result) = results.first_mut() {
                *result = Val::I32(ENOSYS);
            }
            Ok(())
        })?;
    }
    Ok(())
}
