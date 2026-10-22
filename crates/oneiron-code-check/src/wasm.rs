//! The Wasmtime runner of the in-process backends: tsc-rs
//! (`components/tsc-rs`) and tsrs (`vendor/tsrs`).
//!
//! The ports keep one program per process (`set_prog`), so a native library
//! could check one program per process. One Wasm instance stands in for that
//! process: each check instantiates the compiled module afresh, and the
//! check's memory goes with it. The instance sees a read-only, in-memory file
//! system holding only the check's files; its WASI calls get a fixed clock and
//! seeded random bytes, so a check depends on its files alone. A trap, an
//! exit, the deadline or a memory cap ends the check, never the engine.
//!
//! Checks take the checker's slots in the order they arrive. A check that
//! finds every slot taken waits its turn until its own deadline, and times
//! out there (FIX 8561).
//!
//! A backend names its module's ABI in an [`Abi`]; the request, the file
//! system and the WASI calls are the same for both.
//!
//! A check keeps everything the checker prints on stdout, with no bound of
//! its own: the wall time and the memory bound end a check, and whatever it
//! printed whole by then stays as a partial report (FIX 8277).

use crate::{CheckFailure, CheckInput, Exited, Stopped, TSC_ARGS, TscRsBudget, project_files};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, VecDeque};
use std::sync::{Condvar, Mutex, PoisonError, mpsc};
use std::time::{Duration, Instant};
use wasmtime::{
    Caller, Config, Engine, ExternType, ImportType, InstancePre, Linker, Module, ResourceLimiter,
    Store, UpdateDeadline, Val,
};

/// The directory the check's files sit in, and tsc's working directory.
const ROOT: &str = "/check";
/// The request flags of `crates/ts_wasm` and `crates/tsrs_wasm`: text
/// diagnostics on stdout, a case-sensitive file system, and no terminal.
const FLAGS: u32 = 0;
/// The check's thread holds the guest's native frames and this much more.
const THREAD_STACK_SLACK: usize = 8 << 20;
/// How often a check past its deadline is woken to end.
const EPOCH_TICK: Duration = Duration::from_millis(10);
/// Host calls that loop over guest memory check the deadline every this many
/// bytes or entries.
const HOST_WORK_BLOCK: usize = 1 << 16;
const WASI: &str = "wasi_snapshot_preview1";
/// The calls of a backend's host module: the file system the checker reads.
const HOST_CALLS: [&str; 2] = ["fs", "fs_take"];

const ESUCCESS: i32 = 0;
const EBADF: i32 = 8;
const EFAULT: i32 = 21;
const ENOSYS: i32 = 52;

/// How one backend's module meets the runner.
#[derive(Clone, Copy)]
pub(crate) struct Abi {
    /// The backend's name, in its logs and its check thread's name.
    pub(crate) name: &'static str,
    /// The module the file-system calls ([`fs`], [`fs_take`]) are imported
    /// from. Any other import outside WASI fails the load.
    pub(crate) host: &'static str,
    /// `(length) -> pointer`: a buffer for the request.
    pub(crate) input: &'static str,
    /// `() -> status`: runs the request.
    pub(crate) run: &'static str,
    /// Whether the module exports `_initialize`, called before the request.
    pub(crate) initialize: bool,
    /// The native stack the guest's frames may take on the check's thread.
    /// The guest's own shadow stack sits in its linear memory.
    pub(crate) max_wasm_stack: usize,
    /// Registers [`fs`] and [`fs_take`] under [`Self::host`].
    pub(crate) link_host: fn(&mut Linker<Host>) -> wasmtime::Result<()>,
}

/// One backend's module, compiled once, checking each program in a fresh
/// instance.
pub(crate) struct WasmCheck {
    abi: Abi,
    engine: Engine,
    pre: InstancePre<Host>,
    budget: TscRsBudget,
    slots: Slots,
}

impl WasmCheck {
    /// Verifies the pinned module and compiles it. Compiling takes seconds:
    /// load once, off any async runtime, and share the checker.
    ///
    /// # Errors
    ///
    /// [`CheckFailure::Unavailable`] when the module fails its pin, imports a
    /// call no host serves, or does not compile and link.
    pub(crate) fn load(
        abi: Abi,
        artifact: &[u8],
        sha256: &str,
        budget: TscRsBudget,
    ) -> Result<Self, CheckFailure> {
        if format!("{:x}", Sha256::digest(artifact)) != sha256 {
            tracing::warn!("the {} module fails its pin", abi.name);
            return Err(CheckFailure::Unavailable);
        }
        let unavailable = |error: wasmtime::Error| {
            tracing::warn!(%error, "the {} module did not load", abi.name);
            CheckFailure::Unavailable
        };
        let mut config = Config::new();
        // Wasmtime bounds the stack by the async stack size even when no
        // async call runs.
        config
            .epoch_interruption(true)
            .max_wasm_stack(abi.max_wasm_stack)
            .async_stack_size(abi.max_wasm_stack);
        let engine = Engine::new(&config).map_err(unavailable)?;
        let module = Module::new(&engine, artifact).map_err(unavailable)?;
        // A custom import is never answered as an unknown WASI call.
        if let Some(import) = module.imports().find(|import| !served(&abi, import)) {
            tracing::warn!(
                module = import.module(),
                name = import.name(),
                "the {} module imports a call no host serves",
                abi.name
            );
            return Err(CheckFailure::Unavailable);
        }
        let mut linker = Linker::new(&engine);
        (abi.link_host)(&mut linker).map_err(unavailable)?;
        link_wasi(&mut linker, &module).map_err(unavailable)?;
        let pre = linker.instantiate_pre(&module).map_err(unavailable)?;
        Ok(Self {
            abi,
            engine,
            pre,
            budget,
            slots: Slots::new(budget.concurrent),
        })
    }

    /// Checks one program: how its run of tsc ended, and its peak linear
    /// memory; or why it stopped, with what it had printed.
    pub(crate) fn check(&self, input: &CheckInput<'_>) -> Result<(Exited, u64), Stopped> {
        let deadline = Instant::now() + self.budget.wall_time;
        let files = project_files(input, self.budget.input_bytes)?
            .into_iter()
            .map(|(name, bytes)| (format!("{ROOT}/{name}"), bytes))
            .collect();
        let _slot = self.slots.take(deadline)?;
        std::thread::scope(|scope| {
            let (sender, receiver) = mpsc::sync_channel(1);
            let thread = std::thread::Builder::new()
                .name(format!("{}-check", self.abi.name))
                .stack_size(self.abi.max_wasm_stack + THREAD_STACK_SLACK)
                .spawn_scoped(scope, move || {
                    let _ = sender.send(self.run(files, deadline));
                })
                .map_err(|_| Stopped::from(CheckFailure::Unavailable))?;
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
                    Err(mpsc::RecvTimeoutError::Disconnected) => {
                        break Err(Stopped::from(CheckFailure::Crashed));
                    }
                }
            };
            // Joined here, a panicked check is a crash: the scope would
            // otherwise re-raise it on the caller's thread.
            thread
                .join()
                .map_err(|_| Stopped::from(CheckFailure::Crashed))?;
            result
        })
    }

    /// Runs tsc once over `files` in a new instance: how it ended, and its
    /// peak linear memory; or why it stopped, with what it had printed.
    fn run(
        &self,
        files: BTreeMap<String, Vec<u8>>,
        deadline: Instant,
    ) -> Result<(Exited, u64), Stopped> {
        if Instant::now() >= deadline {
            return Err(CheckFailure::Timeout.into());
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
        let ended = |error: &wasmtime::Error, host: &mut Host| Stopped {
            failure: if error.is::<Deadline>() {
                CheckFailure::Timeout
            } else if host.over_budget {
                CheckFailure::OverBudget
            } else {
                CheckFailure::Crashed
            },
            stdout: std::mem::take(&mut host.stdout),
        };
        let instance = match self.pre.instantiate(&mut store) {
            Ok(instance) => instance,
            Err(error) => return Err(ended(&error, store.data_mut())),
        };
        let memory = instance
            .get_memory(&mut store, "memory")
            .ok_or(CheckFailure::Crashed)?;
        if self.abi.initialize {
            let initialize = instance
                .get_typed_func::<(), ()>(&mut store, "_initialize")
                .map_err(|_| CheckFailure::Crashed)?;
            if let Err(error) = initialize.call(&mut store, ()) {
                return Err(ended(&error, store.data_mut()));
            }
        }
        let input = instance
            .get_typed_func::<u32, u32>(&mut store, self.abi.input)
            .map_err(|_| CheckFailure::Crashed)?;
        let run = instance
            .get_typed_func::<(), i32>(&mut store, self.abi.run)
            .map_err(|_| CheckFailure::Crashed)?;
        let request = [ROOT.to_owned(), FLAGS.to_string()]
            .into_iter()
            .chain(TSC_ARGS.map(str::to_owned))
            .collect::<Vec<_>>()
            .join("\0");
        let length = u32::try_from(request.len()).map_err(|_| CheckFailure::InvalidInput)?;
        let at = match input.call(&mut store, length) {
            Ok(at) => at,
            Err(error) => return Err(ended(&error, store.data_mut())),
        };
        memory
            .write(&mut store, at as usize, request.as_bytes())
            .map_err(|_| CheckFailure::Crashed)?;
        // A panic leaves through WASI `proc_exit`, never as a return.
        let status = match run.call(&mut store, ()) {
            Ok(status) => status,
            Err(error) => return Err(ended(&error, store.data_mut())),
        };
        let host = store.into_data();
        if host.over_budget {
            return Err(Stopped {
                failure: CheckFailure::OverBudget,
                stdout: host.stdout,
            });
        }
        let exited = Exited {
            status,
            stdout: host.stdout,
            stderr: host.stderr,
        };
        Ok((exited, host.peak_memory))
    }
}

/// The checker's concurrent slots, taken in arrival order.
struct Slots {
    limit: usize,
    queue: Mutex<Queue>,
    /// Signalled whenever a slot frees or the head of the line changes.
    turn: Condvar,
}

#[derive(Default)]
struct Queue {
    running: usize,
    next_ticket: u64,
    /// The tickets of the checks waiting for a slot, oldest first.
    waiting: VecDeque<u64>,
}

impl Slots {
    fn new(limit: usize) -> Self {
        Self {
            limit,
            queue: Mutex::default(),
            turn: Condvar::new(),
        }
    }

    /// A slot, once every check that came first has one and one is free; a
    /// timeout when `deadline` comes first.
    fn take(&self, deadline: Instant) -> Result<Slot<'_>, CheckFailure> {
        let mut queue = self.queue.lock().unwrap_or_else(PoisonError::into_inner);
        let ticket = queue.next_ticket;
        queue.next_ticket += 1;
        queue.waiting.push_back(ticket);
        loop {
            if queue.waiting.front() == Some(&ticket) && queue.running < self.limit {
                queue.waiting.pop_front();
                queue.running += 1;
                // The next in line may find a slot free too.
                self.turn.notify_all();
                return Ok(Slot(self));
            }
            let left = deadline.saturating_duration_since(Instant::now());
            if left.is_zero() {
                queue.waiting.retain(|waiting| *waiting != ticket);
                // Its leaving may put the next in line at the head.
                self.turn.notify_all();
                return Err(CheckFailure::Timeout);
            }
            queue = self
                .turn
                .wait_timeout(queue, left)
                .unwrap_or_else(PoisonError::into_inner)
                .0;
        }
    }
}

/// One of the checker's concurrent slots, released on drop.
struct Slot<'a>(&'a Slots);

impl Drop for Slot<'_> {
    fn drop(&mut self) {
        let mut queue = self.0.queue.lock().unwrap_or_else(PoisonError::into_inner);
        queue.running -= 1;
        self.0.turn.notify_all();
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
pub(crate) struct Host {
    /// Absolute path to bytes. Every ancestor of a file is a directory.
    files: BTreeMap<String, Vec<u8>>,
    /// The result of the last host `fs` call, until `fs_take` copies it.
    staged: Vec<u8>,
    stdout: Vec<u8>,
    stderr: bool,
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

    /// One file operation of `crates/ts_wasm/src/host.rs` (the numbering
    /// `crates/tsrs_wasm/src/host.rs` keeps), or `None` when it fails. The
    /// file system is read-only: tsc writes nothing under `noEmit`.
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

/// The host module's `fs(op, at, length)`: one file operation on the
/// request at `at`. Its result is staged for [`fs_take`] and its length
/// returned; a failed operation is -1, "not found".
pub(crate) fn fs(
    mut caller: Caller<'_, Host>,
    op: i32,
    at: i32,
    length: i32,
) -> wasmtime::Result<i32> {
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
}

/// The host module's `fs_take(at)`: copies the staged result to `at`.
pub(crate) fn fs_take(mut caller: Caller<'_, Host>, at: i32) -> wasmtime::Result<()> {
    let staged = std::mem::take(&mut caller.data_mut().staged);
    if write_bytes(&mut caller, at, &staged)? == ESUCCESS {
        Ok(())
    } else {
        Err(wasmtime::Error::new(Exit))
    }
}

/// Whether the runner serves `import`: WASI answers any WASI call, and the
/// backend's host module its file-system calls.
fn served(abi: &Abi, import: &ImportType<'_>) -> bool {
    import.module() == WASI || (import.module() == abi.host && HOST_CALLS.contains(&import.name()))
}

/// Links every WASI call the module imports. The calls of the ports' JS
/// hosts (`npm/wasm/core.js`) behave as there; any other WASI call is
/// `ENOSYS`.
fn link_wasi(linker: &mut Linker<Host>, module: &Module) -> wasmtime::Result<()> {
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
