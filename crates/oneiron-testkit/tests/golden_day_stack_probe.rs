//! Scratch stack probe for the golden day (OPUS-TESTKIT, row
//! DREAMER-MICRO-CONSOLIDATION-DEV-STACK-DEPTH; never a PR). Each test runs
//! the whole day with its Dreamer pass on the calling thread's own stack.
//!
//! - `stack_high_water_of_the_whole_day`: a 64 MiB thread whose stack is
//!   painted first; after the day the deepest overwritten word gives the
//!   stack the day used (`## STACK-HIGH-WATER`).
//! - `overflow_chain_of_the_whole_day`: a thread of `PROBE_STACK_KIB` KiB
//!   (default 2048) with a SIGSEGV handler on its own 8 MiB alternate stack.
//!   On an overflow it prints the depth of the faulting stack pointer
//!   (`## OVERFLOW-AT`); with `PROBE_CHAIN` set also every word on the live
//!   stack that points into the test binary's text (`## RA depth= vaddr=`,
//!   return-address candidates, symbolised by the batch script) and the std
//!   backtrace; then it exits 86. A day that fits prints `## OVERFLOW-NONE`.

use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use oneiron_testkit::dreamer::PassStack;
use oneiron_testkit::golden_day;

const MIB: usize = 1024 * 1024;
const KIB: usize = 1024;
const PAINT: u64 = 0xA5A5_A5A5_A5A5_A5A5;
const ALT_STACK_BYTES: usize = 8 * MIB;
const OVERFLOW_EXIT: i32 = 86;

static TOP: AtomicUsize = AtomicUsize::new(0);
static STACK_LO: AtomicUsize = AtomicUsize::new(0);
static TEXT_LO: AtomicUsize = AtomicUsize::new(usize::MAX);
static TEXT_HI: AtomicUsize = AtomicUsize::new(0);
static BIAS: AtomicUsize = AtomicUsize::new(usize::MAX);
static STACK_KIB: AtomicUsize = AtomicUsize::new(0);
static CHAIN: AtomicBool = AtomicBool::new(false);

#[inline(never)]
fn stack_address() -> usize {
    let marker = 0_u8;
    std::hint::black_box(&raw const marker) as usize
}

fn run_day() -> String {
    let backend = golden_day::backend();
    let outcome = match golden_day::run_on(&backend, PassStack::CallingThread) {
        Ok(_) => "ok".to_owned(),
        Err(error) => format!("refused: {error}"),
    };
    match backend.check() {
        Ok(()) => outcome,
        Err(mismatch) => format!("{outcome}; script mismatch: {mismatch}"),
    }
}

/// Reads this process's mappings: the lowest address of the mapping that
/// holds `top` (this thread's stack), and the test binary's load bias and
/// text range.
fn read_maps(top: usize) {
    let maps = std::fs::read_to_string("/proc/self/maps").unwrap_or_default();
    let exe = std::fs::read_link("/proc/self/exe")
        .map(|path| path.display().to_string())
        .unwrap_or_default();
    for line in maps.lines() {
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.len() < 5 {
            continue;
        }
        let Some((start, end)) = fields[0].split_once('-') else {
            continue;
        };
        let (Ok(start), Ok(end), Ok(offset)) = (
            usize::from_str_radix(start, 16),
            usize::from_str_radix(end, 16),
            usize::from_str_radix(fields[2], 16),
        ) else {
            continue;
        };
        if start <= top && top < end {
            STACK_LO.store(start, Ordering::Relaxed);
        }
        if fields.get(5).copied() == Some(exe.as_str()) {
            if offset == 0 {
                BIAS.fetch_min(start, Ordering::Relaxed);
            }
            if fields[1].contains('x') {
                TEXT_LO.fetch_min(start, Ordering::Relaxed);
                TEXT_HI.fetch_max(end, Ordering::Relaxed);
            }
        }
    }
}

#[inline(never)]
fn paint(low: usize, high: usize) {
    let mut address = low;
    while address < high {
        // SAFETY: [low, high) lies inside this thread's own stack mapping,
        // below every live frame (high is 64 KiB under the thread's entry).
        unsafe { std::ptr::write_volatile(address as *mut u64, PAINT) };
        address += 8;
    }
}

#[inline(never)]
fn deepest_written(low: usize, high: usize) -> usize {
    let mut address = low;
    while address < high {
        // SAFETY: as in `paint`; the region is mapped and only read here.
        if unsafe { std::ptr::read_volatile(address as *const u64) } != PAINT {
            return address;
        }
        address += 8;
    }
    high
}

#[test]
fn stack_high_water_of_the_whole_day() {
    let bytes = 64 * MIB;
    let (depth, outcome) = std::thread::Builder::new()
        .stack_size(bytes)
        .spawn(|| {
            let top = stack_address();
            read_maps(top);
            let stack_lo = STACK_LO.load(Ordering::Relaxed);
            assert!(
                stack_lo != 0 && stack_lo < top,
                "no stack mapping holds {top:#x}"
            );
            let low = stack_lo + 64 * KIB;
            let high = top - 64 * KIB;
            paint(low, high);
            let outcome = run_day();
            (top - deepest_written(low, high), outcome)
        })
        .unwrap_or_else(|error| panic!("spawn: {error}"))
        .join()
        .unwrap_or_else(|_| panic!("the day panicked"));
    println!(
        "## STACK-HIGH-WATER bytes={depth} kib={} outcome={outcome}",
        depth / KIB
    );
}

extern "C" fn on_fault(
    _signal: libc::c_int,
    info: *mut libc::siginfo_t,
    context: *mut libc::c_void,
) {
    let top = TOP.load(Ordering::Relaxed);
    // SAFETY: an SA_SIGINFO handler is passed the kernel's siginfo_t and
    // ucontext_t for the fault.
    let (rsp, fault) = unsafe {
        let context = &*context.cast::<libc::ucontext_t>();
        (
            context.uc_mcontext.gregs[libc::REG_RSP as usize] as usize,
            (*info).si_addr() as usize,
        )
    };
    eprintln!(
        "## OVERFLOW-AT stack_kib={} rsp_depth={} fault_depth={}",
        STACK_KIB.load(Ordering::Relaxed),
        top.wrapping_sub(rsp),
        top.wrapping_sub(fault)
    );
    if CHAIN.load(Ordering::Relaxed) {
        let (lo, hi) = (
            TEXT_LO.load(Ordering::Relaxed),
            TEXT_HI.load(Ordering::Relaxed),
        );
        let bias = match BIAS.load(Ordering::Relaxed) {
            usize::MAX => 0,
            bias => bias,
        };
        eprintln!("## RA-MAP bias={bias:#x} text={lo:#x}-{hi:#x}");
        let mut slot = rsp.max(STACK_LO.load(Ordering::Relaxed)) & !7;
        let mut printed = 0_usize;
        while slot < top && printed < 20_000 {
            // SAFETY: [max(rsp, stack_lo), top) is this thread's mapped stack.
            let word = unsafe { std::ptr::read_volatile(slot as *const usize) };
            if word >= lo && word < hi {
                eprintln!("## RA depth={} vaddr={:#x}", top - slot, word - bias);
                printed += 1;
            }
            slot += 8;
        }
        let trace = std::backtrace::Backtrace::force_capture();
        eprintln!("## OVERFLOW-BACKTRACE BEGIN\n{trace}\n## OVERFLOW-BACKTRACE END");
    }
    // SAFETY: ends the process at once; nothing may run after an overflow.
    unsafe { libc::_exit(OVERFLOW_EXIT) }
}

fn arm_overflow_trace(top: usize, kib: usize, chain: bool) {
    TOP.store(top, Ordering::Relaxed);
    STACK_KIB.store(kib, Ordering::Relaxed);
    CHAIN.store(chain, Ordering::Relaxed);
    read_maps(top);
    let stack_lo = STACK_LO.load(Ordering::Relaxed);
    eprintln!(
        "## OVERFLOW-ARMED stack_kib={kib} usable_below_entry={} chain={chain}",
        top.saturating_sub(stack_lo)
    );
    let handler: extern "C" fn(libc::c_int, *mut libc::siginfo_t, *mut libc::c_void) = on_fault;
    // SAFETY: a fresh anonymous mapping becomes this thread's alternate signal
    // stack, and the handler above replaces the process's SIGSEGV and SIGBUS
    // handlers for the rest of this probe process.
    unsafe {
        let alt = libc::mmap(
            std::ptr::null_mut(),
            ALT_STACK_BYTES,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
            -1,
            0,
        );
        assert!(alt != libc::MAP_FAILED, "no alternate stack");
        let stack = libc::stack_t {
            ss_sp: alt,
            ss_flags: 0,
            ss_size: ALT_STACK_BYTES,
        };
        assert_eq!(libc::sigaltstack(&raw const stack, std::ptr::null_mut()), 0);
        let mut action: libc::sigaction = std::mem::zeroed();
        action.sa_sigaction = handler as libc::sighandler_t;
        action.sa_flags = libc::SA_SIGINFO | libc::SA_ONSTACK;
        libc::sigemptyset(&raw mut action.sa_mask);
        assert_eq!(
            libc::sigaction(libc::SIGSEGV, &raw const action, std::ptr::null_mut()),
            0
        );
        assert_eq!(
            libc::sigaction(libc::SIGBUS, &raw const action, std::ptr::null_mut()),
            0
        );
    }
}

#[test]
fn overflow_chain_of_the_whole_day() {
    let kib = std::env::var("PROBE_STACK_KIB")
        .ok()
        .and_then(|value| value.parse::<usize>().ok())
        .unwrap_or(2048);
    let chain = std::env::var_os("PROBE_CHAIN").is_some();
    let outcome = std::thread::Builder::new()
        .stack_size(kib * KIB)
        .spawn(move || {
            arm_overflow_trace(stack_address(), kib, chain);
            run_day()
        })
        .unwrap_or_else(|error| panic!("spawn: {error}"))
        .join()
        .unwrap_or_else(|_| panic!("the day panicked"));
    println!("## OVERFLOW-NONE stack_kib={kib} outcome={outcome}");
}
