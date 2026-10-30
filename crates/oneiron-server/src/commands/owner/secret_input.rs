//! A secret read from stdin (FIX 1490). From a terminal, the command asks
//! for it on stderr and turns the terminal's echo off until the read ends,
//! however it ends, so the secret never shows on the screen or in its
//! scrollback. A signal (Unix) or a console control event (Windows) that
//! ends the process mid-read (Ctrl-C) turns the echo back on before it ends
//! it. From a pipe or a file it is
//! read as given, as before. The caller reads into its own wiped buffer;
//! nothing is copied here.

use std::io::{self, Read};
#[cfg(unix)]
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
#[cfg(windows)]
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicUsize, Ordering};

/// How much of a terminal's input one secret is.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum TerminalRead {
    /// One line: the secret ends at the line break the owner types (a
    /// password, a PRF output, a seed, a kit passphrase).
    Line,
    /// Everything up to the end of input, Ctrl-D: a secret value kept
    /// exactly as typed, or a kit of several lines.
    ToEnd,
}

/// Runs `read` over stdin for the secret `what` names. On a terminal it is
/// asked for on stderr first, its input is not echoed, and with
/// [`TerminalRead::Line`] the read ends at the first line break; the echo
/// comes back before this returns, on every path. A pipe or a file is
/// handed to `read` whole, as before.
pub(super) fn read_stdin_secret<T>(
    what: &str,
    terminal: TerminalRead,
    read: impl FnOnce(&mut dyn Read) -> anyhow::Result<T>,
) -> anyhow::Result<T> {
    let mut stdin = super::raw_stdin()?;
    let Some(echo) = EchoOff::on_terminal()? else {
        return read(&mut stdin);
    };
    match terminal {
        TerminalRead::Line => eprint!("Enter {what} (input hidden): "),
        TerminalRead::ToEnd => eprint!("Enter {what}, then Ctrl-D (input hidden): "),
    }
    let answer = match terminal {
        TerminalRead::Line => read(&mut OneLine {
            input: &mut stdin,
            ended: false,
        }),
        TerminalRead::ToEnd => read(&mut stdin),
    };
    drop(echo);
    // The line break the owner typed was not echoed.
    eprintln!();
    answer
}

/// A terminal's input up to and including its first line break. It reads
/// one byte at a time into the caller's buffer, so nothing past the line
/// is taken from the terminal and no copy of the secret is left behind.
struct OneLine<R> {
    input: R,
    ended: bool,
}

impl<R: Read> Read for OneLine<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if self.ended || buf.is_empty() {
            return Ok(0);
        }
        let read = self.input.read(&mut buf[..1])?;
        if read == 0 || buf[0] == b'\n' {
            self.ended = true;
        }
        Ok(read)
    }
}

/// The echo bits a hidden read turned off: what a signal that ends the
/// process turns back on, since it runs no `Drop`
/// ([`restore_echo_then_end`]).
#[cfg(unix)]
static ECHO_BITS: AtomicU64 = AtomicU64::new(0);

/// Whether a hidden read is under way: what an ending signal (Unix) or a
/// console control event (Windows) restores, since neither runs `Drop`.
#[cfg(any(unix, windows))]
static ECHO_HIDDEN: AtomicBool = AtomicBool::new(false);

/// The console a hidden read quieted, and the mode it had: what a console
/// control event puts back when it ends the process, since that runs no
/// `Drop` ([`restore_echo_then_end`]).
#[cfg(windows)]
static ECHO_CONSOLE: AtomicUsize = AtomicUsize::new(0);
#[cfg(windows)]
static ECHO_SAVED_MODE: AtomicU32 = AtomicU32::new(0);

/// The signals whose default action ends the process while a read is
/// hidden: Ctrl-C, Ctrl-\, a hangup and a termination.
#[cfg(unix)]
const ENDING_SIGNALS: [libc::c_int; 4] = [libc::SIGINT, libc::SIGQUIT, libc::SIGHUP, libc::SIGTERM];

/// Stdin's terminal with its echo turned off, turned back on when dropped,
/// and by [`restore_echo_then_end`] when a signal ends the process first.
#[cfg(unix)]
struct EchoOff {
    saved: libc::termios,
    /// Each of [`ENDING_SIGNALS`]' actions before the read, put back on drop.
    previous: [libc::sigaction; 4],
}

#[cfg(unix)]
impl EchoOff {
    /// Turns echo off when stdin is a terminal; `None` for a pipe or a file.
    fn on_terminal() -> io::Result<Option<Self>> {
        // SAFETY: `isatty` reads the kind of a descriptor and touches no
        // memory of ours.
        if unsafe { libc::isatty(libc::STDIN_FILENO) } != 1 {
            return Ok(None);
        }
        let mut saved = std::mem::MaybeUninit::<libc::termios>::uninit();
        // SAFETY: `tcgetattr` writes the struct it is handed and nothing else.
        if unsafe { libc::tcgetattr(libc::STDIN_FILENO, saved.as_mut_ptr()) } != 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: `tcgetattr` returned 0, so it filled the struct.
        let saved = unsafe { saved.assume_init() };
        let hidden = libc::ECHO | libc::ECHONL;
        ECHO_BITS.store(u64::from(saved.c_lflag & hidden), Ordering::SeqCst);
        ECHO_HIDDEN.store(true, Ordering::SeqCst);
        // From here the guard puts the terminal and the handlers back.
        let guard = Self {
            saved,
            previous: ENDING_SIGNALS.map(restore_echo_on),
        };
        let mut quiet = saved;
        quiet.c_lflag &= !hidden;
        // SAFETY: `tcsetattr` reads the struct it is handed and nothing else.
        if unsafe { libc::tcsetattr(libc::STDIN_FILENO, libc::TCSAFLUSH, &raw const quiet) } != 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(Some(guard))
    }
}

#[cfg(unix)]
impl Drop for EchoOff {
    fn drop(&mut self) {
        // SAFETY: `tcsetattr` reads the struct it is handed and nothing else.
        unsafe {
            libc::tcsetattr(libc::STDIN_FILENO, libc::TCSANOW, &raw const self.saved);
        }
        ECHO_HIDDEN.store(false, Ordering::SeqCst);
        for (signal, previous) in ENDING_SIGNALS.iter().zip(&self.previous) {
            // SAFETY: `sigaction` reads the action it is handed and nothing
            // else.
            unsafe {
                libc::sigaction(*signal, previous, std::ptr::null_mut());
            }
        }
    }
}

/// Points `signal` at [`restore_echo_then_end`] and returns its action
/// before.
#[cfg(unix)]
fn restore_echo_on(signal: libc::c_int) -> libc::sigaction {
    // SAFETY: an all-zero `sigaction` is plain data: no handler, no flags,
    // an empty mask until `sigemptyset` sets it.
    let mut action: libc::sigaction = unsafe { std::mem::zeroed() };
    action.sa_sigaction = restore_echo_then_end as libc::sighandler_t;
    // SAFETY: as above, a zeroed action is a valid place to receive one.
    let mut previous: libc::sigaction = unsafe { std::mem::zeroed() };
    // SAFETY: `sigemptyset` writes the set it is handed, and `sigaction`
    // reads `action` and writes `previous`, nothing else.
    unsafe {
        libc::sigemptyset(&raw mut action.sa_mask);
        libc::sigaction(signal, &raw const action, &raw mut previous);
    }
    previous
}

/// A signal that ends the process arrived while a read was hidden: turn the
/// terminal's echo back on, end the line, and end the process as the
/// signal's default action would. Only async-signal-safe calls.
#[cfg(unix)]
extern "C" fn restore_echo_then_end(signal: libc::c_int) {
    if ECHO_HIDDEN.load(Ordering::SeqCst) {
        // SAFETY: an all-zero `termios` is plain data that `tcgetattr` fills.
        let mut current: libc::termios = unsafe { std::mem::zeroed() };
        let bits = ECHO_BITS.load(Ordering::SeqCst) as libc::tcflag_t;
        // SAFETY: `tcgetattr`, `tcsetattr` and `write` are async-signal-safe
        // and touch only the struct and the byte they are handed.
        unsafe {
            if libc::tcgetattr(libc::STDIN_FILENO, &raw mut current) == 0 {
                current.c_lflag |= bits;
                libc::tcsetattr(libc::STDIN_FILENO, libc::TCSANOW, &raw const current);
            }
            libc::write(libc::STDERR_FILENO, b"\n".as_ptr().cast(), 1);
        }
    }
    // SAFETY: `signal` and `raise` are async-signal-safe; with the default
    // action back, the raised signal ends the process.
    unsafe {
        libc::signal(signal, libc::SIG_DFL);
        libc::raise(signal);
    }
}

/// Stdin's console with its echo turned off, turned back on when dropped,
/// and by [`restore_echo_then_end`] when a console control event ends the
/// process first (FIX 11387, FIX 11719).
#[cfg(windows)]
struct EchoOff {
    console: windows_sys::Win32::Foundation::HANDLE,
    saved: u32,
}

#[cfg(windows)]
impl EchoOff {
    /// Turns echo off when stdin is a console; `None` for a pipe or a file.
    fn on_terminal() -> io::Result<Option<Self>> {
        use windows_sys::Win32::Foundation::{INVALID_HANDLE_VALUE, TRUE};
        use windows_sys::Win32::System::Console::{
            ENABLE_ECHO_INPUT, GetConsoleMode, GetStdHandle, STD_INPUT_HANDLE,
            SetConsoleCtrlHandler, SetConsoleMode,
        };
        // SAFETY: `GetStdHandle` reads the process's standard input handle
        // and touches no memory of ours.
        let console = unsafe { GetStdHandle(STD_INPUT_HANDLE) };
        if console == INVALID_HANDLE_VALUE {
            return Err(io::Error::last_os_error());
        }
        let mut saved: u32 = 0;
        // SAFETY: `GetConsoleMode` writes the mode it is handed and nothing
        // else; a pipe or a file is no console, so it fails and stdin is
        // read as given.
        if unsafe { GetConsoleMode(console, &mut saved) } == 0 {
            return Ok(None);
        }
        ECHO_CONSOLE.store(console as usize, Ordering::SeqCst);
        ECHO_SAVED_MODE.store(saved, Ordering::SeqCst);
        ECHO_HIDDEN.store(true, Ordering::SeqCst);
        // From here the guard puts the mode and the handler back.
        let guard = Self { console, saved };
        // SAFETY: `SetConsoleCtrlHandler` registers the routine it is
        // handed and touches no memory of ours.
        unsafe {
            SetConsoleCtrlHandler(Some(restore_echo_then_end), TRUE);
        }
        // SAFETY: `SetConsoleMode` reads the mode it is handed and nothing else.
        if unsafe { SetConsoleMode(console, saved & !ENABLE_ECHO_INPUT) } == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(Some(guard))
    }
}

#[cfg(windows)]
impl Drop for EchoOff {
    fn drop(&mut self) {
        use windows_sys::Win32::Foundation::FALSE;
        use windows_sys::Win32::System::Console::{SetConsoleCtrlHandler, SetConsoleMode};
        // SAFETY: `SetConsoleMode` reads the mode it is handed and nothing else.
        unsafe {
            SetConsoleMode(self.console, self.saved);
        }
        ECHO_HIDDEN.store(false, Ordering::SeqCst);
        // SAFETY: `SetConsoleCtrlHandler` unregisters the routine it is
        // handed and touches no memory of ours.
        unsafe {
            SetConsoleCtrlHandler(Some(restore_echo_then_end), FALSE);
        }
    }
}

/// A console control event arrived while a read was hidden: put the
/// console's mode back, then decline the event so its default action ends
/// the process, as the Unix handler re-raises its signal. Runs on the
/// system's control thread; only the mode write and atomic loads.
#[cfg(windows)]
unsafe extern "system" fn restore_echo_then_end(_event: u32) -> i32 {
    use windows_sys::Win32::Foundation::{FALSE, HANDLE};
    use windows_sys::Win32::System::Console::SetConsoleMode;
    if ECHO_HIDDEN.load(Ordering::SeqCst) {
        let console = ECHO_CONSOLE.load(Ordering::SeqCst) as HANDLE;
        let saved = ECHO_SAVED_MODE.load(Ordering::SeqCst);
        // SAFETY: `SetConsoleMode` reads the mode it is handed and nothing
        // else; the handle is stdin's console while a read is hidden.
        unsafe {
            SetConsoleMode(console, saved);
        }
    }
    FALSE
}

/// No terminal echo control off Unix and Windows: stdin is read as given.
#[cfg(not(any(unix, windows)))]
struct EchoOff;

#[cfg(not(any(unix, windows)))]
impl EchoOff {
    fn on_terminal() -> io::Result<Option<Self>> {
        Ok(None)
    }
}
