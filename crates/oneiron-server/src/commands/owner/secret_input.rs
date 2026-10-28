//! A secret read from stdin (FIX 1490). From a terminal, the command asks
//! for it on stderr and turns the terminal's echo off until the read ends,
//! however it ends, so the secret never shows on the screen or in its
//! scrollback. From a pipe or a file it is read as given, as before. The
//! caller reads into its own wiped buffer; nothing is copied here.

use std::io::{self, Read};

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

/// Stdin's terminal with its echo turned off, turned back on when dropped.
#[cfg(unix)]
struct EchoOff {
    saved: libc::termios,
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
        let mut quiet = saved;
        quiet.c_lflag &= !(libc::ECHO | libc::ECHONL);
        // SAFETY: `tcsetattr` reads the struct it is handed and nothing else.
        if unsafe { libc::tcsetattr(libc::STDIN_FILENO, libc::TCSAFLUSH, &raw const quiet) } != 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(Some(Self { saved }))
    }
}

#[cfg(unix)]
impl Drop for EchoOff {
    fn drop(&mut self) {
        // SAFETY: `tcsetattr` reads the struct it is handed and nothing else.
        unsafe {
            libc::tcsetattr(libc::STDIN_FILENO, libc::TCSANOW, &raw const self.saved);
        }
    }
}

/// No terminal echo control off Unix: stdin is read as given.
#[cfg(not(unix))]
struct EchoOff;

#[cfg(not(unix))]
impl EchoOff {
    fn on_terminal() -> io::Result<Option<Self>> {
        Ok(None)
    }
}
