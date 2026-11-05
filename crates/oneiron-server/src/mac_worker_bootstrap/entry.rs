use std::ffi::OsString;
use std::io::{self, Read, Write};
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::net::UnixStream;
use std::os::unix::process::CommandExt;
use std::process::Stdio;

use super::sys::{self, ParentEvent};
use super::wire::{self, ExecSpec};

pub(super) fn run(args: &[OsString]) -> io::Result<()> {
    let role = args.first().and_then(|arg| arg.to_str());
    match role {
        Some("worker") if args.len() == 5 => {
            let _original = pid(&args[1])?;
            distinct(&args[2..])?;
            let control = stream(&args[2])?;
            let peer = stream(&args[3])?;
            let mut status = stream(&args[4])?;
            sys::cloexec(status.as_raw_fd())?;
            let error = worker(control, peer);
            if let Err(error) = &error {
                let code = error.raw_os_error().unwrap_or(libc::EIO);
                let _ = status.write_all(&code.to_be_bytes());
            }
            error
        }
        Some("guardian") if args.len() == 4 => {
            let original = pid(&args[1])?;
            distinct(&args[2..])?;
            let control = stream(&args[2])?;
            let peer = if args[3] == "-" {
                None
            } else {
                Some(stream(&args[3])?)
            };
            guardian(original, control, peer)
        }
        _ => Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid worker bootstrap role",
        )),
    }
}

fn pid(arg: &OsString) -> io::Result<libc::pid_t> {
    arg.to_str()
        .and_then(|value| value.parse().ok())
        .filter(|&value| value > 0)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "invalid bootstrap parent"))
}

fn distinct(args: &[OsString]) -> io::Result<()> {
    let mut descriptors = Vec::new();
    for arg in args.iter().filter(|arg| arg.as_os_str() != "-") {
        let fd = arg
            .to_str()
            .and_then(|value| value.parse::<i32>().ok())
            .filter(|&fd| fd >= 3)
            .ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidInput, "invalid bootstrap descriptor")
            })?;
        if descriptors.contains(&fd) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "repeated bootstrap descriptor",
            ));
        }
        // SAFETY: checks descriptor existence before any from_raw_fd ownership.
        if unsafe { libc::fcntl(fd, libc::F_GETFD) } < 0 {
            return Err(io::Error::last_os_error());
        }
        descriptors.push(fd);
    }
    Ok(())
}

fn stream(arg: &OsString) -> io::Result<UnixStream> {
    let fd = arg
        .to_str()
        .and_then(|value| value.parse::<i32>().ok())
        .filter(|&fd| fd >= 3)
        .ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidInput, "invalid bootstrap descriptor")
        })?;
    // SAFETY: the private role receives this single named right from the spawn
    // factory; the caller consumes each role descriptor exactly once.
    let stream = unsafe { UnixStream::from_raw_fd(fd) };
    stream.peer_addr()?;
    Ok(stream)
}

fn worker(mut control: UnixStream, mut peer: UnixStream) -> io::Result<()> {
    let spec = ExecSpec::read(&mut control);
    // Even a failed Spec/control read retains the group anchor until no join
    // can still happen. An unauthorized guardian exits and closes this peer.
    wire::byte(&mut peer, wire::JOINED)?;
    peer.write_all(&[wire::ACK])?;
    let spec = match spec {
        Ok(spec) => spec,
        Err(error) => {
            let _ = sys::term_own_group();
            return Err(error);
        }
    };
    if let Err(error) = wire::byte(&mut control, wire::EXEC) {
        let _ = sys::term_own_group();
        return Err(error);
    }
    drop(peer);
    drop(control);
    let mut command = oneiron_spawn::command(&spec.program);
    command
        .args(spec.args)
        .current_dir(spec.dir)
        .env_clear()
        .envs(spec.env)
        .stdin(Stdio::null())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit());
    // No runtime or other thread exists in this private process. The factory
    // marks the still-open exec-error writer CLOEXEC at the actual exec boundary.
    Err(command.exec())
}

fn guardian(
    original: libc::pid_t,
    mut control: UnixStream,
    mut peer: Option<UnixStream>,
) -> io::Result<()> {
    let mut parent = ParentEvent::attach(original)?;
    control.set_nonblocking(true)?;
    let Some(group) = authorization(&mut control, &mut parent)? else {
        // No complete authorization: do NOT await a W peer or late-join.
        // Closing this process's only peer right releases W's bootstrap anchor.
        return Ok(());
    };
    control.set_nonblocking(false)?;
    default_terminate()?;
    // SAFETY: this non-session-leader changes only its own group, in normal
    // pre-runtime code, after S attached the actual owned-child group pin.
    if unsafe { libc::setpgid(0, group) } < 0 {
        return Err(io::Error::last_os_error());
    }
    if let Some(peer) = &mut peer {
        peer.write_all(&[wire::JOINED])?;
        wire::byte(peer, wire::ACK)?;
    }
    drop(peer);
    // Membership is now established. An EOF/write error is NOT S's death:
    // retain the actual original-parent NOTE_EXIT watch until S really exits.
    let mut control = if control.write_all(&[wire::ARMED]).is_ok() {
        Some(control)
    } else {
        None
    };
    loop {
        if parent.dead()? {
            sys::term_own_group()?;
            return Ok(());
        }
        let fd = control.as_ref().map_or(-1, AsRawFd::as_raw_fd);
        let ready = sys::readable(&[parent.fd(), fd])?;
        if ready[1] {
            let mut byte = [0];
            match control.as_mut().map(|stream| stream.read(&mut byte)) {
                Some(Err(error)) if error.kind() == io::ErrorKind::Interrupted => continue,
                _ => {
                    control.take();
                }
            }
        }
    }
}

fn authorization(
    control: &mut UnixStream,
    parent: &mut ParentEvent,
) -> io::Result<Option<libc::pid_t>> {
    let mut bytes = [0; 4];
    let mut read = 0;
    while read != bytes.len() {
        if parent.dead()? {
            return Ok(None);
        }
        let ready = sys::readable(&[parent.fd(), control.as_raw_fd()])?;
        if !ready[1] {
            continue;
        }
        match control.read(&mut bytes[read..]) {
            Ok(0) => return Ok(None),
            Ok(got) => read += got,
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::Interrupted | io::ErrorKind::WouldBlock
                ) =>
            {
                continue;
            }
            Err(error) => return Err(error),
        }
    }
    let group = i32::from_be_bytes(bytes);
    if group <= 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid bootstrap group",
        ));
    }
    Ok(Some(group))
}

fn default_terminate() -> io::Result<()> {
    // Only G's disposition/mask changes. The configured worker keeps every
    // inherited signal disposition and mask it would have received directly.
    unsafe {
        // SAFETY: initialized sigaction and sigset buffers for these libc calls.
        let mut action: libc::sigaction = std::mem::zeroed();
        action.sa_sigaction = libc::SIG_DFL;
        libc::sigemptyset(&mut action.sa_mask);
        if libc::sigaction(libc::SIGTERM, &action, std::ptr::null_mut()) < 0 {
            return Err(io::Error::last_os_error());
        }
        let mut signals: libc::sigset_t = std::mem::zeroed();
        libc::sigemptyset(&mut signals);
        libc::sigaddset(&mut signals, libc::SIGTERM);
        if libc::sigprocmask(libc::SIG_UNBLOCK, &signals, std::ptr::null_mut()) < 0 {
            return Err(io::Error::last_os_error());
        }
    }
    Ok(())
}
