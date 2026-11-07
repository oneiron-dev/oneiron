//! One native thread owns each private G child, independently of Tokio teardown.
use std::io::{self, Read, Write};
use std::os::fd::AsRawFd;
use std::os::unix::net::UnixStream;
use std::os::unix::process::CommandExt;
use std::path::PathBuf;
use std::process::{Child, Stdio};
use std::sync::{Mutex, Weak};

use oneiron_driver::WorkerExit;
use tokio::sync::{oneshot, watch};

use super::super::{Custody, GroupPin, pin_group};
use crate::mac_worker_bootstrap::{sys, wire};

type Ready = oneshot::Sender<io::Result<()>>;

pub(super) struct Start {
    pub(super) cli: PathBuf,
    pub(super) original: libc::pid_t,
    pub(super) peer: UnixStream,
    pub(super) stop: UnixStream,
    pub(super) terminal: UnixStream,
}

pub(super) fn start(
    state: Weak<Mutex<Custody>>,
    exit: watch::Receiver<Option<WorkerExit>>,
    start: Start,
) -> io::Result<(
    oneshot::Receiver<io::Result<()>>,
    oneshot::Receiver<io::Error>,
)> {
    let (ready_tx, ready) = oneshot::channel();
    let (failed_tx, failed) = oneshot::channel();
    crate::engine_thread("worker-guardian".to_owned()).spawn(move || {
        let mut ready = Some(ready_tx);
        if let Err(error) = control(state, exit, start, &mut ready) {
            if let Some(ready) = ready.take() {
                let _ = ready.send(Err(error));
            } else {
                let _ = failed_tx.send(error);
            }
        }
    })?;
    Ok((ready, failed))
}

fn control(
    state: Weak<Mutex<Custody>>,
    exit: watch::Receiver<Option<WorkerExit>>,
    start: Start,
    ready: &mut Option<Ready>,
) -> io::Result<()> {
    let Start {
        cli,
        original,
        peer,
        stop,
        terminal,
    } = start;
    let mut peer = Some(peer);
    let mut stop = Some(stop);
    let mut terminal = Some(terminal);
    let mut stopping = false;
    let mut reaper_unknown = false;
    loop {
        // This spawn may block before initial CLI exec. It holds no W pin and
        // knows no W group, so W stop/reaping cannot depend on it returning.
        let mut guardian = Guardian::spawn(&cli, original, peer.take())?;
        let Some(state) = state.upgrade() else {
            guardian.finish()?;
            return Ok(());
        };
        let Some(pin) = pin_group(&state, &exit) else {
            guardian.finish()?;
            return Ok(());
        };
        drop(state);
        let group = pin.group();
        guardian.pin = Some(pin);
        let armed = guardian.arm(group, &mut stop, &mut terminal, &exit);
        match armed {
            Ok(true) => {
                guardian.pin.take();
            }
            Ok(false) => {
                guardian.finish()?;
                return Ok(());
            }
            Err(error) => {
                guardian.finish()?;
                return Err(error);
            }
        }
        // The only numeric join finished, and initial W peer-ACK was received.
        // A closed ready receiver is ordinary preOk cancellation, not S death.
        if let Some(ready) = ready.take() {
            let _ = ready.send(Ok(()));
        }
        guardian.control.take();
        loop {
            if exit.borrow().is_some() {
                guardian.finish()?;
                return Ok(());
            }
            let fds = [fd(&stop), fd(&terminal), guardian.event.fd()];
            let read = sys::readable(&fds)?;
            if read[0] {
                stop.take();
                stopping = true;
            }
            if read[1] {
                terminal.take();
                if exit.borrow().is_some() {
                    guardian.finish()?;
                    return Ok(());
                }
                // Sender loss is UNKNOWN, not a worker exit. Keep the armed G
                // and its parent watch until the real CLI process exits.
                reaper_unknown = exit.has_changed().is_err();
            }
            if read[2] {
                if guardian.exited()? {
                    if stopping
                        || reaper_unknown
                        || exit.has_changed().is_err()
                        || exit.borrow().is_some()
                    {
                        return Ok(());
                    }
                    break;
                }
            }
        }
    }
}

fn fd(stream: &Option<UnixStream>) -> i32 {
    stream.as_ref().map_or(-1, AsRawFd::as_raw_fd)
}

struct Guardian {
    child: Option<Child>,
    event: sys::ProcessEvent,
    control: Option<UnixStream>,
    pin: Option<GroupPin>,
    terminal: bool,
    custody_lost: bool,
}

impl Guardian {
    fn spawn(
        cli: &std::path::Path,
        original: libc::pid_t,
        peer: Option<UnixStream>,
    ) -> io::Result<Self> {
        let (control, theirs) = sys::socket_pair()?;
        control.set_nonblocking(true)?;
        let mut sources = vec![theirs.as_raw_fd()];
        if let Some(peer) = &peer {
            sources.push(peer.as_raw_fd());
        }
        let placed = sys::placements(&sources);
        let peer_arg = placed
            .get(1)
            .map_or_else(|| "-".to_owned(), |pair| pair.1.to_string());
        let mut command = oneiron_spawn::command_with_fds(cli, &placed);
        command
            .args([
                wire::MARKER,
                "guardian",
                &original.to_string(),
                &placed[0].1.to_string(),
                &peer_arg,
            ])
            .process_group(0)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        let mut child = command.spawn()?;
        // No duplicated peer writer survives here; W's peer EOF is meaningful.
        drop(peer);
        drop(theirs);
        let event = match sys::ProcessEvent::attach(child.id() as _) {
            Ok(event) => event,
            Err(error) => {
                // No W identity or authorization exists yet on this path.
                let killed = child.kill();
                match child.wait() {
                    Ok(_) => {
                        let _ = killed;
                        return Err(error);
                    }
                    Err(wait) => {
                        // Keep the actual handle on an ownership break; no later
                        // numeric signal or fabricated terminal result is safe.
                        let _ = Box::leak(Box::new(child));
                        return Err(wait);
                    }
                }
            }
        };
        Ok(Self {
            child: Some(child),
            event,
            control: Some(control),
            pin: None,
            terminal: false,
            custody_lost: false,
        })
    }

    fn arm(
        &mut self,
        group: i32,
        stop: &mut Option<UnixStream>,
        terminal: &mut Option<UnixStream>,
        exit: &watch::Receiver<Option<WorkerExit>>,
    ) -> io::Result<bool> {
        let bytes = group.to_be_bytes();
        let mut written = 0;
        loop {
            if exit.borrow().is_some() {
                return Ok(false);
            }
            if written != bytes.len() {
                match self.control.as_mut().unwrap().write(&bytes[written..]) {
                    Ok(0) => return Err(io::ErrorKind::WriteZero.into()),
                    Ok(got) => {
                        written += got;
                        continue;
                    }
                    Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock => {}
                    Err(error) => return Err(error),
                }
            }
            let control = self.control.as_ref().unwrap().as_raw_fd();
            // Authorization is four bytes on an otherwise empty private socket.
            // POLLOUT is needed only if the nonblocking write was interrupted
            // by backpressure; stop/terminal events remain independently live.
            let mut polls = [
                libc::pollfd {
                    fd: fd(stop),
                    events: libc::POLLIN,
                    revents: 0,
                },
                libc::pollfd {
                    fd: fd(terminal),
                    events: libc::POLLIN,
                    revents: 0,
                },
                libc::pollfd {
                    fd: self.event.fd(),
                    events: libc::POLLIN,
                    revents: 0,
                },
                libc::pollfd {
                    fd: control,
                    events: if written == bytes.len() {
                        libc::POLLIN
                    } else {
                        libc::POLLOUT
                    },
                    revents: 0,
                },
            ];
            // SAFETY: initialized pollfd array retained throughout this call.
            let rc = unsafe { libc::poll(polls.as_mut_ptr(), polls.len() as _, -1) };
            if rc < 0 {
                let error = io::Error::last_os_error();
                if error.kind() == io::ErrorKind::Interrupted {
                    continue;
                }
                return Err(error);
            }
            if polls[0].revents != 0 {
                stop.take();
                return Ok(false);
            }
            if polls[1].revents != 0 {
                terminal.take();
                return Ok(false);
            }
            if polls[2].revents != 0 && self.exited()? {
                return Err(io::Error::other("guardian exited before arming"));
            }
            if written == bytes.len() && polls[3].revents != 0 {
                let mut reply = [0];
                match self.control.as_mut().unwrap().read(&mut reply) {
                    Ok(1) if reply[0] == wire::ARMED => return Ok(true),
                    Err(error)
                        if matches!(
                            error.kind(),
                            io::ErrorKind::Interrupted | io::ErrorKind::WouldBlock
                        ) =>
                    {
                        continue;
                    }
                    _ => return Err(io::Error::other("guardian did not arm")),
                }
            }
        }
    }

    fn exited(&mut self) -> io::Result<bool> {
        if !self.event.exited()? {
            return Ok(false);
        }
        // Consume the actual G exit event before the sole owned wait. Even if
        // kernel exit notification precedes waitability, do not spin on an
        // unread kqueue event or substitute it for the owned terminal result.
        match self.child.as_mut().unwrap().wait() {
            Ok(_) => {
                self.terminal = true;
                self.pin.take();
                Ok(true)
            }
            Err(error) => {
                self.custody_lost = true;
                Err(error)
            }
        }
    }

    fn finish(&mut self) -> io::Result<()> {
        if self.terminal {
            return Ok(());
        }
        let killed = self.child.as_mut().unwrap().kill();
        match self.child.as_mut().unwrap().wait() {
            Ok(_) => {
                self.terminal = true;
                self.pin.take();
                // A failed signal is not a failed terminal confirmation.
                let _ = killed;
                Ok(())
            }
            Err(error) => {
                self.custody_lost = true;
                Err(error)
            }
        }
    }
}

impl Drop for Guardian {
    fn drop(&mut self) {
        if self.terminal {
            return;
        }
        if !self.custody_lost {
            if let Err(error) = self.finish() {
                tracing::error!(kind = ?error.kind(), "private guardian custody was lost");
            }
        }
        if self.custody_lost {
            // Outside the sole-owned-child/no-external-reaper contract, keep
            // actual custody until process exit. A still-join-capable G never
            // releases W's pin on an unknown status. Stop may remain pending.
            if let Some(child) = self.child.take() {
                let _ = Box::leak(Box::new((child, self.pin.take())));
            }
        }
    }
}
