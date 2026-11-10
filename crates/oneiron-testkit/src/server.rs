//! A server process on a free port, started and stopped by the test.
//!
//! The test process binds `127.0.0.1:0` itself and hands the listening socket
//! to the server through systemd socket activation (`LISTEN_FDS=1`, the
//! socket at descriptor 3, `LISTEN_PID` the server's own pid), the way
//! `oneiron-server serve` adopts one (`DesktopHost::detect`). It then blocks
//! on `NOTIFY_SOCKET` until the server sends `READY=1`, which serve does only
//! once its startup has finished. So there is no port race, no fixed port,
//! no health polling and no sleep. The test keeps the socket, so a server
//! killed and started again comes back on the same port, and requests made
//! in between wait in the socket's backlog.
//!
//! Unix only: socket activation and the notify socket are Unix facilities.

use std::ffi::{OsStr, OsString};
use std::io;
use std::net::{SocketAddr, TcpListener};
use std::os::fd::AsRawFd;
use std::os::unix::net::UnixDatagram;
use std::path::{Path, PathBuf};
use std::process::{Child, ExitStatus};
use std::time::{Duration, Instant};

/// The longest a server may take to send `READY=1`.
pub const STARTUP_LIMIT: Duration = Duration::from_secs(120);
/// How often the wait for `READY=1` checks that the server is still alive.
const LIVENESS_CHECK: Duration = Duration::from_millis(250);
/// The descriptor socket activation passes the listener at.
const LISTEN_FD: i32 = 3;
/// The notify socket's file name inside its temporary directory.
const NOTIFY_SOCKET_NAME: &str = "notify.sock";
/// The longest notify socket path this kit binds. A Unix socket path must fit
/// `sun_path`: 108 bytes on Linux and 104 on macOS, the closing NUL included.
const NOTIFY_PATH_LIMIT: usize = 100;
/// Where the notify directory goes when the temporary directory's own path is
/// too long for a socket (a CI job's `TMPDIR` under a deep work directory).
const SHORT_TEMP_ROOT: &str = "/tmp";

/// A fresh directory for the notify socket: under the temporary directory, or
/// under [`SHORT_TEMP_ROOT`] when the socket path there would not fit
/// [`NOTIFY_PATH_LIMIT`].
fn notify_dir() -> io::Result<tempfile::TempDir> {
    let mut builder = tempfile::Builder::new();
    builder.prefix("oneiron-testkit-notify-");
    let dir = builder.tempdir()?;
    if dir.path().join(NOTIFY_SOCKET_NAME).as_os_str().len() <= NOTIFY_PATH_LIMIT {
        return Ok(dir);
    }
    drop(dir);
    builder.tempdir_in(SHORT_TEMP_ROOT)
}

/// What to start: a program, its arguments and environment.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServerSpec {
    program: PathBuf,
    args: Vec<OsString>,
    env: Vec<(OsString, OsString)>,
    current_dir: Option<PathBuf>,
}

impl ServerSpec {
    /// `program` with no arguments. A server test passes
    /// `env!("CARGO_BIN_EXE_oneiron-server")`; the E2E seeding script passes
    /// the prebuilt artifact's path.
    #[must_use]
    pub fn new(program: impl Into<PathBuf>) -> Self {
        Self {
            program: program.into(),
            args: Vec::new(),
            env: Vec::new(),
            current_dir: None,
        }
    }

    /// `program serve --config <config>`: the oneiron server on a config
    /// file the test wrote (`host`, `port`, `vault_path`, `[keystore]`, as
    /// `tests/e2e/support/engine.ts` writes one). The port in it is not
    /// used: the server listens on the socket this kit hands it.
    #[must_use]
    pub fn serve(program: impl Into<PathBuf>, config: &Path) -> Self {
        Self::new(program)
            .arg("serve")
            .arg("--config")
            .arg(config)
    }

    /// Adds one argument.
    #[must_use]
    pub fn arg(mut self, arg: impl AsRef<OsStr>) -> Self {
        self.args.push(arg.as_ref().to_owned());
        self
    }

    /// Sets one environment variable for the server.
    #[must_use]
    pub fn env(mut self, key: impl AsRef<OsStr>, value: impl AsRef<OsStr>) -> Self {
        self.env.push((key.as_ref().to_owned(), value.as_ref().to_owned()));
        self
    }

    /// Runs the server in `dir`.
    #[must_use]
    pub fn current_dir(mut self, dir: impl Into<PathBuf>) -> Self {
        self.current_dir = Some(dir.into());
        self
    }
}

/// A running server, killed when dropped.
#[derive(Debug)]
pub struct ServerProcess {
    spec: ServerSpec,
    listener: TcpListener,
    addr: SocketAddr,
    notify_dir: tempfile::TempDir,
    /// The notify socket the running server reports to. Held until the child
    /// is reaped: serve sends `STOPPING=1` on a graceful stop, and fails its
    /// shutdown when nothing listens.
    notify: Option<UnixDatagram>,
    child: Option<Child>,
}

impl ServerProcess {
    /// Binds a free loopback port, starts `spec` on it and returns once the
    /// server says it is ready.
    ///
    /// # Errors
    /// The port cannot be bound, the server cannot be started, or it exits or
    /// stays silent past [`STARTUP_LIMIT`] before saying it is ready.
    pub fn spawn(spec: ServerSpec) -> io::Result<Self> {
        let listener = TcpListener::bind(("127.0.0.1", 0))?;
        let addr = listener.local_addr()?;
        let notify_dir = notify_dir()?;
        let mut server = Self {
            spec,
            listener,
            addr,
            notify_dir,
            notify: None,
            child: None,
        };
        server.start()?;
        Ok(server)
    }

    fn start(&mut self) -> io::Result<()> {
        let notify_path = self.notify_dir.path().join(NOTIFY_SOCKET_NAME);
        let _ = std::fs::remove_file(&notify_path);
        let notify = UnixDatagram::bind(&notify_path)?;
        notify.set_read_timeout(Some(LIVENESS_CHECK))?;
        // `sh` puts the server's own pid in LISTEN_PID: `exec` keeps the pid
        // `$$` names, and socket activation is only taken by that pid.
        let mut command =
            oneiron_spawn::command_with_fds("/bin/sh", &[(self.listener.as_raw_fd(), LISTEN_FD)]);
        command
            .arg("-c")
            .arg("LISTEN_PID=$$; export LISTEN_PID; exec \"$0\" \"$@\"")
            .arg(&self.spec.program)
            .args(&self.spec.args)
            .env_remove("LISTEN_PID")
            .env_remove("LISTEN_FDNAMES")
            .env("LISTEN_FDS", "1")
            .env("NOTIFY_SOCKET", &notify_path);
        for (key, value) in &self.spec.env {
            command.env(key, value);
        }
        if let Some(dir) = &self.spec.current_dir {
            command.current_dir(dir);
        }
        let mut child = command.spawn()?;
        let started = Instant::now(); // testkit-lint: allow(wall-clock) the startup limit only
        let mut message = [0_u8; 512];
        loop {
            match notify.recv(&mut message) {
                Ok(read) if String::from_utf8_lossy(&message[..read]).lines().any(|line| line == "READY=1") => {
                    break;
                }
                Ok(_) => {}
                Err(error)
                    if matches!(error.kind(), io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut) => {}
                Err(error) => {
                    let _ = child.kill();
                    let _ = child.wait();
                    return Err(error);
                }
            }
            if let Some(status) = child.try_wait()? {
                return Err(io::Error::other(format!(
                    "{} exited ({status}) before it was ready",
                    self.spec.program.display()
                )));
            }
            if started.elapsed() > STARTUP_LIMIT {
                let _ = child.kill();
                let _ = child.wait();
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    format!("{} was not ready within {STARTUP_LIMIT:?}", self.spec.program.display()),
                ));
            }
        }
        self.child = Some(child);
        self.notify = Some(notify);
        Ok(())
    }

    /// `http://127.0.0.1:<port>`.
    #[must_use]
    pub fn base_url(&self) -> String {
        format!("http://{}", self.addr)
    }

    /// The loopback address the server listens on.
    #[must_use]
    pub fn addr(&self) -> SocketAddr {
        self.addr
    }

    /// The server's pid, while it runs.
    #[must_use]
    pub fn pid(&self) -> Option<u32> {
        self.child.as_ref().map(Child::id)
    }

    /// Kills the server with SIGKILL, as a crash or power cut would, and
    /// reaps it. Nothing it had not made durable survives.
    ///
    /// # Errors
    /// The server is not running, or the kill fails.
    pub fn kill(&mut self) -> io::Result<ExitStatus> {
        let mut child = self
            .child
            .take()
            .ok_or_else(|| io::Error::other("the server is not running"))?;
        child.kill()?;
        let status = child.wait();
        self.notify = None;
        status
    }

    /// Stops the server with SIGTERM, as a service manager would, and waits
    /// for it to exit.
    ///
    /// # Errors
    /// The server is not running, or the signal fails.
    pub fn stop(&mut self) -> io::Result<ExitStatus> {
        let mut child = self
            .child
            .take()
            .ok_or_else(|| io::Error::other("the server is not running"))?;
        let pid = libc::pid_t::try_from(child.id()).map_err(io::Error::other)?;
        // SAFETY: kill(2) on the pid of a child this process has not reaped,
        // so it cannot name another process.
        if unsafe { libc::kill(pid, libc::SIGTERM) } != 0 {
            return Err(io::Error::last_os_error());
        }
        let status = child.wait();
        self.notify = None;
        status
    }

    /// Starts the server again with the same spec, on the same port, and
    /// waits until it is ready. Kill or stop it first.
    ///
    /// # Errors
    /// It is still running, or it does not start (see [`Self::spawn`]).
    pub fn restart(&mut self) -> io::Result<()> {
        if self.child.is_some() {
            return Err(io::Error::other("the server is still running; kill or stop it first"));
        }
        self.start()
    }
}

impl Drop for ServerProcess {
    fn drop(&mut self) {
        if let Some(mut child) = self.child.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}
