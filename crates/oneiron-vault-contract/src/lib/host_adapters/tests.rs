use super::*;
use crate::host::{Host, HostLimits, shed_before_reap};
use std::{
    collections::BTreeMap,
    sync::{Arc, Mutex},
    time::{Duration, SystemTime},
};

const LIMITS: HostLimits = HostLimits {
    memory_bytes: 1 << 20,
    cpu_millis_per_second: 1000,
};

#[tokio::test]
async fn in_process_boot_ready_idle_wake_and_restart() -> anyhow::Result<()> {
    let events = Arc::new(Mutex::new(Vec::new()));
    let (r, s) = (events.clone(), events.clone());
    let listener = std::net::TcpListener::bind("127.0.0.1:0")?;
    let address = listener.local_addr()?;
    let mut host = InProcessHost::new(
        listener,
        LIMITS,
        move || {
            r.lock().unwrap().push("ready");
            Ok(())
        },
        move || {
            s.lock().unwrap().push("stop");
            Ok(())
        },
    );
    host.insert_secret("dek".into(), Zeroizing::new(vec![7; 32]));
    assert_eq!(host.secret("dek")?.as_slice(), &[7; 32]);
    assert!(host.secret("missing").is_err());
    assert_eq!(host.limits(), LIMITS);
    host.start(|listener| {
        assert_eq!(listener.local_addr()?, address);
        Ok(())
    })?;
    let wake = host.wake_handle();
    // An idle without a deadline must really park until an inbound wake.
    assert!(
        tokio::time::timeout(Duration::from_millis(2), host.idle(None))
            .await
            .is_err()
    );
    wake.notify_one();
    tokio::time::timeout(Duration::from_secs(1), host.idle(None)).await??;
    host.idle(Some(SystemTime::now())).await?;
    host.restart(|_| Ok(()))?;
    host.stop()?;
    assert_eq!(*events.lock().unwrap(), ["ready", "stop", "ready", "stop"]);
    Ok(())
}

#[cfg(unix)]
#[tokio::test]
async fn activated_adapters_keep_socket_and_deliver_readiness() -> anyhow::Result<()> {
    use std::io::Read;
    use std::os::unix::net::{UnixDatagram, UnixListener, UnixStream};
    let dir = tempfile::tempdir()?;
    let path = dir.path().join("systemd.sock");
    let listener = UnixListener::bind(&path)?;
    let (notify, receiver) = UnixDatagram::pair()?;
    let mut systemd =
        SystemdHost::with_notify_socket(listener, BTreeMap::new(), LIMITS, notify, || Ok(()));
    systemd.start(|adopted| {
        let _client = UnixStream::connect(&path)?;
        adopted.accept()?;
        Ok(())
    })?;
    let mut buf = [0; 16];
    let len = receiver.recv(&mut buf)?;
    assert_eq!(&buf[..len], b"READY=1");
    systemd.idle(Some(SystemTime::now())).await?;
    systemd.restart(|_| Ok(()))?;
    systemd.stop()?;
    assert!(path.exists());

    let path = dir.path().join("launchd.sock");
    let listener = UnixListener::bind(&path)?;
    let (ready, mut receiver) = UnixStream::pair()?;
    let mut launchd = LaunchdHost::new(listener, BTreeMap::new(), LIMITS, ready, || Ok(()));
    launchd.start(|adopted| {
        assert_eq!(adopted.local_addr()?.as_pathname(), Some(path.as_path()));
        Ok(())
    })?;
    let mut byte = [0];
    receiver.read_exact(&mut byte)?;
    assert_eq!(byte, [crate::READY_BYTE]);
    launchd.idle(Some(SystemTime::now())).await?;
    launchd.restart(|_| Ok(()))?;
    receiver.read_exact(&mut byte)?;
    assert_eq!(byte, [crate::READY_BYTE]);
    launchd.stop()?;
    assert!(path.exists());
    Ok(())
}

#[derive(Default)]
struct Sandbox {
    events: Vec<&'static str>,
    wake: Option<SystemTime>,
}
impl SandboxBackend for Sandbox {
    type Listener = ();
    fn listener(&mut self) -> anyhow::Result<()> {
        self.events.push("listen");
        Ok(())
    }
    fn ready(&mut self) -> anyhow::Result<()> {
        self.events.push("ready");
        Ok(())
    }
    fn secret(&mut self, _: &str) -> anyhow::Result<Zeroizing<Vec<u8>>> {
        Ok(Zeroizing::new(vec![1]))
    }
    fn stop(&mut self) -> anyhow::Result<()> {
        self.events.push("stop");
        Ok(())
    }
    fn limits(&self) -> HostLimits {
        LIMITS
    }
    fn sleep(&mut self, next: Option<SystemTime>) -> HostFuture<'_> {
        Box::pin(async move {
            self.wake = next;
            self.events.push("sleep");
            Ok(())
        })
    }
}
impl EdgeBackend for Sandbox {
    fn boot(&mut self) -> anyhow::Result<()> {
        self.events.push("boot");
        Ok(())
    }
    fn suspend_until(&mut self, next: Option<SystemTime>) -> HostFuture<'_> {
        self.events.push("suspend");
        self.sleep(next)
    }
}
#[tokio::test]
async fn sandbox_and_edge_forward_capabilities_and_next_wake_without_exit() -> anyhow::Result<()> {
    let at = SystemTime::now();
    let mut wasm = WasmHost(Sandbox::default());
    wasm.start(|_| Ok(()))?;
    assert_eq!(wasm.secret("dek")?.as_slice(), &[1]);
    assert_eq!(wasm.limits(), LIMITS);
    wasm.idle(Some(at)).await?;
    assert_eq!(wasm.0.wake, Some(at));
    wasm.restart(|_| Ok(()))?;
    wasm.stop()?;
    assert_eq!(
        wasm.0.events,
        [
            "listen", "ready", "sleep", "stop", "listen", "ready", "stop"
        ]
    );
    let mut edge = MicroVmHost(Sandbox::default());
    edge.start(|_| Ok(()))?;
    edge.idle(Some(at)).await?;
    assert_eq!(edge.0.wake, Some(at));
    edge.restart(|_| Ok(()))?;
    edge.stop()?;
    assert_eq!(
        edge.0.events,
        [
            "boot", "listen", "ready", "suspend", "sleep", "stop", "boot", "listen", "ready",
            "stop"
        ]
    );
    Ok(())
}

#[test]
fn pressure_sheds_before_unchanged_reap_decision() -> anyhow::Result<()> {
    let events = std::cell::RefCell::new(Vec::new());
    let outcome = shed_before_reap(
        2,
        |request| {
            assert!(matches!(
                request,
                crate::CtlRequest::Shed {
                    cause: crate::ShedCause::MemoryPressure,
                    waited_secs: 2
                }
            ));
            events.borrow_mut().push("shed");
            Ok("refused")
        },
        || {
            events.borrow_mut().push("reap");
            false
        },
    );
    assert_eq!(outcome.0?, "refused");
    assert!(!outcome.1);
    assert_eq!(*events.borrow(), ["shed", "reap"]);
    Ok(())
}

#[test]
fn ctl_failure_does_not_skip_or_replace_the_host_reap_predicate() {
    let attempted = std::cell::Cell::new(false);
    let (shed, reap) = shed_before_reap(2, |_| {
        attempted.set(true);
        Err::<(),_>(anyhow::anyhow!("ctl unavailable"))
    }, || {assert!(attempted.get()); true});
    assert!(shed.is_err());
    assert!(reap);
}
