//! Native OCI sessions in a no-NIC Firecracker VM. The OCI digest is bound
//! by host configuration to a pinned, bootable rootfs containing the guest agent.

use super::{FirecrackerHostConfig, config, launch, refused};
use crate::{
    Result,
    code_sandbox::{
        SandboxGuestTier,
        microvm::{ExecutionBudget, GuestImage, MicroVmHandle},
    },
};
use oneiron_container::{
    EgressRelay, FenceProof, GuestSeccomp, GuestSpec, SessionLease, SessionManifest,
    SessionTransport, image_release,
};
use serde::Deserialize;
use std::os::unix::net::{UnixListener, UnixStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::{
    ffi::OsString,
    io::{Read, Write},
    path::PathBuf,
    process::Child,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct OciBoot {
    image: String,
    kernel: PathBuf,
    rootfs: PathBuf,
    component: PathBuf,
}
pub(super) fn resolve(image: &str, source: &str) -> Result<GuestImage> {
    let path = std::env::var_os("ONEIRON_MICROVM_OCI_IMAGES")
        .ok_or_else(|| refused("OCI boot-image registry unavailable"))?;
    let bytes = config::read_regular_bounded(std::path::Path::new(&path), 64 * 1024)?;
    let images: Vec<OciBoot> =
        serde_json::from_slice(&bytes).map_err(|_| refused("OCI boot-image registry malformed"))?;
    let row = images
        .into_iter()
        .find(|row| row.image == image)
        .ok_or_else(|| refused("OCI digest has no pinned microVM rootfs"))?;
    Ok(GuestImage::new(row.kernel, row.rootfs, row.component).with_source(source))
}

struct Lease {
    alive: Arc<AtomicBool>,
    _control_directory: std::fs::File,
    _egress_directory: std::fs::File,
    process: launch::ProcessCustody,
    _jail: launch::JailCustody,
    _socket_directory: std::fs::File,
    _scratch: tempfile::TempDir,
}
impl Drop for Lease {
    fn drop(&mut self) {
        self.alive.store(false, Ordering::Release);
    }
}
impl SessionLease for Lease {
    fn abandoned(&self) -> bool {
        !self.alive.load(Ordering::Acquire)
    }
    fn is_running(&mut self) -> bool {
        self.process
            .0
            .lock()
            .ok()
            .and_then(|mut child| child.as_mut().map(|c| matches!(c.try_wait(), Ok(None))))
            .unwrap_or(false)
    }
}
pub(super) fn start(
    config: &FirecrackerHostConfig,
    spec: &GuestSpec,
    command: &[OsString],
    relay: Arc<dyn EgressRelay>,
) -> Result<SessionTransport> {
    config.validate()?;
    if spec.user.0 == 0
        || spec.user.1 == 0
        || [
            spec.limits.memory_mib,
            spec.limits.cpu_millis,
            spec.limits.pids,
            spec.limits.tmpfs_mib,
        ]
        .contains(&0)
    {
        return Err(refused(
            "native VM requires non-root identity and bounded resources",
        ));
    }
    let image = resolve(spec.image.as_str(), "")?;
    config.pins.verify(&image)?;
    let image_release = image_release::observe_bound_release(
        image_release::SelectedImage::Oci(&spec.image),
        &image_release::ObservedArtifacts::from_firecracker_pins(
            config.pins.kernel,
            config.pins.rootfs,
        )
        .with_image_ref(&spec.image),
        &image_release::NoVerifierConfigured,
    );
    let scratch = tempfile::tempdir()?;
    let vm = MicroVmHandle::new(
        format!("oci-{}", uuid::Uuid::now_v7().simple()),
        SandboxGuestTier::Untrusted,
        scratch.path(),
        scratch.path(),
        scratch.path().join("egress"),
    )?;
    let budget = ExecutionBudget::new(30, spec.limits.memory_mib, spec.limits.pids);
    let (jail, root, _) = launch::stage_images(config, &vm, &image, budget)?;
    let mut machine = launch::machine_config(config, budget);
    machine["boot-source"]["boot_args"] = serde_json::json!(
        "console=ttyS0 reboot=k panic=1 pci=off root=/dev/vda ro init=/sbin/oneiron-guest oneiron.native_session=1"
    );
    let machine_bytes =
        serde_json::to_vec(&machine).map_err(|_| refused("native machine config"))?;
    std::fs::write(root.join("machine.json"), &machine_bytes)?;
    let (directory, endpoint, listener) =
        launch::bind_guest_listener(&root, config.uid, config.gid)?;
    let (control_directory, _, control_listener) =
        launch::bind_guest_listener_port(&root, config.uid, config.gid, 53)?;
    let (egress_directory, _, egress_listener) =
        launch::bind_guest_listener_port(&root, config.uid, config.gid, 54)?;
    egress_listener.set_nonblocking(true)?;
    control_listener.set_nonblocking(true)?;
    listener.set_nonblocking(true)?;
    let child = launch::jailer_command_with_cpu(config, &vm, budget, spec.limits.cpu_millis)
        .spawn()
        .map_err(|_| refused("OCI VM launch"))?;
    let child: Arc<Mutex<Option<Child>>> = Arc::new(Mutex::new(Some(child)));
    let process = launch::ProcessCustody(Arc::clone(&child));
    let deadline = Instant::now() + Duration::from_secs(30);
    let mut stream = loop {
        match listener.accept() {
            Ok((stream, _)) => break stream,
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock && Instant::now() < deadline => {
                std::thread::sleep(Duration::from_millis(10))
            }
            _ => return Err(refused("OCI VM did not connect")),
        }
    };
    stream.set_read_timeout(Some(Duration::from_secs(30)))?;
    stream.set_write_timeout(Some(Duration::from_secs(30)))?;
    let command: Vec<_> = command
        .iter()
        .map(|s| {
            s.to_str()
                .map(str::to_owned)
                .ok_or_else(|| refused("native command encoding"))
        })
        .collect::<Result<_>>()?;
    let token = uuid::Uuid::now_v7().simple().to_string();
    let reconnect = oneiron_container::bridge_reconnect_window()
        .map_err(|_| refused("invalid bridge reconnect window"))?;
    let start = serde_json::to_vec(&serde_json::json!({"command": command, "pids": spec.limits.pids,
        "tmpfs_mib": spec.limits.tmpfs_mib, "reconnect_ms": reconnect.as_millis() as u64, "bridge_token": token})).map_err(|_| refused("native session start"))?;
    stream.write_all(&(start.len() as u32).to_be_bytes())?;
    stream.write_all(&start)?;
    let alive = Arc::new(AtomicBool::new(true));
    super::egress::serve(egress_listener, relay, Arc::clone(&alive));
    let control_alive = Arc::clone(&alive);
    let control_child = Arc::clone(&child);
    std::thread::spawn(move || {
        control(
            control_listener,
            token,
            control_alive,
            control_child,
            reconnect,
        )
    });
    let mut ready = [0; 1];
    stream.read_exact(&mut ready)?;
    if ready != [1] {
        return Err(refused("native guest refused"));
    }
    stream.set_read_timeout(None)?;
    stream.set_write_timeout(None)?;
    let hash = blake3::hash(&machine_bytes).to_hex().to_string();
    let mut argv = blake3::Hasher::new();
    let invocation = launch::jailer_command_with_cpu(config, &vm, budget, spec.limits.cpu_millis);
    argv.update(invocation.get_program().as_encoded_bytes());
    for arg in invocation.get_args() {
        argv.update(&[0]);
        argv.update(arg.as_encoded_bytes());
    }
    argv.update(&start);
    let proof = FenceProof { ruleset_hash: hash.clone(), seccomp_hash: blake3::hash(&config::read_regular_bounded(&config.firecracker, 256*1024*1024)?).to_hex().to_string(),
        network_routes: vec!["no NIC; vsock CDP/control/egress; every native connect and DNS lookup relayed by engine".into()], network_evidence_digest: hash.clone(),
        sandbox_generation: vm.id().to_owned(), launcher_digest: config.pins.rootfs.iter().map(|b| format!("{b:02x}")).collect() };
    let manifest = SessionManifest {
        backend: "firecracker-oci".into(),
        runtime: config.firecracker.display().to_string(),
        image: spec.image.as_str().into(),
        argv_digest: argv.finalize().to_hex().to_string(),
        network: "no-nic; engine-egress-relay".into(),
        seccomp: GuestSeccomp::RuntimeDefault,
        generation: vm.id().to_owned(),
        fence_proof: Some(proof),
        fence_unproven: false,
        image_release,
    };
    // The lease owns listener-path custody until the VM stops. The browser's
    // network stays on the host CDP Fetch door, not a guest NIC.
    let writer = stream.try_clone()?;
    let _ = (endpoint, listener);
    Ok(SessionTransport {
        reader: Box::new(stream),
        writer: Box::new(writer),
        manifest,
        lease: Box::new(Lease {
            alive,
            _control_directory: control_directory,
            _egress_directory: egress_directory,
            process,
            _jail: jail,
            _socket_directory: directory,
            _scratch: scratch,
        }),
    })
}

fn control(
    listener: UnixListener,
    token: String,
    alive: Arc<AtomicBool>,
    child: Arc<Mutex<Option<Child>>>,
    window: Duration,
) {
    let mut last_seen = Instant::now();
    while alive.load(Ordering::Acquire) {
        if last_seen.elapsed() >= window {
            alive.store(false, Ordering::Release);
            launch::terminate(&child);
            return;
        }
        let mut stream = match listener.accept() {
            Ok((stream, _)) => stream,
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                std::thread::sleep(Duration::from_millis(20));
                continue;
            }
            Err(_) => return,
        };
        let _ = stream.set_read_timeout(Some(Duration::from_millis(500)));
        let _ = stream.set_write_timeout(Some(Duration::from_millis(500)));
        let mut bytes = [0; 32];
        if stream.read_exact(&mut bytes).is_err() || bytes.as_slice() != token.as_bytes() {
            continue;
        }
        if stream.write_all(&[1]).is_err() {
            continue;
        }
        while alive.load(Ordering::Acquire) {
            if last_seen.elapsed() >= window {
                break;
            }
            let mut ping = [0; 1];
            match stream.read_exact(&mut ping) {
                Ok(()) => {
                    last_seen = Instant::now();
                    if stream.write_all(&[1]).is_err() {
                        break;
                    }
                }
                Err(e)
                    if matches!(
                        e.kind(),
                        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                    ) =>
                {
                    continue;
                }
                Err(_) => break,
            }
        }
        let _ = stream.shutdown(std::net::Shutdown::Both);
    }
}
