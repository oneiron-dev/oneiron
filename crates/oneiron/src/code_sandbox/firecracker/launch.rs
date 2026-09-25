//! Jailer launch, resource ceilings and process custody for one microVM.

use super::{FirecrackerHostConfig, config, protocol, refused};
use crate::{
    Result,
    code_sandbox::{
        SandboxProposalWrite,
        microvm::{
            CredentialEgressProxy, CredentialReadTransport, ExecutionBudget, GuestImage,
            MicroVmExit, MicroVmHandle,
        },
    },
};
use serde_json::json;
use std::{
    fs, io,
    os::fd::AsRawFd,
    os::unix::{
        fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
        net::{UnixListener, UnixStream},
        process::CommandExt,
    },
    path::Path,
    process::{Child, Command, Stdio},
    sync::{Arc, Mutex, mpsc},
    time::{Duration, Instant},
};

pub(super) fn run(
    config: &FirecrackerHostConfig,
    vm: &MicroVmHandle,
    image: &GuestImage,
    budget: ExecutionBudget,
    proxy: &CredentialEgressProxy,
    transport: Option<&dyn CredentialReadTransport>,
) -> Result<(MicroVmExit, Vec<SandboxProposalWrite>)> {
    let (_jail_custody, jail_root, staged) = stage_images(config, vm, image, budget)?;
    // Firecracker's guest-initiated vsock connects to <uds_path>_<port>.
    // Bind BEFORE boot so there is no transport-ready race or permissive retry.
    let (_socket_directory, endpoint, listener) =
        bind_guest_listener(&jail_root, config.uid, config.gid)?;
    let mut command = jailer_command(config, vm, budget);
    let child = command
        .spawn()
        .map_err(|_| refused("jailer launch failed"))?;
    let child = Arc::new(Mutex::new(Some(child)));
    let custody = ProcessCustody(child.clone());
    let deadline = Instant::now()
        .checked_add(Duration::from_secs(budget.wall_clock_secs))
        .ok_or_else(|| refused("invalid VM deadline"))?;
    let (finish, wait) = mpsc::channel();
    let output = std::thread::scope(|scope| {
        let endpoint = endpoint.clone();
        scope.spawn(move || {
            if matches!(
                wait.recv_timeout(Duration::from_secs(budget.wall_clock_secs)),
                Err(mpsc::RecvTimeoutError::Timeout)
            ) {
                terminate(&child);
                // Unblock accept without leaving a detached wait thread.
                let _ = UnixStream::connect(endpoint);
            }
        });
        let result = (|| {
            let (stream, _) = listener
                .accept()
                .map_err(|_| refused("guest connection failed"))?;
            let component = config::read_regular_bounded(&staged.component, 64 * 1024 * 1024)?;
            protocol::exchange(
                stream,
                vm,
                protocol::GuestProgram {
                    component: &component,
                    source: &image.source,
                },
                budget,
                deadline,
                proxy,
                transport,
            )
        })();
        let _ = finish.send(());
        result
    });
    // Success seals proposals then terminates this guest. Error and timeout
    // terminate it too. Never leave a guest running while collecting deltas.
    drop(custody);
    output
}

// Keep the directory descriptor alive until both the listener and watchdog are
// finished. A /proc/self/fd path avoids sockaddr_un's small pathname limit,
// without chdir (process-global), a public short-path alias, or a different jail.
fn bind_guest_listener(
    jail_root: &Path,
    uid: u32,
    gid: u32,
) -> Result<(fs::File, std::path::PathBuf, UnixListener)> {
    let directory = fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(jail_root)
        .map_err(|_| refused("vsock directory open failed"))?;
    let endpoint = std::path::PathBuf::from(format!(
        "/proc/self/fd/{}/vsock.sock_52",
        directory.as_raw_fd()
    ));
    let listener =
        UnixListener::bind(&endpoint).map_err(|_| refused("vsock listener bind failed"))?;
    fs::set_permissions(&endpoint, fs::Permissions::from_mode(0o600))
        .map_err(|_| refused("vsock permissions failed"))?;
    std::os::unix::fs::chown(&endpoint, Some(uid), Some(gid))
        .map_err(|_| refused("vsock owner setup failed"))?;
    Ok((directory, endpoint, listener))
}

fn stage_images(
    config: &FirecrackerHostConfig,
    vm: &MicroVmHandle,
    image: &GuestImage,
    budget: ExecutionBudget,
) -> Result<(JailCustody, std::path::PathBuf, GuestImage)> {
    // Host copies, never hard links: even a mistaken guest/VMM write cannot
    // alter the original host artifacts. Recheck pins on these exact copies.
    ensure_private_tree(&config.chroot_base)?;
    let name = config
        .firecracker
        .file_name()
        .ok_or_else(|| refused("binary has no file name"))?;
    let executable_dir = config.chroot_base.join(name);
    ensure_private_tree(&executable_dir)?;
    let jail = executable_dir.join(vm.id());
    fs::create_dir(&jail)
        .map_err(|_| refused("jailer instance already exists or cannot be created"))?;
    fs::set_permissions(&jail, fs::Permissions::from_mode(0o700))
        .map_err(|_| refused("jailer instance permissions failed"))?;
    let jail_custody = JailCustody {
        path: jail.clone(),
        cgroup: std::path::PathBuf::from("/sys/fs/cgroup")
            .join(&config.cgroup_parent)
            .join(vm.id()),
    };
    let jail_root = jail.join("root");
    fs::create_dir(&jail_root).map_err(|_| refused("jailer root creation failed"))?;
    let staged = GuestImage::new(
        jail_root.join("kernel"),
        jail_root.join("rootfs"),
        jail_root.join("component"),
    );
    for (source, target, max) in [
        (&image.kernel, &staged.kernel, 64 * 1024 * 1024),
        (&image.rootfs, &staged.rootfs, 4 * 1024 * 1024 * 1024_u64),
        (&image.component, &staged.component, 64 * 1024 * 1024),
    ] {
        config::stage_artifact(source, target, max)?;
        fs::set_permissions(target, fs::Permissions::from_mode(0o444))
            .map_err(|_| refused("jailer artifact permissions failed"))?;
    }
    config.pins.verify(&staged)?;
    let machine = machine_config(config, budget);
    fs::write(jail_root.join("machine.json"), machine.to_string())
        .map_err(|_| refused("machine config write failed"))?;
    Ok((jail_custody, jail_root, staged))
}

fn machine_config(config: &FirecrackerHostConfig, budget: ExecutionBudget) -> serde_json::Value {
    json!({
        "boot-source": {
            "kernel_image_path":"/kernel",
            "boot_args":"console=ttyS0 reboot=k panic=1 pci=off root=/dev/vda ro init=/sbin/oneiron-guest"
        },
        "drives":[{"drive_id":"rootfs","path_on_host":"/rootfs","is_root_device":true,"is_read_only":true}],
        "machine-config":{"vcpu_count":config.vcpus,"mem_size_mib":budget.mem_mib,"smt":false},
        "vsock":{"guest_cid":3,"uds_path":"/vsock.sock"}
    })
}

fn jailer_command(
    config: &FirecrackerHostConfig,
    vm: &MicroVmHandle,
    budget: ExecutionBudget,
) -> Command {
    let mut command = Command::new(&config.jailer);
    // No environment passthrough, shell, NIC, daemonization, or extra host mounts.
    command
        .env_clear()
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .process_group(0)
        .arg("--id")
        .arg(vm.id())
        .arg("--exec-file")
        .arg(&config.firecracker)
        .arg("--uid")
        .arg(config.uid.to_string())
        .arg("--gid")
        .arg(config.gid.to_string())
        .arg("--chroot-base-dir")
        .arg(&config.chroot_base)
        .args(["--cgroup-version", "2", "--parent-cgroup"])
        .arg(&config.cgroup_parent)
        .arg("--cgroup")
        .arg(format!("pids.max={}", budget.pids))
        .arg("--cgroup")
        .arg(format!(
            "memory.max={}",
            (u64::from(budget.mem_mib) + 128) * 1024 * 1024
        ))
        .arg("--cgroup")
        .arg("memory.swap.max=0")
        .arg("--cgroup")
        .arg(format!(
            "cpu.max={} 100000",
            u64::from(config.vcpus) * 100_000
        ))
        .args(["--", "--no-api", "--config-file", "/machine.json"]);
    command
}

fn ensure_private_tree(path: &Path) -> Result<()> {
    // Check all ancestors, not only the final pathname. Root and the configured
    // state parents must remain host-owned; no guest-writable symlink walk.
    let mut current = std::path::PathBuf::new();
    for part in path.components() {
        current.push(part);
        match fs::symlink_metadata(&current) {
            Ok(metadata) if metadata.is_dir() && !metadata.is_symlink() => {}
            Ok(_) => return Err(refused("jailer state crosses a non-directory or symlink")),
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                fs::create_dir(&current).map_err(|_| refused("jailer state creation failed"))?;
                fs::set_permissions(&current, fs::Permissions::from_mode(0o700))
                    .map_err(|_| refused("jailer state permissions failed"))?;
            }
            Err(_) => return Err(refused("jailer state inspection failed")),
        }
    }
    let metadata =
        fs::symlink_metadata(path).map_err(|_| refused("jailer directory metadata unavailable"))?;
    if metadata.uid() != 0 || metadata.permissions().mode() & 0o022 != 0 {
        return Err(refused("jailer directory is not privately host-owned"));
    }
    Ok(())
}

struct JailCustody {
    path: std::path::PathBuf,
    cgroup: std::path::PathBuf,
}
impl Drop for JailCustody {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
        let _ = fs::remove_dir(&self.cgroup);
    }
}

struct ProcessCustody(Arc<Mutex<Option<Child>>>);
impl Drop for ProcessCustody {
    fn drop(&mut self) {
        terminate(&self.0);
    }
}
fn terminate(child: &Mutex<Option<Child>>) {
    if let Ok(mut slot) = child.lock()
        && let Some(mut child) = slot.take()
    {
        let Ok(pid) = i32::try_from(child.id()) else {
            return;
        };
        // SAFETY: the child was started in its own process group with pgid=pid.
        // Negative pid targets only that owned group, never the engine's group.
        unsafe { libc::kill(-pid, libc::SIGKILL) };
        let _ = child.kill();
        let _ = child.wait();
    }
}

#[cfg(test)]
#[path = "launch/tests.rs"]
mod tests;
