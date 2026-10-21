//! Native OCI session inside a no-NIC microVM.
use crate::{Error, Result};
use serde::Deserialize;
use std::{
    io::{Read, Write},
    os::unix::process::CommandExt,
    process::{Command, Stdio},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant},
};

/// The inode allowance of a native session's `/tmp`. Boot mounts it with
/// 1024 inodes; a session's scratch (a cargo dependency store and target
/// dir) holds far more files than that.
const NATIVE_SCRATCH_INODES: u32 = 1_048_576;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Start {
    command: Vec<String>,
    pids: u32,
    tmpfs_mib: u32,
    reconnect_ms: u64,
    bridge_token: String,
}

pub(crate) fn run() -> Result<()> {
    let mut channel = super::boot::connect_vsock()?;
    let mut len = [0; 4];
    channel.read_exact(&mut len)?;
    let len = u32::from_be_bytes(len) as usize;
    if len == 0 || len > 65536 {
        return Err(Error::Protocol("native session frame"));
    }
    let mut bytes = vec![0; len];
    channel.read_exact(&mut bytes)?;
    let start: Start =
        serde_json::from_slice(&bytes).map_err(|_| Error::Protocol("native session start"))?;
    if start.command.is_empty()
        || !start.command[0].starts_with('/')
        || start.pids == 0
        || start.tmpfs_mib == 0
        || start.reconnect_ms == 0
    {
        return Err(Error::Protocol("native session bounds"));
    }
    let data = std::ffi::CString::new(format!(
        "size={}m,nr_inodes={NATIVE_SCRATCH_INODES},mode=1777",
        start.tmpfs_mib
    ))
    .map_err(|_| Error::Runtime("tmpfs size"))?;
    // SAFETY: remount only the guest's existing scratch tmpfs, with a valid
    // NUL-terminated data string. This runs as the trusted guest PID 1.
    if unsafe {
        libc::mount(
            std::ptr::null(),
            c"/tmp".as_ptr(),
            std::ptr::null(),
            libc::MS_REMOUNT | libc::MS_NOSUID | libc::MS_NODEV,
            data.as_ptr().cast(),
        )
    } != 0
    {
        return Err(std::io::Error::last_os_error().into());
    }
    super::boot::prepare_pids(start.pids)?;
    let control = connect_control(&start.bridge_token)?;
    use std::os::unix::fs::PermissionsExt;
    let directory = std::path::Path::new("/run/oneiron-native");
    std::fs::create_dir(directory)?;
    std::fs::set_permissions(directory, std::fs::Permissions::from_mode(0o711))?;
    let socket = directory.join("bridge.sock");
    let listener = std::os::unix::net::UnixListener::bind(&socket)?;
    std::fs::set_permissions(&socket, std::fs::Permissions::from_mode(0o666))?;
    let mut command = Command::new("/usr/local/bin/oneiron-fence");
    command
        .arg(&socket)
        .arg(&start.bridge_token)
        .arg(start.reconnect_ms.to_string())
        .arg("--")
        .args(&start.command)
        .env_clear()
        .env("ONEIRON_FENCE_INHERIT_GROUP", "1")
        .env("PATH", "/usr/local/bin:/usr/bin:/bin")
        .env("HOME", "/tmp")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .process_group(0);
    // SAFETY: pre_exec only applies the existing syscall-only privilege drop.
    unsafe {
        command.pre_exec(move || {
            super::boot::restrict_native_child(start.pids, start.tmpfs_mib)
                .map_err(std::io::Error::other)
        });
    }
    let mut child = command.spawn()?;
    let _fence = oneiron_container::serve_native_fence(
        listener,
        child.id() as i32,
        &start.bridge_token,
        Arc::new(crate::egress::VsockRelay),
    )
    .map_err(std::io::Error::other)?;
    channel.write_all(&[1])?;
    let mut input = child.stdin.take().ok_or(Error::Runtime("native stdin"))?;
    let mut output = child.stdout.take().ok_or(Error::Runtime("native stdout"))?;
    let mut writer = channel.try_clone()?;
    std::thread::spawn(move || {
        let _ = std::io::copy(&mut output, &mut writer);
    });
    let alive = Arc::new(AtomicBool::new(true));
    let cdp_lost = Arc::new(AtomicBool::new(false));
    let lost = Arc::clone(&cdp_lost);
    std::thread::spawn(move || {
        let _ = std::io::copy(&mut channel, &mut input);
        lost.store(true, Ordering::Release);
    });
    let monitor_alive = Arc::clone(&alive);
    let pid = child.id() as i32;
    std::thread::spawn(move || {
        monitor(
            control,
            start.bridge_token,
            pid,
            start.reconnect_ms,
            monitor_alive,
            cdp_lost,
        )
    });
    let status = child.wait()?;
    alive.store(false, Ordering::Release);
    if status.success() {
        Ok(())
    } else {
        Err(Error::Runtime("native session abandoned or failed"))
    }
}
fn connect_control(token: &str) -> Result<std::fs::File> {
    if token.len() != 32 {
        return Err(Error::Protocol("native bridge token"));
    }
    let mut stream = super::boot::connect_vsock_port(53)?;
    stream.write_all(token.as_bytes())?;
    let mut accepted = [0; 1];
    stream.read_exact(&mut accepted)?;
    if accepted != [1] {
        return Err(Error::Protocol("native bridge refused"));
    }
    Ok(stream)
}
fn monitor(
    mut stream: std::fs::File,
    token: String,
    pid: i32,
    window: u64,
    alive: Arc<AtomicBool>,
    cdp_lost: Arc<AtomicBool>,
) {
    while alive.load(Ordering::Acquire) {
        let mut ping = [0; 1];
        if !cdp_lost.load(Ordering::Acquire)
            && stream
                .write_all(&[1])
                .and_then(|()| stream.read_exact(&mut ping))
                .is_ok()
        {
            std::thread::sleep(Duration::from_millis(250));
            continue;
        }
        // SAFETY: native was spawned in the owned group pgid=pid.
        unsafe {
            libc::kill(-pid, libc::SIGSTOP);
        }
        let deadline = Instant::now() + Duration::from_millis(window);
        let mut recovered = false;
        while alive.load(Ordering::Acquire) && Instant::now() < deadline {
            if !cdp_lost.load(Ordering::Acquire)
                && let Ok(next) = connect_control(&token)
            {
                stream = next;
                recovered = true;
                break;
            }
            std::thread::sleep(Duration::from_millis(100));
        }
        if !alive.load(Ordering::Acquire) {
            return;
        }
        // SAFETY: resume or terminate only the same owned native group.
        unsafe {
            libc::kill(
                -pid,
                if recovered {
                    libc::SIGCONT
                } else {
                    libc::SIGKILL
                },
            );
        }
        if !recovered {
            return;
        }
    }
}
