//! Bounded native-host process lifetime and output. No shell or global state.
use std::io::Read;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

pub(super) fn capture(
    command: &mut Command,
    limit: usize,
    timeout: Duration,
) -> Result<(bool, Vec<u8>), &'static str> {
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        command.process_group(0);
    }
    let mut child = command
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|_| "SpawnFailed")?;
    let Some(stdout) = child.stdout.take() else {
        stop(&mut child);
        return Err("MissingStdout");
    };
    let (sender, receiver) = std::sync::mpsc::sync_channel(1);
    let reader = std::thread::Builder::new()
        .name("oneiron-audio-output".into())
        .spawn(move || {
            let mut output = Vec::new();
            let result = stdout
                .take(limit as u64 + 1)
                .read_to_end(&mut output)
                .map(|_| output);
            let _ = sender.send(result);
        });
    if reader.is_err() {
        stop(&mut child);
        return Err("OutputWorkerUnavailable");
    }
    let started = Instant::now();
    let mut output = None;
    let mut status = None;
    let result = loop {
        if started.elapsed() >= timeout {
            break Err("HostDeadlineExceeded");
        }
        if output.is_none() {
            match receiver.recv_timeout(
                timeout
                    .saturating_sub(started.elapsed())
                    .min(Duration::from_millis(10)),
            ) {
                Ok(Ok(bytes)) if bytes.len() <= limit => output = Some(bytes),
                Ok(_) => break Err("ResponseTooLargeOrIo"),
                Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {}
                Err(_) => break Err("OutputWorkerFailed"),
            }
        }
        if status.is_none() {
            match child.try_wait() {
                Ok(found) => status = found,
                Err(_) => break Err("WaitFailed"),
            }
        }
        if let (Some(status), Some(bytes)) = (status, output.as_mut()) {
            break Ok((status.success(), std::mem::take(bytes)));
        }
        if output.is_some() {
            std::thread::sleep(Duration::from_millis(1));
        }
    };
    // A live leader retains its process-group id. Do not signal a potentially
    // recycled id after observing/reaping its exit.
    if result.is_err() && status.is_none() {
        stop(&mut child);
    }
    // Never join a pipe reader indefinitely if a custom trusted host has
    // escaped the process group. The stock bridge does not daemonize.
    if let Ok(reader) = reader
        && reader.is_finished()
    {
        let _ = reader.join();
    }
    result
}

fn stop(child: &mut std::process::Child) {
    #[cfg(unix)]
    if let Ok(pid) = i32::try_from(child.id()) {
        // SAFETY: this live child was spawned into its own process group above.
        unsafe {
            libc::kill(-pid, libc::SIGKILL);
        }
    }
    let _ = child.kill();
    let _ = child.wait();
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;

    #[test]
    fn blocked_native_process_returns_a_typed_deadline() {
        let mut command = Command::new("/bin/cat");
        command.stdin(Stdio::piped());
        assert_eq!(
            capture(&mut command, 128, Duration::from_millis(20)),
            Err("HostDeadlineExceeded")
        );
    }

    #[test]
    fn oversized_native_output_is_bounded_before_process_exit() {
        let mut command = Command::new("/usr/bin/yes");
        assert_eq!(
            capture(&mut command, 128, Duration::from_secs(5)),
            Err("ResponseTooLargeOrIo")
        );
    }
}
