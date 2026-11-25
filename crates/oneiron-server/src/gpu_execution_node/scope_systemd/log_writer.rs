//! The unit's log writer (pass 34, 7.2; R4's Q3-LOG-CONTRACT, 25 Nov 02:07,
//! with its 12:02 additions). `job-exec` starts it after the gate's go and
//! before the exec mark ([`start`]): two pipes become the workload's standard
//! output and error, and a writer process copies each into `log/<stream>`
//! beneath the payload directory.
//!
//! A file keeps at most the template's cap (`log_max_mib`). Up to the cap it
//! holds the whole stream. Past it, it holds the stream's first half-cap of
//! bytes (the head) and then the stream's newest bytes, and
//! `log/<stream>.dropped` says `{"at": <head bytes>, "dropped": <bytes
//! dropped between>}`. A rotation first writes that record with
//! `"rotating": true`, then moves the kept tail down to the head's end and
//! truncates the file, then writes the record again with `"rotating": false`;
//! each record goes through a staging name, a sync and a rename, so a reader
//! sees one record or the other, whole. Each rotation drops at least one
//! byte, so the record after it always differs from the record before it.
//! R4's reader (`jobs/log_tail.rs`) maps a stream offset by the record and
//! reads again when the record changed or the file shrank under its read.
//!
//! A rotation that fails after its first record keeps only the head, which
//! no rotation writes, and settles the record with `"rotating": false` and
//! every byte past the head counted as dropped, so a reader never waits on a
//! rotation that will not finish (review r6 R6-03). Only a writer killed
//! inside a rotation, or a failure of the settling itself, leaves
//! `"rotating": true` behind; the reader answers that once the job has ended.
//!
//! The writer is `job-exec`'s grandchild, not the workload's child, so a
//! workload that waits for all of its children never waits for it. It runs
//! as the job account inside the unit: under the file wall, the cgroup, the
//! memory cap and the tree kill. It ignores TERM, so the unit's stop lets it
//! copy what the workload wrote before it ended; it leaves when both pipes
//! close, or with the unit's KILL after the stop grace. `job-exec` goes on
//! only after the writer said it is ready ([`READY_BYTE`]): TERM ignored and
//! every other descriptor closed (review r6 R6-01). `log/` is the
//! workload's own directory, so the files and the records are its untrusted
//! bytes once it runs: the writer creates its files before the workload
//! exists and never follows a link.

use std::fs::File;
use std::io::{self, Write as _};
use std::os::fd::{AsFd as _, AsRawFd as _, BorrowedFd, FromRawFd as _, OwnedFd, RawFd};
use std::os::unix::fs::FileExt as _;
use std::path::Path;
use std::time::{Duration, Instant};

use rustix::fs::{AtFlags, Mode, OFlags};
use serde::Serialize;

/// The workload's standard output, beneath `log/`.
pub const STDOUT_FILE_NAME: &str = "stdout";

/// The workload's standard error, beneath `log/`.
pub const STDERR_FILE_NAME: &str = "stderr";

/// The drop record's suffix: `log/<stream>.dropped`.
pub const DROP_RECORD_SUFFIX: &str = ".dropped";

/// The drop record's staging suffix, renamed over the record.
const DROP_RECORD_STAGING_SUFFIX: &str = ".dropped.new";

/// The most one read of a pipe takes.
const READ_CHUNK_BYTES: usize = 64 * 1024;

/// The most one step of a rotation's move copies.
const MOVE_CHUNK_BYTES: usize = 1024 * 1024;

/// How long `job-exec` waits for the writer to say it is ready.
const READY_WAIT: Duration = Duration::from_secs(5);

/// The writer's one byte on the ready pipe: it ignores TERM and holds only
/// its own descriptors. The pipe closing without it is a writer that died
/// in its setup.
const READY_BYTE: u8 = b'R';

/// The workload's ends of the two log pipes.
#[derive(Debug)]
pub struct WorkloadStreams {
    /// Becomes the workload's descriptor 1.
    pub stdout: OwnedFd,
    /// Becomes the workload's descriptor 2.
    pub stderr: OwnedFd,
}

/// Creates `log/stdout` and `log/stderr` beneath `log_dir` (job account,
/// mode 0644, never through a link, never over an existing file), makes the
/// two pipes and starts the writer with `cap` bytes per file. Returns once
/// the writer said it is ready: it ignores TERM and holds nothing but its
/// files and its pipes' read ends, so no gate pipe stays open in it.
///
/// `job-exec` runs one thread, so the forked children may run any code.
///
/// # Errors
///
/// Why the writer did not start; nothing of the workload exists then.
pub fn start(log_dir: &Path, cap: u64) -> Result<WorkloadStreams, String> {
    let dir = rustix::fs::open(
        log_dir,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|error| format!("{}: {error}", log_dir.display()))?;
    let stdout_file = create_log_file(&dir, STDOUT_FILE_NAME)?;
    let stderr_file = create_log_file(&dir, STDERR_FILE_NAME)?;
    let (stdout_read, stdout_write) = pipe().map_err(|error| format!("stdout pipe: {error}"))?;
    let (stderr_read, stderr_write) = pipe().map_err(|error| format!("stderr pipe: {error}"))?;
    let (ready_read, ready_write) = pipe().map_err(|error| format!("ready pipe: {error}"))?;
    // SAFETY: job-exec runs one thread (above).
    let child = unsafe { libc::fork() };
    if child < 0 {
        return Err(format!("fork: {}", io::Error::last_os_error()));
    }
    if child == 0 {
        // SAFETY: as above; this child only forks the writer and leaves.
        let writer = unsafe { libc::fork() };
        if writer == 0 {
            // SAFETY: SIG_IGN is a valid disposition for TERM. Set before the
            // ready byte, so the unit's stop never ends a writer that said it
            // is ready (review r6 R6-01).
            unsafe {
                libc::signal(libc::SIGTERM, libc::SIG_IGN);
            }
            let keep = [
                dir.as_raw_fd(),
                stdout_file.as_raw_fd(),
                stderr_file.as_raw_fd(),
                stdout_read.as_raw_fd(),
                stderr_read.as_raw_fd(),
                ready_write.as_raw_fd(),
            ];
            let ready = close_all_but(&keep).is_ok() && say_ready(ready_write);
            let status = if ready {
                run_writer(
                    &dir,
                    [
                        Stream::new(
                            stdout_read,
                            LogFile::new(STDOUT_FILE_NAME, stdout_file, cap),
                        ),
                        Stream::new(
                            stderr_read,
                            LogFile::new(STDERR_FILE_NAME, stderr_file, cap),
                        ),
                    ],
                )
            } else {
                1
            };
            // SAFETY: the writer ends here without running the parent's
            // destructors or flushing its buffers.
            unsafe { libc::_exit(status) }
        }
        // SAFETY: as above.
        unsafe { libc::_exit(i32::from(writer < 0)) }
    }
    drop(ready_write);
    drop((dir, stdout_file, stderr_file, stdout_read, stderr_read));
    let status = reap(child).map_err(|error| format!("the writer's parent: {error}"))?;
    if status != 0 {
        return Err("the writer's fork failed".to_owned());
    }
    wait_ready(&ready_read, READY_WAIT)?;
    Ok(WorkloadStreams {
        stdout: stdout_write,
        stderr: stderr_write,
    })
}

fn create_log_file(dir: &OwnedFd, name: &str) -> Result<File, String> {
    let fd = rustix::fs::openat(
        dir,
        name,
        OFlags::RDWR | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::from_raw_mode(0o644),
    )
    .map_err(|error| format!("log/{name}: {error}"))?;
    rustix::fs::fchmod(&fd, Mode::from_raw_mode(0o644))
        .map_err(|error| format!("log/{name}: {error}"))?;
    Ok(File::from(fd))
}

/// A pipe, both ends close-on-exec: (read end, write end).
fn pipe() -> io::Result<(OwnedFd, OwnedFd)> {
    let mut ends: [RawFd; 2] = [-1; 2];
    // SAFETY: ends has room for the two descriptors.
    if unsafe { libc::pipe2(ends.as_mut_ptr(), libc::O_CLOEXEC) } != 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: pipe2 returned two new descriptors.
    Ok(unsafe { (OwnedFd::from_raw_fd(ends[0]), OwnedFd::from_raw_fd(ends[1])) })
}

/// Closes every descriptor from 3 up except `keep`.
fn close_all_but(keep: &[RawFd]) -> io::Result<()> {
    for (first, last) in ranges_between(keep) {
        close_range(first, last)?;
    }
    Ok(())
}

/// The descriptor ranges from 3 up that hold none of `keep`.
fn ranges_between(keep: &[RawFd]) -> Vec<(u32, u32)> {
    let mut kept: Vec<u32> = keep
        .iter()
        .filter_map(|fd| u32::try_from(*fd).ok())
        .collect();
    kept.sort_unstable();
    let mut ranges = Vec::new();
    let mut first = 3_u32;
    for fd in kept.into_iter().chain([u32::MAX]) {
        if fd > first {
            ranges.push((first, fd - 1));
        }
        first = first.max(fd.saturating_add(1));
    }
    ranges
}

fn close_range(first: u32, last: u32) -> io::Result<()> {
    // SAFETY: closes descriptors this process no longer uses; the writer's
    // own are outside the range.
    if unsafe { libc::syscall(libc::SYS_close_range, first, last, 0_u32) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// Waits for `child` and returns its exit status.
fn reap(child: libc::pid_t) -> io::Result<i32> {
    loop {
        let mut status = 0;
        // SAFETY: status is writable.
        let reaped = unsafe { libc::waitpid(child, &raw mut status, 0) };
        if reaped == child {
            return Ok(if libc::WIFEXITED(status) {
                libc::WEXITSTATUS(status)
            } else {
                -1
            });
        }
        let error = io::Error::last_os_error();
        if error.kind() != io::ErrorKind::Interrupted {
            return Err(error);
        }
    }
}

/// The writer's side of the ready pipe: one [`READY_BYTE`], then the pipe
/// closes. False when the byte was not written.
fn say_ready(ready: OwnedFd) -> bool {
    let byte = [READY_BYTE];
    // SAFETY: one readable byte; the descriptor is open.
    let written = unsafe { libc::write(ready.as_raw_fd(), byte.as_ptr().cast(), 1) };
    written == 1
}

/// Reads `ready` until the writer's [`READY_BYTE`]. The pipe closing first
/// is a writer that died in its setup (review r6 R6-01).
fn wait_ready(ready: &OwnedFd, wait: Duration) -> Result<(), String> {
    let started = Instant::now();
    let mut byte = [0_u8; 1];
    loop {
        let left = wait.saturating_sub(started.elapsed());
        if left.is_zero() {
            return Err("the writer did not say it is ready in time".to_owned());
        }
        let mut poll = libc::pollfd {
            fd: ready.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        let millis = libc::c_int::try_from(left.as_millis()).unwrap_or(libc::c_int::MAX);
        // SAFETY: one valid pollfd.
        if unsafe { libc::poll(&raw mut poll, 1, millis) } <= 0 {
            continue;
        }
        // SAFETY: byte is writable for its length.
        match unsafe { libc::read(ready.as_raw_fd(), byte.as_mut_ptr().cast(), 1) } {
            0 => return Err("the writer ended before it was ready".to_owned()),
            1 if byte[0] == READY_BYTE => return Ok(()),
            read if read > 0 => {
                return Err("the writer wrote something other than ready".to_owned());
            }
            _ if io::Error::last_os_error().kind() == io::ErrorKind::Interrupted => {}
            _ => return Err(format!("ready pipe: {}", io::Error::last_os_error())),
        }
    }
}

/// One pipe and the file it fills.
struct Stream {
    pipe: OwnedFd,
    open: bool,
    file: LogFile,
}

impl Stream {
    fn new(pipe: OwnedFd, file: LogFile) -> Self {
        Self {
            pipe,
            open: true,
            file,
        }
    }
}

/// The writer's loop: copies each pipe into its file until both close.
fn run_writer(dir: &OwnedFd, mut streams: [Stream; 2]) -> i32 {
    let mut buffer = vec![0_u8; READ_CHUNK_BYTES];
    while streams.iter().any(|stream| stream.open) {
        let mut polls: Vec<libc::pollfd> = streams
            .iter()
            .map(|stream| libc::pollfd {
                fd: if stream.open {
                    stream.pipe.as_raw_fd()
                } else {
                    -1
                },
                events: libc::POLLIN,
                revents: 0,
            })
            .collect();
        let count = libc::nfds_t::try_from(polls.len()).unwrap_or(0);
        // SAFETY: polls holds `count` valid entries.
        if unsafe { libc::poll(polls.as_mut_ptr(), count, -1) } < 0 {
            continue;
        }
        for (stream, poll) in streams.iter_mut().zip(&polls) {
            if !stream.open || poll.revents == 0 {
                continue;
            }
            // SAFETY: buffer is writable for its length.
            let read = unsafe {
                libc::read(
                    stream.pipe.as_raw_fd(),
                    buffer.as_mut_ptr().cast(),
                    buffer.len(),
                )
            };
            match usize::try_from(read) {
                Ok(0) => stream.open = false,
                Ok(read) => stream.file.append(dir.as_fd(), &buffer[..read]),
                Err(_) if io::Error::last_os_error().kind() == io::ErrorKind::Interrupted => {}
                Err(_) => stream.open = false,
            }
        }
    }
    0
}

/// `log/<stream>.dropped`, as R4's reader reads it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
struct DropRecord {
    at: u64,
    dropped: u64,
    rotating: bool,
}

/// What one chunk does to a file of `len` bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Step {
    /// The chunk goes at the file's end.
    Append,
    /// The file keeps its `at` bytes of head, then the last `keep_old` bytes
    /// it holds, then the chunk from `skip_new` on; `dropped` more bytes of
    /// the stream are gone.
    Rotate {
        at: u64,
        keep_old: u64,
        skip_new: u64,
        dropped: u64,
    },
}

/// The step for a chunk of `n` bytes on a file of `len` bytes whose head
/// ends at `at` (`None`: nothing dropped yet, the head is the first half of
/// `cap`). A rotation keeps half the room after the head, the newest bytes,
/// so the next one comes only after that much more output. `len` is at
/// least the head's end whenever the chunk does not fit (the caller fills
/// the head first).
fn step(len: u64, at: Option<u64>, cap: u64, n: u64) -> Step {
    if len.saturating_add(n) <= cap {
        return Step::Append;
    }
    let at = at.unwrap_or(cap / 2);
    let keep = (cap.saturating_sub(at) / 2).max(1);
    let kept_new = n.min(keep);
    let old_tail = len.saturating_sub(at);
    let keep_old = old_tail.min(keep - kept_new);
    Step::Rotate {
        at,
        keep_old,
        skip_new: n - kept_new,
        dropped: (old_tail - keep_old) + (n - kept_new),
    }
}

/// One log file and what the writer knows of it.
struct LogFile {
    name: &'static str,
    file: File,
    cap: u64,
    len: u64,
    /// The head's end once something was dropped.
    at: Option<u64>,
    dropped: u64,
    /// A write failed: the rest of the stream is drained and not kept.
    failed: bool,
}

impl LogFile {
    fn new(name: &'static str, file: File, cap: u64) -> Self {
        Self {
            name,
            file,
            cap: cap.max(2),
            len: 0,
            at: None,
            dropped: 0,
            failed: false,
        }
    }

    fn append(&mut self, dir: BorrowedFd<'_>, bytes: &[u8]) {
        if self.failed {
            return;
        }
        if let Err(error) = self.try_append(dir, bytes) {
            self.failed = true;
            journal_line!(
                "job-exec log writer: log/{}: {error}; the rest of the stream is not kept",
                self.name
            );
        }
    }

    fn try_append(&mut self, dir: BorrowedFd<'_>, mut bytes: &[u8]) -> io::Result<()> {
        let n = |bytes: &[u8]| u64::try_from(bytes.len()).unwrap_or(u64::MAX);
        let head = self.cap / 2;
        if self.at.is_none() && self.len < head && self.len.saturating_add(n(bytes)) > self.cap {
            let fill = usize::try_from(head - self.len).unwrap_or(usize::MAX);
            let (first, rest) = bytes.split_at(fill.min(bytes.len()));
            self.file.write_all_at(first, self.len)?;
            self.len += n(first);
            bytes = rest;
        }
        match step(self.len, self.at, self.cap, n(bytes)) {
            Step::Append => {
                self.file.write_all_at(bytes, self.len)?;
                self.len += n(bytes);
            }
            Step::Rotate {
                at,
                keep_old,
                skip_new,
                dropped,
            } => {
                self.write_record(
                    dir,
                    DropRecord {
                        at,
                        dropped: self.dropped,
                        rotating: true,
                    },
                )?;
                let new = &bytes[usize::try_from(skip_new).unwrap_or(bytes.len())..];
                let len = at + keep_old + n(new);
                let total_dropped = self.dropped.saturating_add(dropped);
                let rotated = self
                    .move_down(self.len - keep_old, at, keep_old)
                    .and_then(|()| self.file.write_all_at(new, at + keep_old))
                    .and_then(|()| self.file.set_len(len))
                    .and_then(|()| {
                        self.write_record(
                            dir,
                            DropRecord {
                                at,
                                dropped: total_dropped,
                                rotating: false,
                            },
                        )
                    });
                if let Err(error) = rotated {
                    self.settle_failed_rotation(dir, at, n(bytes));
                    return Err(error);
                }
                self.len = len;
                self.at = Some(at);
                self.dropped = total_dropped;
            }
        }
        Ok(())
    }

    /// After a rotation failed past its first record: keeps the file's head
    /// alone, which no rotation writes, and settles the record with every
    /// byte past the head, `chunk` included, counted as dropped (review r6
    /// R6-03). When the record cannot be written, it is removed: the file is
    /// then the stream's first bytes, which a reader without a record reads
    /// truly. When the file cannot be cut, the record stays `rotating`.
    fn settle_failed_rotation(&mut self, dir: BorrowedFd<'_>, at: u64, chunk: u64) {
        let dropped = self
            .dropped
            .saturating_add(self.len.saturating_sub(at))
            .saturating_add(chunk);
        if let Err(error) = self.file.set_len(at) {
            journal_line!(
                "job-exec log writer: log/{}: the failed rotation left the record rotating: {error}",
                self.name
            );
            return;
        }
        self.len = at;
        self.at = Some(at);
        self.dropped = dropped;
        let record = DropRecord {
            at,
            dropped,
            rotating: false,
        };
        if let Err(error) = self.write_record(dir, record) {
            let name = format!("{}{DROP_RECORD_SUFFIX}", self.name);
            let removed = rustix::fs::unlinkat(dir, name.as_str(), AtFlags::empty());
            journal_line!(
                "job-exec log writer: log/{}: the settled record was not written ({error}); record removed: {}",
                self.name,
                removed.is_ok()
            );
        }
    }

    /// Copies `count` bytes from `from` down to `to` (`to <= from`), front
    /// first, so no byte is overwritten before it is read.
    fn move_down(&self, from: u64, to: u64, count: u64) -> io::Result<()> {
        let mut buffer = vec![0_u8; MOVE_CHUNK_BYTES];
        let mut done = 0_u64;
        while done < count {
            let take = usize::try_from(count - done)
                .unwrap_or(usize::MAX)
                .min(buffer.len());
            self.file.read_exact_at(&mut buffer[..take], from + done)?;
            self.file.write_all_at(&buffer[..take], to + done)?;
            done += u64::try_from(take).unwrap_or(u64::MAX);
        }
        Ok(())
    }

    /// Writes the record through its staging name, a sync and a rename.
    fn write_record(&self, dir: BorrowedFd<'_>, record: DropRecord) -> io::Result<()> {
        let bytes = serde_json::to_vec(&record).map_err(io::Error::other)?;
        let staging = format!("{}{DROP_RECORD_STAGING_SUFFIX}", self.name);
        let name = format!("{}{DROP_RECORD_SUFFIX}", self.name);
        match rustix::fs::unlinkat(dir, staging.as_str(), AtFlags::empty()) {
            Ok(()) | Err(rustix::io::Errno::NOENT) => {}
            Err(error) => return Err(error.into()),
        }
        let fd = rustix::fs::openat(
            dir,
            staging.as_str(),
            OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::from_raw_mode(0o644),
        )?;
        let mut file = File::from(fd);
        file.write_all(&bytes)?;
        file.sync_all()?;
        rustix::fs::renameat(dir, staging.as_str(), dir, name.as_str())?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const CAP: u64 = 1 << 20;

    #[test]
    fn a_chunk_that_fits_is_appended() {
        assert_eq!(step(0, None, CAP, 100), Step::Append);
        assert_eq!(step(CAP - 100, None, CAP, 100), Step::Append);
        assert_eq!(step(CAP - 100, Some(CAP / 2), CAP, 100), Step::Append);
    }

    #[test]
    fn the_first_rotation_keeps_the_head_and_half_the_room_after_it() {
        let step = step(CAP, None, CAP, 1000);
        let keep = CAP / 4;
        assert_eq!(
            step,
            Step::Rotate {
                at: CAP / 2,
                keep_old: keep - 1000,
                skip_new: 0,
                dropped: CAP / 2 - (keep - 1000),
            }
        );
    }

    #[test]
    fn a_chunk_larger_than_the_kept_tail_keeps_only_its_own_newest_bytes() {
        let keep = CAP / 4;
        assert_eq!(
            step(CAP - 10, Some(CAP / 2), CAP, keep + 7),
            Step::Rotate {
                at: CAP / 2,
                keep_old: 0,
                skip_new: 7,
                dropped: (CAP / 2 - 10) + 7,
            }
        );
    }

    /// Writes `stream` in chunks through a real file and checks the file and
    /// its record against the contract.
    fn written(stream: &[u8], cap: u64, chunk: usize) -> (Vec<u8>, Option<serde_json::Value>) {
        let dir = tempfile::tempdir().expect("temp dir");
        let fd = rustix::fs::open(
            dir.path(),
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .expect("dir");
        let file = create_log_file(&fd, STDOUT_FILE_NAME).expect("file");
        let mut log = LogFile::new(STDOUT_FILE_NAME, file, cap);
        for part in stream.chunks(chunk) {
            log.append(fd.as_fd(), part);
        }
        assert!(!log.failed);
        let bytes = std::fs::read(dir.path().join(STDOUT_FILE_NAME)).expect("read");
        let record = std::fs::read(dir.path().join("stdout.dropped"))
            .ok()
            .map(|bytes| serde_json::from_slice(&bytes).expect("record"));
        (bytes, record)
    }

    /// A stream of `len` bytes that repeats only every 251 bytes.
    fn numbered(len: u32) -> Vec<u8> {
        (0..len)
            .map(|i| u8::try_from(i % 251).unwrap_or(0))
            .collect()
    }

    fn bytes_u64(len: usize) -> u64 {
        u64::try_from(len).unwrap_or(u64::MAX)
    }

    #[test]
    fn a_stream_under_its_cap_is_kept_whole_with_no_record() {
        let stream = numbered(300_000);
        let (bytes, record) = written(&stream, CAP, 4096);
        assert_eq!(bytes, stream);
        assert_eq!(record, None);
    }

    /// One-byte chunks on a shorter stream; the pipe's chunk size; and one
    /// chunk larger than the kept tail.
    #[test]
    fn a_stream_past_its_cap_keeps_its_head_and_its_newest_bytes() {
        for (len, chunk) in [
            (1_200_000, 1),
            (5_600_000, 4096),
            (5_600_000, 65_536),
            (5_600_000, 300_000),
        ] {
            check_contract(&numbered(len), CAP, chunk);
        }
    }

    fn check_contract(stream: &[u8], cap: u64, chunk: usize) {
        let (bytes, record) = written(stream, cap, chunk);
        let record = record.expect("a drop record");
        let at = record["at"].as_u64().expect("at");
        let dropped = record["dropped"].as_u64().expect("dropped");
        assert_eq!(record["rotating"], serde_json::Value::Bool(false));
        let len = bytes_u64(bytes.len());
        assert_eq!(at, cap / 2, "chunk {chunk}");
        assert!(len <= cap, "chunk {chunk}: {len}");
        assert_eq!(len + dropped, bytes_u64(stream.len()), "chunk {chunk}");
        let at = usize::try_from(at).expect("at fits");
        assert_eq!(&bytes[..at], &stream[..at], "chunk {chunk}: head");
        let tail = bytes.len() - at;
        assert_eq!(
            &bytes[at..],
            &stream[stream.len() - tail..],
            "chunk {chunk}: tail"
        );
    }

    /// A rotation that failed after its first record leaves the head and a
    /// settled record that counts every byte past the head as dropped.
    #[test]
    fn a_failed_rotation_settles_to_the_head_and_a_record_that_is_not_rotating() {
        let dir = tempfile::tempdir().expect("temp dir");
        let fd = rustix::fs::open(
            dir.path(),
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .expect("dir");
        let file = create_log_file(&fd, STDOUT_FILE_NAME).expect("file");
        let mut log = LogFile::new(STDOUT_FILE_NAME, file, CAP);
        let stream = numbered(1_200_000);
        for part in stream.chunks(65_536) {
            log.append(fd.as_fd(), part);
        }
        let at = log.at.expect("rotated once");
        let before = log.len + log.dropped;
        log.write_record(
            fd.as_fd(),
            DropRecord {
                at,
                dropped: log.dropped,
                rotating: true,
            },
        )
        .expect("rotating record");
        log.settle_failed_rotation(fd.as_fd(), at, 4096);
        let bytes = std::fs::read(dir.path().join(STDOUT_FILE_NAME)).expect("read");
        let at_bytes = usize::try_from(at).expect("at fits");
        assert_eq!(bytes, &stream[..at_bytes]);
        let record: serde_json::Value = serde_json::from_slice(
            &std::fs::read(dir.path().join("stdout.dropped")).expect("record"),
        )
        .expect("json");
        assert_eq!(record["rotating"], serde_json::Value::Bool(false));
        assert_eq!(record["at"].as_u64(), Some(at));
        assert_eq!(record["dropped"].as_u64(), Some(before + 4096 - at));
    }

    #[test]
    fn every_descriptor_but_the_kept_ones_is_in_a_closed_range() {
        assert_eq!(
            ranges_between(&[9, 4, 5]),
            vec![(3, 3), (6, 8), (10, u32::MAX - 1)]
        );
        assert_eq!(ranges_between(&[3]), vec![(4, u32::MAX - 1)]);
        assert_eq!(ranges_between(&[]), vec![(3, u32::MAX - 1)]);
    }
}
