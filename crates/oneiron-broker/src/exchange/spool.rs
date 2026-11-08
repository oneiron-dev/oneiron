//! The broker's hold on a spooled exchange's body: read into a private
//! unnamed file as its chunks come, its digest taken again as they pass,
//! acknowledged, and then read back as the request's body as the send
//! takes it.

use std::io::{self, SeekFrom};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use reqwest::Body;
use tokio::io::{AsyncReadExt, AsyncSeekExt, AsyncWriteExt};
use tokio::net::UnixStream;

use super::{Prepared, idle_bound};
use crate::digest::BodyDigest;
use crate::frame::{read_chunk, write_segment};
use crate::{PROTOCOL_VERSION, Refusal};

/// How much of the spool one read takes as it streams to the far end.
const SPOOL_READ: usize = 64 << 10;

/// A body held for its one send: a private unnamed file, rewound, of the
/// header's length and digest.
pub(crate) struct Spool {
    file: tokio::fs::File,
    pub(crate) len: u64,
}

/// Reads the body's chunks into a private unnamed file, taking `digest`
/// as they pass. The body is refused when the disk has no room for its
/// `body_len` bytes, it runs past that length, or its digest is not
/// `expected`; its chunks are still read to its end, so the refusal
/// answers in turn.
pub(crate) async fn spool(
    stream: &mut UnixStream,
    body_len: u64,
    mut digest: BodyDigest,
    expected: &str,
    idle: Duration,
) -> io::Result<Result<Spool, Refusal>> {
    let file = match tempfile::tempfile() {
        Ok(file) if room_for(&file, body_len) => file,
        Ok(_) | Err(_) => {
            drain(stream, idle).await?;
            return Ok(Err(Refusal::Spool));
        }
    };
    let mut file = tokio::fs::File::from_std(file);
    let mut seen = 0_u64;
    let mut refused = None;
    while let Some(chunk) = idle_bound(idle, read_chunk(stream)).await? {
        if refused.is_some() {
            continue;
        }
        seen = seen.saturating_add(chunk.len() as u64);
        if seen > body_len {
            refused = Some(Refusal::Body);
            continue;
        }
        digest.update(&chunk);
        if file.write_all(&chunk).await.is_err() {
            refused = Some(Refusal::Spool);
        }
    }
    if let Some(reason) = refused {
        return Ok(Err(reason));
    }
    match digest.finish() {
        Ok(found) if found == expected => {}
        Ok(_) => return Ok(Err(Refusal::Digest)),
        Err(reason) => return Ok(Err(reason)),
    }
    if file.flush().await.is_err() || file.seek(SeekFrom::Start(0)).await.is_err() {
        return Ok(Err(Refusal::Spool));
    }
    Ok(Ok(Spool {
        file,
        len: body_len,
    }))
}

/// Whether the disk under `file` has room for `len` more bytes.
fn room_for(file: &std::fs::File, len: u64) -> bool {
    rustix::fs::fstatvfs(file).is_ok_and(|stat| stat.f_bavail.saturating_mul(stat.f_frsize) >= len)
}

/// Reads a refused body's chunks to its end, keeping none.
pub(crate) async fn drain(stream: &mut UnixStream, idle: Duration) -> io::Result<()> {
    while idle_bound(idle, read_chunk(stream)).await?.is_some() {}
    Ok(())
}

/// Answers the exchange `call`'s header and body, whose digest is
/// `digest`: prepared, or refused.
pub(crate) async fn acknowledge(
    stream: &mut UnixStream,
    call: &str,
    digest: &str,
    refused: Option<Refusal>,
    idle: Duration,
) -> io::Result<()> {
    let prepared = Prepared {
        version: PROTOCOL_VERSION,
        call: call.to_owned(),
        digest: digest.to_owned(),
        refused,
    };
    let bytes = serde_json::to_vec(&prepared).map_err(io::Error::other)?;
    idle_bound(idle, async {
        write_segment(stream, &bytes).await?;
        stream.flush().await
    })
    .await
}

/// The spool as the request's body, read as the send takes it; each read
/// counts as progress.
pub(crate) fn spool_body(spool: Spool, progress: Arc<AtomicU64>) -> Body {
    let reads = futures_util::stream::try_unfold(
        (spool.file, progress),
        |(mut file, progress)| async move {
            let mut buffer = vec![0; SPOOL_READ];
            let read = file.read(&mut buffer).await?;
            if read == 0 {
                return Ok::<_, io::Error>(None);
            }
            buffer.truncate(read);
            progress.fetch_add(read as u64, Ordering::Relaxed);
            Ok(Some((buffer, (file, progress))))
        },
    );
    Body::wrap_stream(reads)
}
