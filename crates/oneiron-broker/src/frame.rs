//! The wire between the daemon and the broker, one connection per call.
//!
//! A call is three segments: the JSON [`CallHeader`], the body bytes and the
//! key bytes. A reply is two: the JSON [`ReplyHeader`] and the stripped body.
//! Each segment is a 4-byte big-endian length, then its bytes. The key travels
//! raw, with no encoded copy, and is read into a buffer wiped on drop.
//!
//! A reply whose shape streams ([`crate::Shape::streams`]) can run past one
//! segment, so its body comes as chunks: the header, then one segment per
//! chunk of at most [`STREAM_CHUNK`] bytes, then an empty segment and a JSON
//! trailer that says whether the body ended clean or was cut, and why. The
//! daemon keeps the chunks only once the trailer says clean.

use std::io;

use serde::{Deserialize, Serialize};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use zeroize::Zeroizing;

use crate::{CallHeader, Failure, Refusal, ReplyHeader};

/// The frame protocol's version.
pub const PROTOCOL_VERSION: u32 = 1;

/// The largest request or reply body, the server transport's own bound.
pub const MAX_BODY: usize = 16 << 20;

/// The largest streamed reply body, a binary one ([`crate::Shape::streams`]).
pub const MAX_STREAM: usize = 512 << 20;

/// The largest chunk of a streamed reply.
pub(crate) const STREAM_CHUNK: usize = 1 << 20;

/// The largest key.
pub const MAX_SECRET: usize = 4096;

/// The largest JSON header segment.
pub(crate) const MAX_HEADER: usize = 64 << 10;

async fn write_segment<W: AsyncWrite + Unpin>(writer: &mut W, bytes: &[u8]) -> io::Result<()> {
    let len =
        u32::try_from(bytes.len()).map_err(|_| io::Error::from(io::ErrorKind::InvalidInput))?;
    writer.write_all(&len.to_be_bytes()).await?;
    writer.write_all(bytes).await
}

async fn read_segment<R: AsyncRead + Unpin>(
    reader: &mut R,
    max: usize,
) -> io::Result<Zeroizing<Vec<u8>>> {
    let mut len = [0; 4];
    reader.read_exact(&mut len).await?;
    let len = usize::try_from(u32::from_be_bytes(len))
        .ok()
        .filter(|len| *len <= max)
        .ok_or_else(|| io::Error::from(io::ErrorKind::InvalidData))?;
    // Sized once, so no reallocation leaves an unwiped copy behind.
    let mut bytes = Zeroizing::new(vec![0; len]);
    reader.read_exact(&mut bytes).await?;
    Ok(bytes)
}

/// Writes one call: its header, its body, then the key.
pub(crate) async fn write_call<W: AsyncWrite + Unpin>(
    writer: &mut W,
    header: &CallHeader,
    body: &[u8],
    secret: &[u8],
) -> io::Result<()> {
    let header = serde_json::to_vec(header).map_err(io::Error::other)?;
    write_segment(writer, &header).await?;
    write_segment(writer, body).await?;
    write_segment(writer, secret).await?;
    writer.flush().await
}

/// One call as read from the wire: its header, body and key.
pub(crate) struct ReadCall {
    pub(crate) header: CallHeader,
    pub(crate) body: Zeroizing<Vec<u8>>,
    pub(crate) secret: Zeroizing<Vec<u8>>,
}

/// Reads one call. Any cut, oversized or undecodable segment is
/// [`Refusal::Frame`].
pub(crate) async fn read_call<R: AsyncRead + Unpin>(reader: &mut R) -> Result<ReadCall, Refusal> {
    let header = read_segment(reader, MAX_HEADER)
        .await
        .map_err(|_| Refusal::Frame)?;
    let header: CallHeader = serde_json::from_slice(&header).map_err(|_| Refusal::Frame)?;
    let body = read_segment(reader, MAX_BODY)
        .await
        .map_err(|_| Refusal::Frame)?;
    let secret = read_segment(reader, MAX_SECRET)
        .await
        .map_err(|_| Refusal::Frame)?;
    Ok(ReadCall {
        header,
        body,
        secret,
    })
}

/// Writes one reply: its header, then its body.
pub(crate) async fn write_reply<W: AsyncWrite + Unpin>(
    writer: &mut W,
    header: &ReplyHeader,
    body: &[u8],
) -> io::Result<()> {
    let header = serde_json::to_vec(header).map_err(io::Error::other)?;
    write_segment(writer, &header).await?;
    write_segment(writer, body).await?;
    writer.flush().await
}

/// Reads one reply.
pub(crate) async fn read_reply<R: AsyncRead + Unpin>(
    reader: &mut R,
) -> io::Result<(ReplyHeader, Zeroizing<Vec<u8>>)> {
    let header = read_reply_header(reader).await?;
    let body = read_segment(reader, MAX_BODY).await?;
    Ok((header, body))
}

/// Reads a reply's header: a streamed reply's chunks follow it.
pub(crate) async fn read_reply_header<R: AsyncRead + Unpin>(
    reader: &mut R,
) -> io::Result<ReplyHeader> {
    let header = read_segment(reader, MAX_HEADER).await?;
    serde_json::from_slice(&header).map_err(|_| io::Error::from(io::ErrorKind::InvalidData))
}

/// The trailer after a streamed reply's last chunk.
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct StreamEnd {
    /// Why the body was cut, or `None` when it ended clean.
    failure: Option<Failure>,
}

/// Writes a streamed reply's header.
pub(crate) async fn write_stream_header<W: AsyncWrite + Unpin>(
    writer: &mut W,
    header: &ReplyHeader,
) -> io::Result<()> {
    let header = serde_json::to_vec(header).map_err(io::Error::other)?;
    write_segment(writer, &header).await?;
    writer.flush().await
}

/// Writes one chunk of a streamed reply: not empty, at most
/// [`STREAM_CHUNK`] bytes.
pub(crate) async fn write_chunk<W: AsyncWrite + Unpin>(
    writer: &mut W,
    chunk: &[u8],
) -> io::Result<()> {
    if chunk.is_empty() || chunk.len() > STREAM_CHUNK {
        return Err(io::ErrorKind::InvalidInput.into());
    }
    write_segment(writer, chunk).await?;
    writer.flush().await
}

/// Ends a streamed reply: clean, or cut for `failure`.
pub(crate) async fn write_stream_end<W: AsyncWrite + Unpin>(
    writer: &mut W,
    failure: Option<Failure>,
) -> io::Result<()> {
    let end = serde_json::to_vec(&StreamEnd { failure }).map_err(io::Error::other)?;
    write_segment(writer, &[]).await?;
    write_segment(writer, &end).await?;
    writer.flush().await
}

/// Reads the next chunk of a streamed reply, or `None` at its end.
pub(crate) async fn read_chunk<R: AsyncRead + Unpin>(
    reader: &mut R,
) -> io::Result<Option<Zeroizing<Vec<u8>>>> {
    let chunk = read_segment(reader, STREAM_CHUNK).await?;
    Ok((!chunk.is_empty()).then_some(chunk))
}

/// Reads the trailer after a streamed reply's last chunk: `None` when the
/// body ended clean, or why it was cut.
pub(crate) async fn read_stream_end<R: AsyncRead + Unpin>(
    reader: &mut R,
) -> io::Result<Option<Failure>> {
    let end = read_segment(reader, MAX_HEADER).await?;
    serde_json::from_slice::<StreamEnd>(&end)
        .map(|end| end.failure)
        .map_err(|_| io::Error::from(io::ErrorKind::InvalidData))
}
