//! The wire between the daemon and the broker, one connection per call.
//!
//! A call is three segments: the JSON [`CallHeader`], the body bytes and the
//! key bytes. A reply is two: the JSON [`ReplyHeader`] and the stripped body.
//! Each segment is a 4-byte big-endian length, then its bytes. The key travels
//! raw, with no encoded copy, and is read into a buffer wiped on drop.

use std::io;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use zeroize::Zeroizing;

use crate::{CallHeader, Refusal, ReplyHeader};

/// The frame protocol's version.
pub const PROTOCOL_VERSION: u32 = 1;

/// The largest request or reply body, the server transport's own bound.
pub const MAX_BODY: usize = 16 << 20;

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
    let header = read_segment(reader, MAX_HEADER).await?;
    let header: ReplyHeader =
        serde_json::from_slice(&header).map_err(|_| io::Error::from(io::ErrorKind::InvalidData))?;
    let body = read_segment(reader, MAX_BODY).await?;
    Ok((header, body))
}
