//! Same-call release checks before physical provider writes.

use std::io;

use serde::{Deserialize, Serialize};
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};
use tokio::time::Instant;
use zeroize::Zeroizing;

use super::{MAX_HEADER, read_len, read_segment, read_sized, write_segment};
use crate::{BrokerError, CallHeader, Shape};

/// A broker transport failure, or the caller's original release error.
#[derive(Debug)]
pub enum DispatchError<E> {
    /// The broker connection failed under its existing transport rules.
    Broker(BrokerError),
    /// The daemon rejected this physical send; never serialized to the broker.
    Release(E),
}

impl<E> From<BrokerError> for DispatchError<E> {
    fn from(error: BrokerError) -> Self {
        Self::Broker(error)
    }
}

impl<E> From<io::Error> for DispatchError<E> {
    fn from(_: io::Error) -> Self {
        Self::Broker(BrokerError::Lost)
    }
}

// Outside every valid header/chunk length; never parsed as provider bytes.
const DISPATCH_CHECK: u32 = u32::MAX - 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum DispatchPoint {
    Initial,
    WholeRetry,
    PlainRetry,
    Redirect,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum DispatchPhase {
    BeforeHeader,
    Body,
}

impl DispatchPoint {
    fn phase(self) -> DispatchPhase {
        match self {
            Self::WholeRetry => DispatchPhase::Body,
            Self::Initial | Self::PlainRetry | Self::Redirect => DispatchPhase::BeforeHeader,
        }
    }
}

#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct DispatchRequest {
    call: String,
    digest: String,
    point: DispatchPoint,
}

#[derive(Debug)]
pub(crate) struct DispatchState {
    call: String,
    digest: String,
    next: Option<DispatchPoint>,
    retry: Option<DispatchPoint>,
}

impl DispatchState {
    pub(crate) fn new(call: &CallHeader) -> Self {
        Self {
            call: call.call.clone(),
            digest: call.digest.clone(),
            next: Some(DispatchPoint::Initial),
            retry: match call.shape {
                Shape::OpenAiResponses => Some(DispatchPoint::WholeRetry),
                Shape::AnthropicMessages => Some(DispatchPoint::PlainRetry),
                shape if shape.redirect().is_some() => Some(DispatchPoint::Redirect),
                _ => None,
            },
        }
    }
}

/// The broker waits on this same call's socket, not on a lease id or a grant
/// carried to another process. EOF or a mismatched answer permits no send.
pub(crate) async fn request_dispatch<S: AsyncRead + AsyncWrite + Unpin>(
    stream: &mut S,
    call: &CallHeader,
    point: DispatchPoint,
) -> io::Result<()> {
    let request = DispatchRequest {
        call: call.call.clone(),
        digest: call.digest.clone(),
        point,
    };
    let bytes = serde_json::to_vec(&request).map_err(io::Error::other)?;
    stream.write_all(&DISPATCH_CHECK.to_be_bytes()).await?;
    write_segment(stream, &bytes).await?;
    stream.flush().await?;
    let answer = read_segment(stream, MAX_HEADER).await?;
    let answer: DispatchRequest = serde_json::from_slice(&answer).map_err(io::Error::other)?;
    if answer != request {
        return Err(io::ErrorKind::InvalidData.into());
    }
    Ok(())
}

/// Reads one data segment while answering only this call's next release check.
/// A failed check returns its original error without writing any approval.
pub(crate) async fn read_released_segment<S, E>(
    stream: &mut S,
    max: usize,
    state: &mut DispatchState,
    phase: DispatchPhase,
    release: &(dyn Fn() -> Result<(), E> + Sync),
    deadline: Instant,
) -> Result<Zeroizing<Vec<u8>>, DispatchError<E>>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    loop {
        let len = read_len(stream).await?;
        if len != DISPATCH_CHECK {
            return Ok(read_sized(stream, len, max).await?);
        }
        let bytes = read_segment(stream, MAX_HEADER).await?;
        let request: DispatchRequest =
            serde_json::from_slice(&bytes).map_err(|_| BrokerError::Lost)?;
        if request.call != state.call
            || request.digest != state.digest
            || Some(request.point) != state.next
            || request.point.phase() != phase
        {
            return Err(BrokerError::Lost.into());
        }
        release().map_err(DispatchError::Release)?;
        if Instant::now() >= deadline {
            return Err(BrokerError::Lost.into());
        }
        write_segment(stream, &bytes).await?;
        stream.flush().await?;
        state.next = match request.point {
            DispatchPoint::Initial => state.retry.take(),
            DispatchPoint::WholeRetry | DispatchPoint::PlainRetry | DispatchPoint::Redirect => None,
        };
    }
}
