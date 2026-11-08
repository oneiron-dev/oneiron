//! Released provider sends use the existing call socket in both directions.

use tokio::io::AsyncWriteExt;
use zeroize::Zeroizing;

use super::{BrokerConnection, BrokerReply, BrokerStream, StreamPart};
use crate::frame::dispatch::{DispatchPhase, DispatchState, read_released_segment};
use crate::frame::{
    MAX_HEADER, STREAM_CHUNK, read_stream_end, write_call_released, write_call_with_whole,
};
use crate::send::push_wiped;
use crate::{
    BrokerError, CallHeader, DispatchError, Failure, MAX_BODY, Outcome, PROTOCOL_VERSION,
    ReplyHeader,
};

impl BrokerConnection {
    /// Sends one HTTP call, checking the original daemon release before every
    /// physical send, including a gzip/plain resend or the shape's download hop.
    pub async fn call_released<E>(
        self,
        call: &CallHeader,
        body: &[u8],
        secret: Zeroizing<Vec<u8>>,
        release: &(dyn Fn() -> Result<(), E> + Sync),
    ) -> Result<BrokerReply, DispatchError<E>> {
        let mut reply = self.open_released(call, body, secret, release).await?;
        let mut whole = Zeroizing::new(Vec::new());
        loop {
            match reply.next_released(release).await? {
                StreamPart::Chunk(chunk) if whole.is_empty() => whole = chunk,
                StreamPart::Chunk(chunk) => {
                    push_wiped(&mut whole, &chunk)?;
                }
                StreamPart::End => break,
                StreamPart::Cut(reason) => {
                    return Ok(BrokerReply {
                        outcome: Outcome::Failed { reason },
                        body: Zeroizing::new(Vec::new()),
                    });
                }
            }
        }
        Ok(BrokerReply {
            outcome: reply.outcome,
            body: whole,
        })
    }

    /// Opens a released HTTP reply on this same call's duplex socket.
    pub async fn open_released<E>(
        self,
        call: &CallHeader,
        body: &[u8],
        secret: Zeroizing<Vec<u8>>,
        release: &(dyn Fn() -> Result<(), E> + Sync),
    ) -> Result<BrokerStream, DispatchError<E>> {
        self.open_parts_released(call, body, None, secret, release)
            .await
    }

    /// Opens the same Responses call, checking the daemon's original release
    /// before the broker sends its initial create and any same-socket whole retry.
    /// A release error stays local and closes the connection without approval.
    pub async fn open_with_whole_released<E>(
        self,
        call: &CallHeader,
        body: &[u8],
        whole: &[u8],
        secret: Zeroizing<Vec<u8>>,
        release: &(dyn Fn() -> Result<(), E> + Sync),
    ) -> Result<BrokerStream, DispatchError<E>> {
        self.open_parts_released(call, body, Some(whole), secret, release)
            .await
    }

    async fn open_parts_released<E>(
        mut self,
        call: &CallHeader,
        body: &[u8],
        whole: Option<&[u8]>,
        secret: Zeroizing<Vec<u8>>,
        release: &(dyn Fn() -> Result<(), E> + Sync),
    ) -> Result<BrokerStream, DispatchError<E>> {
        if let Some(whole) = whole {
            call.check_responses(body, whole)
                .map_err(BrokerError::Refused)?;
        } else {
            if call.shape == crate::Shape::OpenAiResponses {
                return Err(BrokerError::Refused(crate::Refusal::Frame).into());
            }
            call.check(body).map_err(BrokerError::Refused)?;
        }
        let deadline = tokio::time::Instant::now() + self.reply_timeout;
        let written = if let Some(whole) = whole {
            tokio::time::timeout_at(
                deadline,
                write_call_with_whole(&mut self.stream, call, body, whole, &secret, true),
            )
            .await
        } else {
            tokio::time::timeout_at(
                deadline,
                write_call_released(&mut self.stream, call, body, &secret),
            )
            .await
        };
        drop(secret);
        written.map_err(|_| BrokerError::Lost)??;
        let mut dispatch = DispatchState::new(call);
        let header = tokio::time::timeout_at(
            deadline,
            read_released_segment(
                &mut self.stream,
                MAX_HEADER,
                &mut dispatch,
                DispatchPhase::BeforeHeader,
                release,
                deadline,
            ),
        )
        .await
        .map_err(|_| BrokerError::Lost)??;
        let reply: ReplyHeader = serde_json::from_slice(&header).map_err(|_| BrokerError::Lost)?;
        if reply.version != PROTOCOL_VERSION
            || reply.call != call.call
            || reply.digest != call.digest
        {
            return Err(BrokerError::Lost.into());
        }
        let whole = if call.shape.streams() {
            None
        } else {
            Some(
                tokio::time::timeout_at(
                    deadline,
                    read_released_segment(
                        &mut self.stream,
                        MAX_BODY,
                        &mut dispatch,
                        DispatchPhase::Body,
                        release,
                        deadline,
                    ),
                )
                .await
                .map_err(|_| BrokerError::Lost)??,
            )
        };
        Ok(BrokerStream {
            outcome: reply.outcome,
            stream: self.stream,
            deadline,
            whole,
            ended: None,
            dispatch: Some(dispatch),
        })
    }
}

impl BrokerStream {
    /// Reads the next part, answering this call's next physical-send check with
    /// the same original daemon release. Failure returns that error unchanged
    /// and closes the write side so the broker cannot wait for a later approval.
    pub async fn next_released<E>(
        &mut self,
        release: &(dyn Fn() -> Result<(), E> + Sync),
    ) -> Result<StreamPart, DispatchError<E>> {
        if self.dispatch.is_none() || self.whole.is_some() {
            return self.next().await.map_err(DispatchError::Broker);
        }
        let result = self.next_dispatch(release).await;
        if result.is_err() {
            self.ended = Some(Some(Failure::Send));
            let _ = tokio::time::timeout_at(self.deadline, self.stream.shutdown()).await;
        }
        result
    }

    async fn next_dispatch<E>(
        &mut self,
        release: &(dyn Fn() -> Result<(), E> + Sync),
    ) -> Result<StreamPart, DispatchError<E>> {
        if let Some(end) = self.ended {
            return Ok(end.map_or(StreamPart::End, StreamPart::Cut));
        }
        let chunk = tokio::time::timeout_at(
            self.deadline,
            read_released_segment(
                &mut self.stream,
                STREAM_CHUNK,
                self.dispatch.as_mut().expect("released Responses state"),
                DispatchPhase::Body,
                release,
                self.deadline,
            ),
        )
        .await
        .map_err(|_| BrokerError::Lost)??;
        if !chunk.is_empty() {
            // No cumulative byte limit on a streamed body (#5393, FIX 1895): each chunk is bounded.
            return Ok(StreamPart::Chunk(chunk));
        }
        let end = tokio::time::timeout_at(self.deadline, read_stream_end(&mut self.stream))
            .await
            .map_err(|_| BrokerError::Lost)??;
        self.ended = Some(end);
        Ok(end.map_or(StreamPart::End, StreamPart::Cut))
    }
}
