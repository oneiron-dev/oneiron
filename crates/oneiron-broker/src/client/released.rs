//! Released Responses uses the existing call socket in both directions.

use tokio::io::AsyncWriteExt;
use zeroize::Zeroizing;

use super::{BrokerConnection, BrokerStream, StreamPart};
use crate::frame::dispatch::{DispatchPoint, DispatchState, read_released_segment};
use crate::frame::{MAX_HEADER, STREAM_CHUNK, read_stream_end, write_call_with_whole};
use crate::{
    BrokerError, CallHeader, DispatchError, Failure, MAX_STREAM, PROTOCOL_VERSION, ReplyHeader,
};

impl BrokerConnection {
    /// Opens the same Responses call, checking the daemon's original release
    /// before the broker sends its initial create and any same-socket whole retry.
    /// A release error stays local and closes the connection without approval.
    pub async fn open_with_whole_released<E>(
        mut self,
        call: &CallHeader,
        body: &[u8],
        whole: &[u8],
        secret: Zeroizing<Vec<u8>>,
        release: &(dyn Fn() -> Result<(), E> + Sync),
    ) -> Result<BrokerStream, DispatchError<E>> {
        call.check_responses(body, whole)
            .map_err(BrokerError::Refused)?;
        let deadline = tokio::time::Instant::now() + self.reply_timeout;
        let written = tokio::time::timeout_at(
            deadline,
            write_call_with_whole(&mut self.stream, call, body, whole, &secret, true),
        )
        .await;
        drop(secret);
        written.map_err(|_| BrokerError::Lost)??;
        let mut dispatch = DispatchState::new(call);
        let header = tokio::time::timeout_at(
            deadline,
            read_released_segment(
                &mut self.stream,
                MAX_HEADER,
                &mut dispatch,
                DispatchPoint::Initial,
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
        Ok(BrokerStream {
            outcome: reply.outcome,
            stream: self.stream,
            deadline,
            whole: None,
            received: 0,
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
        if self.dispatch.is_none() {
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
                DispatchPoint::WholeRetry,
                release,
                self.deadline,
            ),
        )
        .await
        .map_err(|_| BrokerError::Lost)??;
        if !chunk.is_empty() {
            self.received += chunk.len();
            if self.received > MAX_STREAM {
                return Err(BrokerError::Lost.into());
            }
            return Ok(StreamPart::Chunk(chunk));
        }
        let end = tokio::time::timeout_at(self.deadline, read_stream_end(&mut self.stream))
            .await
            .map_err(|_| BrokerError::Lost)??;
        self.ended = Some(end);
        Ok(end.map_or(StreamPart::End, StreamPart::Cut))
    }
}
