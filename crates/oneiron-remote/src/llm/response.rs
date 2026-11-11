//! Async raw-LLM replies decode without retaining a whole raw body.
use serde::de::DeserializeOwned;
use std::io::{Cursor, Read};

pub(super) async fn read_json<T>(
    mut response: reqwest::Response,
    limit: usize,
) -> oneiron::LlmResult<Result<T, serde_json::Error>>
where
    T: DeserializeOwned + Send + 'static,
{
    let (send, decoder) = decoder();
    let mut received = 0usize;
    while let Some(chunk) = response.chunk().await.map_err(|error| {
        if error.is_timeout() {
            oneiron::RetryableLlmError::Timeout
        } else {
            oneiron::RetryableLlmError::StreamCut
        }
    })? {
        received = received.saturating_add(chunk.len());
        if received > limit {
            return Err(oneiron::FatalLlmError::InvalidRequest.into());
        }
        // A decode error closes the receiver, but transport failures and the
        // complete-body size check still take precedence over that error.
        let _ = send.send(chunk).await;
    }
    drop(send);
    decoder
        .await
        .map_err(|_| oneiron::LlmError::from(oneiron::RetryableLlmError::StreamCut))
}

pub(super) fn decoder<B, T>() -> (
    tokio::sync::mpsc::Sender<B>,
    tokio::task::JoinHandle<Result<T, serde_json::Error>>,
)
where
    B: AsRef<[u8]> + Send + 'static,
    T: DeserializeOwned + Send + 'static,
{
    let (send, receive) = tokio::sync::mpsc::channel(1);
    let decoded = tokio::task::spawn_blocking(move || {
        serde_json::from_reader(ChunkReader {
            receive,
            current: None,
        })
    });
    (send, decoded)
}

struct ChunkReader<B> {
    receive: tokio::sync::mpsc::Receiver<B>,
    current: Option<Cursor<B>>,
}

impl<B: AsRef<[u8]>> Read for ChunkReader<B> {
    fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
        if buffer.is_empty() {
            return Ok(0);
        }
        loop {
            if let Some(current) = &mut self.current {
                let read = current.read(buffer)?;
                if read != 0 {
                    return Ok(read);
                }
            }
            self.current = None;
            self.current = self.receive.blocking_recv().map(Cursor::new);
            if self.current.is_none() {
                return Ok(0);
            }
        }
    }
}
