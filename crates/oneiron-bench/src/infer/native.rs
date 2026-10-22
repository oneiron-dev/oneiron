//! An external EXL3 worker over codec v1. No HTTP fallback or resend.
//! Request mapping and stream parsing stay in the OpenAI adapter; only the
//! carrier changes. Closing a cut call cancels it at the worker.

use std::io::{self, IoSlice};
use std::mem::MaybeUninit;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use oneiron::BudgetLease;
use oneiron_llm_openai::{
    OpenAiCompatFuture, OpenAiCompatHttpRequest, OpenAiCompatProviderStream,
    OpenAiCompatStreamFrame, OpenAiCompatTransport, OpenAiCompatTransportError,
};
use oneiron_organ_protocol::SharedRegion;
use oneiron_server::config::models::{ProviderConfig, ResponseFormatWire};
use rustix::net::{SendAncillaryBuffer, SendAncillaryMessage, SendFlags, sendmsg};
use serde::Deserialize;
use serde_json::{Value, json};
use tokio::io::{AsyncReadExt, AsyncWriteExt, Interest};
use tokio::net::UnixStream;

static NEXT_ID: AtomicU64 = AtomicU64::new(1);

#[derive(Deserialize)]
struct Frame {
    v: u64,
    op: String,
    request_id: u64,
    epoch: String,
    seq: Option<u64>,
    body: Value,
}

struct Channel(UnixStream);

impl Channel {
    async fn connect(path: &Path) -> io::Result<Self> {
        let stream = UnixStream::connect(path).await?;
        if stream.peer_cred()?.uid() != rustix::process::geteuid().as_raw() {
            return Err(io::ErrorKind::PermissionDenied.into());
        }
        Ok(Self(stream))
    }

    fn bytes(op: &str, id: u64, epoch: Option<&str>, body: Value) -> io::Result<Vec<u8>> {
        let payload = serde_json::to_vec(&json!({
            "v": 1, "op": op, "request_id": id, "epoch": epoch, "body": body,
        }))?;
        let mut bytes = (payload.len() as u64).to_be_bytes().to_vec();
        bytes.extend(payload);
        Ok(bytes)
    }

    async fn next(&mut self) -> io::Result<Frame> {
        let length = self.0.read_u64().await?;
        let mut payload = Vec::new();
        let got = (&mut self.0).take(length).read_to_end(&mut payload).await?;
        if got as u64 != length {
            return Err(io::ErrorKind::UnexpectedEof.into());
        }
        let frame: Frame = serde_json::from_slice(&payload)?;
        if frame.v != 1 {
            return Err(io::ErrorKind::InvalidData.into());
        }
        Ok(frame)
    }

    async fn ask(&mut self, op: &str, body: Value) -> io::Result<Frame> {
        let id = NEXT_ID.fetch_add(1, Ordering::Relaxed);
        self.0.write_all(&Self::bytes(op, id, None, body)?).await?;
        let frame = self.next().await?;
        if frame.op != op || frame.request_id != id {
            return Err(io::ErrorKind::InvalidData.into());
        }
        Ok(frame)
    }

    /// Sends one `generate` with its input region; each failure names its
    /// step, and whether any byte of the call had left.
    async fn generate(
        &mut self,
        id: u64,
        epoch: &str,
        body: Value,
    ) -> Result<(), OpenAiCompatTransportError> {
        let mut conversation = serde_json::Map::new();
        let mut params = body
            .as_object()
            .cloned()
            .ok_or_else(|| not_sent("params", "the request body is not an object"))?;
        for key in ["messages", "tools"] {
            if let Some(value) = params.remove(key) {
                conversation.insert(key.to_owned(), value);
            }
        }
        params.remove("stream");
        params.remove("stream_options");
        let bytes = serde_json::to_vec(&conversation).map_err(|e| not_sent("encode input", e))?;
        let input = SharedRegion::from_bytes(&bytes).map_err(|e| not_sent("input region", e))?;
        let frame = Self::bytes(
            "generate",
            id,
            Some(epoch),
            json!({
                "input": {"buffer_id": id, "fd_index": 0, "offset": 0,
                          "length": input.len(), "encoding": "chat_json"},
                "params": params, "stream": true,
            }),
        )
        .map_err(|e| not_sent("encode frame", e))?;
        let fds = [input.fd()];
        let mut space = [MaybeUninit::uninit(); rustix::cmsg_space!(ScmRights(1))];
        let mut control = SendAncillaryBuffer::new(&mut space);
        if !control.push(SendAncillaryMessage::ScmRights(&fds)) {
            return Err(not_sent(
                "SCM_RIGHTS",
                "the descriptor does not fit its buffer",
            ));
        }
        #[cfg(target_os = "linux")]
        let flags = SendFlags::NOSIGNAL;
        #[cfg(not(target_os = "linux"))]
        let flags = SendFlags::empty();
        let sent = self
            .0
            .async_io(Interest::WRITABLE, || {
                sendmsg(&self.0, &[IoSlice::new(&frame)], &mut control, flags)
                    .map_err(io::Error::from)
            })
            .await
            .map_err(|e| not_sent("sendmsg SCM_RIGHTS", e))?;
        if sent == 0 {
            return Err(not_sent("sendmsg SCM_RIGHTS", "no byte went out"));
        }
        self.0.write_all(&frame[sent..]).await.map_err(|e| {
            fault(OpenAiCompatTransportError::Io {
                stage: "frame suffix",
                detail: e.to_string(),
            })
        })
    }
}

pub(super) struct Transport {
    socket: PathBuf,
    epoch: String,
    ceiling: Option<u64>,
    limit_field: &'static str,
    omit_schema: bool,
    hello: Value,
    stats: Value,
}

impl Transport {
    /// Qualification and the explicit stats op are outside measured time.
    pub(super) async fn connect(socket: &Path, provider: &ProviderConfig) -> Result<Self, String> {
        let mut channel = Channel::connect(socket).await.map_err(|e| e.to_string())?;
        let hello = channel
            .ask("hello", json!({}))
            .await
            .map_err(|e| e.to_string())?;
        let epoch = hello.body["epoch"]
            .as_str()
            .ok_or("hello has no epoch")?
            .to_owned();
        if hello.body["schema"] != 1 || hello.body["worker"]["kind"] != "exl3" {
            return Err("not an EXL3 codec-v1 worker".to_owned());
        }
        let stats = channel
            .ask("stats", json!({"detail": "full"}))
            .await
            .map_err(|e| e.to_string())?
            .body;
        Ok(Self {
            socket: socket.to_path_buf(),
            epoch,
            ceiling: provider.max_output_tokens,
            limit_field: provider.output_limit_field.key(),
            omit_schema: provider.response_format == ResponseFormatWire::Omitted,
            hello: hello.body,
            stats,
        })
    }

    fn shape(&self, mut body: Value) -> Value {
        let asked = body
            .as_object_mut()
            .and_then(|b| b.remove("max_tokens"))
            .and_then(|n| n.as_u64());
        let limit = match (asked, self.ceiling) {
            (Some(a), Some(c)) => Some(a.min(c)),
            (a, c) => a.or(c),
        };
        if let Some(limit) = limit {
            body[self.limit_field] = json!(limit);
        }
        if self.omit_schema
            && let Some(fields) = body.as_object_mut()
        {
            fields.remove("response_format");
        }
        body
    }
}

impl oneiron::llm::SingleSend for Transport {}

/// A failed step before the call left this side.
fn not_sent(stage: &'static str, cause: impl std::fmt::Display) -> OpenAiCompatTransportError {
    fault(OpenAiCompatTransportError::NotSent {
        stage,
        detail: cause.to_string(),
    })
}

/// Every native call fault reaches the screen's log with its cause; the
/// adapter turns each into the same retryable cut.
fn fault(error: OpenAiCompatTransportError) -> OpenAiCompatTransportError {
    eprintln!("NATIVE_CLIENT_ERROR {error}");
    error
}

struct Live {
    channel: Channel,
    id: u64,
    epoch: String,
    seq: u64,
    hello: Value,
    stats: Value,
}

impl Live {
    async fn begin(transport: &Transport, body: Value) -> Result<Self, OpenAiCompatTransportError> {
        let mut channel = Channel::connect(&transport.socket)
            .await
            .map_err(|e| not_sent("connect", e))?;
        let id = NEXT_ID.fetch_add(1, Ordering::Relaxed);
        channel
            .generate(id, &transport.epoch, transport.shape(body))
            .await?;
        Ok(Self {
            channel,
            id,
            epoch: transport.epoch.clone(),
            seq: 0,
            hello: transport.hello.clone(),
            stats: transport.stats.clone(),
        })
    }

    async fn step(
        mut self,
    ) -> Option<(
        Result<OpenAiCompatStreamFrame, OpenAiCompatTransportError>,
        Option<Self>,
    )> {
        loop {
            let frame = match self.channel.next().await {
                Ok(frame) => frame,
                Err(e) => {
                    let error = OpenAiCompatTransportError::Io {
                        stage: "receive",
                        detail: e.to_string(),
                    };
                    return Some((Err(fault(error)), None));
                }
            };
            // A refusal carries no seq: read it before the envelope check.
            if frame.op == "refused" && frame.request_id == self.id {
                let error = OpenAiCompatTransportError::Refused {
                    code: frame.body["code"].as_str().unwrap_or_default().to_owned(),
                    message: frame.body["message"]
                        .as_str()
                        .map_or_else(|| frame.body.to_string(), str::to_owned),
                };
                return Some((Err(fault(error)), None));
            }
            if frame.request_id != self.id
                || frame.epoch != self.epoch
                || frame.seq != Some(self.seq)
            {
                let error = OpenAiCompatTransportError::UnexpectedFrame(format!(
                    "`{}` id={} epoch={} seq={:?}; expected id={} epoch={} seq={}",
                    frame.op,
                    frame.request_id,
                    frame.epoch,
                    frame.seq,
                    self.id,
                    self.epoch,
                    self.seq,
                ));
                return Some((Err(fault(error)), None));
            }
            self.seq += 1;
            let mut body = frame.body;
            let mut chunk = json!({"choices": [{"index": 0, "delta": {}, "finish_reason": null}]});
            match frame.op.as_str() {
                "accepted" | "first_token" => continue,
                "token" => {
                    let field = if body["phase"] == "reasoning" {
                        "reasoning_content"
                    } else {
                        "content"
                    };
                    chunk["choices"][0]["delta"][field] = body["text"].take();
                    return Some((Ok(OpenAiCompatStreamFrame::Chunk(chunk)), Some(self)));
                }
                "final" if body["outcome"] == "done" => {
                    if let Some(tail) = body.get("tail") {
                        chunk["choices"][0]["delta"]["content"] = tail.clone();
                    }
                    if let Some(calls) = body.get("tool_calls") {
                        chunk["choices"][0]["delta"]["tool_calls"] = calls.clone();
                    }
                    chunk["choices"][0]["finish_reason"] = body["finish_reason"].take();
                    chunk["model"] = body["model"].take();
                    chunk["usage"] = body["usage"].take();
                    chunk["timings"] = body["timings"].take();
                    chunk["usage"]["bench_native_stats"] = body["stats"].take();
                    chunk["usage"]["bench_hello"] = self.hello;
                    chunk["usage"]["bench_stats_op"] = self.stats;
                    return Some((Ok(OpenAiCompatStreamFrame::Chunk(chunk)), None));
                }
                "final" => {
                    let error =
                        OpenAiCompatTransportError::EndedWithError(body["error"].to_string());
                    return Some((Err(fault(error)), None));
                }
                op => {
                    let error = OpenAiCompatTransportError::UnexpectedFrame(format!("`{op}`"));
                    return Some((Err(fault(error)), None));
                }
            }
        }
    }
}

impl OpenAiCompatTransport for Transport {
    fn execute<'a>(
        &'a self,
        _request: OpenAiCompatHttpRequest,
        _lease: &'a BudgetLease,
    ) -> OpenAiCompatFuture<'a> {
        Box::pin(async { Err(OpenAiCompatTransportError::Server) })
    }

    fn stream<'a>(
        &'a self,
        request: OpenAiCompatHttpRequest,
        _lease: &'a BudgetLease,
    ) -> Result<OpenAiCompatProviderStream<'a>, OpenAiCompatTransportError> {
        let initial = async move { Live::begin(self, request.body).await };
        let stream = futures_util::stream::once(initial);
        use futures_util::StreamExt as _;
        Ok(Box::pin(stream.flat_map(|live| {
            futures_util::stream::unfold(Some(live), |state| async {
                match state? {
                    Ok(live) => live.step().await.map(|(frame, next)| (frame, next.map(Ok))),
                    Err(error) => Some((Err(error), None)),
                }
            })
        })))
    }
}
