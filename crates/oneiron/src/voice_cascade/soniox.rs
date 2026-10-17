//! Soniox streaming ASR wire client. Transport queues audio; callbacks normalize token frames.
//! The owner's cut is authoritative: `finalize` asks Soniox to make every word
//! spoken so far final, and its `<fin>` ack hands them back as one Final. A
//! `<end>` from Soniox's own endpoint detection is an advisory Endpoint, and
//! its words stay pending until the owner cuts. Neither marker is transcript text.
use super::retrieval::invalid;
use super::{AsrEvent, AsrEventKind, AsrStream, AsrToken};
use crate::error::Result;

/// Host-owned transport: submit only, no provider work under the session lock.
pub trait SonioxTransport {
    fn submit_audio(&mut self, bytes: &[u8]) -> Result<()>;
    /// Sends `{"type":"finalize"}`, after every audio byte submitted before it.
    fn submit_finalize(&mut self) -> Result<()>;
    fn submit_end(&mut self) -> Result<()>;
}
/// One frame's meaning, in the order Soniox said it.
#[derive(Debug, Clone, PartialEq)]
pub enum SonioxUpdate {
    Asr(AsrEvent),
    /// `<fin>`: a finalize the host asked for is done, and every word before
    /// it came back in the Final just before this.
    Finalized,
}
pub struct SonioxAsrClient<T> {
    transport: T,
    committed: Vec<AsrToken>,
    /// Finalizes sent whose `<fin>` has not come back.
    finalizing: usize,
    ended: bool,
}
impl<T: SonioxTransport> SonioxAsrClient<T> {
    pub fn new(transport: T) -> Self {
        Self {
            transport,
            committed: Vec::new(),
            finalizing: 0,
            ended: false,
        }
    }
    pub fn transport(&self) -> &T {
        &self.transport
    }
    pub fn transport_mut(&mut self) -> &mut T {
        &mut self.transport
    }
    /// The owner's cut: asks Soniox to finalize every word spoken so far.
    /// Its `<fin>` comes back as [`SonioxUpdate::Finalized`].
    pub fn finalize(&mut self) -> Result<()> {
        if self.ended {
            return Err(invalid("Soniox stream closed"));
        }
        self.transport.submit_finalize()?;
        self.finalizing = self.finalizing.saturating_add(1);
        Ok(())
    }
    /// Whether a finalize is waiting for its `<fin>`.
    #[must_use]
    pub fn finalizing(&self) -> bool {
        self.finalizing > 0
    }
    /// Receive a provider WebSocket JSON frame outside session state. Final
    /// tokens accumulate until `<fin>` or `finished`; non-final tokens are
    /// replacement hypotheses.
    pub fn receive(&mut self, frame: &serde_json::Value) -> Result<Vec<SonioxUpdate>> {
        if frame.get("error_code").is_some() || frame.get("error_message").is_some() {
            let field = |key: &str| {
                frame
                    .get(key)
                    .filter(|value| !value.is_null())
                    .map(|value| {
                        value
                            .as_str()
                            .map_or_else(|| value.to_string(), str::to_owned)
                    })
            };
            let error = match (field("error_code"), field("error_message")) {
                (Some(code), Some(message)) => format!("{code}: {message}"),
                (Some(text), None) | (None, Some(text)) => text,
                (None, None) => "Soniox error".to_owned(),
            };
            return Ok(vec![SonioxUpdate::Asr(AsrEvent {
                error: Some(error),
                ..event(AsrEventKind::Error, Vec::new())
            })]);
        }
        let mut updates = Vec::new();
        let mut partial = Vec::new();
        if let Some(tokens) = frame.get("tokens") {
            for token in tokens
                .as_array()
                .ok_or_else(|| invalid("Soniox tokens must be an array"))?
            {
                let text = token["text"]
                    .as_str()
                    .ok_or_else(|| invalid("Soniox token text missing"))?;
                match text {
                    "<end>" => {
                        updates.push(SonioxUpdate::Asr(event(AsrEventKind::Endpoint, Vec::new())));
                        continue;
                    }
                    "<fin>" => {
                        self.finalizing = self
                            .finalizing
                            .checked_sub(1)
                            .ok_or_else(|| invalid("Soniox finalized unasked"))?;
                        self.flush(&mut updates);
                        updates.push(SonioxUpdate::Finalized);
                        continue;
                    }
                    _ => {}
                }
                let normalized = AsrToken {
                    text: text.into(),
                    is_final: token["is_final"]
                        .as_bool()
                        .ok_or_else(|| invalid("Soniox final flag missing"))?,
                    start_ms: optional_number(token, "start_ms")?,
                    end_ms: optional_number(token, "end_ms")?,
                    confidence: optional_number(token, "confidence")?,
                };
                let validation = event(AsrEventKind::Partial, vec![normalized.clone()]);
                validation.validate()?;
                if normalized.is_final {
                    self.committed.push(normalized);
                } else {
                    partial.push(normalized);
                }
            }
        }
        if frame.get("finished").and_then(serde_json::Value::as_bool) == Some(true) {
            self.flush(&mut updates);
            updates.push(SonioxUpdate::Asr(event(AsrEventKind::Closed, Vec::new())));
            self.ended = true;
        } else if !self.committed.is_empty() || !partial.is_empty() {
            let mut hypothesis = self.committed.clone();
            hypothesis.extend(partial);
            updates.push(SonioxUpdate::Asr(event(AsrEventKind::Partial, hypothesis)));
        }
        for update in &updates {
            if let SonioxUpdate::Asr(event) = update {
                event.validate()?;
            }
        }
        Ok(updates)
    }
    /// The words made final so far, as one Final.
    fn flush(&mut self, updates: &mut Vec<SonioxUpdate>) {
        if !self.committed.is_empty() {
            updates.push(SonioxUpdate::Asr(event(
                AsrEventKind::Final,
                std::mem::take(&mut self.committed),
            )));
        }
    }
}
fn optional_number(value: &serde_json::Value, key: &str) -> Result<Option<f64>> {
    match value.get(key) {
        None | Some(serde_json::Value::Null) => Ok(None),
        Some(value) => value
            .as_f64()
            .map(Some)
            .ok_or_else(|| invalid("Soniox numeric metadata invalid")),
    }
}
fn event(kind: AsrEventKind, tokens: Vec<AsrToken>) -> AsrEvent {
    AsrEvent {
        kind,
        text: tokens.iter().map(|t| t.text.as_str()).collect(),
        tokens,
        provider_latency_ms: None,
        endpoint_delay_ms: None,
        error: None,
    }
}
impl<T: SonioxTransport> AsrStream for SonioxAsrClient<T> {
    fn accept_audio(&mut self, pcm: &[u8]) -> Result<()> {
        if self.ended || pcm.is_empty() {
            return Err(invalid("Soniox stream closed or audio empty"));
        }
        self.transport.submit_audio(pcm)
    }
    fn end(&mut self) -> Result<()> {
        if !self.ended {
            self.transport.submit_end()?;
            self.ended = true;
        }
        Ok(())
    }
}
