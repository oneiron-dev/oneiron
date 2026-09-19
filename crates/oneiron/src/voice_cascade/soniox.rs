//! Soniox streaming ASR wire client. Transport queues audio; callbacks normalize token frames.
use super::{AsrStream, AsrEvent, AsrEventKind, AsrToken};
use crate::error::Result;
use super::retrieval::invalid;

/// Host-owned transport: submit only, no provider work under the session lock.
pub trait SonioxTransport {
    fn submit_audio(&mut self, bytes: &[u8]) -> Result<()>;
    fn submit_end(&mut self) -> Result<()>;
}
pub struct SonioxAsrClient<T> { transport: T, committed: Vec<AsrToken>, ended: bool }
impl<T: SonioxTransport> SonioxAsrClient<T> {
    pub fn new(transport: T) -> Self { Self { transport, committed: Vec::new(), ended: false } }
    pub fn transport(&self) -> &T { &self.transport }
    /// Receive a provider WebSocket JSON frame outside session state. Final
    /// tokens accumulate until endpoint; non-final tokens are replacement hypotheses.
    pub fn receive(&mut self, frame: &serde_json::Value) -> Result<Vec<AsrEvent>> {
        if frame.get("error_code").is_some() {
            return Ok(vec![AsrEvent { kind: AsrEventKind::Error, text: String::new(), tokens: vec![], provider_latency_ms: None, endpoint_delay_ms: None, error: Some(frame["error_code"].to_string()) }]);
        }
        let mut partial = Vec::new(); let mut endpoint = false;
        if let Some(tokens) = frame.get("tokens") {
            for token in tokens.as_array().ok_or_else(|| invalid("Soniox tokens must be an array"))? {
                let text = token["text"].as_str().ok_or_else(|| invalid("Soniox token text missing"))?;
                if text == "<end>" { endpoint = true; continue; }
                let normalized = AsrToken { text: text.into(), is_final: token["is_final"].as_bool().ok_or_else(|| invalid("Soniox final flag missing"))?, start_ms: optional_number(token, "start_ms")?, end_ms: optional_number(token, "end_ms")?, confidence: optional_number(token, "confidence")? };
                let validation = event(AsrEventKind::Partial, vec![normalized.clone()]); validation.validate()?;
                if normalized.is_final { self.committed.push(normalized); } else { partial.push(normalized); }
            }
        }
        let mut events = Vec::new();
        if endpoint {
            if !self.committed.is_empty() { events.push(event(AsrEventKind::Final, std::mem::take(&mut self.committed))); }
            events.push(event(AsrEventKind::Endpoint, Vec::new()));
        } else if !self.committed.is_empty() || !partial.is_empty() {
            let mut hypothesis = self.committed.clone(); hypothesis.extend(partial); events.push(event(AsrEventKind::Partial, hypothesis));
        }
        if frame.get("finished").and_then(serde_json::Value::as_bool) == Some(true) {
            if !self.committed.is_empty() { events.push(event(AsrEventKind::Final, std::mem::take(&mut self.committed))); }
            events.push(event(AsrEventKind::Closed, Vec::new())); self.ended = true;
        }
        for event in &events { event.validate()?; } Ok(events)
    }
}
fn optional_number(value: &serde_json::Value, key: &str) -> Result<Option<f64>> {
    match value.get(key) { None | Some(serde_json::Value::Null) => Ok(None), Some(value) => value.as_f64().map(Some).ok_or_else(|| invalid("Soniox numeric metadata invalid")) }
}
fn event(kind: AsrEventKind, tokens: Vec<AsrToken>) -> AsrEvent {
    AsrEvent { kind, text: tokens.iter().map(|t| t.text.as_str()).collect(), tokens, provider_latency_ms: None, endpoint_delay_ms: None, error: None }
}
impl<T: SonioxTransport> AsrStream for SonioxAsrClient<T> {
    fn accept_audio(&mut self, pcm: &[u8]) -> Result<()> {
        if self.ended || pcm.is_empty() { return Err(invalid("Soniox stream closed or audio empty")); }
        self.transport.submit_audio(pcm)
    }
    fn end(&mut self) -> Result<()> { if !self.ended { self.transport.submit_end()?; self.ended = true; } Ok(()) }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[derive(Default)] struct Transport { audio: Vec<u8>, ends: usize }
    impl SonioxTransport for Transport {
        fn submit_audio(&mut self, bytes: &[u8]) -> Result<()> { self.audio.extend(bytes); Ok(()) }
        fn submit_end(&mut self) -> Result<()> { self.ends+=1; Ok(()) }
    }
    #[test]
    fn audio_submission_and_partial_final_endpoint_normalize() -> Result<()> {
        let mut client = SonioxAsrClient::new(Transport::default()); client.accept_audio(&[1,2,3,4])?;
        assert_eq!(client.transport().audio, [1,2,3,4]);
        let partial = client.receive(&serde_json::json!({"tokens":[{"text":"hello","is_final":false,"start_ms":0,"end_ms":50,"confidence":0.9}]}))?;
        assert_eq!(partial[0].kind, AsrEventKind::Partial); partial[0].validate()?;
        let final_events = client.receive(&serde_json::json!({"tokens":[{"text":"hello","is_final":true},{"text":"<end>","is_final":true}]}))?;
        assert_eq!(final_events[0].kind, AsrEventKind::Final); assert_eq!(final_events[0].text,"hello"); assert_eq!(final_events[1].kind, AsrEventKind::Endpoint);
        for event in final_events { event.validate()?; }
        client.end()?; client.end()?; assert_eq!(client.transport().ends, 1); assert!(client.accept_audio(&[0]).is_err()); Ok(())
    }
}
