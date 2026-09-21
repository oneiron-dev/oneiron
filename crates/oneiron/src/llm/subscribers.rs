//! Pure clock-injected progress and voice stages. Neither has a ledger handle.
use super::LlmStreamEvent;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProgressSnapshot {
    pub text_bytes: usize,
    pub terminal: bool,
}
#[derive(Debug, Default)]
pub struct ProgressSubscriber {
    last_ms: Option<u64>,
    bytes: usize,
}
impl ProgressSubscriber {
    pub fn observe(&mut self, event: &LlmStreamEvent, now_ms: u64) -> Option<ProgressSnapshot> {
        if let LlmStreamEvent::TextDelta { text, .. } = event {
            self.bytes = self.bytes.saturating_add(text.len());
        }
        let terminal = matches!(event, LlmStreamEvent::Done { .. });
        let previous = *self.last_ms.get_or_insert(now_ms);
        if terminal || now_ms.saturating_sub(previous) >= 1_000 {
            self.last_ms = Some(now_ms);
            Some(ProgressSnapshot {
                text_bytes: self.bytes,
                terminal,
            })
        } else {
            None
        }
    }
}

#[derive(Debug, Default)]
pub struct VoiceChunker {
    pending: String,
    since_ms: Option<u64>,
}
impl VoiceChunker {
    pub fn observe(&mut self, event: &LlmStreamEvent, now_ms: u64) -> Vec<String> {
        let mut chunks = Vec::new();
        if let LlmStreamEvent::TextDelta { text, .. } = event {
            for ch in text.chars() {
                self.since_ms.get_or_insert(now_ms);
                self.pending.push(ch);
                if (matches!(ch, '.' | '!' | '?' | ';' | ':' | ',' | '\n')
                    || (ch.is_whitespace() && self.pending.split_whitespace().count() >= 6))
                    && let Some(chunk) = self.flush()
                {
                    chunks.push(chunk);
                }
            }
        }
        if matches!(event, LlmStreamEvent::Done { .. }) {
            if let Some(chunk) = self.flush() {
                chunks.push(chunk);
            }
        } else if let Some(chunk) = self.tick(now_ms) {
            chunks.push(chunk);
        }
        chunks
    }
    /// Hosts call this on a 150ms timer even while the model is quiet.
    pub fn tick(&mut self, now_ms: u64) -> Option<String> {
        if self
            .since_ms
            .is_some_and(|start| now_ms.saturating_sub(start) >= 150)
        {
            self.flush()
        } else {
            None
        }
    }
    fn flush(&mut self) -> Option<String> {
        self.since_ms = None;
        let text = std::mem::take(&mut self.pending);
        (!text.trim().is_empty()).then_some(text)
    }
}
