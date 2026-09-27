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

    /// Emit a heartbeat on an injected clock even when the model is quiet.
    pub fn tick(&mut self, now_ms: u64) -> Option<ProgressSnapshot> {
        let previous = self.last_ms?;
        if now_ms.saturating_sub(previous) < 1_000 {
            return None;
        }
        self.last_ms = Some(now_ms);
        Some(ProgressSnapshot {
            text_bytes: self.bytes,
            terminal: false,
        })
    }
}

/// Session-local voice cadence. A resident may select values for its current
/// session; this policy is never written to the ledger.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VoiceChunkPolicy {
    pub punctuation: String,
    pub min_words: usize,
    pub max_wait_ms: u64,
}

impl Default for VoiceChunkPolicy {
    fn default() -> Self {
        Self {
            punctuation: ".!?;:,\n".into(),
            min_words: 6,
            max_wait_ms: 150,
        }
    }
}

#[derive(Debug, Default)]
pub struct VoiceChunker {
    pending: String,
    since_ms: Option<u64>,
    policy: VoiceChunkPolicy,
}
impl VoiceChunker {
    /// Reject policies that could flush every character or never flush on time.
    pub fn with_policy(policy: VoiceChunkPolicy) -> Option<Self> {
        (policy.min_words > 0 && policy.max_wait_ms > 0).then(|| Self {
            pending: String::new(),
            since_ms: None,
            policy,
        })
    }
    pub fn observe(&mut self, event: &LlmStreamEvent, now_ms: u64) -> Vec<String> {
        let mut chunks = Vec::new();
        if let LlmStreamEvent::TextDelta { text, .. } = event {
            for ch in text.chars() {
                self.since_ms.get_or_insert(now_ms);
                self.pending.push(ch);
                if (self.policy.punctuation.contains(ch)
                    || (ch.is_whitespace()
                        && self.pending.split_whitespace().count() >= self.policy.min_words))
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
    /// Hosts call this on the selected timer even while the model is quiet.
    pub fn tick(&mut self, now_ms: u64) -> Option<String> {
        if self
            .since_ms
            .is_some_and(|start| now_ms.saturating_sub(start) >= self.policy.max_wait_ms)
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
