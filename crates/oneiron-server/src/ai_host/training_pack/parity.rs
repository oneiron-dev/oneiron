//! The host's Candle-side reproduction of a question head's receipt (FIX
//! 7568), before the head may serve.
//!
//! The trainer's encoder is a hand PyTorch port of the oneironer trunk, so
//! its word on its own probes is checked here, on the stack that serves:
//! each probe is rendered as the trainer renders it
//! ([`QuestionTarget::render_target_text`]), tokenized with the export's own
//! pinned tokenizer through the Rust tokenizer the oneironer serves on, with
//! no padding and no truncation, and cut into the trainer's windows. The
//! BLAKE3 of those ids must be the receipt's. A probe that does not
//! reproduce is named on the check, the check fails, and so does the run's
//! export check: the head never serves.
//!
//! The logits half waits on a Candle classifier loader. Until one is built
//! here, `logits_match` stays unknown: never run, never a pass.

use oneiron::training_pack::{
    CandleParityCheck, CheckpointFileKind, CheckpointUpload, ProbeCase, ProbeMeasurement,
    QuestionTarget,
};
use serde_json::Value;
use tokenizers::Tokenizer;

/// The encoder config key the trainer reads its window length from.
const POSITIONS_KEY: &str = "max_position_embeddings";

/// The check of `probes`, the receipt's measurements of the plan's `cases`,
/// against `export`, the head's exported load set.
pub(super) fn candle_parity(
    question: &QuestionTarget,
    cases: &[ProbeCase],
    export: &CheckpointUpload,
    probes: &[ProbeMeasurement],
) -> CandleParityCheck {
    let encoder = Encoder::of(export);
    if encoder.is_none() {
        tracing::warn!(
            "a question head's exported tokenizer or config did not load here; its Candle parity fails"
        );
    }
    let token_mismatches: Vec<String> = probes
        .iter()
        .filter(|probe| {
            let reproduced = encoder
                .as_ref()
                .zip(cases.iter().find(|case| case.id == probe.probe_id))
                .and_then(|(encoder, case)| encoder.tokens_blake3(question, &case.input));
            reproduced.is_none() || reproduced != probe.tokens_blake3
        })
        .map(|probe| probe.probe_id.clone())
        .collect();
    CandleParityCheck {
        tokens_match: token_mismatches.is_empty(),
        token_mismatches,
        logits_match: None,
    }
}

/// The export's tokenizer and its encoder's window length.
struct Encoder {
    tokenizer: Tokenizer,
    positions: usize,
}

impl Encoder {
    /// The export's pinned tokenizer, without padding or truncation, and
    /// its config's positions; `None` when either does not read.
    fn of(export: &CheckpointUpload) -> Option<Self> {
        let file = |kind: CheckpointFileKind| {
            export
                .files
                .iter()
                .find(|file| file.kind == kind)
                .map(|file| file.bytes.as_slice())
        };
        let mut tokenizer = Tokenizer::from_bytes(file(CheckpointFileKind::Tokenizer)?).ok()?;
        tokenizer.with_padding(None);
        tokenizer.with_truncation(None).ok()?;
        let config: Value = serde_json::from_slice(file(CheckpointFileKind::Config)?).ok()?;
        let positions = usize::try_from(config.get(POSITIONS_KEY)?.as_u64()?).ok()?;
        Some(Self {
            tokenizer,
            positions,
        })
    }

    /// `input`'s token ids as the trainer's windows, hashed as the trainer
    /// hashes them: BLAKE3 of their canonical JSON.
    fn tokens_blake3(&self, question: &QuestionTarget, input: &Value) -> Option<[u8; 32]> {
        let text = question.render_target_text(input).ok()?;
        let windows = self.windows(&text)?;
        let bytes = serde_json::to_vec(&windows).ok()?;
        Some(*blake3::hash(&bytes).as_bytes())
    }

    /// `text` as consecutive windows of at most `positions` ids, each with
    /// the specials the tokenizer adds around it, as the trainer cuts them
    /// (`encoder.tokenize_targets`): its content ids in runs of `positions`
    /// minus the specials' count, each wrapped in that prefix and suffix. A
    /// text that fits is one window. `None` where the trainer refuses: a
    /// tokenizer that changes a sequence beyond adding specials, or specials
    /// that fill every position.
    fn windows(&self, text: &str) -> Option<Vec<Vec<u32>>> {
        let full = self.tokenizer.encode(text, true).ok()?.get_ids().to_vec();
        let content = self.tokenizer.encode(text, false).ok()?.get_ids().to_vec();
        let start = (0..=full.len().checked_sub(content.len())?)
            .find(|&start| full[start..start + content.len()] == content[..])?;
        let (prefix, suffix) = (&full[..start], &full[start + content.len()..]);
        let room = self
            .positions
            .checked_sub(prefix.len() + suffix.len())
            .filter(|room| *room > 0)?;
        let runs: Vec<&[u32]> = if content.is_empty() {
            vec![&content[..]]
        } else {
            content.chunks(room).collect()
        };
        Some(
            runs.into_iter()
                .map(|run| [prefix, run, suffix].concat())
                .collect(),
        )
    }
}
