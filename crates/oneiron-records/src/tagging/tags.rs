//! Moved from `crates/oneiron/src/tagging/tags.rs` (lib split R1: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use oneiron_store::config::tagging::TaggingMarkerConfig;
use oneiron_verb_wire::memory::extraction::types::SpeakerTarget;
use serde::Deserialize;
use serde::Serialize;
use std::collections::BTreeSet;

/// The memo-key of one tag set (ARCH-0035). Two tag sets under one envelope
/// are interchangeable, so a save under the envelope the turn already holds
/// writes nothing, and a new tagger re-tags by it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DerivationEnvelope {
    /// Digest of the input the tags were read from.
    pub content_hash: String,
    /// What made them: `model@checkpoint` for the slot's tagger,
    /// `held@checkpoint` for tags an importer held.
    pub model_id: String,
    /// The served stack the answer names beside the checkpoint, when it
    /// names one: a head swap at a fixed checkpoint is another derivation.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stack: Option<String>,
    /// Digest of the turn's own text, when `content_hash` is a conversation
    /// register's, whose later turns move with the conversation (FIX 10167):
    /// what tells whether the set still indexes the turn's words.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub text_hash: Option<String>,
    /// The save path's version.
    pub version: String,
    /// Digest of the decode parameters: the label table and the live window.
    pub params_hash: String,
}

impl DerivationEnvelope {
    /// Whether the tagger `config` arms made the set: its checkpoint is the
    /// part of `model_id` after the last `@` (a model id may hold `@`
    /// itself), and a stack `config` pins is the set's stack. An unpinned
    /// tagger accepts the stack any answer names, so every saved stack is its.
    pub fn made_by_tagger(&self, config: &TaggingMarkerConfig) -> bool {
        let checkpoint = self
            .model_id
            .rsplit_once('@')
            .map(|(_, checkpoint)| checkpoint);
        checkpoint == Some(config.checkpoint.as_str())
            && config
                .stack
                .as_ref()
                .is_none_or(|stack| self.stack.as_ref() == Some(stack))
    }
}

/// A coreference decision that reaches outside the turn's own spans. A span
/// takes the link it resolves to as it takes an antecedent's.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum MentionReference {
    /// The span corefers with a span of an earlier turn in its window, and
    /// the save found that span saved: the span took its link.
    Context,
    /// The span is its turn's speaker or addressee. `resolved` says whether
    /// the save named one person for it: the turn's author for the speaker,
    /// the one other party of a 1:1 room for the addressee. An unresolved
    /// decision names no one.
    Speaker {
        target: SpeakerTarget,
        resolved: bool,
    },
}

/// A coreference link that joins two spans linked to different entities:
/// evidence that they may be one, for the Dreamer. The save never merges.
/// It is kept only while the two spans name different entities.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MergeEvidence {
    pub span: usize,
    pub antecedent: usize,
    pub confidence: f32,
}
