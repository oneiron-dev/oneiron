//! Moved from `crates/oneiron/src/tagging/tags.rs` (lib split R1: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use crate::tagging::provisional;
use oneiron_contracts::entity_id::EntityId;
use oneiron_store::config::tagging::TaggingMarkerConfig;
use oneiron_verb_wire::memory::extraction::types::SpeakerTarget;
use serde::Deserialize;
use serde::Serialize;
use std::collections::BTreeSet;
use std::ops::Bound;

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

/// Where an unconfirmed mention points. None of these is an edge.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MentionLink {
    /// The label maps to no entity kind: the span stays a tag.
    Tag,
    /// The identity key named these entities, real or provisional; or, for
    /// a person's name of two or more parts the key misses, the phonetic
    /// rung found two or more persons it sounds like (ARCH-0024 signal 2;
    /// one alone mints, and the nightly re-check asks about it); or the
    /// span took them from what it corefers with: an antecedent, an earlier
    /// turn's saved span, or the turn's speaker or addressee. A hit, even a
    /// single one, is a soft link: the linker decides whether the mention is
    /// any of them (ARCH-0055 §10).
    Candidates { kind: u8, entities: Vec<EntityId> },
    /// The key named nothing, so the save minted this provisional entity.
    Minted { kind: u8, entity: EntityId },
}

impl MentionLink {
    /// The entity kind the span was linked as; `None` for a tag.
    #[must_use]
    pub fn kind(&self) -> Option<u8> {
        match self {
            Self::Tag => None,
            Self::Candidates { kind, .. } | Self::Minted { kind, .. } => Some(*kind),
        }
    }

    /// Every entity the link names.
    #[must_use]
    pub fn entities(&self) -> &[EntityId] {
        match self {
            Self::Tag => &[],
            Self::Candidates { entities, .. } => entities,
            Self::Minted { entity, .. } => std::slice::from_ref(entity),
        }
    }

    /// The link with `entity` gone; a link left naming nothing is a tag.
    pub fn without(&self, entity: &EntityId) -> Self {
        match self {
            Self::Minted { entity: minted, .. } if minted == entity => Self::Tag,
            Self::Candidates { kind, entities } if entities.contains(entity) => {
                let entities: Vec<_> = entities.iter().filter(|e| *e != entity).copied().collect();
                if entities.is_empty() {
                    Self::Tag
                } else {
                    Self::Candidates {
                        kind: *kind,
                        entities,
                    }
                }
            }
            other => other.clone(),
        }
    }

    /// The link with `from` named as `to`.
    fn redirected(&self, from: &EntityId, to: EntityId) -> Self {
        match self {
            Self::Minted { kind, entity } if entity == from => Self::Minted {
                kind: *kind,
                entity: to,
            },
            Self::Candidates { kind, entities } if entities.contains(from) => {
                let entities: BTreeSet<_> = entities
                    .iter()
                    .map(|e| if e == from { to } else { *e })
                    .collect();
                Self::Candidates {
                    kind: *kind,
                    entities: entities.into_iter().collect(),
                }
            }
            other => other.clone(),
        }
    }
}

/// One span as a derived suggestion: never a `mentions` edge, never synced.
/// The Dreamer or an actor confirms it.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TaggedMention {
    /// The MESSAGE the span is in.
    pub message: EntityId,
    /// Byte offsets into the message's text.
    pub start: usize,
    pub end: usize,
    pub label: String,
    pub confidence: f32,
    pub link: MentionLink,
    /// The span this one corefers with, when the tagger linked them. A
    /// coreferent span takes its antecedent's link unless its own name keys
    /// to an entity.
    pub antecedent: Option<usize>,
    /// Where the tagger put this span's referent outside this turn's spans,
    /// when it did and the save kept the decision.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reference: Option<MentionReference>,
    /// The tagger's confidence in the span's link, context link or speaker
    /// link, when it gave one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub link_confidence: Option<f32>,
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
