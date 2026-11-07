//! A bound question head answers its typed question on the Local rung (FIX
//! 3864, OF-577).
//!
//! The host's Local slot holds [`QuestionHeadRung`]. A yes/no call whose
//! question id and version the owner bound a head to
//! (`Vault::approve_training_question_head`), and whose state carries the
//! head's input (a `target` and a `context` list, rendered as the head was
//! trained: `oneiron.detector-target-text/1`), is answered by that head at its
//! fitted temperature. Every other call goes to the seat the slot held before
//! (the Local-vision seat, when one is bound), or abstains so the ladder steps
//! to its next rung: the model call, as before. A head that cannot load or
//! read abstains the same way; it never fails the call.
//!
//! A head loads once, from custody, every file's hash rechecked as its
//! bytes are read, and stays loaded under its question while it is bound
//! there. A head no binding names any more (unbound, replaced, or its
//! question erased) is dropped when the owner's bind or unbind door returns,
//! and otherwise within a minute of the slot's next call. Its rotary
//! tables cover the longest window it has read; a longer input loads it
//! again at that length.
//!
//! A pack in which no question has a bound head goes to the seat whole, as
//! before. With no seat in the slot, the slot takes only yes/no questions,
//! the one kind a head answers; a receipt then names its abstain as the
//! Local rung's read.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant};

use oneiron::llm::decision::{
    AnswerContract, DecisionAnswer, DecisionCall, DecisionPack, DecisionProvider, DecisionRung,
    ProviderCapability, ProviderDecision, ProviderPin,
};
use oneiron::training_pack::{
    CheckpointFileUpload, CheckpointUpload, PinnedCheckpoint, QuestionHeadBinding,
};
use oneiron::{EntityId, Error, Vault};
use serde_json::Value;

use super::question_evaluation::calibration::yes_probability;
use crate::oneironer::QuestionHead;

/// The model the slot names when no seat filled it before: one name for
/// every head it serves, each answer naming its own head. Both names read
/// as a model id (`provider/name@revision`) with the pin's version.
const QUESTION_HEADS_MODEL: &str = "oneiron/question-heads";
const QUESTION_HEADS_VERSION: &str = "1";
/// How often the slot drops the loaded heads no binding names, at most.
const PRUNE_EVERY: Duration = Duration::from_secs(60);
/// How an answer names the head that gave it, before its checkpoint hash.
const QUESTION_HEAD_MODEL_PREFIX: &str = "oneiron/question-head.";

fn failed(detail: &str) -> Error {
    Error::InvalidConfig(format!("question head: {detail}"))
}

fn abstain() -> ProviderDecision {
    ProviderDecision {
        answer: DecisionAnswer::Abstain,
        probability: None,
        paired: None,
        person: None,
        served: None,
        cost_per_thousand: None,
    }
}

/// A loaded head and the load-set hash of the checkpoint it loaded.
struct LoadedHead {
    checkpoint: [u8; 32],
    head: Arc<QuestionHead>,
}

/// The Local slot with the owner's bound question heads in front of the
/// seat it held before.
pub(crate) struct QuestionHeadRung {
    vault: Arc<Vault>,
    /// The seat the slot held before, which every other call reaches.
    inner: Option<Arc<dyn DecisionProvider>>,
    /// Each loaded head by its typed question and version, with its
    /// checkpoint's load-set hash.
    heads: Mutex<BTreeMap<(EntityId, u32), LoadedHead>>,
    /// When the slot last dropped the heads no binding names.
    pruned_at: Mutex<Instant>,
}

impl QuestionHeadRung {
    pub(crate) fn new(vault: Arc<Vault>, inner: Option<Arc<dyn DecisionProvider>>) -> Self {
        Self {
            vault,
            inner,
            heads: Mutex::new(BTreeMap::new()),
            pruned_at: Mutex::new(Instant::now()),
        }
    }

    /// The bound head's answer to `call`, or `None` when no head answers it:
    /// not a yes/no question, no head bound to its id and version, or a
    /// state that is not the head's input.
    fn head_answer(&self, call: &DecisionCall<'_>) -> oneiron::Result<Option<ProviderDecision>> {
        if !matches!(call.question.contract, AnswerContract::Noul)
            || !call.images.is_empty()
            || !call.audio.is_empty()
            || call.state.get("target").is_none()
            || !call.state.get("context").is_some_and(Value::is_array)
        {
            return Ok(None);
        }
        let Some(binding) = self
            .vault
            .training_question_head(call.question.id, call.question.version)?
        else {
            return Ok(None);
        };
        let head = self.loaded(&binding, call.state)?;
        let raw = head
            .logits(call.state)
            .map_err(|error| failed(&error.to_string()))?;
        let yes = yes_probability(raw, binding.temperature);
        if !yes.is_finite() {
            return Err(failed("a non-finite probability"));
        }
        Ok(Some(ProviderDecision {
            answer: DecisionAnswer::Noul(yes >= 0.5),
            probability: Some(yes),
            paired: None,
            person: None,
            served: Some(self.head_pin(&binding)?),
            // A local head's answer costs the provider's rate (#5770).
            cost_per_thousand: None,
        }))
    }

    /// The pin an answer of `binding`'s head names: the slot's rung and
    /// version (a served pin keeps its provider's version), and the head by
    /// its checkpoint's load-set hash, which the binding pairs with its
    /// model.
    fn head_pin(&self, binding: &QuestionHeadBinding) -> oneiron::Result<ProviderPin> {
        let checkpoint = blake3::Hash::from(binding.checkpoint.content_hash()?).to_hex();
        Ok(ProviderPin {
            rung: DecisionRung::Local,
            model: format!("{QUESTION_HEAD_MODEL_PREFIX}{}", checkpoint.as_str()),
            version: self.pin().version,
        })
    }

    /// `binding`'s head, loaded for windows as long as `input` needs. The
    /// binding is read again under the cache's lock, which [`Self::prune`]
    /// takes too: a head unbound since the call read it is neither used nor
    /// loaded, so no unbound head stays cached after an unbind's prune.
    fn loaded(
        &self,
        binding: &QuestionHeadBinding,
        input: &Value,
    ) -> oneiron::Result<Arc<QuestionHead>> {
        let checkpoint = binding.checkpoint.content_hash()?;
        let key = (binding.question, binding.question_version);
        let mut heads = self.heads.lock().unwrap_or_else(PoisonError::into_inner);
        let live = self
            .vault
            .training_question_head(binding.question, binding.question_version)?
            .map(|live| live.checkpoint.content_hash())
            .transpose()?;
        if live != Some(checkpoint) {
            heads.remove(&key);
            return Err(failed("the head was unbound while the call read it"));
        }
        if let Some(loaded) = heads.get(&key)
            && loaded.checkpoint == checkpoint
            && loaded
                .head
                .window_need(input)
                .map_err(|error| failed(&error.to_string()))?
                <= loaded.head.cap()
        {
            return Ok(Arc::clone(&loaded.head));
        }
        // The question's earlier head, if any, is dropped before the load.
        heads.remove(&key);
        let export = checkpoint_upload(&self.vault, &binding.checkpoint)?;
        let head = Arc::new(
            QuestionHead::load(&binding.target, &export, &[input])
                .map_err(|error| failed(&error.to_string()))?,
        );
        heads.insert(
            key,
            LoadedHead {
                checkpoint,
                head: Arc::clone(&head),
            },
        );
        Ok(head)
    }

    /// The bound head's answer to `call`; an abstain when its head could not
    /// answer, so the next rung does; `None` when no head is bound to it.
    fn head_or_abstain(&self, call: &DecisionCall<'_>) -> Option<ProviderDecision> {
        self.head_answer(call).unwrap_or_else(|error| {
            tracing::warn!(%error, "a bound question head did not answer; the next rung answers");
            Some(abstain())
        })
    }

    /// Drops every loaded head no binding names any more, so an unbound,
    /// replaced or erased head frees its encoder.
    ///
    /// # Errors
    ///
    /// Storage errors, or a binding whose checkpoint cannot be hashed.
    pub(crate) fn prune(&self) -> oneiron::Result<()> {
        *self
            .pruned_at
            .lock()
            .unwrap_or_else(PoisonError::into_inner) = Instant::now();
        if self
            .heads
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .is_empty()
        {
            return Ok(());
        }
        let bound = self
            .vault
            .training_question_heads()?
            .iter()
            .map(|binding| {
                Ok((
                    (binding.question, binding.question_version),
                    binding.checkpoint.content_hash()?,
                ))
            })
            .collect::<oneiron::Result<BTreeSet<_>>>()?;
        self.heads
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .retain(|key, loaded| bound.contains(&(*key, loaded.checkpoint)));
        Ok(())
    }

    /// [`Self::prune`] once [`PRUNE_EVERY`] has passed since the last one.
    fn prune_when_due(&self) {
        let due = self
            .pruned_at
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .elapsed()
            >= PRUNE_EVERY;
        if due && let Err(error) = self.prune() {
            tracing::warn!(%error, "the loaded question heads were not pruned");
        }
    }

    /// What the seat the slot held before answers `call`; an abstain with
    /// no seat.
    fn seat_decide(&self, call: &DecisionCall<'_>) -> oneiron::Result<ProviderDecision> {
        match &self.inner {
            Some(inner) => inner.decide(call),
            None => Ok(abstain()),
        }
    }
}

/// `checkpoint`'s load set from custody, each file's hash rechecked as its
/// bytes are read.
fn checkpoint_upload(
    vault: &Vault,
    checkpoint: &PinnedCheckpoint,
) -> oneiron::Result<CheckpointUpload> {
    Ok(CheckpointUpload {
        model: checkpoint.model.clone(),
        files: checkpoint
            .files
            .iter()
            .map(|file| {
                Ok(CheckpointFileUpload {
                    name: file.name.clone(),
                    kind: file.kind,
                    source: file.source.clone(),
                    blake3: file.content.blake3,
                    bytes: vault.read_training_artifact(&file.content)?,
                })
            })
            .collect::<oneiron::Result<Vec<_>>>()?,
    })
}

impl DecisionProvider for QuestionHeadRung {
    fn pin(&self) -> ProviderPin {
        self.inner.as_ref().map_or_else(
            || ProviderPin {
                rung: DecisionRung::Local,
                model: QUESTION_HEADS_MODEL.to_owned(),
                version: QUESTION_HEADS_VERSION.to_owned(),
            },
            |inner| inner.pin(),
        )
    }

    /// The seat's; with no seat, yes/no questions only: no choice or score
    /// question reaches an empty slot, as before.
    fn capability(&self) -> ProviderCapability {
        self.inner.as_ref().map_or(
            ProviderCapability {
                max_options: 0,
                score: false,
            },
            |inner| inner.capability(),
        )
    }

    fn reads_images(&self) -> bool {
        self.inner
            .as_ref()
            .is_some_and(|inner| inner.reads_images())
    }

    fn image_edge(&self) -> Option<u32> {
        self.inner.as_ref().and_then(|inner| inner.image_edge())
    }

    fn reads_audio(&self) -> bool {
        self.inner.as_ref().is_some_and(|inner| inner.reads_audio())
    }

    /// A head reads on this host; the seat it fronts may not, so the slot
    /// says what that seat says.
    fn leaves_host(&self) -> bool {
        self.inner.as_ref().is_some_and(|inner| inner.leaves_host())
    }

    fn cost_per_thousand(&self) -> Option<f64> {
        self.inner
            .as_ref()
            .and_then(|inner| inner.cost_per_thousand())
    }

    fn state_budget_bytes(&self) -> Option<usize> {
        self.inner
            .as_ref()
            .and_then(|inner| inner.state_budget_bytes())
    }

    fn decide(&self, call: &DecisionCall<'_>) -> oneiron::Result<ProviderDecision> {
        self.prune_when_due();
        match self.head_or_abstain(call) {
            Some(decision) => Ok(decision),
            None => self.seat_decide(call),
        }
    }

    /// A pack in which no question has a bound head goes to the seat whole,
    /// as before. Otherwise each bound question gets its head's answer and
    /// each other question the seat's, asked alone.
    fn decide_pack(&self, pack: &DecisionPack<'_>) -> oneiron::Result<Vec<ProviderDecision>> {
        self.prune_when_due();
        let calls: Vec<DecisionCall<'_>> = (0..pack.questions.len())
            .filter_map(|index| pack.call(index))
            .collect();
        let heads: Vec<Option<ProviderDecision>> = calls
            .iter()
            .map(|call| self.head_or_abstain(call))
            .collect();
        if heads.iter().all(Option::is_none) {
            return match &self.inner {
                Some(inner) => inner.decide_pack(pack),
                None => Ok(calls.iter().map(|_| abstain()).collect()),
            };
        }
        calls
            .iter()
            .zip(heads)
            .map(|(call, head)| head.map_or_else(|| self.seat_decide(call), Ok))
            .collect()
    }
}
