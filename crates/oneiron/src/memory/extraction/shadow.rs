//! Shadow execution never runs under the witness transaction or writes another row.
use super::types::*;
use crate::embed::EmbedderLocality;
use crate::memory::{Memory, MemoryResult, WitnessTurn};
use sha2::{Digest, Sha256};
impl Memory<'_> {
    /// Witnesses through the ordinary base door, then runs a local served head.
    /// Off-record/session writes use their own door and never enter this hook.
    /// A failed or invalid inference becomes a trace, not a failed write.
    pub fn witness_with_shadow(
        &self,
        turn: &WitnessTurn,
        encoder: &dyn ExtractionEncoder,
    ) -> MemoryResult<WitnessWithShadow> {
        let witness = self.witness(turn)?;
        let input_result = (|| -> MemoryResult<EncoderInput> {
            let turn_id = self.resolve_ref(&witness.turn_short_id)?;
            let messages = witness
                .message_short_ids
                .iter()
                .zip(&turn.messages)
                .map(|(id, message)| {
                    Ok(EncoderMessage {
                        id: self.resolve_ref(id)?.to_hex(),
                        text: message.content.clone(),
                    })
                })
                .collect::<MemoryResult<Vec<_>>>()?;
            Ok(EncoderInput {
                turn: turn_id.to_hex(),
                messages,
                context: Vec::new(),
                language: None,
                // The side the witnessed messages' authors name, as the
                // witness stores them.
                speaker: crate::tagging::turn_role(
                    turn.messages.iter().map(|message| message.author.as_str()),
                ),
            })
        })();
        let input = match input_result {
            Ok(input) => input,
            Err(error) => {
                let input = EncoderInput {
                    turn: witness.turn_short_id.clone(),
                    messages: Vec::new(),
                    context: Vec::new(),
                    language: None,
                    speaker: None,
                };
                return Ok(WitnessWithShadow {
                    witness,
                    trace: ShadowTrace {
                        model: "unavailable".into(),
                        input_hash: hash_input(&input),
                        output: None,
                        failure: Some(error.code),
                        input,
                    },
                });
            }
        };
        let input_hash = hash_input(&input);
        let served = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let model = encoder.model_id().as_str().to_owned();
            let result = infer_encoder(&input, encoder);
            (model, result)
        }));
        let (model, result) =
            served.unwrap_or_else(|_| ("unavailable".into(), Err("encoder_panicked".into())));
        let (output, failure) = match result {
            Ok(output) => (Some(output), None),
            Err(error) => (None, Some(error)),
        };
        Ok(WitnessWithShadow {
            witness,
            trace: ShadowTrace {
                model,
                input_hash,
                output,
                failure,
                input,
            },
        })
    }
}
/// Write-free execution through the same locality and output guards as
/// witness shadowing. A network tagger still needs an egress-aware serving
/// door; this helper never turns a caller's route into that authority.
pub fn infer_encoder(
    input: &EncoderInput,
    encoder: &dyn ExtractionEncoder,
) -> Result<EncoderOutput, String> {
    if encoder.locality() != EmbedderLocality::OnDevice {
        return Err("off_device_shadow_denied".into());
    }
    let output = encoder
        .infer(input)
        .map_err(|error| format!("{:?}", error.kind()))?;
    validate(input, &output).map_err(str::to_owned)?;
    Ok(output)
}

/// The input digest: the turn, then each message's id, length and text. A
/// window folds in after them only when it holds a turn, so a turn read
/// alone digests as it always has; a NUL cannot begin a message id, so the
/// window never reads as one more message. A language, then the turns'
/// speaker roles, fold in last and only when the input carries them, so an
/// input without them digests as it did before they existed.
pub(crate) fn hash_input(input: &EncoderInput) -> String {
    let mut hash = Sha256::new();
    hash.update(input.turn.as_bytes());
    let message = |hash: &mut Sha256, message: &EncoderMessage| {
        hash.update(message.id.as_bytes());
        hash.update((message.text.len() as u64).to_le_bytes());
        hash.update(message.text.as_bytes());
    };
    for each in &input.messages {
        message(&mut hash, each);
    }
    if !input.context.is_empty() {
        hash.update(b"\0context");
        hash.update((input.context.len() as u64).to_le_bytes());
        for turn in &input.context {
            hash.update(turn.turn.as_bytes());
            hash.update((turn.messages.len() as u64).to_le_bytes());
            for each in &turn.messages {
                message(&mut hash, each);
            }
        }
    }
    if let Some(language) = &input.language {
        hash.update(b"\0language");
        hash.update((language.len() as u64).to_le_bytes());
        hash.update(language.as_bytes());
    }
    let roles = std::iter::once(input.speaker).chain(input.context.iter().map(|turn| turn.speaker));
    if roles.clone().any(|role| role.is_some()) {
        // The current turn's role, then each context turn's in order.
        hash.update(b"\0speaker");
        for role in roles {
            hash.update(match role {
                None => b"-",
                Some(SpeakerRole::User) => b"A",
                Some(SpeakerRole::Companion) => b"B",
            });
        }
    }
    format!("{:x}", hash.finalize())
}
fn validate(input: &EncoderInput, output: &EncoderOutput) -> Result<(), &'static str> {
    if output.spans.len() > 4096
        || output.links.len() > 4096
        || output.vad.is_some_and(|vad| vad.validate().is_err())
    {
        return Err("invalid_encoder_output");
    }
    for span in &output.spans {
        let Some(message) = input.messages.get(span.message) else {
            return Err("invalid_span_message");
        };
        if span.start >= span.end
            || span.end > message.text.len()
            || !message.text.is_char_boundary(span.start)
            || !message.text.is_char_boundary(span.end)
            || span.label.is_empty()
            || span.label.len() > 64
            || !span.confidence.is_finite()
            || !(0.0..=1.0).contains(&span.confidence)
        {
            return Err("invalid_ner_span");
        }
    }
    crate::tagging::check_span_order(output).map_err(|_| "invalid_ner_span")?;
    crate::tagging::check_links(input, output).map_err(|_| "invalid_coreference_link")
}
