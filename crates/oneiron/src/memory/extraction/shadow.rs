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
            })
        })();
        let input = match input_result {
            Ok(input) => input,
            Err(error) => {
                let input = EncoderInput {
                    turn: witness.turn_short_id.clone(),
                    messages: Vec::new(),
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
            let result = if encoder.locality() != EmbedderLocality::OnDevice {
                Err("off_device_shadow_denied".into())
            } else {
                encoder
                    .infer(&input)
                    .map_err(|error| format!("{:?}", error.kind()))
            };
            (model, result)
        }));
        let (model, result) =
            served.unwrap_or_else(|_| ("unavailable".into(), Err("encoder_panicked".into())));
        let (output, failure) = match result {
            Ok(output) => match validate(&input, &output) {
                Ok(()) => (Some(output), None),
                Err(error) => (None, Some(error.into())),
            },
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
pub(super) fn hash_input(input: &EncoderInput) -> String {
    let mut hash = Sha256::new();
    hash.update(input.turn.as_bytes());
    for message in &input.messages {
        hash.update(message.id.as_bytes());
        hash.update((message.text.len() as u64).to_le_bytes());
        hash.update(message.text.as_bytes());
    }
    format!("{:x}", hash.finalize())
}
fn validate(input: &EncoderInput, output: &EncoderOutput) -> Result<(), &'static str> {
    if output.spans.len() > 4096 || output.links.len() > 4096 || output.vad.validate().is_err() {
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
    let mut linked = std::collections::BTreeSet::new();
    for link in &output.links {
        if link.span >= output.spans.len()
            || link.antecedent >= link.span
            || !linked.insert(link.span)
        {
            return Err("invalid_coreference_link");
        }
    }
    Ok(())
}
