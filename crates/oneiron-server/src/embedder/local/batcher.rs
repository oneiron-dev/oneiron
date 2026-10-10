//! Tokenisation and packing.
//!
//! Inputs are never padded. On the CPU a forward packs several inputs' tokens
//! back to back, runs every row-wise step over all of them at once, and splits
//! them only for attention ([`super::qwen3_embedding::Model::forward`]). On a
//! GPU a forward takes inputs of IDENTICAL length, as the upstream runtime
//! did. Either way there is no padding mask and no position shift: a causal
//! model keeps its pure causal mask, a bidirectional one needs no mask, and a
//! mean pool averages exactly the input's own rows.
//!
//! Real text rarely shares a length, so grouping by length runs about one
//! input per forward. That is cheap on a GPU and was the CPU's bottleneck.

use tokenizers::{Tokenizer, TruncationDirection, TruncationParams, TruncationStrategy};

/// One input's tokens.
pub(super) struct Tokenized {
    pub(super) ids: Vec<u32>,
    pub(super) truncated: bool,
}

/// Readies the model's own tokenizer for this provider: no padding, and its
/// own truncation at the input cap.
///
/// Truncation is the tokenizer's rather than a cut of the encoded ids because
/// only the tokenizer knows what its post-processor adds. One model's appends
/// an end-of-text token, which must survive a cut because last-token pooling
/// reads it; another's adds nothing, and keeping the final token there would
/// splice the end of the text onto its start. The tokenizer reserves room for
/// whatever it adds and cuts the text to fit, which is also what
/// sentence-transformers does with the same file.
///
/// Padding is switched off whatever the file says: a padded input would need a
/// key mask and a masked pool, and packing is what makes both unnecessary.
pub(super) fn for_provider(
    mut tokenizer: Tokenizer,
    max_input_tokens: usize,
) -> oneiron::Result<Tokenizer> {
    tokenizer.with_padding(None);
    tokenizer
        .with_truncation(Some(TruncationParams {
            max_length: max_input_tokens.max(1),
            strategy: TruncationStrategy::LongestFirst,
            stride: 0,
            direction: TruncationDirection::Right,
        }))
        .map_err(|e| {
            oneiron::Error::InvalidConfig(format!(
                "embedder max_input_tokens {max_input_tokens} does not fit the tokenizer: {e}"
            ))
        })?;
    Ok(tokenizer)
}

/// Encodes every text, dropping tokens from the END of an over-long one.
///
/// Each text is stripped first, as the sentence-transformers `Transformer`
/// module strips it: leading and trailing whitespace is not part of what the
/// model embeds, and keeping it moves a padded text away from the same text
/// unpadded.
///
/// `add_special_tokens` is left on: the model's own `tokenizer.json`
/// post-processor decides what surrounds the text, and hand-rolling that here
/// would put a different token sequence through the model than every bench
/// measured. `tokenizer` must come from [`for_provider`].
///
/// An input left with no tokens at all is refused: there is no row to pool.
pub(super) fn tokenize(tokenizer: &Tokenizer, texts: &[String]) -> oneiron::Result<Vec<Tokenized>> {
    let encodings = tokenizer
        .encode_batch(
            texts.iter().map(|text| strip(text)).collect::<Vec<_>>(),
            true,
        )
        .map_err(|e| oneiron::Error::UpstreamToolFailure {
            tool: "embedder-tokenizer",
            code: e.to_string(),
        })?;
    encodings
        .into_iter()
        .map(|encoding| {
            if encoding.get_ids().is_empty() {
                return Err(oneiron::Error::InvariantViolation(
                    "an embedder input tokenized to no tokens",
                ));
            }
            Ok(Tokenized {
                truncated: !encoding.get_overflowing().is_empty(),
                ids: encoding.get_ids().to_vec(),
            })
        })
        .collect()
}

/// How many leading tokens a prompt takes, as sentence-transformers counts
/// them for a pool that excludes the prompt: the prompt tokenized on its own,
/// less one for the token the post-processor closes a sequence with.
pub(super) fn prompt_tokens(tokenizer: &Tokenizer, prompt: &str) -> oneiron::Result<usize> {
    if strip(prompt).is_empty() {
        return Ok(0);
    }
    let encoded = tokenize(tokenizer, &[prompt.to_owned()])?;
    Ok(encoded
        .first()
        .map_or(0, |item| item.ids.len().saturating_sub(1)))
}

/// Python's `str.strip()`: Unicode whitespace plus the four ASCII separators
/// (`\x1c`–`\x1f`) Python also counts as space.
fn strip(text: &str) -> &str {
    text.trim_matches(|c: char| c.is_whitespace() || ('\u{1c}'..='\u{1f}').contains(&c))
}

/// Splits inputs, in order, into forwards of at most `max_inputs` inputs and
/// `max_tokens` tokens. An input longer than `max_tokens` runs alone. For the
/// CPU, where an input's states do not depend on what it is packed with.
pub(super) fn pack(lengths: &[usize], max_inputs: usize, max_tokens: usize) -> Vec<Vec<usize>> {
    let mut forwards = Vec::new();
    let mut forward: Vec<usize> = Vec::new();
    let mut tokens = 0;
    for (index, &length) in lengths.iter().enumerate() {
        let full = forward.len() >= max_inputs.max(1) || tokens + length > max_tokens;
        if !forward.is_empty() && full {
            forwards.push(std::mem::take(&mut forward));
            tokens = 0;
        }
        forward.push(index);
        tokens += length;
    }
    if !forward.is_empty() {
        forwards.push(forward);
    }
    forwards
}

/// Groups input indices by identical token length, in first-appearance order,
/// chunked at `batch_size`: every forward on a GPU, whose quantised kernels
/// pick by row count, so its vectors stay the ones it always made.
///
/// Stable on purpose: the caller scatters results back by index, and a group
/// order that depended on a hash would make two identical batches produce two
/// different orders of the same work.
pub(super) fn group_equal_lengths(lengths: &[usize], batch_size: usize) -> Vec<Vec<usize>> {
    let cap = batch_size.max(1);
    let mut buckets: Vec<(usize, Vec<usize>)> = Vec::new();
    for (index, &length) in lengths.iter().enumerate() {
        match buckets.iter_mut().find(|(bucket, _)| *bucket == length) {
            Some((_, members)) => members.push(index),
            None => buckets.push((length, vec![index])),
        }
    }
    let mut groups = Vec::new();
    for (_, members) in buckets {
        for chunk in members.chunks(cap) {
            groups.push(chunk.to_vec());
        }
    }
    groups
}
