//! Tokenisation and no-padding batching.
//!
//! The upstream runtime reached its measured throughput by bucketing waiting
//! sequences by IDENTICAL length and running one bucket per step — which is the
//! only reason its right-padding with no attention mask was ever correct, since
//! padding never actually happened. This keeps the correct half at the provider
//! level: sort by token length, group equal lengths, restore the input order
//! afterwards. No padding, no padding mask, no position shifts: a causal model
//! keeps its pure causal mask, a bidirectional one needs no mask, and a mean
//! pool averages exactly the input's own rows.

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
/// Padding is switched off whatever the file says: a padded group would need a
/// key mask and a masked pool, and grouping equal lengths is what makes both
/// unnecessary.
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

/// Groups input indices by identical token length, in first-appearance order,
/// chunked at `batch_size`.
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
