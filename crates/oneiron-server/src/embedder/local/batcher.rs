//! Tokenisation and no-padding batching.
//!
//! The upstream runtime reached its measured throughput by bucketing waiting
//! sequences by IDENTICAL length and running one bucket per step — which is the
//! only reason its right-padding with no attention mask was ever correct, since
//! padding never actually happened. This keeps the correct half at the provider
//! level: sort by token length, group equal lengths, restore the input order
//! afterwards. No padding, no padding mask, no position shifts, and the model
//! keeps its pure causal mask.

use tokenizers::Tokenizer;

/// One input's tokens.
pub(super) struct Tokenized {
    pub(super) ids: Vec<u32>,
    pub(super) truncated: bool,
}

/// Encodes every text, dropping tokens from the END of an over-long one.
///
/// `add_special_tokens` is left on: the model's own `tokenizer.json`
/// post-processor appends its end-of-text token to every input, and
/// hand-rolling that here would put a different token sequence through the
/// model than every bench measured.
pub(super) fn tokenize(
    tokenizer: &Tokenizer,
    texts: &[String],
    max_input_tokens: usize,
) -> oneiron::Result<Vec<Tokenized>> {
    let encodings = tokenizer
        .encode_batch(texts.iter().map(String::as_str).collect::<Vec<_>>(), true)
        .map_err(|e| oneiron::Error::UpstreamToolFailure {
            tool: "embedder-tokenizer",
            code: e.to_string(),
        })?;
    Ok(encodings
        .into_iter()
        .map(|encoding| truncate_tail(encoding.get_ids().to_vec(), max_input_tokens))
        .collect())
}

/// Drops tokens from the end, keeping the final token in place.
///
/// The post-processor's end-of-text token is what last-token pooling reads, so
/// a truncation that simply cut the tail would pool a mid-sentence token and
/// land the vector somewhere else in the space.
fn truncate_tail(mut ids: Vec<u32>, max_input_tokens: usize) -> Tokenized {
    let cap = max_input_tokens.max(1);
    if ids.len() <= cap {
        return Tokenized {
            ids,
            truncated: false,
        };
    }
    let last = ids[ids.len() - 1];
    ids.truncate(cap);
    if let Some(slot) = ids.last_mut() {
        *slot = last;
    }
    Tokenized {
        ids,
        truncated: true,
    }
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
