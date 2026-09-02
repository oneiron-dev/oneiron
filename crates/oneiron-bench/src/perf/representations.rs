//! Candidate vector representations for the ONE-1579 precision axis, and the
//! scans that rank a query against each of them.
//!
//! Every representation here is a BENCH representation: it is built and
//! scanned inside the bench over its own copy of the corpus vectors. No engine
//! type, engine config or on-disk layout is touched, and nothing here changes
//! what the engine persists.
//!
//! All four scans share one deterministic ordering rule — ascending by
//! distance with ties broken by index — so a recall difference between rows is
//! attributable to the representation rather than to tie-breaking.

use super::binary16::{f16_bits_to_f32, f32_to_f16_bits};

/// Per-vector symmetric int8 scalar quantisation.
pub(crate) struct Int8Vector {
    codes: Vec<i8>,
    scale: f32,
}

pub(crate) fn encode_f16(vector: &[f32]) -> Vec<u16> {
    vector.iter().map(|value| f32_to_f16_bits(*value)).collect()
}

pub(crate) fn encode_int8(vector: &[f32]) -> Int8Vector {
    let peak = vector
        .iter()
        .fold(0.0_f32, |acc, value| acc.max(value.abs()));
    let scale = if peak > 0.0 { peak / 127.0 } else { 1.0 };
    let codes = vector
        .iter()
        .map(|value| (value / scale).round().clamp(-127.0, 127.0) as i8)
        .collect();
    Int8Vector { codes, scale }
}

/// Sign-bit binary code, packed 64 components per word.
pub(crate) fn encode_binary(vector: &[f32]) -> Vec<u64> {
    let mut words = vec![0_u64; vector.len().div_ceil(64)];
    for (index, value) in vector.iter().enumerate() {
        if *value >= 0.0 {
            words[index / 64] |= 1_u64 << (index % 64);
        }
    }
    words
}

pub(crate) fn scan_f32(vectors: &[Vec<f32>], query: &[f32], k: usize) -> Vec<usize> {
    let scored = vectors
        .iter()
        .enumerate()
        .map(|(index, vector)| (index, cosine_distance(query, vector.iter().copied())))
        .collect();
    top_k(scored, k)
}

pub(crate) fn scan_f16(codes: &[Vec<u16>], query: &[f32], k: usize) -> Vec<usize> {
    let scored = codes
        .iter()
        .enumerate()
        .map(|(index, code)| {
            (
                index,
                cosine_distance(query, code.iter().map(|bits| f16_bits_to_f32(*bits))),
            )
        })
        .collect();
    top_k(scored, k)
}

pub(crate) fn scan_int8(codes: &[Int8Vector], query: &[f32], k: usize) -> Vec<usize> {
    let scored = codes
        .iter()
        .enumerate()
        .map(|(index, code)| {
            let scale = code.scale;
            (
                index,
                cosine_distance(query, code.codes.iter().map(|raw| f32::from(*raw) * scale)),
            )
        })
        .collect();
    top_k(scored, k)
}

/// Stage 1 ranks every vector by Hamming distance between sign-bit codes and
/// keeps the `breadth`-long prefix; stage 2 rescores exactly that prefix in
/// float32 and returns the top `k`.
pub(crate) fn scan_binary_prefix(
    codes: &[Vec<u64>],
    vectors: &[Vec<f32>],
    query: &[f32],
    k: usize,
    breadth: usize,
) -> Vec<usize> {
    let query_code = encode_binary(query);
    let hamming: Vec<(usize, f32)> = codes
        .iter()
        .enumerate()
        .map(|(index, code)| (index, hamming_distance(code, &query_code)))
        .collect();
    let prefix = top_k(hamming, breadth.max(k));
    let rescored = prefix
        .into_iter()
        .map(|index| {
            (
                index,
                cosine_distance(query, vectors[index].iter().copied()),
            )
        })
        .collect();
    top_k(rescored, k)
}

fn hamming_distance(left: &[u64], right: &[u64]) -> f32 {
    let mut distance = 0_u32;
    for (a, b) in left.iter().zip(right) {
        distance += (a ^ b).count_ones();
    }
    distance as f32
}

/// `1 - cos(a, b)` in sequential float32 over a lazily dequantised candidate.
fn cosine_distance<I>(query: &[f32], candidate: I) -> f32
where
    I: Iterator<Item = f32>,
{
    let mut dot = 0.0_f32;
    let mut query_norm = 0.0_f32;
    let mut candidate_norm = 0.0_f32;
    for (left, right) in query.iter().zip(candidate) {
        dot += left * right;
        query_norm += left * left;
        candidate_norm += right * right;
    }
    let denominator = query_norm.sqrt() * candidate_norm.sqrt();
    if denominator == 0.0 {
        return 1.0;
    }
    1.0 - dot / denominator
}

/// Ascending by distance, ties broken by index so every candidate sees the
/// same deterministic ordering.
fn top_k(mut scored: Vec<(usize, f32)>, k: usize) -> Vec<usize> {
    scored.sort_by(|left, right| {
        left.1
            .total_cmp(&right.1)
            .then_with(|| left.0.cmp(&right.0))
    });
    scored.truncate(k);
    scored.into_iter().map(|(index, _)| index).collect()
}
