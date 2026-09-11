//! Attention: the fused Metal kernel where it applies, eager matmul elsewhere.
//!
//! Rebuilt from mistral.rs's no-flash attention dispatch — see
//! `NOTICE-mistralrs.md`. Two branches, taken from a 736-line file, and nothing
//! else: the model is a pure-causal encoder with no cache, no paging and no
//! padding, so there is no third case.

use candle_core::{D, Device, Tensor};

/// Grouped-query attention over equal-length, unpadded sequences.
///
/// `q` is `[b, heads, seq, head_dim]`, `k` and `v` are
/// `[b, kv_heads, seq, head_dim]`, NOT pre-tiled to `heads`: candle's fused
/// kernel does the grouping itself, and the eager branch tiles only when it
/// reaches the matmul.
///
/// `mask` is the additive causal mask the eager branch needs, shaped
/// `[1, 1, seq, seq]`. The Metal branch ignores it and asks the kernel for
/// causal masking instead, which is the same mask without materialising
/// `heads × seq × seq` values.
pub(super) fn grouped_causal_attention(
    q: &Tensor,
    k: &Tensor,
    v: &Tensor,
    mask: &Tensor,
    scale: f32,
) -> candle_core::Result<Tensor> {
    if matches!(q.device(), Device::Metal(_)) {
        return candle_nn::ops::sdpa(q, k, v, None, true, scale, 1.0);
    }
    eager_attention(q, k, v, mask, scale)
}

/// The source's tail path: tile the KV heads, score, mask, softmax, weight.
pub(super) fn eager_attention(
    q: &Tensor,
    k: &Tensor,
    v: &Tensor,
    mask: &Tensor,
    scale: f32,
) -> candle_core::Result<Tensor> {
    let heads = q.dim(1)?;
    let kv_heads = k.dim(1)?;
    let groups = heads / kv_heads.max(1);
    let k = repeat_kv(k.clone(), groups)?;
    let v = repeat_kv(v.clone(), groups)?;
    let scores = (q.contiguous()?.matmul(&k.transpose(2, 3)?.contiguous()?)? * f64::from(scale))?;
    let scores = scores.broadcast_add(&mask.to_dtype(scores.dtype())?)?;
    let weights = candle_nn::ops::softmax_last_dim(&scores)?;
    weights.matmul(&v.contiguous()?)
}

/// Tiles each KV head `groups` times so the eager matmul sees one K per Q head.
fn repeat_kv(xs: Tensor, groups: usize) -> candle_core::Result<Tensor> {
    if groups <= 1 {
        return Ok(xs);
    }
    let (batch, kv_heads, seq, head_dim) = xs.dims4()?;
    Tensor::cat(&vec![&xs; groups], 2)?.reshape((batch, kv_heads * groups, seq, head_dim))
}

/// The additive causal mask for one sequence length: `0` where a position may
/// attend, `-inf` where it may not.
pub(super) fn causal_mask(seq: usize, device: &Device) -> candle_core::Result<Tensor> {
    let mut values = vec![0f32; seq * seq];
    for (row, chunk) in values.chunks_mut(seq).enumerate() {
        for (col, value) in chunk.iter_mut().enumerate() {
            if col > row {
                *value = f32::NEG_INFINITY;
            }
        }
    }
    Tensor::from_vec(values, (1, 1, seq, seq), device)
}

/// L2-normalises the last dimension.
pub(super) fn l2_normalize(xs: &Tensor) -> candle_core::Result<Tensor> {
    let norm = xs.sqr()?.sum_keepdim(D::Minus1)?.sqrt()?;
    xs.broadcast_div(&norm)
}
