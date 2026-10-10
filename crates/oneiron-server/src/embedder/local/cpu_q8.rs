//! Q8_0 projections on the CPU that read each weight once per forward pass.
//!
//! candle 0.11 runs a quantised matmul on the CPU as one matrix-vector product
//! per input row, with a thread-pool barrier per row, so a forward over a
//! thousand tokens streams every weight a thousand times. On x86_64 its SIMD
//! dot product is compiled in only when the build itself targets AVX2, which
//! the shipped builds do not, so every one of those products is scalar too.
//! Measured on 2026-10-10 at about 20 tokens a second on 8 threads.
//!
//! This kernel takes candle's own Q8_0 blocks at load and multiplies a whole
//! packed forward against them in tiles that stay in cache: four weight
//! columns are read once for every two input rows, tasks cover 32 rows by 64
//! columns, and AVX2 is picked at run time rather than at build time.
//!
//! The numbers are candle's portable dot product's, bit for bit, which is the
//! path every x86_64 build without `target-feature=+avx2` runs. Each input row
//! is quantised to Q8_0 exactly as candle quantises it. A 32-value block's
//! integer dot product is exact in any order. The float sum runs block by
//! block, in order, as `sum + (dot * weight_scale) * input_scale`, with no
//! fused multiply-add. So a vault's stored vectors do not move.

use candle_core::quantized::{GgmlDType, QTensor};
use candle_core::{DType, Device, Storage, Tensor};
use rayon::prelude::*;

/// Values per Q8_0 block, and per scale.
const BLOCK: usize = 32;
/// Bytes per Q8_0 block in candle's layout: an f16 scale, then 32 values.
const BLOCK_BYTES: usize = 2 + BLOCK;
/// Input rows one task covers.
const TASK_ROWS: usize = 32;
/// Weight columns one task covers, in groups of four.
const TASK_COLUMNS: usize = 64;
/// Weight columns one kernel call reads.
const QUAD: usize = 4;

/// Whether this build's candle runs the portable dot product this kernel
/// reproduces. Elsewhere candle keeps the projection: aarch64 and an AVX2
/// build sum in another order, and their vaults hold vectors made that way.
pub(super) const REPRODUCES_CANDLE: bool =
    cfg!(all(target_arch = "x86_64", not(target_feature = "avx2")));

/// One projection's weights.
pub(super) struct CpuQ8 {
    out_dim: usize,
    in_dim: usize,
    /// Every value, one row of `in_dim` per output column.
    values: Vec<i8>,
    /// Each block's f16 scale bits, by groups of four columns: for every group
    /// and block, the four columns' scales side by side.
    scales: Vec<[u16; QUAD]>,
}

impl CpuQ8 {
    /// Takes over a CPU Q8_0 tensor shaped `(out, in)`, or `None` for one this
    /// kernel does not cover: another type, another device, or an output width
    /// that is not a multiple of four.
    pub(super) fn from_qtensor(tensor: &QTensor) -> candle_core::Result<Option<Self>> {
        if tensor.dtype() != GgmlDType::Q8_0 || !matches!(tensor.device(), Device::Cpu) {
            return Ok(None);
        }
        let (out_dim, in_dim) = tensor.shape().dims2()?;
        if !out_dim.is_multiple_of(QUAD) || !in_dim.is_multiple_of(BLOCK) {
            return Ok(None);
        }
        let blocks = in_dim / BLOCK;
        let data = tensor.data()?;
        if data.len() != out_dim * blocks * BLOCK_BYTES {
            candle_core::bail!(
                "Q8_0 tensor ({out_dim}, {in_dim}) holds {} bytes, expected {}",
                data.len(),
                out_dim * blocks * BLOCK_BYTES
            );
        }
        let mut values = Vec::with_capacity(out_dim * in_dim);
        let mut scales = vec![[0u16; QUAD]; out_dim / QUAD * blocks];
        for (index, block) in data.chunks_exact(BLOCK_BYTES).enumerate() {
            let (column, at) = (index / blocks, index % blocks);
            scales[column / QUAD * blocks + at][column % QUAD] =
                u16::from_le_bytes([block[0], block[1]]);
            values.extend(block[2..].iter().map(|&byte| byte.cast_signed()));
        }
        Ok(Some(Self {
            out_dim,
            in_dim,
            values,
            scales,
        }))
    }

    /// `xs` is `[.., in]` at f32 on the CPU; the result is `[.., out]`.
    pub(super) fn forward(&self, xs: &Tensor) -> candle_core::Result<Tensor> {
        let mut shape = xs.dims().to_vec();
        if shape.last() != Some(&self.in_dim) || xs.dtype() != DType::F32 {
            candle_core::bail!(
                "Q8_0 projection takes [.., {}] at f32, got {:?} at {:?}",
                self.in_dim,
                shape,
                xs.dtype()
            );
        }
        let xs = xs.contiguous()?;
        let input = Rows::quantise(&xs, self.in_dim)?;
        let output = self.matmul(&input);
        if let Some(last) = shape.last_mut() {
            *last = self.out_dim;
        }
        Tensor::from_vec(output, shape, &Device::Cpu)
    }

    /// `input` against every column, rows of `out_dim` in row order.
    fn matmul(&self, input: &Rows) -> Vec<f32> {
        let simd = simd::available();
        let row_blocks = input.rows.div_ceil(TASK_ROWS);
        let column_blocks = self.out_dim.div_ceil(TASK_COLUMNS);
        let tiles: Vec<Vec<f32>> = (0..row_blocks * column_blocks)
            .into_par_iter()
            .map(|task| {
                let rows = task / column_blocks * TASK_ROWS
                    ..input.rows.min((task / column_blocks + 1) * TASK_ROWS);
                let columns = task % column_blocks * TASK_COLUMNS
                    ..self.out_dim.min((task % column_blocks + 1) * TASK_COLUMNS);
                self.tile(input, rows, columns, simd)
            })
            .collect();
        let mut output = vec![0f32; input.rows * self.out_dim];
        output
            .par_chunks_mut(TASK_ROWS * self.out_dim)
            .zip(tiles.par_chunks(column_blocks))
            .for_each(|(output, tiles)| {
                for (column_block, tile) in tiles.iter().enumerate() {
                    let start = column_block * TASK_COLUMNS;
                    let width = TASK_COLUMNS.min(self.out_dim - start);
                    for (row, values) in output
                        .chunks_exact_mut(self.out_dim)
                        .zip(tile.chunks(width))
                    {
                        row[start..start + width].copy_from_slice(values);
                    }
                }
            });
        output
    }

    /// One task: `rows` against `columns`, as rows of `columns.len()`.
    fn tile(
        &self,
        input: &Rows,
        rows: std::ops::Range<usize>,
        columns: std::ops::Range<usize>,
        simd: bool,
    ) -> Vec<f32> {
        let width = columns.len();
        let mut out = vec![0f32; rows.len() * width];
        for quad in (columns.start..columns.end).step_by(QUAD) {
            let weights = self.quad(quad);
            for first in rows.clone().step_by(2) {
                // An odd last row runs as its own pair and keeps one half.
                let second = if first + 1 < rows.end {
                    first + 1
                } else {
                    first
                };
                let pair = [input.row(first), input.row(second)];
                let sums = if simd {
                    simd::pair_by_quad(pair, weights)
                } else {
                    portable_pair_by_quad(pair, weights)
                };
                for (offset, row) in [first, second].into_iter().enumerate() {
                    let at = (row - rows.start) * width + quad - columns.start;
                    out[at..at + QUAD].copy_from_slice(&sums[offset * QUAD..(offset + 1) * QUAD]);
                }
            }
        }
        out
    }

    /// The four columns starting at `first`.
    fn quad(&self, first: usize) -> Quad<'_> {
        let blocks = self.in_dim / BLOCK;
        let column = |offset: usize| {
            let start = (first + offset) * self.in_dim;
            &self.values[start..start + self.in_dim]
        };
        Quad {
            values: [column(0), column(1), column(2), column(3)],
            scales: &self.scales[first / QUAD * blocks..(first / QUAD + 1) * blocks],
        }
    }
}

/// Four weight columns and their block scales.
#[derive(Clone, Copy)]
struct Quad<'a> {
    values: [&'a [i8]; QUAD],
    scales: &'a [[u16; QUAD]],
}

/// One input row, quantised: its values and each block's scale as the dot
/// product reads it.
#[derive(Clone, Copy)]
struct Row<'a> {
    values: &'a [i8],
    scales: &'a [f32],
}

/// Every input row, quantised the way candle quantises them.
struct Rows {
    rows: usize,
    in_dim: usize,
    values: Vec<i8>,
    scales: Vec<f32>,
}

impl Rows {
    fn quantise(xs: &Tensor, in_dim: usize) -> candle_core::Result<Self> {
        let (storage, layout) = xs.storage_and_layout();
        let Storage::Cpu(storage) = &*storage else {
            candle_core::bail!("Q8_0 projection input is not on the CPU");
        };
        let Some((start, end)) = layout.contiguous_offsets() else {
            candle_core::bail!("Q8_0 projection input is not contiguous");
        };
        let input = &storage.as_slice::<f32>()?[start..end];
        let rows = input.len() / in_dim;
        let blocks = in_dim / BLOCK;
        let mut values = vec![0i8; rows * in_dim];
        let mut scales = vec![0f32; rows * blocks];
        values
            .par_chunks_mut(in_dim)
            .zip(scales.par_chunks_mut(blocks))
            .zip(input.par_chunks(in_dim))
            .for_each(|((values, scales), input)| {
                for ((values, scale), input) in values
                    .chunks_exact_mut(BLOCK)
                    .zip(scales)
                    .zip(input.chunks_exact(BLOCK))
                {
                    *scale = quantise_block(input, values);
                }
            });
        Ok(Self {
            rows,
            in_dim,
            values,
            scales,
        })
    }

    fn row(&self, index: usize) -> Row<'_> {
        let blocks = self.in_dim / BLOCK;
        Row {
            values: &self.values[index * self.in_dim..(index + 1) * self.in_dim],
            scales: &self.scales[index * blocks..(index + 1) * blocks],
        }
    }
}

/// candle's `BlockQ8_0::from_float` for one block. Returns the block's scale
/// as candle's dot product reads it: stored as f16, read back widened.
fn quantise_block(input: &[f32], values: &mut [i8]) -> f32 {
    let mut amax = 0f32;
    for &x in input {
        amax = amax.max(x.abs());
    }
    let d = amax / 127f32;
    let id = if d != 0f32 { 1. / d } else { 0. };
    for (value, &x) in values.iter_mut().zip(input) {
        *value = f32::round(x * id) as i8;
    }
    half::f16::from_f32(d).to_f32()
}

/// Two rows against four columns without SIMD: lane `r * 4 + c` is row `r`
/// against column `c`, summed exactly as candle's `vec_dot_unopt` sums it.
fn portable_pair_by_quad(rows: [Row<'_>; 2], quad: Quad<'_>) -> [f32; 2 * QUAD] {
    let mut sums = [0f32; 2 * QUAD];
    for (block, (column_scales, at)) in quad.scales.iter().zip((0..).step_by(BLOCK)).enumerate() {
        for (r, row) in rows.iter().enumerate() {
            let input = &row.values[at..at + BLOCK];
            for (c, column) in quad.values.iter().enumerate() {
                let dot: i32 = column[at..at + BLOCK]
                    .iter()
                    .zip(input)
                    .map(|(&w, &x)| i32::from(w) * i32::from(x))
                    .sum();
                let weight_scale = half::f16::from_bits(column_scales[c]).to_f32();
                sums[r * QUAD + c] += dot as f32 * weight_scale * row.scales[block];
            }
        }
    }
    sums
}

/// AVX2 and F16C, detected at run time.
#[cfg(target_arch = "x86_64")]
mod simd {
    use std::arch::x86_64::{
        __m128i, __m256i, _mm_cvtph_ps, _mm_loadl_epi64, _mm_set1_ps, _mm256_abs_epi8,
        _mm256_add_epi32, _mm256_add_ps, _mm256_cvtepi32_ps, _mm256_hadd_epi32, _mm256_loadu_si256,
        _mm256_madd_epi16, _mm256_maddubs_epi16, _mm256_mul_ps, _mm256_permute2x128_si256,
        _mm256_set_m128, _mm256_set1_epi16, _mm256_setzero_ps, _mm256_sign_epi8, _mm256_storeu_ps,
    };

    use super::{BLOCK, QUAD, Quad, Row};

    pub(super) fn available() -> bool {
        std::arch::is_x86_feature_detected!("avx2") && std::arch::is_x86_feature_detected!("f16c")
    }

    /// [`super::portable_pair_by_quad`], eight dot products at a time.
    pub(super) fn pair_by_quad(rows: [Row<'_>; 2], quad: Quad<'_>) -> [f32; 2 * QUAD] {
        // SAFETY: the caller asked `available`, which found both features.
        unsafe { pair_by_quad_avx2(rows, quad) }
    }

    #[target_feature(enable = "avx2,f16c")]
    fn pair_by_quad_avx2(rows: [Row<'_>; 2], quad: Quad<'_>) -> [f32; 2 * QUAD] {
        let mut sums = _mm256_setzero_ps();
        let (row0, _) = rows[0].values.as_chunks::<BLOCK>();
        let (row1, _) = rows[1].values.as_chunks::<BLOCK>();
        let (c0, _) = quad.values[0].as_chunks::<BLOCK>();
        let (c1, _) = quad.values[1].as_chunks::<BLOCK>();
        let (c2, _) = quad.values[2].as_chunks::<BLOCK>();
        let (c3, _) = quad.values[3].as_chunks::<BLOCK>();
        for (block, column_scales) in quad.scales.iter().enumerate() {
            let w = [
                load(&c0[block]),
                load(&c1[block]),
                load(&c2[block]),
                load(&c3[block]),
            ];
            let w_abs = [
                _mm256_abs_epi8(w[0]),
                _mm256_abs_epi8(w[1]),
                _mm256_abs_epi8(w[2]),
                _mm256_abs_epi8(w[3]),
            ];
            let x0 = load(&row0[block]);
            let x1 = load(&row1[block]);
            let dots = totals([
                partial(w[0], w_abs[0], x0),
                partial(w[1], w_abs[1], x0),
                partial(w[2], w_abs[2], x0),
                partial(w[3], w_abs[3], x0),
                partial(w[0], w_abs[0], x1),
                partial(w[1], w_abs[1], x1),
                partial(w[2], w_abs[2], x1),
                partial(w[3], w_abs[3], x1),
            ]);
            // SAFETY: four f16 bit patterns are exactly the eight bytes read.
            let scales4 =
                _mm_cvtph_ps(unsafe { _mm_loadl_epi64(column_scales.as_ptr().cast::<__m128i>()) });
            let weight_scales = _mm256_set_m128(scales4, scales4);
            let input_scales = _mm256_set_m128(
                _mm_set1_ps(rows[1].scales[block]),
                _mm_set1_ps(rows[0].scales[block]),
            );
            let term = _mm256_mul_ps(
                _mm256_mul_ps(_mm256_cvtepi32_ps(dots), weight_scales),
                input_scales,
            );
            sums = _mm256_add_ps(sums, term);
        }
        let mut out = [0f32; 2 * QUAD];
        // SAFETY: `out` is eight writable floats; the store is unaligned.
        unsafe { _mm256_storeu_ps(out.as_mut_ptr(), sums) };
        out
    }

    #[target_feature(enable = "avx2")]
    fn load(values: &[i8; BLOCK]) -> __m256i {
        // SAFETY: `values` is 32 readable bytes; the load is unaligned.
        unsafe { _mm256_loadu_si256(values.as_ptr().cast::<__m256i>()) }
    }

    /// One block of one column against one row, as eight partial sums. Every
    /// value is in -127..=127, so a pair of products fits an i16.
    #[target_feature(enable = "avx2")]
    fn partial(w: __m256i, w_abs: __m256i, x: __m256i) -> __m256i {
        let products = _mm256_maddubs_epi16(w_abs, _mm256_sign_epi8(x, w));
        _mm256_madd_epi16(products, _mm256_set1_epi16(1))
    }

    /// Lane `i` of the result is the sum of `partials[i]`'s eight lanes.
    #[target_feature(enable = "avx2")]
    fn totals(partials: [__m256i; 8]) -> __m256i {
        let p01 = _mm256_hadd_epi32(partials[0], partials[1]);
        let p23 = _mm256_hadd_epi32(partials[2], partials[3]);
        let p45 = _mm256_hadd_epi32(partials[4], partials[5]);
        let p67 = _mm256_hadd_epi32(partials[6], partials[7]);
        let p0123 = _mm256_hadd_epi32(p01, p23);
        let p4567 = _mm256_hadd_epi32(p45, p67);
        _mm256_add_epi32(
            _mm256_permute2x128_si256::<0x20>(p0123, p4567),
            _mm256_permute2x128_si256::<0x31>(p0123, p4567),
        )
    }
}

/// No SIMD path off x86_64: there candle keeps the projection.
#[cfg(not(target_arch = "x86_64"))]
mod simd {
    use super::{QUAD, Quad, Row};

    pub(super) const fn available() -> bool {
        false
    }

    pub(super) fn pair_by_quad(rows: [Row<'_>; 2], quad: Quad<'_>) -> [f32; 2 * QUAD] {
        super::portable_pair_by_quad(rows, quad)
    }
}

#[cfg(test)]
mod tests {
    use candle_core::Module;
    use candle_core::quantized::QMatMul;

    use super::*;

    /// A fixed pseudo-random sequence, so a failure reproduces.
    fn values(count: usize, seed: u64) -> Vec<f32> {
        let mut state = seed;
        (0..count)
            .map(|_| {
                state = state
                    .wrapping_mul(6_364_136_223_846_793_005)
                    .wrapping_add(1_442_695_040_888_963_407);
                ((state >> 40) as f32 / (1u64 << 24) as f32 - 0.5) * 4.0
            })
            .collect()
    }

    /// The kernel against candle's own quantised matmul on the same blocks, at
    /// every shape the tiling has an edge for: one row, an odd row count, a
    /// partial task in both directions, and the model's widest projection.
    /// Equal to the bit wherever candle runs the dot product this kernel
    /// reproduces.
    #[test]
    fn the_tiled_kernel_matches_candle_to_the_bit() {
        for (rows, out_dim, in_dim) in [(1, 4, 32), (7, 68, 96), (33, 132, 1024), (70, 1024, 3072)]
        {
            let weight =
                Tensor::from_vec(values(out_dim * in_dim, 7), (out_dim, in_dim), &Device::Cpu)
                    .expect("weight");
            let quantised = QTensor::quantize(&weight, GgmlDType::Q8_0).expect("quantised");
            let ours = CpuQ8::from_qtensor(&quantised)
                .expect("read")
                .expect("a Q8_0 CPU tensor is covered");
            let candle = QMatMul::from_qtensor(quantised).expect("qmatmul");
            let input =
                Tensor::from_vec(values(rows * in_dim, 11), (1, rows, in_dim), &Device::Cpu)
                    .expect("input");
            let theirs: Vec<f32> = candle
                .forward(&input)
                .and_then(|t| t.flatten_all()?.to_vec1())
                .expect("candle");
            let mine: Vec<f32> = ours
                .forward(&input)
                .and_then(|t| t.flatten_all()?.to_vec1())
                .expect("ours");
            if REPRODUCES_CANDLE {
                let differing = mine
                    .iter()
                    .zip(&theirs)
                    .filter(|(a, b)| a.to_bits() != b.to_bits())
                    .count();
                assert_eq!(
                    differing, 0,
                    "{rows}x{in_dim} by {out_dim}: {differing} values differ"
                );
            } else {
                for (a, b) in mine.iter().zip(&theirs) {
                    assert!((a - b).abs() <= 1e-3 * b.abs().max(1.0), "{a} vs {b}");
                }
            }
        }
    }
}
