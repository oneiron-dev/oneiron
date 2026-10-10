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
//! packed forward against them in tiles that stay in cache: eight weight
//! columns are read once for every four input rows, tasks cover 32 rows by 64
//! columns, and AVX2 is picked at run time rather than at build time. The
//! columns are stored interleaved, four values of each in turn, so one vector
//! lane accumulates one column's block and no product is summed across lanes.
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
/// Values of one column side by side in the interleaved layout: one 32-bit
/// vector lane.
const RUN: usize = 4;
/// Input rows one task covers.
const TASK_ROWS: usize = 32;
/// Weight columns one task covers, in groups of eight.
const TASK_COLUMNS: usize = 64;
/// Weight columns one kernel call reads: one per lane of a 256-bit vector.
const OCT: usize = 8;
/// Input rows one kernel call reads at most.
const ROWS: usize = 4;

/// Whether this build's candle runs the portable dot product this kernel
/// reproduces. Elsewhere candle keeps the projection: aarch64 and an AVX2
/// build sum in another order, and their vaults hold vectors made that way.
pub(super) const REPRODUCES_CANDLE: bool =
    cfg!(all(target_arch = "x86_64", not(target_feature = "avx2")));

/// One projection's weights.
pub(super) struct CpuQ8 {
    out_dim: usize,
    in_dim: usize,
    /// Every value, by groups of eight columns: for every group and block,
    /// eight runs of 32 bytes, each the eight columns' next four values side
    /// by side.
    values: Vec<i8>,
    /// Each block's f16 scale bits, by groups of eight columns: for every
    /// group and block, the eight columns' scales side by side.
    scales: Vec<[u16; OCT]>,
}

impl CpuQ8 {
    /// Takes over a CPU Q8_0 tensor shaped `(out, in)`, or `None` for one this
    /// kernel does not cover: another type, another device, or an output width
    /// that is not a multiple of eight.
    pub(super) fn from_qtensor(tensor: &QTensor) -> candle_core::Result<Option<Self>> {
        if tensor.dtype() != GgmlDType::Q8_0 || !matches!(tensor.device(), Device::Cpu) {
            return Ok(None);
        }
        let (out_dim, in_dim) = tensor.shape().dims2()?;
        if !out_dim.is_multiple_of(OCT) || !in_dim.is_multiple_of(BLOCK) {
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
        let mut values = vec![0i8; out_dim * in_dim];
        let mut scales = vec![[0u16; OCT]; out_dim / OCT * blocks];
        for (index, block) in data.chunks_exact(BLOCK_BYTES).enumerate() {
            let (column, at) = (index / blocks, index % blocks);
            let group = column / OCT * blocks + at;
            scales[group][column % OCT] = u16::from_le_bytes([block[0], block[1]]);
            for (run, source) in block[2..].chunks_exact(RUN).enumerate() {
                let start = (group * (BLOCK / RUN) + run) * OCT * RUN + column % OCT * RUN;
                for (value, &byte) in values[start..start + RUN].iter_mut().zip(source) {
                    *value = byte.cast_signed();
                }
            }
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
        let mut sums = [[0f32; OCT]; ROWS];
        for first_column in columns.clone().step_by(OCT) {
            let weights = self.oct(first_column);
            for first in rows.clone().step_by(ROWS) {
                let count = ROWS.min(rows.end - first);
                match count {
                    1 => by_oct::<1>(input, first, weights, simd, &mut sums),
                    2 => by_oct::<2>(input, first, weights, simd, &mut sums),
                    3 => by_oct::<3>(input, first, weights, simd, &mut sums),
                    _ => by_oct::<ROWS>(input, first, weights, simd, &mut sums),
                }
                for (offset, row) in sums[..count].iter().enumerate() {
                    let at = (first + offset - rows.start) * width + first_column - columns.start;
                    out[at..at + OCT].copy_from_slice(row);
                }
            }
        }
        out
    }

    /// The eight columns starting at `first`.
    fn oct(&self, first: usize) -> Oct<'_> {
        let blocks = self.in_dim / BLOCK;
        let group = first / OCT;
        Oct {
            values: &self.values[group * OCT * self.in_dim..(group + 1) * OCT * self.in_dim],
            scales: &self.scales[group * blocks..(group + 1) * blocks],
        }
    }
}

/// `R` rows from `first` against eight columns, into `sums`' first `R` rows.
fn by_oct<const R: usize>(
    input: &Rows,
    first: usize,
    weights: Oct<'_>,
    simd: bool,
    sums: &mut [[f32; OCT]; ROWS],
) {
    let rows: [Row<'_>; R] = std::array::from_fn(|offset| input.row(first + offset));
    let got = if simd {
        simd::rows_by_oct(rows, weights)
    } else {
        portable_rows_by_oct(rows, weights)
    };
    sums[..R].copy_from_slice(&got);
}

/// Eight weight columns, interleaved, and their block scales.
#[derive(Clone, Copy)]
struct Oct<'a> {
    values: &'a [i8],
    scales: &'a [[u16; OCT]],
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

/// `R` rows against eight columns without SIMD, summed exactly as candle's
/// `vec_dot_unopt` sums each pair.
fn portable_rows_by_oct<const R: usize>(rows: [Row<'_>; R], oct: Oct<'_>) -> [[f32; OCT]; R] {
    let mut sums = [[0f32; OCT]; R];
    let (runs, _) = oct.values.as_chunks::<{ OCT * RUN }>();
    for (block, column_scales) in oct.scales.iter().enumerate() {
        let runs = &runs[block * BLOCK / RUN..(block + 1) * BLOCK / RUN];
        for (row, sums) in rows.iter().zip(&mut sums) {
            let input = &row.values[block * BLOCK..(block + 1) * BLOCK];
            for (column, sum) in sums.iter_mut().enumerate() {
                let dot: i32 = runs
                    .iter()
                    .zip(input.chunks_exact(RUN))
                    .flat_map(|(run, input)| {
                        run[column * RUN..(column + 1) * RUN].iter().zip(input)
                    })
                    .map(|(&w, &x)| i32::from(w) * i32::from(x))
                    .sum();
                let weight_scale = half::f16::from_bits(column_scales[column]).to_f32();
                *sum += dot as f32 * weight_scale * row.scales[block];
            }
        }
    }
    sums
}

/// AVX2 and F16C, detected at run time.
#[cfg(target_arch = "x86_64")]
mod simd {
    use std::arch::x86_64::{
        __m128i, __m256, __m256i, _mm_loadu_si128, _mm256_abs_epi8, _mm256_add_epi32,
        _mm256_add_ps, _mm256_cvtepi32_ps, _mm256_cvtph_ps, _mm256_loadu_si256, _mm256_madd_epi16,
        _mm256_maddubs_epi16, _mm256_mul_ps, _mm256_set1_epi16, _mm256_set1_epi32, _mm256_set1_ps,
        _mm256_setzero_ps, _mm256_setzero_si256, _mm256_sign_epi8, _mm256_storeu_ps,
    };

    use super::{BLOCK, OCT, Oct, RUN, Row};

    pub(super) fn available() -> bool {
        std::arch::is_x86_feature_detected!("avx2") && std::arch::is_x86_feature_detected!("f16c")
    }

    /// [`super::portable_rows_by_oct`], one column per lane.
    pub(super) fn rows_by_oct<const R: usize>(rows: [Row<'_>; R], oct: Oct<'_>) -> [[f32; OCT]; R] {
        // SAFETY: the caller asked `available`, which found both features.
        unsafe { rows_by_oct_avx2(rows, oct) }
    }

    #[target_feature(enable = "avx2,f16c")]
    fn rows_by_oct_avx2<const R: usize>(rows: [Row<'_>; R], oct: Oct<'_>) -> [[f32; OCT]; R] {
        let ones = _mm256_set1_epi16(1);
        let mut sums = [_mm256_setzero_ps(); R];
        let (runs, _) = oct.values.as_chunks::<{ OCT * RUN }>();
        let inputs: [&[[i8; RUN]]; R] = std::array::from_fn(|r| rows[r].values.as_chunks().0);
        for (block, column_scales) in oct.scales.iter().enumerate() {
            let mut dots = [_mm256_setzero_si256(); R];
            let first_run = block * BLOCK / RUN;
            for (run, weights) in runs[first_run..first_run + BLOCK / RUN].iter().enumerate() {
                // SAFETY: `weights` is 32 readable bytes; the load is unaligned.
                let w = unsafe { _mm256_loadu_si256(weights.as_ptr().cast::<__m256i>()) };
                let w_abs = _mm256_abs_epi8(w);
                for (dot, input) in dots.iter_mut().zip(&inputs) {
                    let x = input[first_run + run].map(i8::cast_unsigned);
                    let x = _mm256_set1_epi32(i32::from_le_bytes(x));
                    // Every value is in -127..=127, so a pair of products fits
                    // an i16; lane `c` then sums column `c`'s four products.
                    let products = _mm256_maddubs_epi16(w_abs, _mm256_sign_epi8(x, w));
                    *dot = _mm256_add_epi32(*dot, _mm256_madd_epi16(products, ones));
                }
            }
            let weight_scales = scales(column_scales);
            for ((sum, dot), row) in sums.iter_mut().zip(dots).zip(&rows) {
                let term = _mm256_mul_ps(
                    _mm256_mul_ps(_mm256_cvtepi32_ps(dot), weight_scales),
                    _mm256_set1_ps(row.scales[block]),
                );
                *sum = _mm256_add_ps(*sum, term);
            }
        }
        let mut out = [[0f32; OCT]; R];
        for (out, sum) in out.iter_mut().zip(sums) {
            // SAFETY: `out` is eight writable floats; the store is unaligned.
            unsafe { _mm256_storeu_ps(out.as_mut_ptr(), sum) };
        }
        out
    }

    /// Eight f16 scales, widened.
    #[target_feature(enable = "avx2,f16c")]
    fn scales(bits: &[u16; OCT]) -> __m256 {
        // SAFETY: eight f16 bit patterns are exactly the sixteen bytes read.
        _mm256_cvtph_ps(unsafe { _mm_loadu_si128(bits.as_ptr().cast::<__m128i>()) })
    }
}

/// No SIMD path off x86_64: there candle keeps the projection.
#[cfg(not(target_arch = "x86_64"))]
mod simd {
    use super::{OCT, Oct, Row};

    pub(super) const fn available() -> bool {
        false
    }

    pub(super) fn rows_by_oct<const R: usize>(rows: [Row<'_>; R], oct: Oct<'_>) -> [[f32; OCT]; R] {
        super::portable_rows_by_oct(rows, oct)
    }
}

#[cfg(test)]
mod tests {
    use std::time::{Duration, Instant};

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
        for (rows, out_dim, in_dim) in [(1, 8, 32), (7, 72, 96), (33, 136, 1024), (70, 1024, 3072)]
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

    /// One projection's throughput, this kernel against candle's, on synthetic
    /// weights at the model's widest shapes. Threads come from
    /// `RAYON_NUM_THREADS`; each shape prints one `BENCH kernel` line.
    #[test]
    #[ignore = "a timing row, reported in the PR body"]
    fn bench_projection() {
        let time = |run: &dyn Fn() -> Tensor| {
            run();
            let started = Instant::now();
            let mut runs = 0u32;
            while runs < 3 || started.elapsed() < Duration::from_secs(2) {
                run();
                runs += 1;
            }
            started.elapsed().as_secs_f64() / f64::from(runs)
        };
        for (rows, out_dim, in_dim) in [(512, 3072, 1024), (512, 1024, 3072), (16, 3072, 1024)] {
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
            let tiled = time(&|| ours.forward(&input).expect("ours"));
            let theirs = time(&|| candle.forward(&input).expect("candle"));
            let macs = (rows * out_dim * in_dim) as f64;
            println!(
                "BENCH kernel threads={} rows={rows} out={out_dim} in={in_dim} tiled_ms={:.2} tiled_gmacs={:.1} candle_ms={:.2} candle_gmacs={:.2}",
                std::env::var("RAYON_NUM_THREADS").unwrap_or_default(),
                tiled * 1e3,
                macs / tiled / 1e9,
                theirs * 1e3,
                macs / theirs / 1e9
            );
        }
    }
}
