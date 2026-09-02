use super::*;

/// Which kernel a prepared query scores with. Chosen once per query by the
/// same predicates [`cosine_similarity`] applies per call, so a prepared
/// query always lands in the kernel the legacy dispatcher would have picked
/// for the same operands.
#[derive(Clone, Copy)]
enum Kernel {
    Scalar,
    #[cfg(target_arch = "x86_64")]
    Avx2,
    #[cfg(target_arch = "aarch64")]
    Neon,
}

impl Kernel {
    fn select(len: usize) -> Self {
        #[cfg(target_arch = "x86_64")]
        {
            let _ = len;
            if std::arch::is_x86_feature_detected!("avx2")
                && std::arch::is_x86_feature_detected!("fma")
            {
                return Self::Avx2;
            }

            Self::Scalar
        }

        #[cfg(target_arch = "aarch64")]
        {
            if len < 4 {
                return Self::Scalar;
            }

            Self::Neon
        }

        #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
        {
            let _ = len;
            Self::Scalar
        }
    }
}

/// A query vector with its own norm summed once, for scoring many candidates.
///
/// [`cosine_distance`] recomputes BOTH operands' norms on every call, so a
/// beam that scores `n` candidates against one query sums the query's norm
/// `n` times over — pure loop-invariant work, and the dominant redundancy on
/// the HNSW insert path (one construction beam plus a prune pass per
/// neighbor, all against the same query vector). A prepared query sums that
/// norm once, resolves the SIMD dispatch once, and reuses both for every
/// candidate.
///
/// Exactness contract — this is a hoist, not an approximation:
/// `PreparedCosine::new(a).distance(b)` is bit-for-bit `cosine_distance(a, b)`
/// for every input, degenerate cases included. The query's components are
/// never rewritten (normalizing the vector itself WOULD change results), only
/// its norm is cached; every accumulator keeps the legacy kernel's operand
/// order, so no floating-point reassociation happens anywhere. The module
/// tests pin that equality across the SIMD block/tail boundaries and the
/// degenerate contract; `hnsw/tests.rs` pins the graph-level consequence
/// (identical linkage decisions and result ordering).
pub(crate) struct PreparedCosine<'a> {
    query: &'a [f32],
    kernel: Kernel,
    /// Sum of squares of `query`, accumulated in `kernel`'s exact order.
    norm: f32,
    /// `norm.sqrt()`, hoisted out of the per-candidate divide.
    norm_sqrt: f32,
}

impl<'a> PreparedCosine<'a> {
    pub(crate) fn new(query: &'a [f32]) -> Self {
        let kernel = Kernel::select(query.len());
        let norm = match kernel {
            Kernel::Scalar => query_norm_scalar(query),
            #[cfg(target_arch = "x86_64")]
            Kernel::Avx2 => {
                // SAFETY: `Kernel::Avx2` is only selected after runtime
                // AVX2+FMA detection, which is exactly the precondition the
                // legacy dispatcher checks before its own AVX2 call.
                unsafe { query_norm_avx2(query) }
            }
            #[cfg(target_arch = "aarch64")]
            Kernel::Neon => query_norm_neon(query),
        };

        Self {
            query,
            kernel,
            norm,
            norm_sqrt: norm.sqrt(),
        }
    }

    /// Bit-for-bit equal to `cosine_distance(query, candidate)`.
    pub(crate) fn distance(&self, candidate: &[f32]) -> f32 {
        1.0 - self.similarity(candidate)
    }

    /// Bit-for-bit equal to `cosine_similarity(query, candidate)`.
    pub(super) fn similarity(&self, candidate: &[f32]) -> f32 {
        if self.query.len() != candidate.len() {
            return 0.0;
        }

        match self.kernel {
            Kernel::Scalar => {
                prepared_similarity_scalar(self.query, candidate, self.norm, self.norm_sqrt)
            }
            #[cfg(target_arch = "x86_64")]
            Kernel::Avx2 => {
                // SAFETY: `Kernel::Avx2` implies runtime-detected AVX2+FMA,
                // and the length check above establishes `a.len() == b.len()`.
                unsafe {
                    prepared_similarity_avx2(self.query, candidate, self.norm, self.norm_sqrt)
                }
            }
            #[cfg(target_arch = "aarch64")]
            Kernel::Neon => {
                prepared_similarity_neon(self.query, candidate, self.norm, self.norm_sqrt)
            }
        }
    }
}

/// Query-side half of [`cosine_similarity_scalar`]: the `norm_a` chain alone,
/// over the same 8/4/1 blocks in the same order, so it yields the identical
/// `f32` the full kernel would have accumulated.
fn query_norm_scalar(a: &[f32]) -> f32 {
    let len = a.len();
    let mut i = 0;

    let mut norm_a = 0.0_f32;

    while i + 8 <= len {
        let a0 = a[i];
        let a1 = a[i + 1];
        let a2 = a[i + 2];
        let a3 = a[i + 3];
        let a4 = a[i + 4];
        let a5 = a[i + 5];
        let a6 = a[i + 6];
        let a7 = a[i + 7];

        norm_a += a0 * a0 + a1 * a1 + a2 * a2 + a3 * a3 + a4 * a4 + a5 * a5 + a6 * a6 + a7 * a7;

        i += 8;
    }

    while i + 4 <= len {
        let a0 = a[i];
        let a1 = a[i + 1];
        let a2 = a[i + 2];
        let a3 = a[i + 3];

        norm_a += a0 * a0 + a1 * a1 + a2 * a2 + a3 * a3;

        i += 4;
    }

    while i < len {
        let ai = a[i];
        norm_a += ai * ai;
        i += 1;
    }

    norm_a
}

/// Candidate-side half of [`cosine_similarity_scalar`]: the `dot` and
/// `norm_b` chains, untouched, with the query's cached norm folded in at
/// the end.
fn prepared_similarity_scalar(a: &[f32], b: &[f32], norm_a: f32, norm_a_sqrt: f32) -> f32 {
    debug_assert_eq!(a.len(), b.len());

    let len = a.len();
    let mut i = 0;

    let mut dot = 0.0_f32;
    let mut norm_b = 0.0_f32;

    while i + 8 <= len {
        let a0 = a[i];
        let a1 = a[i + 1];
        let a2 = a[i + 2];
        let a3 = a[i + 3];
        let a4 = a[i + 4];
        let a5 = a[i + 5];
        let a6 = a[i + 6];
        let a7 = a[i + 7];

        let b0 = b[i];
        let b1 = b[i + 1];
        let b2 = b[i + 2];
        let b3 = b[i + 3];
        let b4 = b[i + 4];
        let b5 = b[i + 5];
        let b6 = b[i + 6];
        let b7 = b[i + 7];

        dot += a0 * b0 + a1 * b1 + a2 * b2 + a3 * b3 + a4 * b4 + a5 * b5 + a6 * b6 + a7 * b7;
        norm_b += b0 * b0 + b1 * b1 + b2 * b2 + b3 * b3 + b4 * b4 + b5 * b5 + b6 * b6 + b7 * b7;

        i += 8;
    }

    while i + 4 <= len {
        let a0 = a[i];
        let a1 = a[i + 1];
        let a2 = a[i + 2];
        let a3 = a[i + 3];

        let b0 = b[i];
        let b1 = b[i + 1];
        let b2 = b[i + 2];
        let b3 = b[i + 3];

        dot += a0 * b0 + a1 * b1 + a2 * b2 + a3 * b3;
        norm_b += b0 * b0 + b1 * b1 + b2 * b2 + b3 * b3;

        i += 4;
    }

    while i < len {
        let ai = a[i];
        let bi = b[i];
        dot += ai * bi;
        norm_b += bi * bi;
        i += 1;
    }

    normalize_prepared(dot, norm_a, norm_a_sqrt, norm_b)
}

#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "avx2")]
#[target_feature(enable = "fma")]
/// Query-side half of [`cosine_similarity_avx2`]: the `norm_a` lanes alone,
/// reduced in the same lane order and with the same scalar tail, so it
/// yields the identical `f32` the full kernel would have accumulated.
///
/// The caller must ensure AVX2+FMA are supported on the target CPU;
/// [`Kernel::select`] enforces that before [`Kernel::Avx2`] is chosen.
unsafe fn query_norm_avx2(a: &[f32]) -> f32 {
    use std::arch::x86_64::{
        __m256, _mm256_fmadd_ps, _mm256_loadu_ps, _mm256_setzero_ps, _mm256_storeu_ps,
    };

    let len = a.len();
    let mut i = 0;

    // Register-only (safe under #[target_feature] context).
    let mut norm_a: __m256 = _mm256_setzero_ps();

    while i + 8 <= len {
        // SAFETY: `i + 8 <= len` guarantees the 8-lane unaligned load stays
        // in-bounds; `ptr::add` offsets are within the slice. FMA is
        // register-only and enabled via #[target_feature].
        unsafe {
            let va = _mm256_loadu_ps(a.as_ptr().add(i));
            norm_a = _mm256_fmadd_ps(va, va, norm_a);
        }

        i += 8;
    }

    let mut norm_a_buf = [0.0_f32; 8];

    // SAFETY: a stack-allocated 8-lane f32 buffer is sized sufficiently for
    // an unaligned 256-bit store (storeu doesn't require alignment).
    unsafe {
        _mm256_storeu_ps(norm_a_buf.as_mut_ptr(), norm_a);
    }

    let mut norm_a_sum: f32 = norm_a_buf.into_iter().sum();

    while i < len {
        let ai = a[i];
        norm_a_sum += ai * ai;
        i += 1;
    }

    norm_a_sum
}

#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "avx2")]
#[target_feature(enable = "fma")]
/// Candidate-side half of [`cosine_similarity_avx2`]: the `dot` and `norm_b`
/// lanes, untouched, with the query's cached norm folded in at the end.
///
/// Requires `a.len() == b.len()` and runtime AVX2+FMA support; the prepared
/// dispatcher enforces both before calling.
unsafe fn prepared_similarity_avx2(a: &[f32], b: &[f32], norm_a: f32, norm_a_sqrt: f32) -> f32 {
    use std::arch::x86_64::{
        __m256, _mm256_fmadd_ps, _mm256_loadu_ps, _mm256_setzero_ps, _mm256_storeu_ps,
    };

    debug_assert_eq!(a.len(), b.len());

    let len = a.len();
    let mut i = 0;

    // Register-only (safe under #[target_feature] context).
    let mut dot: __m256 = _mm256_setzero_ps();
    let mut norm_b: __m256 = _mm256_setzero_ps();

    while i + 8 <= len {
        // SAFETY: `i + 8 <= len` guarantees both 8-lane unaligned loads stay
        // in-bounds; `ptr::add` offsets are within the slice. FMA is
        // register-only and enabled via #[target_feature].
        unsafe {
            let va = _mm256_loadu_ps(a.as_ptr().add(i));
            let vb = _mm256_loadu_ps(b.as_ptr().add(i));

            dot = _mm256_fmadd_ps(va, vb, dot);
            norm_b = _mm256_fmadd_ps(vb, vb, norm_b);
        }

        i += 8;
    }

    let mut dot_buf = [0.0_f32; 8];
    let mut norm_b_buf = [0.0_f32; 8];

    // SAFETY: stack-allocated 8-lane f32 buffers are sized sufficiently for
    // unaligned 256-bit stores (storeu doesn't require alignment).
    unsafe {
        _mm256_storeu_ps(dot_buf.as_mut_ptr(), dot);
        _mm256_storeu_ps(norm_b_buf.as_mut_ptr(), norm_b);
    }

    let mut dot_sum: f32 = dot_buf.into_iter().sum();
    let mut norm_b_sum: f32 = norm_b_buf.into_iter().sum();

    while i < len {
        let ai = a[i];
        let bi = b[i];
        dot_sum += ai * bi;
        norm_b_sum += bi * bi;
        i += 1;
    }

    normalize_prepared(dot_sum, norm_a, norm_a_sqrt, norm_b_sum)
}

#[cfg(target_arch = "aarch64")]
/// Query-side half of [`cosine_similarity_neon`]: the `norm_a` accumulators
/// alone, over the same 8/4/1 blocks and the same pairwise reduction, so it
/// yields the identical `f32` the full kernel would have accumulated.
fn query_norm_neon(a: &[f32]) -> f32 {
    use std::arch::aarch64::{vaddq_f32, vaddvq_f32, vdupq_n_f32, vfmaq_f32, vld1q_f32};

    let len = a.len();
    let mut i = 0;

    // SAFETY: NEON is mandatory on aarch64, and these intrinsics do not touch
    // memory. The loaded vectors below are separately guarded by loop bounds.
    let (mut norm_a0, mut norm_a1) = unsafe { (vdupq_n_f32(0.0), vdupq_n_f32(0.0)) };

    while i + 8 <= len {
        // SAFETY: `i + 8 <= len` guarantees both 4-lane loads stay in-bounds.
        unsafe {
            let va0 = vld1q_f32(a.as_ptr().add(i));
            let va1 = vld1q_f32(a.as_ptr().add(i + 4));

            norm_a0 = vfmaq_f32(norm_a0, va0, va0);
            norm_a1 = vfmaq_f32(norm_a1, va1, va1);
        }

        i += 8;
    }

    while i + 4 <= len {
        // SAFETY: `i + 4 <= len` guarantees the 4-lane load stays in-bounds.
        unsafe {
            let va = vld1q_f32(a.as_ptr().add(i));
            norm_a0 = vfmaq_f32(norm_a0, va, va);
        }

        i += 4;
    }

    // SAFETY: lane-wise adds operate on initialized NEON accumulators only.
    let mut norm_a_sum = unsafe { vaddvq_f32(vaddq_f32(norm_a0, norm_a1)) };

    while i < len {
        let ai = a[i];
        norm_a_sum += ai * ai;
        i += 1;
    }

    norm_a_sum
}

#[cfg(target_arch = "aarch64")]
/// Candidate-side half of [`cosine_similarity_neon`]: the `dot` and `norm_b`
/// accumulators, untouched, with the query's cached norm folded in at the
/// end. Requires `a.len() == b.len()`.
fn prepared_similarity_neon(a: &[f32], b: &[f32], norm_a: f32, norm_a_sqrt: f32) -> f32 {
    use std::arch::aarch64::{vaddq_f32, vaddvq_f32, vdupq_n_f32, vfmaq_f32, vld1q_f32};

    debug_assert_eq!(a.len(), b.len());

    let len = a.len();
    let mut i = 0;

    // SAFETY: NEON is mandatory on aarch64, and these intrinsics do not touch
    // memory. The loaded vectors below are separately guarded by loop bounds.
    let (mut dot0, mut dot1, mut norm_b0, mut norm_b1) = unsafe {
        (
            vdupq_n_f32(0.0),
            vdupq_n_f32(0.0),
            vdupq_n_f32(0.0),
            vdupq_n_f32(0.0),
        )
    };

    while i + 8 <= len {
        // SAFETY: `i + 8 <= len` guarantees both 4-lane loads stay in-bounds.
        unsafe {
            let va0 = vld1q_f32(a.as_ptr().add(i));
            let vb0 = vld1q_f32(b.as_ptr().add(i));
            let va1 = vld1q_f32(a.as_ptr().add(i + 4));
            let vb1 = vld1q_f32(b.as_ptr().add(i + 4));

            dot0 = vfmaq_f32(dot0, va0, vb0);
            dot1 = vfmaq_f32(dot1, va1, vb1);
            norm_b0 = vfmaq_f32(norm_b0, vb0, vb0);
            norm_b1 = vfmaq_f32(norm_b1, vb1, vb1);
        }

        i += 8;
    }

    while i + 4 <= len {
        // SAFETY: `i + 4 <= len` guarantees the 4-lane loads stay in-bounds.
        unsafe {
            let va = vld1q_f32(a.as_ptr().add(i));
            let vb = vld1q_f32(b.as_ptr().add(i));

            dot0 = vfmaq_f32(dot0, va, vb);
            norm_b0 = vfmaq_f32(norm_b0, vb, vb);
        }

        i += 4;
    }

    // SAFETY: lane-wise adds operate on initialized NEON accumulators only.
    let (mut dot_sum, mut norm_b_sum) = unsafe {
        (
            vaddvq_f32(vaddq_f32(dot0, dot1)),
            vaddvq_f32(vaddq_f32(norm_b0, norm_b1)),
        )
    };

    while i < len {
        let ai = a[i];
        let bi = b[i];
        dot_sum += ai * bi;
        norm_b_sum += bi * bi;
        i += 1;
    }

    normalize_prepared(dot_sum, norm_a, norm_a_sqrt, norm_b_sum)
}
