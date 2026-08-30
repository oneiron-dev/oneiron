pub(crate) fn cosine_distance(a: &[f32], b: &[f32]) -> f32 {
    1.0 - cosine_similarity(a, b)
}

pub(crate) fn cosine_similarity(a: &[f32], b: &[f32]) -> f32 {
    if a.len() != b.len() {
        return 0.0;
    }

    #[cfg(target_arch = "x86_64")]
    {
        if std::arch::is_x86_feature_detected!("avx2") && std::arch::is_x86_feature_detected!("fma")
        {
            // SAFETY: AVX2 and FMA support are checked at runtime.
            return unsafe { cosine_similarity_avx2(a, b) };
        }

        cosine_similarity_scalar(a, b)
    }

    #[cfg(target_arch = "aarch64")]
    {
        if a.len() < 4 {
            return cosine_similarity_scalar(a, b);
        }

        cosine_similarity_neon(a, b)
    }

    #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
    cosine_similarity_scalar(a, b)
}

fn cosine_similarity_scalar(a: &[f32], b: &[f32]) -> f32 {
    let len = a.len();
    let mut i = 0;

    let mut dot = 0.0_f32;
    let mut norm_a = 0.0_f32;
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
        norm_a += a0 * a0 + a1 * a1 + a2 * a2 + a3 * a3 + a4 * a4 + a5 * a5 + a6 * a6 + a7 * a7;
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
        norm_a += a0 * a0 + a1 * a1 + a2 * a2 + a3 * a3;
        norm_b += b0 * b0 + b1 * b1 + b2 * b2 + b3 * b3;

        i += 4;
    }

    while i < len {
        let ai = a[i];
        let bi = b[i];
        dot += ai * bi;
        norm_a += ai * ai;
        norm_b += bi * bi;
        i += 1;
    }

    normalize(dot, norm_a, norm_b)
}

#[inline]
fn normalize(dot: f32, norm_a: f32, norm_b: f32) -> f32 {
    normalize_prepared(dot, norm_a, norm_a.sqrt(), norm_b)
}

/// [`normalize`] with `norm_a.sqrt()` supplied by the caller.
///
/// The square root of a loop-invariant norm is itself loop-invariant, so the
/// prepared path hoists it out of the per-candidate divide. `norm_a_sqrt`
/// must be exactly `norm_a.sqrt()`; `normalize` is defined in terms of this
/// function so the two can never drift apart.
#[inline]
fn normalize_prepared(dot: f32, norm_a: f32, norm_a_sqrt: f32, norm_b: f32) -> f32 {
    if !dot.is_finite()
        || !norm_a.is_finite()
        || !norm_b.is_finite()
        || norm_a <= 0.0
        || norm_b <= 0.0
    {
        return 0.0;
    }

    let similarity = dot / (norm_a_sqrt * norm_b.sqrt());
    similarity.clamp(-1.0, 1.0)
}

#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "avx2")]
#[target_feature(enable = "fma")]
/// Requires `a.len() == b.len()` and the caller must ensure AVX2+FMA are
/// supported on the target CPU. The dispatcher enforces both before calling.
unsafe fn cosine_similarity_avx2(a: &[f32], b: &[f32]) -> f32 {
    use std::arch::x86_64::{
        __m256, _mm256_fmadd_ps, _mm256_loadu_ps, _mm256_setzero_ps, _mm256_storeu_ps,
    };

    debug_assert_eq!(a.len(), b.len());

    let len = a.len();
    let mut i = 0;

    // Register-only (safe under #[target_feature] context).
    let mut dot: __m256 = _mm256_setzero_ps();
    let mut norm_a: __m256 = _mm256_setzero_ps();
    let mut norm_b: __m256 = _mm256_setzero_ps();

    while i + 8 <= len {
        // SAFETY: `i + 8 <= len` guarantees both 8-lane unaligned loads stay
        // in-bounds; `ptr::add` offsets are within the slice. FMA is
        // register-only and enabled via #[target_feature].
        unsafe {
            let va = _mm256_loadu_ps(a.as_ptr().add(i));
            let vb = _mm256_loadu_ps(b.as_ptr().add(i));

            dot = _mm256_fmadd_ps(va, vb, dot);
            norm_a = _mm256_fmadd_ps(va, va, norm_a);
            norm_b = _mm256_fmadd_ps(vb, vb, norm_b);
        }

        i += 8;
    }

    let mut dot_buf = [0.0_f32; 8];
    let mut norm_a_buf = [0.0_f32; 8];
    let mut norm_b_buf = [0.0_f32; 8];

    // SAFETY: stack-allocated 8-lane f32 buffers are sized sufficiently for
    // unaligned 256-bit stores (storeu doesn't require alignment).
    unsafe {
        _mm256_storeu_ps(dot_buf.as_mut_ptr(), dot);
        _mm256_storeu_ps(norm_a_buf.as_mut_ptr(), norm_a);
        _mm256_storeu_ps(norm_b_buf.as_mut_ptr(), norm_b);
    }

    let mut dot_sum: f32 = dot_buf.into_iter().sum();
    let mut norm_a_sum: f32 = norm_a_buf.into_iter().sum();
    let mut norm_b_sum: f32 = norm_b_buf.into_iter().sum();

    while i < len {
        let ai = a[i];
        let bi = b[i];
        dot_sum += ai * bi;
        norm_a_sum += ai * ai;
        norm_b_sum += bi * bi;
        i += 1;
    }

    normalize(dot_sum, norm_a_sum, norm_b_sum)
}

#[cfg(target_arch = "aarch64")]
/// Requires `a.len() == b.len()`. The dispatcher enforces that precondition
/// before calling into the aarch64 NEON hot path.
fn cosine_similarity_neon(a: &[f32], b: &[f32]) -> f32 {
    use std::arch::aarch64::{vaddq_f32, vaddvq_f32, vdupq_n_f32, vfmaq_f32, vld1q_f32};

    debug_assert_eq!(a.len(), b.len());

    let len = a.len();
    let mut i = 0;

    // SAFETY: NEON is mandatory on aarch64, and these intrinsics do not touch
    // memory. The loaded vectors below are separately guarded by loop bounds.
    let (mut dot0, mut dot1, mut norm_a0, mut norm_a1, mut norm_b0, mut norm_b1) = unsafe {
        (
            vdupq_n_f32(0.0),
            vdupq_n_f32(0.0),
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
            norm_a0 = vfmaq_f32(norm_a0, va0, va0);
            norm_a1 = vfmaq_f32(norm_a1, va1, va1);
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
            norm_a0 = vfmaq_f32(norm_a0, va, va);
            norm_b0 = vfmaq_f32(norm_b0, vb, vb);
        }

        i += 4;
    }

    // SAFETY: lane-wise adds operate on initialized NEON accumulators only.
    let (mut dot_sum, mut norm_a_sum, mut norm_b_sum) = unsafe {
        (
            vaddvq_f32(vaddq_f32(dot0, dot1)),
            vaddvq_f32(vaddq_f32(norm_a0, norm_a1)),
            vaddvq_f32(vaddq_f32(norm_b0, norm_b1)),
        )
    };

    while i < len {
        let ai = a[i];
        let bi = b[i];
        dot_sum += ai * bi;
        norm_a_sum += ai * ai;
        norm_b_sum += bi * bi;
        i += 1;
    }

    normalize(dot_sum, norm_a_sum, norm_b_sum)
}

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
    fn similarity(&self, candidate: &[f32]) -> f32 {
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

#[cfg(test)]
mod tests {
    use super::{PreparedCosine, cosine_distance, cosine_similarity};

    fn approx_eq(a: f32, b: f32, eps: f32) {
        assert!((a - b).abs() <= eps, "left={a}, right={b}, eps={eps}");
    }

    fn manual_cosine_similarity(a: &[f32], b: &[f32]) -> f32 {
        let mut dot = 0.0_f32;
        let mut norm_a = 0.0_f32;
        let mut norm_b = 0.0_f32;

        for (&ai, &bi) in a.iter().zip(b.iter()) {
            dot += ai * bi;
            norm_a += ai * ai;
            norm_b += bi * bi;
        }

        if !dot.is_finite()
            || !norm_a.is_finite()
            || !norm_b.is_finite()
            || norm_a <= 0.0
            || norm_b <= 0.0
        {
            return 0.0;
        }

        (dot / (norm_a.sqrt() * norm_b.sqrt())).clamp(-1.0, 1.0)
    }

    /// Table of `(a, b, expected_similarity, expected_distance)` pairs
    /// covering the public `cosine_similarity` / `cosine_distance` contract
    /// across the originally-separate fixture tests.
    ///
    /// Variants:
    /// - `identical_vectors`: sim==1, dist==0.
    /// - `orthogonal_vectors`: sim==0, dist==1.
    /// - `zero_norm_zero_vs_non_zero`: degenerate one-zero pair returns dist==1.
    /// - `zero_norm_zero_vs_zero`: degenerate both-zero pair returns dist==1.
    /// - `mismatched_lengths`: short-circuit returns 0/1.
    /// - `non_finite_inputs_nan`: NaN inputs short-circuit to 0/1.
    /// - `non_finite_inputs_inf`: ±Inf inputs short-circuit to 0/1.
    #[test]
    #[allow(clippy::type_complexity)]
    fn cosine_distance_cases() {
        let identical: Vec<f32> = vec![0.1, -0.2, 0.3, 0.4, -0.5];
        let zero7: Vec<f32> = vec![0.0; 7];
        let non_zero7: Vec<f32> = vec![1.0, 2.0, 3.0, 4.0, 5.0, 6.0, 7.0];
        let nan: Vec<f32> = vec![f32::NAN, 1.0, 2.0, 3.0];
        let inf: Vec<f32> = vec![f32::INFINITY, 1.0, 2.0, 3.0];
        let finite4: Vec<f32> = vec![1.0, 2.0, 3.0, 4.0];

        let cases: Vec<(&str, Vec<f32>, Vec<f32>, f32, f32)> = vec![
            ("identical_vectors", identical.clone(), identical, 1.0, 0.0),
            (
                "orthogonal_vectors",
                vec![1.0, 0.0, 0.0, 0.0, 0.0],
                vec![0.0, 1.0, 0.0, 0.0, 0.0],
                0.0,
                1.0,
            ),
            (
                "zero_norm_zero_vs_non_zero",
                zero7.clone(),
                non_zero7,
                0.0,
                1.0,
            ),
            ("zero_norm_zero_vs_zero", zero7.clone(), zero7, 0.0, 1.0),
            (
                "mismatched_lengths",
                vec![1.0, 2.0, 3.0],
                vec![1.0, 2.0],
                0.0,
                1.0,
            ),
            ("non_finite_inputs_nan", nan, finite4.clone(), 0.0, 1.0),
            ("non_finite_inputs_inf", inf, finite4, 0.0, 1.0),
        ];

        for (case_name, a, b, expected_sim, expected_dist) in cases {
            let sim = cosine_similarity(&a, &b);
            let dist = cosine_distance(&a, &b);
            assert!(
                (sim - expected_sim).abs() <= 1e-6,
                "case {case_name}: similarity left={sim}, right={expected_sim}"
            );
            assert!(
                (dist - expected_dist).abs() <= 1e-6,
                "case {case_name}: distance left={dist}, right={expected_dist}"
            );
        }
    }

    #[test]
    fn cosine_handles_simd_remainder() {
        let a = vec![0.25_f32; 17];
        let b = vec![0.5_f32; 17];

        approx_eq(cosine_similarity(&a, &b), 1.0, 1e-6);
        approx_eq(cosine_distance(&a, &b), 0.0, 1e-6);
    }

    // mismatched_lengths and non_finite_inputs are folded into
    // `cosine_distance_cases` above.

    #[cfg(target_arch = "x86_64")]
    #[test]
    fn cosine_avx2_matches_scalar_across_lengths() {
        // Runtime detection so the test actually runs on default CI builds
        // (which don't include +avx2/+fma in their target_features), not only
        // under `-C target-cpu=native`.
        if !std::arch::is_x86_feature_detected!("avx2")
            || !std::arch::is_x86_feature_detected!("fma")
        {
            // Skip on CPUs without AVX2 + FMA; dispatcher coverage still exercises
            // the scalar fallback via `cosine_similarity`.
            return;
        }

        // Exercise the AVX2 path directly against the scalar reference across
        // lengths that stress the 8-lane main loop + scalar tail.
        for len in [1, 4, 7, 8, 15, 16, 17, 31, 32, 33, 64, 129] {
            let a: Vec<f32> = (0..len).map(|i| (i as f32) * 0.125 - 0.375).collect();
            let b: Vec<f32> = (0..len).map(|i| ((i as f32) * 0.0625).sin()).collect();

            let scalar = super::cosine_similarity_scalar(&a, &b);
            // SAFETY: AVX2 + FMA were runtime-detected above; calling the
            // AVX2 variant is sound. Slice lengths match (constructed equal).
            let avx = unsafe { super::cosine_similarity_avx2(&a, &b) };
            approx_eq(avx, scalar, 1e-5);
        }
    }

    #[test]
    fn cosine_matches_manual_formula_across_unroll_boundaries() {
        let a = [
            0.5_f32, -0.75, 1.25, 0.125, -1.0, 0.625, 0.875, -0.5, 1.5, -1.25, 0.25, 0.75, -0.375,
        ];
        let b = [
            -0.25_f32, 0.5, 0.75, -1.0, 0.125, 1.25, -0.625, 0.375, -1.5, 0.875, 0.5, -0.25, 1.125,
        ];

        let expected = manual_cosine_similarity(&a, &b);
        approx_eq(super::cosine_similarity_scalar(&a, &b), expected, 1e-6);
        approx_eq(
            1.0 - super::cosine_similarity_scalar(&a, &b),
            1.0 - expected,
            1e-6,
        );

        // Keep the public dispatcher covered as well.
        approx_eq(cosine_similarity(&a, &b), expected, 1e-6);
        approx_eq(cosine_distance(&a, &b), 1.0 - expected, 1e-6);
    }

    // ===== ONE-1137: prepared (loop-invariant query norm) cosine =====

    /// SplitMix64 — deterministic test PRNG, no external dependency.
    fn splitmix64(state: &mut u64) -> u64 {
        *state = state.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = *state;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    fn pseudo_vector(state: &mut u64, len: usize) -> Vec<f32> {
        (0..len)
            .map(|_| ((splitmix64(state) >> 40) as f32 / (1 << 24) as f32) * 2.0 - 1.0)
            .collect()
    }

    /// Bit-for-bit, not approximate: the prepared path is a loop-invariant
    /// hoist of the query norm, so ANY difference in the low bit is a
    /// reassociation bug that could reorder a beam's tie-broken results.
    fn assert_same_bits(prepared: f32, legacy: f32, case: &str) {
        assert_eq!(
            prepared.to_bits(),
            legacy.to_bits(),
            "case {case}: prepared={prepared} legacy={legacy}"
        );
    }

    /// Lengths straddle every block/tail boundary of all three kernels: below
    /// the aarch64 4-lane cutoff (1, 3), exactly one 4-block (4), a 4-block
    /// plus scalar tail (7), exactly one 8-block (8), 8-blocks plus a mixed
    /// tail (31), and the production-scale 1024.
    #[test]
    fn prepared_cosine_matches_legacy_bit_for_bit_across_lengths() {
        for len in [1_usize, 3, 4, 7, 8, 31, 1024] {
            let mut state = 0x0011_3700 ^ (len as u64);
            let query = pseudo_vector(&mut state, len);
            // One prepared query, many candidates — the reuse the insert
            // path actually performs.
            let prepared = PreparedCosine::new(&query);

            for round in 0..8 {
                let candidate = pseudo_vector(&mut state, len);
                let case = format!("len={len} round={round}");
                assert_same_bits(
                    prepared.similarity(&candidate),
                    cosine_similarity(&query, &candidate),
                    &case,
                );
                assert_same_bits(
                    prepared.distance(&candidate),
                    cosine_distance(&query, &candidate),
                    &case,
                );
            }

            // Self-comparison exercises the clamp: the ratio can round just
            // above 1.0 and must be pinned to it on both paths.
            let self_similarity = prepared.similarity(&query);
            assert_same_bits(
                self_similarity,
                cosine_similarity(&query, &query),
                &format!("len={len} self"),
            );
            assert!(
                self_similarity <= 1.0,
                "len={len}: clamp must hold, got {self_similarity}"
            );

            // Negated candidate exercises the lower clamp bound.
            let negated: Vec<f32> = query.iter().map(|value| -value).collect();
            assert_same_bits(
                prepared.similarity(&negated),
                cosine_similarity(&query, &negated),
                &format!("len={len} negated"),
            );
            assert!(
                prepared.similarity(&negated) >= -1.0,
                "len={len}: lower clamp must hold"
            );
        }
    }

    /// The degenerate contract is part of the graph's semantics (a zero or
    /// unusable norm scores as maximally distant, never as a near neighbor),
    /// so the prepared path must reproduce it exactly rather than merely
    /// avoid NaN.
    #[test]
    fn prepared_cosine_preserves_degenerate_contract() {
        let zero7 = vec![0.0_f32; 7];
        let non_zero7: Vec<f32> = vec![1.0, 2.0, 3.0, 4.0, 5.0, 6.0, 7.0];
        let nan4 = vec![f32::NAN, 1.0, 2.0, 3.0];
        let inf4 = vec![f32::INFINITY, 1.0, 2.0, 3.0];
        let neg_inf4 = vec![f32::NEG_INFINITY, 1.0, 2.0, 3.0];
        let finite4 = vec![1.0_f32, 2.0, 3.0, 4.0];

        // Every pair below is degenerate on one side or the other, so the
        // contract pins similarity 0.0 / distance 1.0.
        let cases: Vec<(&str, &[f32], &[f32])> = vec![
            ("zero_query", &zero7, &non_zero7),
            ("zero_candidate", &non_zero7, &zero7),
            ("both_zero", &zero7, &zero7),
            ("nan_query", &nan4, &finite4),
            ("nan_candidate", &finite4, &nan4),
            ("inf_query", &inf4, &finite4),
            ("inf_candidate", &finite4, &inf4),
            ("neg_inf_query", &neg_inf4, &finite4),
            // Mismatched lengths short-circuit before any accumulation.
            ("shorter_candidate", &non_zero7, &finite4),
            ("longer_candidate", &finite4, &non_zero7),
            ("empty_query", &[], &finite4),
            ("empty_both", &[], &[]),
        ];

        for (case, query, candidate) in cases {
            let prepared = PreparedCosine::new(query);
            assert_same_bits(
                prepared.similarity(candidate),
                cosine_similarity(query, candidate),
                case,
            );
            assert_same_bits(
                prepared.distance(candidate),
                cosine_distance(query, candidate),
                case,
            );
            assert_eq!(
                prepared.similarity(candidate),
                0.0,
                "case {case}: degenerate similarity must be 0.0"
            );
            assert_eq!(
                prepared.distance(candidate),
                1.0,
                "case {case}: degenerate distance must be 1.0"
            );
        }
    }

    /// A prepared query is stateless across candidates: scoring a degenerate
    /// or mismatched candidate must not disturb the norm cached for the
    /// healthy ones that follow.
    #[test]
    fn prepared_cosine_reuse_is_order_independent() {
        let mut state = 0x1137_0042;
        let query = pseudo_vector(&mut state, 33);
        let candidates: Vec<Vec<f32>> = vec![
            pseudo_vector(&mut state, 33),
            vec![0.0; 33],
            vec![1.0, 2.0],
            vec![f32::NAN; 33],
            pseudo_vector(&mut state, 33),
        ];

        let prepared = PreparedCosine::new(&query);
        for pass in 0..3 {
            for (index, candidate) in candidates.iter().enumerate() {
                assert_same_bits(
                    prepared.distance(candidate),
                    cosine_distance(&query, candidate),
                    &format!("pass={pass} candidate={index}"),
                );
            }
        }
    }
}
