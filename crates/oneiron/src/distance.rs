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
    if !dot.is_finite()
        || !norm_a.is_finite()
        || !norm_b.is_finite()
        || norm_a <= 0.0
        || norm_b <= 0.0
    {
        return 0.0;
    }

    let similarity = dot / (norm_a.sqrt() * norm_b.sqrt());
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

#[cfg(test)]
mod tests {
    use super::{cosine_distance, cosine_similarity};

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

    #[test]
    fn cosine_identical_vectors() {
        let a = [0.1_f32, -0.2, 0.3, 0.4, -0.5];
        let sim = cosine_similarity(&a, &a);
        approx_eq(sim, 1.0, 1e-6);
        approx_eq(cosine_distance(&a, &a), 0.0, 1e-6);
    }

    #[test]
    fn cosine_orthogonal_vectors() {
        let a = [1.0_f32, 0.0, 0.0, 0.0, 0.0];
        let b = [0.0_f32, 1.0, 0.0, 0.0, 0.0];
        approx_eq(cosine_similarity(&a, &b), 0.0, 1e-6);
        approx_eq(cosine_distance(&a, &b), 1.0, 1e-6);
    }

    #[test]
    fn cosine_zero_norm_returns_max_distance() {
        let zero = [0.0_f32; 7];
        let non_zero = [1.0_f32, 2.0, 3.0, 4.0, 5.0, 6.0, 7.0];

        approx_eq(cosine_similarity(&zero, &non_zero), 0.0, 1e-6);
        approx_eq(cosine_distance(&zero, &non_zero), 1.0, 1e-6);
        approx_eq(cosine_distance(&zero, &zero), 1.0, 1e-6);
    }

    #[test]
    fn cosine_handles_simd_remainder() {
        let a = vec![0.25_f32; 17];
        let b = vec![0.5_f32; 17];

        approx_eq(cosine_similarity(&a, &b), 1.0, 1e-6);
        approx_eq(cosine_distance(&a, &b), 0.0, 1e-6);
    }

    #[test]
    fn cosine_returns_zero_for_mismatched_lengths() {
        let a = [1.0_f32, 2.0, 3.0];
        let b = [1.0_f32, 2.0];

        approx_eq(cosine_similarity(&a, &b), 0.0, 1e-6);
        approx_eq(cosine_distance(&a, &b), 1.0, 1e-6);
    }

    #[test]
    fn cosine_returns_zero_for_non_finite_inputs() {
        let nan = [f32::NAN, 1.0, 2.0, 3.0];
        let inf = [f32::INFINITY, 1.0, 2.0, 3.0];
        let finite = [1.0_f32, 2.0, 3.0, 4.0];

        approx_eq(cosine_similarity(&nan, &finite), 0.0, 1e-6);
        approx_eq(cosine_distance(&nan, &finite), 1.0, 1e-6);
        approx_eq(cosine_similarity(&inf, &finite), 0.0, 1e-6);
        approx_eq(cosine_distance(&inf, &finite), 1.0, 1e-6);
    }

    #[cfg(all(
        target_arch = "x86_64",
        target_feature = "avx2",
        target_feature = "fma"
    ))]
    #[test]
    fn cosine_avx2_matches_scalar_across_lengths() {
        // Exercise the AVX2 path directly against the scalar reference across
        // lengths that stress the 8-lane main loop + scalar tail.
        for len in [1, 4, 7, 8, 15, 16, 17, 31, 32, 33, 64, 129] {
            let a: Vec<f32> = (0..len).map(|i| (i as f32) * 0.125 - 0.375).collect();
            let b: Vec<f32> = (0..len).map(|i| ((i as f32) * 0.0625).sin()).collect();

            let scalar = super::cosine_similarity_scalar(&a, &b);
            // SAFETY: cfg-gated on target_feature = avx2 + fma, so calling the
            // AVX2 variant here is sound. Slice lengths match (constructed
            // equal above).
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
}
