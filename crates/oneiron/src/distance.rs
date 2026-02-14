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

        // SAFETY: NEON is a required feature on aarch64.
        unsafe { cosine_similarity_neon(a, b) }
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
    if norm_a <= 0.0 || norm_b <= 0.0 {
        return 0.0;
    }

    let similarity = dot / (norm_a.sqrt() * norm_b.sqrt());
    similarity.clamp(-1.0, 1.0)
}

#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "avx2")]
#[target_feature(enable = "fma")]
unsafe fn cosine_similarity_avx2(a: &[f32], b: &[f32]) -> f32 {
    use std::arch::x86_64::{
        __m256, _mm256_fmadd_ps, _mm256_loadu_ps, _mm256_setzero_ps, _mm256_storeu_ps,
    };

    let len = a.len();
    let mut i = 0;

    let mut dot: __m256 = _mm256_setzero_ps();
    let mut norm_a: __m256 = _mm256_setzero_ps();
    let mut norm_b: __m256 = _mm256_setzero_ps();

    while i + 8 <= len {
        let va = _mm256_loadu_ps(a.as_ptr().add(i));
        let vb = _mm256_loadu_ps(b.as_ptr().add(i));

        dot = _mm256_fmadd_ps(va, vb, dot);
        norm_a = _mm256_fmadd_ps(va, va, norm_a);
        norm_b = _mm256_fmadd_ps(vb, vb, norm_b);

        i += 8;
    }

    let mut dot_buf = [0.0_f32; 8];
    let mut norm_a_buf = [0.0_f32; 8];
    let mut norm_b_buf = [0.0_f32; 8];

    _mm256_storeu_ps(dot_buf.as_mut_ptr(), dot);
    _mm256_storeu_ps(norm_a_buf.as_mut_ptr(), norm_a);
    _mm256_storeu_ps(norm_b_buf.as_mut_ptr(), norm_b);

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
#[target_feature(enable = "neon")]
unsafe fn cosine_similarity_neon(a: &[f32], b: &[f32]) -> f32 {
    use std::arch::aarch64::{float32x4_t, vaddvq_f32, vdupq_n_f32, vfmaq_f32, vld1q_f32};

    let len = a.len();
    let mut i = 0;

    let mut dot: float32x4_t = vdupq_n_f32(0.0);
    let mut norm_a: float32x4_t = vdupq_n_f32(0.0);
    let mut norm_b: float32x4_t = vdupq_n_f32(0.0);

    while i + 4 <= len {
        let va = vld1q_f32(a.as_ptr().add(i));
        let vb = vld1q_f32(b.as_ptr().add(i));

        dot = vfmaq_f32(dot, va, vb);
        norm_a = vfmaq_f32(norm_a, va, va);
        norm_b = vfmaq_f32(norm_b, vb, vb);

        i += 4;
    }

    let mut dot_sum = vaddvq_f32(dot);
    let mut norm_a_sum = vaddvq_f32(norm_a);
    let mut norm_b_sum = vaddvq_f32(norm_b);

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
}
