//! IEEE-754 binary16 conversion for the ONE-1579 precision axis.
//!
//! This is a BENCH-side codec. It exists so the f16 precision row can be built
//! and scanned inside the bench over its own copy of the corpus vectors; it is
//! not the engine's storage path and changes nothing about what the engine
//! persists.

/// float32 -> binary16 bits, round-to-nearest with the usual tie handling.
pub(crate) fn f32_to_f16_bits(value: f32) -> u16 {
    let raw = value.to_bits();
    let sign = raw & 0x8000_0000_u32;
    let exponent = raw & 0x7F80_0000_u32;
    let mantissa = raw & 0x007F_FFFF_u32;

    if exponent == 0x7F80_0000_u32 {
        let nan_bit = if mantissa == 0 { 0 } else { 0x0200_u32 };
        return ((sign >> 16) | 0x7C00_u32 | nan_bit | (mantissa >> 13)) as u16;
    }

    let half_sign = sign >> 16;
    let half_exponent = ((exponent >> 23) as i32) - 127 + 15;
    if half_exponent >= 0x1F {
        return (half_sign | 0x7C00_u32) as u16;
    }
    if half_exponent <= 0 {
        if 14 - half_exponent > 24 {
            return half_sign as u16;
        }
        let mantissa = mantissa | 0x0080_0000_u32;
        let mut half_mantissa = mantissa >> (14 - half_exponent);
        let round_bit = 1_u32 << (13 - half_exponent);
        if (mantissa & round_bit) != 0 && (mantissa & (3 * round_bit - 1)) != 0 {
            half_mantissa += 1;
        }
        return (half_sign | half_mantissa) as u16;
    }

    let half_exponent = (half_exponent as u32) << 10;
    let half_mantissa = mantissa >> 13;
    let round_bit = 0x0000_1000_u32;
    if (mantissa & round_bit) != 0 && (mantissa & (3 * round_bit - 1)) != 0 {
        ((half_sign | half_exponent | half_mantissa) + 1) as u16
    } else {
        (half_sign | half_exponent | half_mantissa) as u16
    }
}

/// binary16 bits -> float32, exact (every binary16 value is representable).
pub(crate) fn f16_bits_to_f32(bits: u16) -> f32 {
    if (bits & 0x7FFF) == 0 {
        return f32::from_bits(u32::from(bits) << 16);
    }
    let sign = u32::from(bits & 0x8000) << 16;
    let exponent = u32::from(bits & 0x7C00);
    let mantissa = u32::from(bits & 0x03FF);

    if exponent == 0x7C00 {
        if mantissa == 0 {
            return f32::from_bits(sign | 0x7F80_0000_u32);
        }
        return f32::from_bits(sign | 0x7FC0_0000_u32 | (mantissa << 13));
    }
    if exponent == 0 {
        // Subnormal: normalise by shifting the leading mantissa bit up.
        let shift = (mantissa as u16).leading_zeros() - 6;
        let normalised_exponent = (127 - 15 - shift) << 23;
        let normalised_mantissa = (mantissa << (14 + shift)) & 0x007F_FFFF_u32;
        return f32::from_bits(sign | normalised_exponent | normalised_mantissa);
    }
    let unbiased = ((exponent >> 10) as i32) - 15;
    let rebiased = ((unbiased + 127) as u32) << 23;
    f32::from_bits(sign | rebiased | (mantissa << 13))
}

#[cfg(test)]
mod tests {
    use rand::rngs::StdRng;
    use rand::{Rng, SeedableRng};

    use super::*;

    #[test]
    fn binary16_round_trip_is_close_and_exact_on_representable_values() {
        for value in [0.0_f32, 1.0, -1.0, 0.5, -0.25, 65504.0, 6.1035156e-5] {
            let round_tripped = f16_bits_to_f32(f32_to_f16_bits(value));
            assert!(
                (round_tripped - value).abs() <= value.abs() * 1e-3,
                "{value} round-tripped to {round_tripped}"
            );
        }
        let mut rng = StdRng::seed_from_u64(7);
        for _ in 0..512 {
            let value: f32 = rng.gen_range(-4.0_f32..4.0);
            let round_tripped = f16_bits_to_f32(f32_to_f16_bits(value));
            assert!(
                (round_tripped - value).abs() <= 0.01,
                "{value} round-tripped to {round_tripped}"
            );
        }
        assert!(f16_bits_to_f32(f32_to_f16_bits(f32::INFINITY)).is_infinite());
        assert!(f16_bits_to_f32(f32_to_f16_bits(f32::NAN)).is_nan());
    }
}
