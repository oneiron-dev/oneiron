//! IEEE-754 binary16 conversion for the ONE-1579 precision axis.
//!
//! This is a BENCH-side codec. It exists so the f16 precision row can be built
//! and scanned inside the bench over its own copy of the corpus vectors; it is
//! not the engine's storage path and changes nothing about what the engine
//! persists.
//!
//! Rounding is IEEE-754 `roundTiesToEven`, and the tie case is the one that
//! matters for a precision row: a value exactly half way between two binary16
//! neighbours rounds to the neighbour whose significand is EVEN, so it rounds
//! DOWN whenever the retained significand is already even. Rounding every tie
//! upward instead would bias the whole F16 candidate away from the exact
//! float32 ranking it is scored against, which is a recall claim rather than a
//! rounding detail. [`rounds_up`] is the single decision both the normal and
//! the subnormal path make, and the exhaustive regression below pins it
//! against every representable binary16 neighbour pair.

/// Round-to-nearest, ties-to-even for one significand about to be truncated.
///
/// `round_bit` is the HIGHEST DISCARDED bit. The tie-break mask deliberately
/// covers only the retained significand's least significant bit and the
/// discarded bits BELOW the round bit — never the round bit itself. Including
/// the round bit would make this test true whenever the first one is, turning
/// every halfway value into a round-up and losing ties-to-even entirely.
const fn rounds_up(significand: u32, round_bit: u32) -> bool {
    // Bits strictly below the round bit: any of them set means the value is
    // ABOVE the halfway point, so it rounds up whatever the retained parity.
    let sticky = round_bit - 1;
    // The retained significand's LSB: at an exact tie this is what decides,
    // and it is set exactly when the retained significand is ODD.
    let retained_lsb = round_bit << 1;
    (significand & round_bit) != 0 && (significand & (retained_lsb | sticky)) != 0
}

/// float32 -> binary16 bits, IEEE-754 round-to-nearest with ties to even.
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
        if rounds_up(mantissa, round_bit) {
            half_mantissa += 1;
        }
        return (half_sign | half_mantissa) as u16;
    }

    let half_exponent = (half_exponent as u32) << 10;
    let half_mantissa = mantissa >> 13;
    let round_bit = 0x0000_1000_u32;
    if rounds_up(mantissa, round_bit) {
        // Carrying into the exponent field is exactly what this addition on
        // the assembled bits does, including the overflow to infinity.
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

    /// The named halfway cases, spelled out. `1.00048828125` is exactly half
    /// way between `1.0` (even significand) and `1.0009765625` (odd), so
    /// ties-to-even must return `1.0`; rounding every tie upward would bias
    /// the whole F16 row away from the exact float32 ranking it is scored
    /// against.
    #[test]
    fn binary16_halfway_values_round_to_the_even_significand() {
        // (input, expected bits, why)
        for (value, expected, note) in [
            // Bit forms keep the exact halfway values without asking a
            // decimal literal to carry precision beyond f32's display width.
            (
                f32::from_bits(0x3F80_1000), // 1.00048828125 exactly
                0x3C00_u16,
                "tie below an odd neighbour",
            ),
            (
                f32::from_bits(0x3F80_3000), // 1.00146484375 exactly
                0x3C02,
                "tie above an odd neighbour",
            ),
            // Subnormal branch: half of the smallest subnormal is the tie
            // between +0 (even) and 2^-24 (odd).
            (f32::from_bits(0x3300_0000), 0x0000, "subnormal tie to zero"),
            // 1.5 * 2^-24 ties between 2^-24 (odd) and 2^-23 (even).
            (f32::from_bits(0x33C0_0000), 0x0002, "subnormal tie upward"),
            // 65520 ties between 65504 (odd) and the unrepresentable 65536,
            // which IEEE resolves to infinity.
            (65_520.0, 0x7C00, "overflow tie"),
        ] {
            let bits = f32_to_f16_bits(value);
            assert_eq!(bits, expected, "{value} ({note}) encoded as {bits:#06x}");
            assert_eq!(
                f32_to_f16_bits(-value),
                expected | 0x8000,
                "{value} ({note}) must round the same way with a sign bit"
            );
        }
    }

    /// Exhaustive over EVERY finite binary16 neighbour pair: the exact
    /// midpoint must land on whichever neighbour has an even significand, and
    /// one ulp either side of that midpoint must land on the nearer one.
    #[test]
    fn every_binary16_midpoint_rounds_to_even_and_its_neighbours_round_near() {
        for low in 0_u16..0x7BFF {
            let high = low + 1;
            let a = f64::from(f16_bits_to_f32(low));
            let b = f64::from(f16_bits_to_f32(high));
            // A binary16 midpoint needs 12 significand bits, so it is exact
            // in float32 and the conversion below loses nothing.
            let midpoint = ((a + b) / 2.0) as f32;
            let even = if low % 2 == 0 { low } else { high };
            assert_eq!(
                f32_to_f16_bits(midpoint),
                even,
                "the midpoint of {low:#06x} and {high:#06x} must round to the even significand"
            );
            assert_eq!(
                f32_to_f16_bits(-midpoint),
                even | 0x8000,
                "negative midpoints round to even too"
            );
            assert_eq!(
                f32_to_f16_bits(f32::from_bits(midpoint.to_bits() - 1)),
                low,
                "one ulp below the midpoint of {low:#06x} rounds down"
            );
            assert_eq!(
                f32_to_f16_bits(f32::from_bits(midpoint.to_bits() + 1)),
                high,
                "one ulp above the midpoint of {low:#06x} rounds up"
            );
        }
    }

    /// Every representable binary16 value must survive f16 -> f32 -> f16
    /// unchanged; a rounding rule that pushed exact values off their own
    /// encoding would show up here first.
    #[test]
    fn every_representable_binary16_round_trips_exactly() {
        for bits in 0_u16..=0x7BFF {
            let value = f16_bits_to_f32(bits);
            assert_eq!(f32_to_f16_bits(value), bits, "{bits:#06x} round-trips");
            assert_eq!(f32_to_f16_bits(-value), bits | 0x8000, "{bits:#06x} signed");
        }
    }
}
