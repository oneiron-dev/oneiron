//! `port-harness floats --out <file>`: `repr` of a fixed corpus of floats, as `scripts/sdk/port_harness.py floats`
//! prints it from Python: every power of two and its two neighbours, decimal sweeps across every exponent, and
//! 200,000 floats from a 64-bit linear congruential generator (both halves step the same one). Each line is the
//! float's bits in hex and its repr.

use crate::error::GenerateError;
use crate::py::value::float_repr;

const USAGE: &str = "usage: oneiron-sdk-generator port-harness floats --out <file>";

/// Knuth's MMIX constants; seed 20261110.
const LCG_MULTIPLIER: u64 = 6_364_136_223_846_793_005;
const LCG_INCREMENT: u64 = 1_442_695_040_888_963_407;
const LCG_SEED: u64 = 20_261_110;
const LCG_COUNT: usize = 200_000;
const SWEEP_MANTISSAS: &[&str] = &[
    "1",
    "2",
    "5",
    "9.999999999999999",
    "1.2345678901234567",
    "4.35",
    "0.1",
    "3.0000000000000004",
];

fn line(out: &mut String, bits: u64) {
    let f = f64::from_bits(bits);
    if f.is_finite() {
        out.push_str(&format!("{bits:016x} {}\n", float_repr(f)));
    }
}

pub(crate) fn run(args: &[String]) -> Result<(), GenerateError> {
    let out = super::flag(args, "--out", USAGE)?;
    let mut dump = String::new();
    for k in -1074_i32..=1023 {
        let bits = if k >= -1022 {
            u64::try_from(k + 1023).unwrap_or(0) << 52
        } else {
            1_u64 << u32::try_from(k + 1074).unwrap_or(0)
        };
        line(&mut dump, bits - 1);
        line(&mut dump, bits);
        line(&mut dump, bits + 1);
    }
    for exponent in -330_i32..=310 {
        for mantissa in SWEEP_MANTISSAS {
            if let Ok(f) = format!("{mantissa}e{exponent}").parse::<f64>() {
                line(&mut dump, f.to_bits());
            }
        }
    }
    let mut state = LCG_SEED;
    for _ in 0..LCG_COUNT {
        state = state
            .wrapping_mul(LCG_MULTIPLIER)
            .wrapping_add(LCG_INCREMENT);
        line(&mut dump, state);
    }
    super::write(out, &dump)
}
