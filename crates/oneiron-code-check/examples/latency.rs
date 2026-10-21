//! Check latency on the synthetic fixtures, per backend:
//! `cargo run --release -p oneiron-code-check --example latency [rounds]`.
//! Set `ONEIRON_TSC_ORACLE` to a pinned Microsoft `tsc` to time it as well.
//! Then larger programs: the correct fixture repeated in block scopes.

use oneiron_code_check::{
    CheckInput, CodeCheck, Declaration, MicrosoftTsc, TscRsBudget, TscRsWasm,
};
use std::time::{Duration, Instant};

const DECLARATIONS: [Declaration<'static>; 3] = [
    Declaration {
        name: "code-run.d.ts",
        text: include_str!("../../oneiron/wit/generated/code-run.d.ts"),
    },
    Declaration {
        name: "code-mode.d.ts",
        text: include_str!("../../oneiron/src/verbs/generated/code-mode.d.ts"),
    },
    Declaration {
        name: "runtime.d.ts",
        text: include_str!("../../../components/code-run-quickjs/runtime.d.ts"),
    },
];

const FIXTURES: [(&str, &str); 7] = [
    (
        "01-correct",
        include_str!("../tests/fixtures/01-correct.js"),
    ),
    (
        "02-wrong-verb",
        include_str!("../tests/fixtures/02-wrong-verb.js"),
    ),
    (
        "03-wrong-argument",
        include_str!("../tests/fixtures/03-wrong-argument.js"),
    ),
    (
        "04-missing-await",
        include_str!("../tests/fixtures/04-missing-await.js"),
    ),
    (
        "05-undefined-path",
        include_str!("../tests/fixtures/05-undefined-path.js"),
    ),
    (
        "06-floating-promise",
        include_str!("../tests/fixtures/06-floating-promise.js"),
    ),
    (
        "07-any-null-path",
        include_str!("../tests/fixtures/07-any-null-path.js"),
    ),
];

fn percentile(sorted: &[Duration], quantile: usize) -> f64 {
    let at = (sorted.len() * quantile).div_ceil(100).saturating_sub(1);
    sorted[at].as_secs_f64() * 1000.0
}

fn time(label: &str, checker: &dyn CodeCheck, rounds: usize) {
    let mut all = Vec::new();
    let mut peak = 0;
    for (name, program) in FIXTURES {
        let mut samples = Vec::with_capacity(rounds);
        for _ in 0..rounds {
            let started = Instant::now();
            let report = checker
                .check(&CheckInput {
                    declarations: &DECLARATIONS,
                    program,
                })
                .unwrap_or_else(|failure| panic!("{name}: {failure}"));
            samples.push(started.elapsed());
            peak = peak.max(report.peak_memory_bytes.unwrap_or(0));
        }
        samples.sort_unstable();
        println!(
            "{label} {name}: p50 {:.2} ms, p95 {:.2} ms",
            percentile(&samples, 50),
            percentile(&samples, 95)
        );
        all.extend(samples);
    }
    all.sort_unstable();
    println!(
        "{label} all {} checks: p50 {:.2} ms, p95 {:.2} ms, max {:.2} ms, peak memory {} MiB",
        all.len(),
        percentile(&all, 50),
        percentile(&all, 95),
        percentile(&all, 100),
        peak >> 20
    );
}

/// The correct fixture `copies` times over, each copy in its own block.
fn scaled(copies: usize) -> String {
    let body = FIXTURES[0].1;
    (0..copies).map(|_| format!("{{\n{body}}}\n")).collect()
}

fn time_scaled(label: &str, checker: &dyn CodeCheck, rounds: usize) {
    for copies in [10, 100, 1000] {
        let program = scaled(copies);
        let mut samples = Vec::with_capacity(rounds);
        for _ in 0..rounds {
            let started = Instant::now();
            let report = checker
                .check(&CheckInput {
                    declarations: &DECLARATIONS,
                    program: &program,
                })
                .unwrap_or_else(|failure| panic!("{copies} copies: {failure}"));
            samples.push(started.elapsed());
            assert!(report.diagnostics.is_empty(), "{copies} copies");
        }
        samples.sort_unstable();
        println!(
            "{label} {} lines: p50 {:.2} ms, p95 {:.2} ms",
            program.lines().count(),
            percentile(&samples, 50),
            percentile(&samples, 95)
        );
    }
}

fn main() {
    let rounds = std::env::args()
        .nth(1)
        .map_or(30, |rounds| rounds.parse().expect("rounds"));
    let started = Instant::now();
    let tsc_rs = TscRsWasm::load(TscRsBudget::default()).expect("tsc-rs module");
    println!(
        "tsc-rs load (pin check + Wasmtime compile): {:.2} s",
        started.elapsed().as_secs_f64()
    );
    time("tsc-rs", &tsc_rs, rounds);
    let microsoft = std::env::var_os("ONEIRON_TSC_ORACLE")
        .map(|tsc| MicrosoftTsc::new(tsc).expect("pinned Microsoft tsc"));
    if let Some(microsoft) = &microsoft {
        time("microsoft", microsoft, rounds);
    }
    let rounds = rounds.div_ceil(3);
    time_scaled("tsc-rs", &tsc_rs, rounds);
    if let Some(microsoft) = &microsoft {
        time_scaled("microsoft", microsoft, rounds);
    }
}
