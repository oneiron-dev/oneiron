//! PAGE-FULL probe (lane branch only, never merged): settlement seed 0 alone,
//! PF_RUNS times (default 20) on a fresh vault each, in one test thread.

use oneiron_testkit::model::Universe;
use oneiron_testkit::model::engine::check_sequence;
use oneiron_testkit::model::generator::sequence;

#[test]
fn settlement_seed_zero_alone() {
    let universe = Universe {
        persons: 3,
        ..Universe::default()
    };
    let steps = sequence(0, 40, &universe);
    for (index, step) in steps.iter().enumerate().take(16) {
        eprintln!("## PF-STEP {index} {step:?}");
    }
    let runs: usize = std::env::var("PF_RUNS")
        .ok()
        .and_then(|text| text.parse().ok())
        .unwrap_or(20);
    let mut failed = 0;
    for run in 0..runs {
        match check_sequence(0, &steps, &universe) {
            Ok(()) => eprintln!("## PF-RUN {run} ok"),
            Err(error) => {
                failed += 1;
                eprintln!("## PF-RUN {run} FAILED {error}");
            }
        }
    }
    eprintln!("## PF-ALONE runs={runs} failed={failed}");
}
