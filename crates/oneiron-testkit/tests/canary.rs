//! The canary leak detector, step 1: each audience class seeded through
//! public verbs reaches the readers in its audience, and no reader outside
//! it finds its word on any surface it reaches.

use oneiron::{DreamerAttemptExecution, DreamerParkCause, EntityId};
use oneiron_testkit::TestVault;
use oneiron_testkit::canary::{
    CanaryActor, CanaryClass, CanaryScan, CanaryVault, ClaimBand, NEUTRAL_PHRASE, PENDING,
};
use oneiron_testkit::dreamer::{
    DreamerAttemptRun, DreamerPass, DreamerPassError, DreamerPassReport, allow_scripted_extraction,
    attach_test_host, grant_dreamer_read, print_seen, read_everything_scope, scripted_backend,
};
use oneiron_testkit::provider::SeenCall;
use serde_json::json;

fn seeded() -> (TestVault, CanaryVault) {
    CanaryVault::seeded("canary-audiences").expect("the canary fixture seeds through public doors")
}

#[test]
fn every_feasible_audience_class_holds_one_unique_canary_and_no_pending_class_is_seeded() {
    let (_vault, canaries) = seeded();
    let classes: Vec<CanaryClass> = canaries
        .canaries()
        .iter()
        .map(|canary| canary.class)
        .collect();
    assert_eq!(classes, CanaryClass::SEEDED.to_vec());
    let mut words: Vec<&str> = canaries
        .canaries()
        .iter()
        .map(|canary| canary.word.as_str())
        .collect();
    words.sort_unstable();
    words.dedup();
    assert_eq!(
        words.len(),
        canaries.canaries().len(),
        "every canary word is unique"
    );
    for canary in canaries.canaries() {
        assert!(
            canary.word.starts_with("canary")
                && canary
                    .word
                    .chars()
                    .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit()),
            "{} is one token of lower-case letters and digits",
            canary.word
        );
        assert!(
            canary.text.contains(NEUTRAL_PHRASE),
            "{} carries the shared phrase",
            canary.class
        );
        assert!(
            !canary.audience.is_empty(),
            "{} has an audience",
            canary.class
        );
    }
    for pending in PENDING {
        assert!(
            !pending.reason.is_empty(),
            "{} says why it is pending",
            pending.name
        );
        assert!(
            CanaryClass::SEEDED
                .iter()
                .all(|class| class.name() != pending.name),
            "{} is both seeded and pending",
            pending.name
        );
    }
}

#[test]
fn an_agent_granted_only_public_rows_reads_no_canary_outside_its_audience() {
    let (test_vault, canaries) = seeded();
    let vault = test_vault.open_owned().expect("open the seeded vault");
    let scan = canaries.assert_no_canary_leak(&vault, CanaryActor::Outside);
    // A clean scan of a reader that reads nothing proves nothing: its Grant
    // must confer, so it reads the public-band claim.
    let public = canaries.surfaces_seeing(&scan, CanaryClass::Claim(ClaimBand::Public));
    assert!(
        !public.is_empty(),
        "the outside agent's public-band Grant confers on no surface; refused: {:#?}",
        scan.refused
    );
    assert!(scan.incomplete.is_empty(), "{:?}", scan.incomplete);
}

#[test]
fn an_agent_granted_every_band_reads_no_other_actors_diary() {
    let (test_vault, canaries) = seeded();
    let vault = test_vault.open_owned().expect("open the seeded vault");
    let scan = canaries.assert_no_canary_leak(&vault, CanaryActor::Inside);
    let restricted = canaries.surfaces_seeing(&scan, CanaryClass::Claim(ClaimBand::Restricted));
    assert!(
        !restricted.is_empty(),
        "the inside agent's every-band Grant confers on no surface; refused: {:#?}",
        scan.refused
    );
    assert!(scan.incomplete.is_empty(), "{:?}", scan.incomplete);
}

#[test]
fn the_vault_owner_reads_no_agents_diary() {
    let (test_vault, canaries) = seeded();
    let vault = test_vault.open_owned().expect("open the seeded vault");
    let scan = canaries.assert_no_canary_leak(&vault, CanaryActor::Owner);
    assert!(scan.incomplete.is_empty(), "{:?}", scan.incomplete);
}

#[test]
fn every_seeded_class_reaches_a_reader_in_its_audience() {
    let (test_vault, canaries) = seeded();
    let vault = test_vault.open_owned().expect("open the seeded vault");
    let scans: Vec<CanaryScan> = CanaryActor::ALL
        .iter()
        .map(|actor| canaries.scan(&vault, *actor))
        .collect();
    for sighting in canaries.assert_not_blind(&scans) {
        println!("{} seen by {:?}", sighting.class, sighting.seen_by);
    }
}

#[test]
fn the_detector_names_each_canary_that_reaches_a_reader_outside_its_audience() {
    let (test_vault, canaries) = seeded();
    let vault = test_vault.open_owned().expect("open the seeded vault");

    // The owner reads its own canaries. Declared outside every audience, it
    // must be reported for them, one line each, surface named.
    let owner = canaries.scan(&vault, CanaryActor::Owner);
    let lines = canaries.excluding(CanaryActor::Owner).leaks(&owner);
    for class in [
        CanaryClass::Diary(CanaryActor::Owner),
        CanaryClass::OwnerKeyValue,
        CanaryClass::Claim(ClaimBand::Restricted),
    ] {
        let head = format!("LEAK: {class} canary {} reached owner via ", class.word());
        assert!(
            lines.iter().any(|line| line.starts_with(&head)),
            "no line starting `{head}` in:\n{}",
            lines.join("\n")
        );
    }
    // The assertion every leak test relies on fails on that same scan: it
    // panics, never returns the scan. (The panic it prints here is expected.)
    let narrowed = canaries.excluding(CanaryActor::Owner);
    let asserted = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        narrowed.assert_no_canary_leak(&vault, CanaryActor::Owner)
    }));
    assert!(
        asserted.is_err(),
        "assert_no_canary_leak returned the scan of a reader that read canaries outside its audience"
    );

    // A prompt is a surface too: the outside agent's diary sent to a model
    // that speaks for the owner leaks it; sent for the outside agent, not.
    let diary = CanaryClass::Diary(CanaryActor::Outside);
    let call = SeenCall {
        step: Some("canary-prompt".to_owned()),
        method: "generate".to_owned(),
        path: String::new(),
        digest: None,
        streamed: false,
        model: None,
        body: json!({"messages": [{"role": "user", "content": [{"type": "text", "text": diary.text()}]}]}),
    };
    let prompt_leaks = canaries.scan_prompts(std::slice::from_ref(&call), &[CanaryActor::Owner]);
    assert_eq!(prompt_leaks.len(), 1, "{prompt_leaks:#?}");
    let head = format!(
        "LEAK: {diary} canary {} reached owner via prompt 0 (step canary-prompt): ",
        diary.word()
    );
    assert!(prompt_leaks[0].starts_with(&head), "{}", prompt_leaks[0]);
    assert!(
        canaries
            .scan_prompts(&[call], &[CanaryActor::Outside])
            .is_empty()
    );
}

/// The turn wake's model calls over the canary vault, as `(prompt digest,
/// reply)` (see tests/dreamer.rs for how a table is filled). The turn wake
/// reads the newest owner turn, the relationship message, with the
/// private-flag claim listed beside it, and its reply proposes no claim. A
/// claim extracted from that message inherits its relationship set
/// (dreamer_consolidation/executor/extraction.rs), and a relationship-stamped
/// claim lands only over a live RELATIONSHIP row, which no public door mints
/// (the pending class `claim/relationship`). The rescan of a row the pass
/// derived waits for that door. Even with no claim proposed, the attempt
/// parks ([`turn_wake_outcome`]).
const DREAMER_TURN_WAKE_CALLS: &[(&str, &str)] = &[(
    "04e5a959f9218289a8ba88ec259eec11a090a694637349ccfcb1103f73d527c2",
    r#"{"candidates":[],"persons":[]}"#,
)];

/// The Timer wake's model calls over the canary vault, after the turn wake.
const DREAMER_TIMER_WAKE_CALLS: &[(&str, &str)] = &[];

/// The turn wake's outcome over the canary vault. The relationship message's
/// micro consolidation parks for a retry after its extraction call, on
/// "invalid active relationship" for the canary relationship space, even
/// when the reply proposes no claim. The witness took that space as the
/// message's `rel`, but no RELATIONSHIP row has its id (FIX row
/// MESSAGE-REL-NOT-RELATIONSHIP-ROW). So the Dreamer never finishes that
/// message. That park, and no other unfinished work, is the outcome this
/// test expects. A turn wake that finishes means the engine has changed:
/// drop this park.
fn turn_wake_outcome(
    pass: Result<DreamerPassReport, DreamerPassError>,
    space: EntityId,
) -> Result<DreamerPassReport, String> {
    let report = match pass {
        Err(DreamerPassError::Unfinished(report)) => report,
        Ok(_) => {
            return Err(format!(
                "finished, so the relationship message's micro consolidation no longer parks \
                 on the canary relationship space {}: FIX row MESSAGE-REL-NOT-RELATIONSHIP-ROW \
                 has moved; drop the expected park in turn_wake_outcome",
                space.to_hex()
            ));
        }
        Err(error) => return Err(error.to_string()),
    };
    let known = format!("invalid active relationship {}: ", space.to_hex());
    let parked: Vec<&DreamerAttemptRun> = report
        .attempts
        .iter()
        .filter(|attempt| {
            !attempt.unlent
                && matches!(
                    attempt.execution,
                    Ok(DreamerAttemptExecution::Park { .. }
                        | DreamerAttemptExecution::ParkWithSpend { .. })
                )
        })
        .collect();
    let expected = match parked.as_slice() {
        [only] => {
            only.attempt_type == "micro"
                && matches!(
                    &only.execution,
                    Ok(DreamerAttemptExecution::ParkWithSpend {
                        reason,
                        cause: DreamerParkCause::Retry,
                        ..
                    }) if reason.starts_with(&known)
                )
        }
        _ => false,
    };
    if expected && report.unfinished() == ["1 attempt(s) parked"] {
        Ok(*report)
    } else {
        Err(DreamerPassError::Unfinished(report).to_string())
    }
}

#[test]
fn a_dreamer_pass_sends_the_model_no_agents_diary_and_leaks_no_canary() {
    let (test_vault, canaries) = seeded();
    let vault = test_vault.open_owned().expect("open the seeded vault");
    attach_test_host(&vault).expect("the test host attaches after the open");
    allow_scripted_extraction(&vault).expect("the owner lets extraction run on the scripted model");
    grant_dreamer_read(&vault, read_everything_scope())
        .expect("the owner grants the Dreamer its reads");

    let turn = scripted_backend("canary-turn-wake", DREAMER_TURN_WAKE_CALLS);
    let turn_pass = DreamerPass::new(&turn)
        .with_run_id("canary-turn-wake")
        .run_turn_wake(&vault, test_vault.clock());
    print_seen(&turn.seen());
    let timer = scripted_backend("canary-timer-wake", DREAMER_TIMER_WAKE_CALLS);
    let timer_pass = DreamerPass::new(&timer)
        .with_run_id("canary-timer-wake")
        .run_timer_wake(&vault, test_vault.clock());
    print_seen(&timer.seen());
    // Both wakes run before either script is checked, so one run names every
    // call a table misses.
    let mut prompts = turn.finish();
    prompts.extend(timer.finish());
    // Either pass's error names the other's outcome too.
    let turn_pass = turn_wake_outcome(turn_pass, canaries.space());
    let (turn_report, timer_report) = match (turn_pass, timer_pass) {
        (Ok(turn), Ok(timer)) => (turn, timer),
        (turn, timer) => panic!(
            "turn wake: {}\ntimer wake: {}",
            turn.err()
                .unwrap_or_else(|| "parked as expected".to_owned()),
            timer.map_or_else(|error| error.to_string(), |_| "finished".to_owned()),
        ),
    };
    for report in [&turn_report, &timer_report] {
        println!(
            "## DREAMER {:?} wake: {} claim(s) landed in {} ms; queue after it: {:?}",
            report.wake,
            report.landed().len(),
            report.wall_ms,
            report.queue
        );
        for attempt in &report.attempts {
            println!(
                "## DREAMER {:?} wake ran {} {} in {} ms (unlent: {}): {:?}",
                report.wake,
                attempt.attempt_type,
                attempt.attempt_id,
                attempt.wall_ms,
                attempt.unlent,
                attempt.execution
            );
        }
    }

    // The Dreamer's model speaks for the owner, so a prompt may carry what
    // the owner may read and never an agent's diary.
    let prompt_leaks = canaries.scan_prompts(&prompts, &[CanaryActor::Owner]);
    assert!(prompt_leaks.is_empty(), "{}", prompt_leaks.join("\n"));
    // The positive control: the prompts did carry restricted canaries, and
    // the scan names each one once the owner is outside its audience.
    let carried = canaries
        .excluding(CanaryActor::Owner)
        .scan_prompts(&prompts, &[CanaryActor::Owner]);
    for class in [
        CanaryClass::RelationshipMessage,
        CanaryClass::PrivateFlagClaim,
    ] {
        let head = format!("LEAK: {class} canary ");
        assert!(
            carried.iter().any(|line| line.starts_with(&head)),
            "the Dreamer's prompts carried no {class} canary, so the prompt scan proves nothing for it:\n{}",
            carried.join("\n")
        );
    }

    // What the passes wrote reaches no reader outside a canary's audience.
    for actor in CanaryActor::ALL {
        let scan = canaries.assert_no_canary_leak(&vault, actor);
        assert!(scan.incomplete.is_empty(), "{actor}: {:?}", scan.incomplete);
    }
}
