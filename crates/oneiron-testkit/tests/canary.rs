//! The canary leak detector, step 1: each audience class seeded through
//! public verbs reaches the readers in its audience, and no reader outside
//! it finds its word on any surface it reaches.

use oneiron_testkit::TestVault;
use oneiron_testkit::canary::{
    CanaryActor, CanaryClass, CanaryScan, CanaryVault, ClaimBand, NEUTRAL_PHRASE, PENDING,
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

// Step 2, not written here: an in-process Dreamer pass over this vault.
// `DreamerWakeDriver::run_wake_pass` is async and this crate has no executor
// dependency; the host `DreamerAttemptExecutor` adapter must build a
// per-attempt `PromotionWriterSink` and forward to a `ConsolidationExecutor`
// over the scripted backend with a `HostInferenceContext` and a
// `BudgetGuard`; and the scripted extraction reply needs the prompt digest a
// first run prints. Then rerun every no-leak test above after the pass, and
// `CanaryVault::scan_prompts` over `ScriptedBackend::seen()` with the
// actors each prompt's destination speaks for.
