//! Pure public-API checks for bound extraction conflict decisions.

use oneiron_dreamer::conflict_decisions::{
    AnsweredPack, DecisionAnswer, DecisionEntry, EarlierAnswer, Error, ExtractionCorrectionPair,
    ExtractionLayout, ExtractionPack, ExtractionPart, Input, Resolution, ResolutionInput, Step,
    correction, correction_pages, correction_step, read_answers, read_layout, resolution,
    resolution_final, resolution_pages, resolution_step,
};
use oneiron_dreamer::extraction_observations::Observations;
use oneiron_dreamer::extraction_routing::JudgeSet;
use serde_json::{Value, json};

fn next_pack<T>(step: Step<T>) -> ExtractionPack {
    match step {
        Step::Ask(pack) => pack,
        Step::Finished(_) => panic!("expected the next pack"),
    }
}
fn fixture() -> Value {
    serde_json::from_str(include_str!("fixtures/conflict_decisions.json")).expect("fixture parses")
}
fn claim_hex(position: usize) -> String {
    format!("{position:032x}")
}
fn operands(count: usize) -> Vec<Value> {
    (0..count)
        .map(|position| json!({"position": position}))
        .collect()
}
fn judge_set(members: Vec<usize>, priors: Vec<String>) -> JudgeSet {
    JudgeSet {
        candidate_indexes: members,
        identity_token: "identity".into(),
        prior_head: (priors.len() == 1).then(|| priors[0].clone()),
        prior_heads: priors,
    }
}
fn choice_entry(key: Vec<String>, answer: &str, probability: Option<f64>) -> DecisionEntry {
    DecisionEntry {
        key,
        answer: DecisionAnswer::Choice(answer.into()),
        p: probability,
        rung: Some("big".into()),
        question: claim_hex(0x999),
        receipt: json!({}),
    }
}
fn abstain_entry(key: Vec<String>) -> DecisionEntry {
    DecisionEntry {
        key,
        answer: DecisionAnswer::Abstain,
        p: None,
        rung: None,
        question: claim_hex(0x999),
        receipt: json!({}),
    }
}
fn answered_pack(pack: &ExtractionPack, entries: Vec<DecisionEntry>) -> AnsweredPack {
    AnsweredPack {
        pack: pack.clone(),
        entries,
    }
}
fn single_choice_answered(
    pack: &ExtractionPack,
    answer: &str,
    probability: Option<f64>,
) -> AnsweredPack {
    let pack_key = pack.questions[0].key.clone();
    answered_pack(pack, vec![choice_entry(pack_key, answer, probability)])
}
fn resolution_answered(pack: &ExtractionPack, resolution: &str, identity: &str) -> AnsweredPack {
    let resolution_key = pack.questions[0].key.clone();
    let identity_key = pack.questions[1].key.clone();
    let resolution_entry = choice_entry(resolution_key, resolution, Some(0.9));
    let identity_entry = choice_entry(identity_key, identity, Some(0.9));
    answered_pack(pack, vec![resolution_entry, identity_entry])
}
fn input<'a>(candidates: &'a [Value], observations: &'a Observations) -> Input<'a> {
    Input {
        candidates,
        observations,
    }
}
fn resolution_input<'a>(
    candidates: &'a [Value],
    observations: &'a Observations,
    judge_set: &'a JudgeSet,
) -> ResolutionInput<'a> {
    ResolutionInput {
        input: input(candidates, observations),
        set: judge_set,
    }
}
fn page_resolution_answer(page: usize, answer: &str) -> EarlierAnswer {
    EarlierAnswer {
        key: vec!["resolution".into(), "page".into(), page.to_string()],
        answer: answer.into(),
    }
}
fn correction_pair(candidate: usize, listed: usize) -> ExtractionCorrectionPair {
    ExtractionCorrectionPair { candidate, listed }
}
fn correction_layout(pages: Vec<Vec<ExtractionCorrectionPair>>) -> ExtractionLayout {
    ExtractionLayout::CorrectionPages { pages }
}
fn resolution_layout(pages: Vec<Vec<usize>>) -> ExtractionLayout {
    ExtractionLayout::ResolutionPages { pages }
}
fn case_observations(fixture_data: &Value, case_name: &str) -> Observations {
    serde_json::from_value(fixture_data[case_name].clone()).expect("case decodes")
}

#[test]
fn correction_initial_packs() {
    let fixture_data = fixture();
    let single_observations = case_observations(&fixture_data, "single_correction");
    let single_operands = operands(1);
    let single_input = input(&single_operands, &single_observations);
    let single_pack = correction(single_input, None).expect("single builds");
    assert_eq!(single_pack.questions.len(), 1); // native: crates/oneiron/src/dreamer_consolidation/executor/extraction/corrections.rs:80 one choice per group
    let single_question = &single_pack.questions[0];
    assert_eq!(single_question.key, ["0", "0"]); // native: crates/oneiron/src/dreamer_consolidation/executor/extraction/corrections.rs:36 position and group decimal
    let single_options = &single_question.options;
    assert_eq!(single_options, &["none".to_string(), claim_hex(0x100)]); // native: crates/oneiron/src/dreamer_consolidation/executor/extraction/corrections.rs:88 every group offers none
    let mut sixty_four_listed = Vec::new();
    for listed_position in 0..64 {
        let mut listed_value = fixture_data["listed"].clone();
        listed_value["claim"] = json!(claim_hex(0x100 + listed_position));
        listed_value["version"]["entity"] = json!(claim_hex(0x100 + listed_position));
        sixty_four_listed.push(listed_value);
    }
    let mut sixty_four_candidate = fixture_data["candidate"].clone();
    sixty_four_candidate["index"] = json!(0);
    sixty_four_candidate["claim"] = json!(claim_hex(1));
    sixty_four_candidate["correctable"] = json!((0..64).collect::<Vec<usize>>());
    let sixty_four_observations: Observations = serde_json::from_value(json!({"attempt": fixture_data["attempt"], "now_ms": fixture_data["now_ms"], "policy_pin": fixture_data["policy_pin"], "facts_pin": fixture_data["facts_pin"], "candidates": [sixty_four_candidate], "listed": sixty_four_listed, "priors": [], "replay": [], "scores": []})).expect("sixty four decodes");
    let sixty_four_input = input(&single_operands, &sixty_four_observations);
    let sixty_four_pack = correction(sixty_four_input, None).expect("sixty four builds");
    assert_eq!(sixty_four_pack.questions.len(), 2); // native: crates/oneiron/src/dreamer_consolidation/executor/decisions.rs:234 splits at sixty three per question
    assert_eq!(sixty_four_pack.questions[0].options.len(), 64); // native: crates/oneiron/src/dreamer_consolidation/executor/decisions.rs:230 none plus sixty three; total over sixty three forces none in all groups
    assert_eq!(
        sixty_four_pack.questions[1].options,
        ["none".to_owned(), claim_hex(0x13f)]
    ); // native: crates/oneiron/src/dreamer_consolidation/executor/decisions.rs:230-244 second group keeps none and its final listed ID
    let two_listed_observations = case_observations(&fixture_data, "two_listed_correction");
    let two_listed_input = input(&single_operands, &two_listed_observations);
    let first_page = vec![correction_pair(0, 0)];
    let second_page = vec![correction_pair(0, 1)];
    let two_page_layout = correction_layout(vec![first_page, second_page]);
    let decoded_pages = correction_pages(&two_page_layout).expect("pages decode");
    let page_pack = correction(two_listed_input, Some(&decoded_pages[0])).expect("page builds");
    assert_eq!(page_pack.questions[0].key, ["0", "0", "page", "0"]); // native: crates/oneiron/src/dreamer_consolidation/executor/extraction/corrections.rs:45 page marker and number
    assert_eq!(
        page_pack.questions[0].options,
        ["none".to_owned(), claim_hex(0x100)]
    ); // native: crates/oneiron/src/dreamer_consolidation/executor/extraction/corrections.rs:55-100 exactly the page's listed IDs
}

#[test]
fn resolution_initial_packs() {
    let fixture_data = fixture();
    let candidate_operands = operands(2);
    let same_observations = case_observations(&fixture_data, "two_candidate_same_with_prior");
    let same_judge_set = judge_set(vec![0, 1], vec![claim_hex(0x200)]);
    let same_input = resolution_input(&candidate_operands, &same_observations, &same_judge_set);
    let same_pack = resolution(same_input, None).expect("same builds");
    let resolution_question = &same_pack.questions[0];
    let identity_question = &same_pack.questions[1];
    assert_eq!(resolution_question.key, ["resolution"]); // native: crates/oneiron/src/dreamer_consolidation/executor/merge_resolution.rs:51 resolution marker whole
    assert_eq!(
        resolution_question.options,
        ["merge", "supersede", "accumulate", "escalate"]
    ); // native: crates/oneiron/src/dreamer_consolidation/executor/merge_resolution.rs:27 resolutions order
    assert_eq!(identity_question.key, ["identity", "0"]); // native: crates/oneiron/src/dreamer_consolidation/executor/merge_resolution.rs:63 identity marker and group
    let same_options = &identity_question.options;
    assert_eq!(same_options, &["none", "candidate:0", "candidate:1"]); // native: crates/oneiron/src/dreamer_consolidation/executor/merge_resolution.rs:412 same predicate offers none
    let cross_observations = case_observations(&fixture_data, "two_candidate_cross");
    let cross_judge_set = judge_set(vec![0, 1], vec![]);
    let cross_input = resolution_input(&candidate_operands, &cross_observations, &cross_judge_set);
    let cross_pack = resolution(cross_input, None).expect("cross builds");
    let cross_options = &cross_pack.questions[1].options;
    assert_eq!(cross_options, &["candidate:0", "candidate:1"]); // native: crates/oneiron/src/dreamer_consolidation/executor/merge_resolution.rs:412 cross whole offers no none
    let paged_layout = resolution_layout(vec![vec![0], vec![1]]);
    let decoded_pages = resolution_pages(&paged_layout).expect("pages decode");
    let paged_input = resolution_input(&candidate_operands, &cross_observations, &cross_judge_set);
    let paged_pack = resolution(paged_input, Some(&decoded_pages[0])).expect("paged builds");
    assert_eq!(paged_pack.questions[0].key, ["resolution", "page", "0"]); // native: crates/oneiron/src/dreamer_consolidation/executor/merge_resolution.rs:51 paged keys page number
    let paged_options = &paged_pack.questions[1].options;
    assert_eq!(paged_options, &["none", "candidate:0"]); // native: crates/oneiron/src/dreamer_consolidation/executor/merge_resolution.rs:387 paged offers none
}

#[test]
fn resolution_final_and_standing() {
    let fixture_data = fixture();
    let candidate_operands = operands(2);
    let listed_observations = case_observations(&fixture_data, "two_candidate_same_with_prior");
    let listed_judge_set = judge_set(vec![0, 1], vec![claim_hex(0x200)]);
    let listed_input =
        resolution_input(&candidate_operands, &listed_observations, &listed_judge_set);
    let first_earlier = page_resolution_answer(0, "merge");
    let second_earlier = page_resolution_answer(1, "accumulate");
    let third_earlier = page_resolution_answer(2, "merge");
    let distinct_earlier = [first_earlier, second_earlier, third_earlier];
    let distinct_result = resolution_final(listed_input, &distinct_earlier).expect("final builds");
    let distinct_pack = distinct_result.expect("some final");
    assert_eq!(distinct_pack.questions[0].key, ["resolution", "final"]); // native: crates/oneiron/src/dreamer_consolidation/executor/merge_resolution.rs:78 final marker
    let distinct_options = &distinct_pack.questions[0].options;
    assert_eq!(distinct_options, &["merge", "accumulate"]); // native: crates/oneiron/src/dreamer_consolidation/executor/merge_resolution.rs:37 distinct first-seen order; Final zero follows read kind per finals.rs:234
    let mut standing_earlier = distinct_earlier[..2].to_vec();
    standing_earlier[1].answer = "merge".into();
    let unanimous_result = resolution_final(listed_input, &standing_earlier).expect("checked");
    assert!(unanimous_result.is_none()); // native: crates/oneiron/src/dreamer_consolidation/extraction_pack/finals.rs:275 unanimous reads no final
    standing_earlier[1].answer = "escalate".into();
    let escalated_result = resolution_final(listed_input, &standing_earlier).expect("checked");
    assert!(escalated_result.is_none()); // native: crates/oneiron/src/dreamer_consolidation/extraction_pack/finals.rs:267 escalate reads no final
    let paged_layout = resolution_layout(vec![vec![0], vec![1]]);
    let decoded_pages = resolution_pages(&paged_layout).expect("pages decode");
    let page_zero_pack =
        resolution(listed_input, Some(&decoded_pages[0])).expect("page zero builds");
    let page_one_pack = resolution(listed_input, Some(&decoded_pages[1])).expect("page one builds");
    let page_zero_answered = resolution_answered(&page_zero_pack, "merge", "none");
    let page_one_resolution_key = page_one_pack.questions[0].key.clone();
    let page_one_identity_key = page_one_pack.questions[1].key.clone();
    let page_one_resolution_entry = abstain_entry(page_one_resolution_key);
    let page_one_identity_entry = choice_entry(page_one_identity_key, "none", Some(0.5));
    let page_one_answered = answered_pack(
        &page_one_pack,
        vec![page_one_resolution_entry, page_one_identity_entry],
    );
    let standing_history = [page_zero_answered, page_one_answered];
    let standing_step =
        resolution_step(listed_input, Some(&paged_layout), &standing_history).expect("reduces");
    match standing_step {
        Step::Finished(conflict_decision) => {
            assert_eq!(conflict_decision.resolution, Resolution::NoStandingAnswer); // native: crates/oneiron/src/dreamer_consolidation/executor/merge_resolution.rs:247 paged absence leaves no standing answer
            let decisions = &conflict_decision.decisions;
            assert!(
                decisions
                    .iter()
                    .any(|entry| entry.answer == DecisionAnswer::Abstain)
            ); // native: crates/oneiron/src/dreamer_runner/attempt_binding/extraction_execution.rs:88 actual abstain stays in trace
        }
        Step::Ask(_) => panic!("abstained pages ask no final"),
    }
}

#[test]
fn identity_final_second_round() {
    let fixture_data = fixture();
    let mut paged_candidates = Vec::new();
    for candidate_position in 0..64 {
        let mut candidate_value = fixture_data["candidate"].clone();
        candidate_value["index"] = json!(candidate_position);
        candidate_value["claim"] = json!(claim_hex(candidate_position + 1));
        paged_candidates.push(candidate_value);
    }
    let paged_observations: Observations = serde_json::from_value(json!({"attempt": fixture_data["attempt"], "now_ms": fixture_data["now_ms"], "policy_pin": fixture_data["policy_pin"], "facts_pin": fixture_data["facts_pin"], "candidates": paged_candidates, "listed": [], "priors": [], "replay": [], "scores": []})).expect("paged observations decode");
    let paged_operands = operands(64);
    let paged_judge_set = judge_set((0..64).collect(), vec![]);
    let paged_input = resolution_input(&paged_operands, &paged_observations, &paged_judge_set);
    let paged_pages: Vec<Vec<usize>> = (0..64)
        .map(|candidate_position| vec![candidate_position])
        .collect();
    let paged_layout = resolution_layout(paged_pages);
    let decoded_pages = resolution_pages(&paged_layout).expect("sixty four pages decode");
    let mut initial_history = Vec::new();
    for decoded_page in &decoded_pages {
        let page_pack = resolution(paged_input, Some(decoded_page)).expect("page pack builds");
        let member_claim = claim_hex(decoded_page.entries[0] + 1);
        initial_history.push(resolution_answered(&page_pack, "merge", &member_claim));
    }
    let first_step =
        resolution_step(paged_input, Some(&paged_layout), &initial_history).expect("asks");
    let first_round_pack = next_pack(first_step);
    assert_eq!(first_round_pack.questions.len(), 2); // native: crates/oneiron/src/dreamer_consolidation/executor/decisions.rs:234 sixty four shortlist splits into two groups
    assert_eq!(first_round_pack.questions[0].options.len(), 64); // native: crates/oneiron/src/dreamer_consolidation/executor/decisions.rs:230 multi-group round always offers none
    let first_group_key = first_round_pack.questions[0].key.clone();
    let second_group_key = first_round_pack.questions[1].key.clone();
    let first_entry = choice_entry(first_group_key, &claim_hex(1), Some(0.9));
    let second_entry = choice_entry(second_group_key, &claim_hex(64), Some(0.9));
    let first_round_answered = answered_pack(&first_round_pack, vec![first_entry, second_entry]);
    let mut second_history = initial_history;
    second_history.push(first_round_answered);
    let second_step =
        resolution_step(paged_input, Some(&paged_layout), &second_history).expect("asks");
    let second_round_pack = next_pack(second_step);
    let second_round_key = &second_round_pack.questions[0].key;
    assert_eq!(second_round_key, &["identity", "final", "2", "0"]); // native: crates/oneiron/src/dreamer_consolidation/executor/decisions/identity_choice.rs:80 second round increments round number
    let second_options = &second_round_pack.questions[0].options;
    assert_eq!(second_options, &["none", "candidate:0", "candidate:63"]); // native: crates/oneiron/src/dreamer_consolidation/executor/decisions/identity_choice.rs:201 next shortlist filters to prior shortlist
    assert_eq!(second_round_pack.earlier.len(), 66); // native: crates/oneiron/src/dreamer_consolidation/extraction_pack/finals.rs:65 earlier holds initial plus every earlier final round
    assert_eq!(second_round_pack.earlier[0].answer, "candidate:0"); // native: crates/oneiron/src/dreamer_consolidation/extraction_pack/finals.rs:65 initial earlier keeps candidate aliases in order
    assert_eq!(second_round_pack.earlier[63].answer, "candidate:63"); // native: crates/oneiron/src/dreamer_consolidation/extraction_pack/finals.rs:65 initial earlier keeps candidate aliases in order
    assert_eq!(second_round_pack.earlier[64].answer, "candidate:0"); // native: crates/oneiron/src/dreamer_consolidation/extraction_pack/finals.rs:65 round one earlier follows initial groups
    assert_eq!(second_round_pack.earlier[65].answer, "candidate:63"); // native: crates/oneiron/src/dreamer_consolidation/extraction_pack/finals.rs:65 round one earlier follows initial groups
}

#[test]
fn correction_identity_choice() {
    let fixture_data = fixture();
    let single_operands = operands(1);
    let single_observations = case_observations(&fixture_data, "single_correction");
    let single_input = input(&single_operands, &single_observations);
    let whole_pack = correction(single_input, None).expect("whole builds");
    let whole_step = correction_step(single_input, None, &[]).expect("whole asks first");
    assert_eq!(next_pack(whole_step).part, ExtractionPart::Whole); // native: crates/oneiron/src/dreamer_consolidation/extraction_pack/reads.rs:601 whole first
    let none_answered = single_choice_answered(&whole_pack, "none", Some(0.9));
    let none_history = [none_answered];
    let none_step = correction_step(single_input, None, &none_history).expect("zero reduces");
    match none_step {
        Step::Finished(corrections) => assert_eq!(corrections[0].corrects, None), // native: crates/oneiron/src/dreamer_consolidation/executor/decisions/identity_choice.rs:34 none names no identifier
        Step::Ask(_) => panic!("zero named asks no final"),
    }
    let single_answered = single_choice_answered(&whole_pack, &claim_hex(0x100), Some(0.9));
    let single_history = [single_answered];
    let single_step = correction_step(single_input, None, &single_history).expect("one reduces");
    match single_step {
        Step::Finished(corrections) => assert_eq!(corrections[0].corrects, Some(claim_hex(0x100))), // native: crates/oneiron/src/dreamer_consolidation/executor/decisions/identity_choice.rs:217 single keeps first named identifier
        Step::Ask(_) => panic!("one named asks no final"),
    }
    let two_listed_observations = case_observations(&fixture_data, "two_listed_correction");
    let two_listed_input = input(&single_operands, &two_listed_observations);
    let first_page = vec![correction_pair(0, 0)];
    let second_page = vec![correction_pair(0, 1)];
    let two_page_layout = correction_layout(vec![first_page, second_page]);
    let decoded_pages = correction_pages(&two_page_layout).expect("pages decode");
    let page_zero_pack =
        correction(two_listed_input, Some(&decoded_pages[0])).expect("page zero builds");
    let page_one_pack =
        correction(two_listed_input, Some(&decoded_pages[1])).expect("page one builds");
    for (first_probability, second_probability, expected_claim) in [
        (Some(0.6), Some(0.9), claim_hex(0x101)),
        (Some(0.5), Some(0.5), claim_hex(0x101)),
        (None, Some(0.5), claim_hex(0x101)),
    ] {
        let page_zero_answered =
            single_choice_answered(&page_zero_pack, &claim_hex(0x100), first_probability);
        let page_one_answered =
            single_choice_answered(&page_one_pack, &claim_hex(0x101), second_probability);
        let ask_history = [page_zero_answered.clone(), page_one_answered.clone()];
        let ask_step =
            correction_step(two_listed_input, Some(&two_page_layout), &ask_history).expect("asks");
        let first_round_pack = next_pack(ask_step);
        assert_eq!(first_round_pack.questions[0].key, ["0", "final", "1", "0"]); // native: crates/oneiron/src/dreamer_consolidation/extraction_pack/finals.rs:207 correction base is candidate position
        let first_round_options = &first_round_pack.questions[0].options;
        assert_eq!(
            first_round_options,
            &[String::from("none"), claim_hex(0x100), claim_hex(0x101)]
        ); // native: crates/oneiron/src/dreamer_consolidation/extraction_pack/finals.rs:29 shortlist keeps first-seen order
        let empty_answered = single_choice_answered(&first_round_pack, "none", Some(0.5));
        let fallback_history = [page_zero_answered, page_one_answered, empty_answered];
        let fallback_step =
            correction_step(two_listed_input, Some(&two_page_layout), &fallback_history)
                .expect("falls back");
        match fallback_step {
            Step::Finished(corrections) => {
                assert_eq!(corrections[0].corrects, Some(expected_claim))
            } // native: crates/oneiron/src/dreamer_consolidation/executor/decisions/identity_choice.rs:50 most probable; tie keeps last at :61; probability required at :55; no-probability still names at :30
            Step::Ask(_) => panic!("empty final is terminal"),
        }
    }
    let filter_zero_answered =
        single_choice_answered(&page_zero_pack, &claim_hex(0x100), Some(0.6));
    let filter_one_answered = single_choice_answered(&page_one_pack, &claim_hex(0x101), Some(0.9));
    let filter_history = [filter_zero_answered.clone(), filter_one_answered.clone()];
    let filter_step =
        correction_step(two_listed_input, Some(&two_page_layout), &filter_history).expect("asks");
    let filter_pack = next_pack(filter_step);
    let single_final_answered = single_choice_answered(&filter_pack, &claim_hex(0x100), Some(0.8));
    let reduce_history = [
        filter_zero_answered,
        filter_one_answered,
        single_final_answered,
    ];
    let reduce_step = correction_step(two_listed_input, Some(&two_page_layout), &reduce_history)
        .expect("reduces");
    match reduce_step {
        Step::Finished(corrections) => assert_eq!(corrections[0].corrects, Some(claim_hex(0x100))), // native: crates/oneiron/src/dreamer_consolidation/executor/decisions/identity_choice.rs:201 next shortlist filters to prior shortlist
        Step::Ask(_) => panic!("single after round finishes"),
    }
}

#[test]
fn correction_abstain_replays_none() {
    let fixture_data = fixture();
    let single_operands = operands(1);
    let three_observations = case_observations(&fixture_data, "three_listed_correction");
    let three_input = input(&single_operands, &three_observations);
    let three_first_page = vec![correction_pair(0, 0)];
    let three_second_page = vec![correction_pair(0, 1)];
    let three_third_page = vec![correction_pair(0, 2)];
    let three_layout =
        correction_layout(vec![three_first_page, three_second_page, three_third_page]);
    let three_pages = correction_pages(&three_layout).expect("three pages decode");
    let three_zero_pack =
        correction(three_input, Some(&three_pages[0])).expect("three zero builds");
    let three_one_pack = correction(three_input, Some(&three_pages[1])).expect("three one builds");
    let three_two_pack = correction(three_input, Some(&three_pages[2])).expect("three two builds");
    let three_zero_answered =
        single_choice_answered(&three_zero_pack, &claim_hex(0x100), Some(0.9));
    let three_one_answered = single_choice_answered(&three_one_pack, &claim_hex(0x101), Some(0.9));
    let three_two_key = three_two_pack.questions[0].key.clone();
    let three_two_answered = answered_pack(&three_two_pack, vec![abstain_entry(three_two_key)]);
    let three_history = [three_zero_answered, three_one_answered, three_two_answered];
    let three_step =
        correction_step(three_input, Some(&three_layout), &three_history).expect("abstain asks");
    match three_step {
        Step::Ask(pack) => assert_eq!(pack.earlier[2].answer, "none"), // native: crates/oneiron/src/dreamer_consolidation/executor/decisions.rs:38 abstain replays as canonical none where offered
        Step::Finished(_) => panic!("abstain with two named asks final"),
    }
}

#[test]
fn verdict_entries() {
    let fixture_data = fixture();
    let single_operands = operands(1);
    let single_observations = case_observations(&fixture_data, "single_correction");
    let single_input = input(&single_operands, &single_observations);
    let single_pack = correction(single_input, None).expect("pack builds");
    let pack_key = &single_pack.questions[0].key;
    let choice_verdict = json!({"pack": [{"key": pack_key, "answer": {"kind": "choice", "value": claim_hex(0x100)}, "p": 0.9, "rung": "big", "question": claim_hex(0x999), "receipt": {}}]});
    let choice_read = read_answers(&single_pack, choice_verdict).expect("choice decodes");
    let actual_answer = &choice_read.entries[0].answer;
    assert_eq!(actual_answer, &DecisionAnswer::Choice(claim_hex(0x100))); // native: crates/oneiron-store/src/model_decision/types.rs:107 tagged kind choice carries value
    let abstain_verdict = json!({"pack": [{"key": pack_key, "answer": {"kind": "abstain"}, "p": Value::Null, "rung": Value::Null, "question": claim_hex(0x999), "receipt": {}}]});
    let abstain_read = read_answers(&single_pack, abstain_verdict).expect("abstain decodes");
    assert_eq!(abstain_read.entries[0].answer, DecisionAnswer::Abstain); // native: crates/oneiron-store/src/model_decision/types.rs:107 tagged kind abstain carries no value
    let count_result = read_answers(&single_pack, json!({"pack": []}));
    assert!(matches!(count_result, Err(Error::Answers(_)))); // native: crates/oneiron/src/dreamer_runner/attempt_binding/extraction_execution.rs:88 one entry per pack question
    let wrong_key = json!({"pack": [{"key": ["9", "9"], "answer": {"kind": "choice", "value": claim_hex(0x100)}, "p": 0.9, "rung": "big", "question": claim_hex(0x999), "receipt": {}}]});
    let wrong_result = read_answers(&single_pack, wrong_key);
    assert!(matches!(wrong_result, Err(Error::Answers(_)))); // native: crates/oneiron/src/verbs/extraction_verdict.rs:164 keys follow pack order
}

#[test]
fn mapping_and_layout() {
    let fixture_data = fixture();
    let candidate_operands = operands(2);
    let same_observations = case_observations(&fixture_data, "two_candidate_same");
    let same_judge_set = judge_set(vec![0, 1], vec![]);
    let same_input = resolution_input(&candidate_operands, &same_observations, &same_judge_set);
    let same_pack = resolution(same_input, None).expect("pack builds");
    let resolution_key = same_pack.questions[0].key.clone();
    let identity_key = same_pack.questions[1].key.clone();
    let mut mapped_entry = choice_entry(identity_key.clone(), &claim_hex(1), Some(0.9));
    mapped_entry.question = claim_hex(2);
    let resolution_entry = choice_entry(resolution_key.clone(), "merge", Some(0.9));
    let mapped_answered = answered_pack(&same_pack, vec![resolution_entry, mapped_entry]);
    let mapped_history = [mapped_answered];
    let mapped_step =
        resolution_step(same_input, None, &mapped_history).expect("served claim maps");
    match mapped_step {
        Step::Finished(conflict_decision) => assert_eq!(conflict_decision.identity, Some(0)), // native: crates/oneiron/src/dreamer_consolidation/extraction_pack.rs:284 alias maps through served claim
        Step::Ask(_) => panic!("single served claim asks no final"),
    }
    let unnamed_history = [resolution_answered(&same_pack, "merge", "none")];
    match resolution_step(same_input, None, &unnamed_history).expect("no identity named") {
        Step::Finished(decision) => assert_eq!(decision.identity, None), // native: crates/oneiron/src/dreamer_consolidation/executor/decisions/identity_choice.rs:34-46 zero names yields no identity
        Step::Ask(_) => panic!("zero named identities ask no final"),
    }
    let unknown_answered = resolution_answered(&same_pack, "merge", &claim_hex(0x777));
    let unknown_history = [unknown_answered];
    let unknown_result = resolution_step(same_input, None, &unknown_history);
    assert!(matches!(unknown_result, Err(Error::Answers(_)))); // native: crates/oneiron/src/dreamer_runner/attempt_binding/extraction_evidence.rs:114 options must match canonical order
    let alias_answered = resolution_answered(&same_pack, "merge", "candidate:0");
    let alias_history = [alias_answered];
    let alias_result = resolution_step(same_input, None, &alias_history);
    assert!(matches!(alias_result, Err(Error::Answers(_)))); // native: crates/oneiron/src/dreamer_consolidation/extraction_pack.rs:284 answers carry served identifiers only
    let resolution_pages_layout = resolution_layout(vec![vec![0], vec![1]]);
    let wrong_correction_result = correction_pages(&resolution_pages_layout);
    assert!(matches!(wrong_correction_result, Err(Error::WrongLayout))); // native: crates/oneiron/src/dreamer_consolidation/extraction_pack/reads.rs:602 correction refuses other layout
    let first_page = vec![correction_pair(0, 0)];
    let second_page = vec![correction_pair(0, 0)];
    let correction_pages_layout = correction_layout(vec![first_page, second_page]);
    let wrong_resolution_result = resolution_pages(&correction_pages_layout);
    assert!(matches!(wrong_resolution_result, Err(Error::WrongLayout))); // native: crates/oneiron/src/dreamer_consolidation/extraction_pack/reads.rs:657 resolution refuses other layout
    let wrong_step_result = resolution_step(same_input, Some(&correction_pages_layout), &[]);
    assert!(matches!(wrong_step_result, Err(Error::WrongLayout))); // native: crates/oneiron/src/dreamer_consolidation/extraction_pack.rs:89 layout kind selects read
}

#[test]
fn layout_field_only() {
    let correction_refusal = json!({"code": "BAD_REQUEST", "message": "ignored prose", "extraction_layout": {"kind": "correction_pages", "pages": [[{"candidate": 0, "listed": 0}]]}});
    match read_layout(&correction_refusal).expect("correction layout decodes") {
        ExtractionLayout::CorrectionPages { pages } => assert_eq!(pages.len(), 1), // native: crates/oneiron-contracts/src/memory/error.rs:195 typed field never parses prose
        _ => panic!("correction kind preserved"),
    }
    let resolution_refusal = json!({"code": "BAD_REQUEST", "message": "ignored prose", "extraction_layout": {"kind": "resolution_pages", "pages": [[0], [1]]}});
    match read_layout(&resolution_refusal).expect("resolution layout decodes") {
        ExtractionLayout::ResolutionPages { pages } => assert_eq!(pages, vec![vec![0], vec![1]]), // native: crates/oneiron/src/dreamer_consolidation/extraction_pack.rs:89 refusal carries typed layout
        _ => panic!("resolution kind preserved"),
    }
    let missing_layout = read_layout(&json!({"code": "BAD_REQUEST"}));
    assert!(matches!(missing_layout, Err(Error::Layout(_)))); // native: crates/oneiron-contracts/src/memory/error.rs:195 absent layout leaves no key
    let step_slices = json!({"extraction_layout": {"kind": "step_slices", "slices": [{"evidence": [0], "pages": 1}]}});
    assert!(matches!(read_layout(&step_slices), Err(Error::Layout(_)))); // native: crates/oneiron-contracts/src/memory/error.rs:267 closed layout mirror refuses step slices
}
