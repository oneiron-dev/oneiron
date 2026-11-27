//! FIX DREAMER-NATIVE-PERSON-TURN-UNATTRIBUTED (ARCH-0043:37): a native person TURN shows its writer's PERSON
//! label beside its role in the extraction transcript. In a shared vault every person turn is labelled, the owner's
//! included; in a personal vault a turn the vault's owner wrote alone shows no label, while a turn another PERSON
//! wrote shows that PERSON's label. Only the transcript line changes: class, landing, review and recall are
//! unchanged. A deleted writer is not labelled, so the call's source rows still stand and the model run's source
//! fence lets the call send, while that writer's MESSAGE keeps its words on the line (REVIEW-10620 round 1). In a
//! personal vault a turn the owner wrote with a since-deleted writer keeps the owner's label: it was not the owner's
//! alone (REVIEW-10620 round 2).
//!
//! Run: `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron --all-features --test dreamer_native_turn_writer_label`

#![cfg(oneiron_test_support)]

use oneiron::test_doors::dreamer_extraction_room::{
    TurnWriter, writer_label_slice_calls, writer_label_slice_calls_after_member_delete,
};

/// How a call's listing names the member PERSON the door seeds: its `entity <label> "mira"` line ends so.
const MEMBER_NAME: &str = "\"mira\"";

/// The head of the one transcript line showing `words`: its call index and what sits between `[` and `]` split on
/// spaces (`[turn_label, role, labels...]`). Panics unless exactly one line of all calls' transcripts ends in
/// `"] {words}"`.
fn turn_head<'a>(calls: &'a [String], words: &str) -> (usize, Vec<&'a str>) {
    let suffix = format!("] {words}");
    let mut found = None;
    for (index, call) in calls.iter().enumerate() {
        for line in call.lines() {
            if !line.ends_with(suffix.as_str()) {
                continue;
            }
            let head = line
                .strip_prefix('[')
                .and_then(|rest| rest.split_once(']'))
                .map(|(head, _)| head)
                .unwrap_or_else(|| {
                    panic!("a turn line opens with `[` and closes its head with `]`: {line:?} in {calls:?}")
                });
            assert!(
                found.is_none(),
                "exactly one turn line ends in {suffix:?}: {calls:?}"
            );
            found = Some((index, head.split(' ').collect()));
        }
    }
    found.unwrap_or_else(|| panic!("no turn line ends in {suffix:?}: {calls:?}"))
}

/// Whether `label` is an entity label as the call map writes it: `P` then a number from 1 in plain decimal (no
/// sign, no leading zero).
fn is_entity_label(label: &str) -> bool {
    let Some(number) = label.strip_prefix('P') else {
        return false;
    };
    !number.is_empty()
        && !number.starts_with('0')
        && number.bytes().all(|byte| byte.is_ascii_digit())
}

fn sole_writer<'a>(head: &[&'a str], calls: &[String]) -> &'a str {
    match head {
        [_, "user", label] if is_entity_label(label) => label,
        _ => panic!("expected a user turn with one entity writer label: {head:?} in {calls:?}"),
    }
}

/// What one call's listing writes after `entity <label>`: the entity's JSON name (empty when it has none), or `None`
/// when the call lists no entity under `label`.
fn listed_as<'a>(call: &'a str, label: &str) -> Option<&'a str> {
    let head = format!("entity {label}");
    call.lines().find_map(|line| {
        let rest = line.strip_prefix(head.as_str())?;
        (rest.is_empty() || rest.starts_with(' ')).then(|| rest.trim_start())
    })
}

#[test]
fn a_members_native_turn_names_its_writer_and_the_owners_turn_names_no_one() {
    let calls = writer_label_slice_calls(
        false,
        &[
            (TurnWriter::Owner, 0, "I prefer tea"),
            (TurnWriter::Member, 1, "I prefer coffee"),
        ],
    )
    .expect("personal vault writer-label calls");
    let (_, tea) = turn_head(&calls, "I prefer tea");
    let (coffee_call, coffee) = turn_head(&calls, "I prefer coffee");
    assert!(
        matches!(tea.as_slice(), [_, "user"]),
        "the owner's user turn names no one beside its role, so none of the member's label: {tea:?} in {calls:?}"
    );
    let member = sole_writer(&coffee, &calls);
    assert_eq!(
        listed_as(&calls[coffee_call], member),
        Some(MEMBER_NAME),
        "the member's turn names the member: its label {member} is the call's listed {MEMBER_NAME}: {calls:?}"
    );
}

#[test]
fn in_a_shared_vault_every_person_turn_names_its_writer_the_owners_included() {
    let calls = writer_label_slice_calls(
        true,
        &[
            (TurnWriter::Owner, 0, "I prefer tea"),
            (TurnWriter::Member, 1, "I prefer coffee"),
        ],
    )
    .expect("shared vault writer-label calls");
    let (tea_call, tea) = turn_head(&calls, "I prefer tea");
    let (coffee_call, coffee) = turn_head(&calls, "I prefer coffee");
    let owner = sole_writer(&tea, &calls);
    let member = sole_writer(&coffee, &calls);
    assert_eq!(
        listed_as(&calls[coffee_call], member),
        Some(MEMBER_NAME),
        "the member's turn names the member: its label {member} is the call's listed {MEMBER_NAME}: {calls:?}"
    );
    assert_ne!(
        listed_as(&calls[tea_call], owner),
        Some(MEMBER_NAME),
        "the owner's turn names its own writer, not the member: its label {owner} in {calls:?}"
    );
}

#[test]
fn a_turn_the_owner_and_a_member_both_wrote_names_both() {
    let calls = writer_label_slice_calls(
        false,
        &[
            (TurnWriter::Owner, 0, "tea for me"),
            (TurnWriter::Member, 0, "coffee for me"),
        ],
    )
    .expect("personal vault mixed-turn writer-label calls");
    let (call, head) = turn_head(&calls, "tea for me");
    assert!(
        calls[call].contains("tea for me\ncoffee for me"),
        "the TURN's line carries both MESSAGEs' words: {:?} in {calls:?}",
        calls[call]
    );
    let [_, "user", first, second] = head.as_slice() else {
        panic!("expected a user turn with two writer labels: {head:?} in {calls:?}");
    };
    assert!(
        is_entity_label(first) && is_entity_label(second),
        "both writer labels are entity labels: {head:?} in {calls:?}"
    );
    assert_ne!(first, second, "the two writers' labels differ: {calls:?}");
    assert_ne!(
        listed_as(&calls[call], first),
        Some(MEMBER_NAME),
        "the first label names the owner, who wrote the first MESSAGE, not the member: {calls:?}"
    );
}

/// The calls after the member PERSON's delete over one TURN the owner opened and the member added to: the
/// transcripts, the TURN line's call and head, and whether every call's source rows stand.
fn after_member_delete(shared: bool) -> (Vec<String>, usize, Vec<String>, bool) {
    let calls = writer_label_slice_calls_after_member_delete(
        shared,
        &[
            (TurnWriter::Owner, 0, "tea for me"),
            (TurnWriter::Member, 0, "coffee for me"),
        ],
    )
    .expect("writer-label calls after the member's delete");
    let transcripts: Vec<String> = calls
        .iter()
        .map(|(transcript, _)| transcript.clone())
        .collect();
    let (call, head) = turn_head(&transcripts, "tea for me");
    let head = head.into_iter().map(str::to_owned).collect();
    let stand = calls.iter().all(|(_, stands)| *stands);
    assert!(
        transcripts[call].contains("tea for me\ncoffee for me"),
        "the TURN's line keeps the deleted member's words: {transcripts:?}"
    );
    (transcripts, call, head, stand)
}

/// After the member PERSON's delete, the TURN's line names one writer, the owner, and every call's source rows stand.
fn a_deleted_co_writer_leaves_the_owners_label(shared: bool) {
    let (transcripts, call, head, stand) = after_member_delete(shared);
    let head: Vec<&str> = head.iter().map(String::as_str).collect();
    let owner = sole_writer(&head, &transcripts);
    assert_ne!(
        listed_as(&transcripts[call], owner),
        Some(MEMBER_NAME),
        "the one label names the owner, not the deleted member: {transcripts:?}"
    );
    assert!(
        stand,
        "every row the calls were read from stands, so the source fence lets them send: {transcripts:?}"
    );
}

#[test]
fn in_a_shared_vault_a_deleted_co_writer_is_not_labelled_and_the_call_still_sends() {
    a_deleted_co_writer_leaves_the_owners_label(true);
}

/// The owner did not write the turn alone, so the personal vault's owner-only exception does not apply, though the
/// owner is its one standing writer.
#[test]
fn in_a_personal_vault_a_turn_whose_co_writer_was_deleted_keeps_the_owners_label_and_still_sends() {
    a_deleted_co_writer_leaves_the_owners_label(false);
}
