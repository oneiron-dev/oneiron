//! Tests of the node's job id table.

use super::*;

const UNIT_A: &str = "oneiron-job@0123456789abcdef0123456789abcdef.service";
const UNIT_B: &str = "oneiron-job@fedcba9876543210fedcba9876543210.service";

fn pick(
    taken: &BTreeMap<u32, String>,
    held: &BTreeSet<u32>,
    ended: &[&str],
    named: &[u32],
) -> Choice {
    choose(
        100..104,
        UNIT_A,
        101,
        taken,
        held,
        &mut |owner: &str| ended.contains(&owner),
        &mut |uid| named.contains(&uid),
    )
}

#[test]
fn the_lowest_id_no_file_process_or_account_holds_is_given_and_never_the_engines() {
    let taken = BTreeMap::from([(100, UNIT_B.to_owned())]);
    // 100 is B's (running), 101 the engine's, 102 a process's.
    assert_eq!(
        pick(&taken, &BTreeSet::from([102]), &[], &[]),
        Choice::Free(103)
    );
    assert_eq!(
        pick(&taken, &BTreeSet::new(), &[], &[102]),
        Choice::Free(103)
    );
    assert_eq!(
        pick(&taken, &BTreeSet::from([102, 103]), &[], &[]),
        Choice::Exhausted
    );
}

#[test]
fn an_id_is_taken_back_only_when_its_unit_ended_and_no_process_holds_it() {
    let taken = BTreeMap::from([(100, UNIT_B.to_owned())]);
    let busy = BTreeSet::from([102, 103]);
    assert_eq!(pick(&taken, &busy, &[UNIT_B], &[]), Choice::TakeBack(100));
    // B ended, but a process still holds 100.
    assert_eq!(
        pick(&taken, &BTreeSet::from([100, 102, 103]), &[UNIT_B], &[]),
        Choice::Exhausted
    );
    // B still runs.
    assert_eq!(pick(&taken, &busy, &[], &[]), Choice::Exhausted);
}

#[test]
fn a_unit_the_table_names_gets_its_own_id_again_only_when_nothing_holds_it() {
    let taken = BTreeMap::from([(102, UNIT_A.to_owned())]);
    assert_eq!(pick(&taken, &BTreeSet::new(), &[], &[]), Choice::Own(102));
    // A process (or a live reserving process) holds it, or an account has it.
    assert_eq!(
        pick(&taken, &BTreeSet::from([102]), &[], &[]),
        Choice::OwnRefused(102)
    );
    assert_eq!(
        pick(&taken, &BTreeSet::new(), &[], &[102]),
        Choice::OwnRefused(102)
    );
    // Outside the range, or the engine's (101).
    let outside = BTreeMap::from([(99, UNIT_A.to_owned())]);
    assert_eq!(
        pick(&outside, &BTreeSet::new(), &[], &[]),
        Choice::OwnRefused(99)
    );
    let engine = BTreeMap::from([(101, UNIT_A.to_owned())]);
    assert_eq!(
        pick(&engine, &BTreeSet::new(), &[], &[]),
        Choice::OwnRefused(101)
    );
    // Two entries of one unit.
    let twice = BTreeMap::from([(102, UNIT_A.to_owned()), (103, UNIT_A.to_owned())]);
    assert_eq!(
        pick(&twice, &BTreeSet::new(), &[], &[]),
        Choice::OwnRefused(102)
    );
}

#[test]
fn one_show_answer_names_the_ended_units_and_a_unit_it_leaves_out_still_runs() {
    let probe = format!("{PROBE_UNIT_PREFIX}00000000000000000000000000000000.service");
    let text = format!(
        "Id={UNIT_A}\nActiveState=inactive\nLoadState=loaded\n\n\
         Id={UNIT_B}\nActiveState=deactivating\nLoadState=loaded\n\n\
         Id={probe}\nActiveState=inactive\nLoadState=not-found\n\n\
         Id=sshd.service\nActiveState=failed\nLoadState=loaded\n"
    );
    let left_out = "oneiron-job@11111111111111111111111111111111.service";
    let ended = ended_in_show(&text, &[UNIT_A, UNIT_B, probe.as_str(), left_out]);
    assert_eq!(ended, vec![UNIT_A.to_owned(), probe.clone()]);
    assert_eq!(unit_id(probe.trim_end_matches(".service")), probe);
    assert_eq!(unit_id(UNIT_A), UNIT_A);
}

#[test]
fn the_status_ids_are_every_user_and_group_id_and_the_supplementary_groups() {
    let text = "Name:\tsleep\nUid:\t1879048192\t1879048192\t0\t1879048193\nGid:\t5\t6\t7\t8\nGroups:\t9 10 \nNgid:\t0\n";
    assert_eq!(
        ids_in_status(text),
        vec![
            1_879_048_192,
            1_879_048_192,
            0,
            1_879_048_193,
            5,
            6,
            7,
            8,
            9,
            10
        ]
    );
    assert!(ids_in_status("Groups:\t\n").is_empty());
}

#[test]
fn an_entry_names_its_unit_and_its_reserving_process() {
    assert_eq!(
        parse_entry(&format!("{UNIT_A}\n4242 987654\n")),
        (UNIT_A.to_owned(), Some((4242, 987_654)))
    );
    // An entry written before the reserving process was recorded.
    assert_eq!(
        parse_entry(&format!("{UNIT_A}\n")),
        (UNIT_A.to_owned(), None)
    );
    assert_eq!(parse_entry(""), (String::new(), None));
    // A command name with spaces and parentheses ends at the last `)`.
    let stat = "4242 (a b) c) S 1 4242 4242 0 -1 4194560 100 0 0 0 1 2 0 0 20 0 1 0 987654 1000 10";
    assert_eq!(start_time_in_stat(stat), Some(987_654));
    assert_eq!(start_time_in_stat("4242 (x"), None);
}

#[test]
fn an_unreadable_or_foreign_entry_is_never_taken_back() {
    let ended = BTreeSet::from([UNIT_A.to_owned()]);
    assert!(owner_ended(UNIT_A, &ended));
    assert!(!owner_ended(UNIT_B, &ended));
    assert!(!owner_ended("", &ended));
    assert!(!owner_ended(
        "sshd.service",
        &BTreeSet::from(["sshd.service".to_owned()])
    ));
}

#[test]
fn the_table_holds_only_job_and_probe_unit_names() {
    assert!(is_table_unit(UNIT_A));
    assert!(is_table_unit(&format!(
        "{PROBE_UNIT_PREFIX}0123456789abcdef0123456789abcdef"
    )));
    assert!(!is_table_unit("oneiron-job@x.service"));
    assert!(!is_table_unit("sshd.service"));
    assert!(!is_table_unit(""));
}
