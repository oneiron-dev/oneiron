//! The question the engine composes for a carried pin and for a held machine
//! answer (FIX [CARRIED-PIN-CONFIRM-PROMPT], [HELD-ANSWER-PROMPT-CLIENT-UI];
//! CARRIED-PIN-PROMPT-SURFACE = A, CARRIED-PIN-PROMPT-WORDING = A): the kit's
//! code, then who asked, read from this install's reading of the key that
//! signed the act and never from the act's own words.
//!
//! Every test calls the public functions with plain arguments: no vault, no
//! log. The listing that feeds them is covered where its fixture lives
//! (`carried_pin_awaits_owner`).
//!
//! `cargo test --locked -p oneiron --all-features --test carrier_prompt_sentences`

use oneiron::EntityId;
use oneiron::authority::{
    CarrierReading, MachineDeviceClass, MachineOwnership, MachineRole, RecoveryRootId,
    held_answer_prompt, machine_code_line, machine_key_code, pin_request_prompt,
    recovery_root_code,
};

const ROOT: RecoveryRootId = RecoveryRootId([0xA5; 32]);
/// [`recovery_root_code`] of [`ROOT`].
const ROOT_CODE: &str = "MPJTB9D5MPJTB9D5MPJTB9D5MM";

const UNKNOWN: &str = "This request doesn't come from any device this vault knows. Only confirm \
     if you started it yourself.";

fn carrier() -> EntityId {
    EntityId::from_bytes([0x71; 16]).expect("an id")
}

fn reading(role: MachineRole, class: MachineDeviceClass, is_mine: bool) -> CarrierReading {
    CarrierReading {
        machine: carrier(),
        role: Some(role),
        device_class: Some(class),
        is_mine,
    }
}

fn unread() -> CarrierReading {
    CarrierReading {
        machine: carrier(),
        role: None,
        device_class: None,
        is_mine: false,
    }
}

/// The code is the first 128 bits of the root's id in the text form of a
/// machine's request code: 26 Crockford base32 symbols. Nothing past those
/// bits enters it.
#[test]
fn a_root_code_is_26_symbols_of_the_ids_first_128_bits() {
    assert_eq!(recovery_root_code(&ROOT), ROOT_CODE);
    assert_eq!(
        recovery_root_code(&RecoveryRootId(std::array::from_fn(|at| at as u8 + 1))),
        "041061050R3GG28A1C60T3GF20"
    );

    let mut last_coded_byte = ROOT;
    last_coded_byte.0[15] ^= 1;
    assert_eq!(
        recovery_root_code(&last_coded_byte),
        "MPJTB9D5MPJTB9D5MPJTB9D5MG",
        "the sixteenth byte is in the code"
    );
    let mut first_uncoded_byte = ROOT;
    first_uncoded_byte.0[16] ^= 1;
    assert_eq!(
        recovery_root_code(&first_uncoded_byte),
        ROOT_CODE,
        "the code is the id's first 128 bits: the fingerprint in full stays what a pin takes"
    );
}

/// "Your" is said for a key this install trusts as the owner's machine, and
/// for no other: a machine the roster lists as his that this install does
/// not trust is named as listed, with the caution an unknown asker gets.
#[test]
fn the_question_says_your_only_for_a_key_this_install_trusts() {
    let yours = MachineRole::Owned(MachineOwnership::Yours);
    let listed = pin_request_prompt(&ROOT, &reading(yours, MachineDeviceClass::Phone, false));
    assert!(
        !listed.contains("Your "),
        "a machine this install does not trust is never called the owner's: {listed}"
    );
    assert_eq!(
        listed,
        format!(
            "Use the recovery kit with code {ROOT_CODE}? A phone this vault lists as yours asked \
             for it, but this device cannot verify that. Only confirm if you started it yourself."
        )
    );
    assert_eq!(
        pin_request_prompt(&ROOT, &reading(yours, MachineDeviceClass::Phone, true)),
        format!("Use the recovery kit with code {ROOT_CODE}? Your phone asked for it.")
    );
}

/// A machine this install's records know and that is not the owner's own is
/// named by its class and its role's noun.
#[test]
fn a_machine_that_is_not_the_owners_is_named_by_its_role() {
    let asked =
        |role| pin_request_prompt(&ROOT, &reading(role, MachineDeviceClass::Computer, false));
    assert_eq!(
        asked(MachineRole::HostedNode),
        format!(
            "Use the recovery kit with code {ROOT_CODE}? A computer (a hosted server, not one of \
             your devices) asked for it."
        )
    );
    assert_eq!(
        asked(MachineRole::ExecutionNode),
        format!(
            "Use the recovery kit with code {ROOT_CODE}? A computer (an execution node, not one \
             of your devices) asked for it."
        )
    );
    assert_eq!(
        asked(MachineRole::Owned(MachineOwnership::WorkSchool)),
        format!(
            "Use the recovery kit with code {ROOT_CODE}? A computer (a work or school machine, \
             not one of your devices) asked for it."
        )
    );
}

/// A key this install's records tie to no machine gets no machine named: the
/// id the act names is its own word, and the sentence leaves it out.
#[test]
fn a_key_no_record_reads_names_no_machine() {
    let asked = pin_request_prompt(&ROOT, &unread());
    assert_eq!(
        asked,
        format!("Use the recovery kit with code {ROOT_CODE}? {UNKNOWN}")
    );
    assert!(
        !asked.contains(&carrier().to_hex()),
        "the machine id the act names is not shown: {asked}"
    );
}

/// A held answer is asked by what it asks for its machine, then by who
/// carried it; one that names other keys than its machine has can only be
/// dismissed, and says so.
#[test]
fn a_held_answer_is_asked_by_what_it_asks_for_then_who_carried_it() {
    let yours = MachineRole::Owned(MachineOwnership::Yours);
    let my_computer = reading(yours, MachineDeviceClass::Computer, true);
    let host = reading(MachineRole::HostedNode, MachineDeviceClass::Computer, false);

    assert_eq!(
        held_answer_prompt(yours, MachineDeviceClass::Phone, Some(&my_computer), false),
        "Add a phone as one of your devices? Your computer asked for it."
    );
    assert_eq!(
        held_answer_prompt(
            MachineRole::Removed,
            MachineDeviceClass::Computer,
            Some(&host),
            false
        ),
        "Remove a computer from this vault? A computer (a hosted server, not one of your \
         devices) asked for it."
    );
    assert_eq!(
        held_answer_prompt(
            MachineRole::Owned(MachineOwnership::WorkSchool),
            MachineDeviceClass::Computer,
            None,
            false
        ),
        format!("Add a computer as a work or school machine? {UNKNOWN}")
    );
    assert_eq!(
        held_answer_prompt(yours, MachineDeviceClass::Phone, Some(&my_computer), true),
        "Add a phone as one of your devices? It names different keys than this machine has. \
         Dismiss it."
    );
}

/// A hosted node and an execution node are asked by what the machine will
/// do, not by a role noun.
#[test]
fn a_held_answer_for_a_node_asks_whether_the_machine_may_run_work() {
    let yours = MachineRole::Owned(MachineOwnership::Yours);
    let my_computer = reading(yours, MachineDeviceClass::Computer, true);
    for role in [MachineRole::HostedNode, MachineRole::ExecutionNode] {
        assert_eq!(
            held_answer_prompt(
                role,
                MachineDeviceClass::Computer,
                Some(&my_computer),
                false
            ),
            "Let a computer run work for this vault? Your computer asked for it."
        );
    }
}

/// A machine key's code is derived as a recovery root's code is, so the
/// owner compares like with like; the line under a held answer's question
/// shows it.
#[test]
fn a_machine_key_code_is_derived_as_a_root_code_is() {
    assert_eq!(machine_key_code(&ROOT.0), ROOT_CODE);
    assert_eq!(
        machine_code_line(&ROOT.0),
        format!("Code shown on that machine: {ROOT_CODE}")
    );
}
