//! The question the engine composes for a carried pin and for a held machine
//! answer (FIX [CARRIED-PIN-CONFIRM-PROMPT], [HELD-ANSWER-PROMPT-CLIENT-UI];
//! CARRIED-PIN-PROMPT-SURFACE = A, CARRIED-PIN-PROMPT-WORDING = A): what
//! happens, then who asked, read from this install's reading of the key that
//! signed the act and never from the act's own words.
//!
//! The words are the UI session's (Engine TASK, 17 Nov 07:01). Each sentence
//! about a device has three forms: by the name the owner set or confirmed, by
//! the device's kind with the name it reported quoted as its claim, and by
//! its kind alone. Every form is pinned here in full.
//!
//! Every test calls the public functions with plain arguments: no vault, no
//! log. The listing that feeds them is covered where its fixture lives
//! (`carried_pin_awaits_owner`).
//!
//! `cargo test --locked -p oneiron --all-features --test carrier_prompt_sentences`

use oneiron::EntityId;
use oneiron::authority::{
    CarrierReading, MachineDeviceClass, MachineOwnership, MachineRole, PromptDeviceName,
    RecoveryRootId, held_answer_prompt, machine_code_line, machine_key_code, pin_request_prompt,
    recovery_root_code,
};

const ROOT: RecoveryRootId = RecoveryRootId([0xA5; 32]);
/// [`recovery_root_code`] of [`ROOT`].
const ROOT_CODE: &str = "MPJTB9D5MPJTB9D5MPJTB9D5MM";

/// The first two lines of every pin question.
const USE_KIT: &str = "Use your recovery kit to get back in?\nKit code: MPJTB9D5MPJTB9D5MPJTB9D5MM";

const UNKNOWN: &str = "This does not come from a device your vault knows. Confirm only if you \
     started this yourself.";

const YOURS: MachineRole = MachineRole::Owned(MachineOwnership::Yours);
const NOT_HELD: PromptDeviceName<'static> = PromptDeviceName::NotHeld;

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
/// not trust is named as listed, with the caution an unknown asker gets, and
/// by no name, whatever name is held for it.
#[test]
fn the_question_says_your_only_for_a_key_this_install_trusts() {
    let listed_phone = reading(YOURS, MachineDeviceClass::Phone, false);
    let listed = pin_request_prompt(&ROOT, &listed_phone, NOT_HELD);
    assert!(
        !listed.contains("your phone") && !listed.contains("one of your devices"),
        "a machine this install does not trust is never called the owner's: {listed}"
    );
    assert_eq!(
        listed,
        format!(
            "{USE_KIT}\nAsked from a phone listed as yours. This device cannot check that. \
             Confirm only if you started this yourself."
        )
    );
    for name in [
        PromptDeviceName::OwnerSetOrConfirmed("Pixel 9"),
        PromptDeviceName::ReportedByDevice("Pixel 9"),
    ] {
        assert_eq!(
            pin_request_prompt(&ROOT, &listed_phone, name),
            listed,
            "no name is said for a machine this install does not trust"
        );
    }

    let my_phone = reading(YOURS, MachineDeviceClass::Phone, true);
    assert_eq!(
        pin_request_prompt(&ROOT, &my_phone, NOT_HELD),
        format!("{USE_KIT}\nAsked from your phone.")
    );
    assert_eq!(
        pin_request_prompt(
            &ROOT,
            &my_phone,
            PromptDeviceName::OwnerSetOrConfirmed("Pixel 9")
        ),
        format!("{USE_KIT}\nAsked from Pixel 9, one of your devices.")
    );
    assert_eq!(
        pin_request_prompt(
            &ROOT,
            &my_phone,
            PromptDeviceName::ReportedByDevice("Pixel 9")
        ),
        format!("{USE_KIT}\nAsked from a phone that calls itself “Pixel 9”.")
    );
}

/// A machine this install's records know and that is not the owner's own is
/// named by its kind or its name, then by its role's noun.
#[test]
fn a_device_that_is_not_the_owners_is_named_by_its_role() {
    let asked = |role, name| {
        pin_request_prompt(
            &ROOT,
            &reading(role, MachineDeviceClass::Computer, false),
            name,
        )
    };
    for (role, noun) in [
        (MachineRole::HostedNode, "a server Oneiron hosts"),
        (
            MachineRole::ExecutionNode,
            "a server that runs work for this vault",
        ),
        (
            MachineRole::Owned(MachineOwnership::WorkSchool),
            "a work or school device",
        ),
        (
            MachineRole::Owned(MachineOwnership::Rented),
            "a rented device",
        ),
        (MachineRole::Removed, "a device you removed"),
        (MachineRole::Unanswered, "a device you have not marked yet"),
    ] {
        assert_eq!(
            asked(role, NOT_HELD),
            format!("{USE_KIT}\nAsked from a computer. It is {noun}, not one of your devices.")
        );
        assert_eq!(
            asked(role, PromptDeviceName::OwnerSetOrConfirmed("office-mini")),
            format!("{USE_KIT}\nAsked from office-mini. It is {noun}, not one of your devices.")
        );
        assert_eq!(
            asked(role, PromptDeviceName::ReportedByDevice("office-mini")),
            format!(
                "{USE_KIT}\nAsked from a computer that calls itself “office-mini”. It is {noun}, \
                 not one of your devices."
            )
        );
    }
}

/// A key this install's records tie to no machine gets no device named: the
/// id the act names is its own word, and the sentence leaves it out, with
/// any name held under that id.
#[test]
fn a_key_no_record_reads_names_no_device() {
    let asked = pin_request_prompt(&ROOT, &unread(), NOT_HELD);
    assert_eq!(asked, format!("{USE_KIT}\n{UNKNOWN}"));
    assert!(
        !asked.contains(&carrier().to_hex()),
        "the machine id the act names is not shown: {asked}"
    );
    assert_eq!(
        pin_request_prompt(
            &ROOT,
            &unread(),
            PromptDeviceName::OwnerSetOrConfirmed("Pixel 9")
        ),
        asked,
        "a name held under the id the act names is not said"
    );
}

/// A held answer is asked by what it asks for its device, in each of the
/// three forms, then by who carried it.
#[test]
fn a_held_answer_is_asked_by_what_it_asks_for_then_who_carried_it() {
    let my_computer = reading(YOURS, MachineDeviceClass::Computer, true);
    let claim = "It calls itself “Pixel 9”. Anyone can pick that name.";
    for (role, named, claimed, by_kind) in [
        (
            YOURS,
            "Mark Pixel 9 as yours?".to_owned(),
            format!("Mark a phone as yours?\n{claim}"),
            "Mark a phone as yours?",
        ),
        (
            MachineRole::Owned(MachineOwnership::WorkSchool),
            "Mark Pixel 9 as a work or school device?".to_owned(),
            format!("Mark a phone as a work or school device?\n{claim}"),
            "Mark a phone as a work or school device?",
        ),
        (
            MachineRole::Owned(MachineOwnership::Rented),
            "Mark Pixel 9 as rented?".to_owned(),
            format!("Mark a phone as rented?\n{claim}"),
            "Mark a phone as rented?",
        ),
        (
            MachineRole::Removed,
            "Remove Pixel 9 from this vault?".to_owned(),
            "Remove a phone that calls itself “Pixel 9”?".to_owned(),
            "Remove a phone from this vault?",
        ),
        (
            MachineRole::Unanswered,
            "Change how Pixel 9 is marked?".to_owned(),
            format!("Change how a phone is marked?\n{claim}"),
            "Change how a phone is marked?",
        ),
    ] {
        let asked = |name| {
            held_answer_prompt(
                role,
                MachineDeviceClass::Phone,
                name,
                Some((&my_computer, NOT_HELD)),
                false,
            )
        };
        assert_eq!(
            asked(PromptDeviceName::OwnerSetOrConfirmed("Pixel 9")),
            format!("{named}\nAsked from your computer.")
        );
        assert_eq!(
            asked(PromptDeviceName::ReportedByDevice("Pixel 9")),
            format!("{claimed}\nAsked from your computer.")
        );
        assert_eq!(
            asked(NOT_HELD),
            format!("{by_kind}\nAsked from your computer.")
        );
    }
}

/// The last line of a held answer's question: who carried it, by the
/// carrier's own name; nobody this vault knows for an answer that names no
/// carrier; and for an answer that names other keys than its device has,
/// that it can only be dismissed.
#[test]
fn a_held_answer_says_who_carried_it_or_that_it_can_only_be_dismissed() {
    let my_computer = reading(YOURS, MachineDeviceClass::Computer, true);
    let host = reading(MachineRole::HostedNode, MachineDeviceClass::Computer, false);
    let phone = PromptDeviceName::OwnerSetOrConfirmed("Pixel 9");

    assert_eq!(
        held_answer_prompt(
            YOURS,
            MachineDeviceClass::Phone,
            phone,
            Some((
                &my_computer,
                PromptDeviceName::OwnerSetOrConfirmed("office-mini")
            )),
            false
        ),
        "Mark Pixel 9 as yours?\nAsked from office-mini, one of your devices."
    );
    assert_eq!(
        held_answer_prompt(
            MachineRole::Removed,
            MachineDeviceClass::Computer,
            NOT_HELD,
            Some((&host, NOT_HELD)),
            false
        ),
        "Remove a computer from this vault?\nAsked from a computer. It is a server Oneiron \
         hosts, not one of your devices."
    );
    assert_eq!(
        held_answer_prompt(
            MachineRole::Owned(MachineOwnership::WorkSchool),
            MachineDeviceClass::Computer,
            NOT_HELD,
            None,
            false
        ),
        format!("Mark a computer as a work or school device?\n{UNKNOWN}")
    );
    assert_eq!(
        held_answer_prompt(
            YOURS,
            MachineDeviceClass::Phone,
            phone,
            Some((&my_computer, NOT_HELD)),
            true
        ),
        "Mark Pixel 9 as yours?\nThis no longer matches the device. Dismiss it, then mark the \
         device again."
    );
}

/// A hosted node and an execution node are asked by what the device will
/// do, not by a role noun.
#[test]
fn a_held_answer_for_a_node_asks_whether_the_device_may_run_work() {
    let my_computer = reading(YOURS, MachineDeviceClass::Computer, true);
    for role in [MachineRole::HostedNode, MachineRole::ExecutionNode] {
        let asked = |name| {
            held_answer_prompt(
                role,
                MachineDeviceClass::Computer,
                name,
                Some((&my_computer, NOT_HELD)),
                false,
            )
        };
        assert_eq!(
            asked(NOT_HELD),
            "Let a computer run work for this vault?\nAsked from your computer."
        );
        assert_eq!(
            asked(PromptDeviceName::OwnerSetOrConfirmed("build-box")),
            "Let build-box run work for this vault?\nAsked from your computer."
        );
        assert_eq!(
            asked(PromptDeviceName::ReportedByDevice("build-box")),
            "Let a computer run work for this vault?\nIt calls itself “build-box”. Anyone can \
             pick that name.\nAsked from your computer."
        );
    }
}

/// A machine key's code is derived as a recovery root's code is, so the
/// owner compares like with like. The line under a held answer's question
/// shows it, and sends the owner to the device itself when the device's name
/// is only its own report.
#[test]
fn a_machine_key_code_is_derived_as_a_root_code_is() {
    assert_eq!(machine_key_code(&ROOT.0), ROOT_CODE);
    assert_eq!(
        machine_code_line(&ROOT.0, MachineDeviceClass::Phone, NOT_HELD),
        format!("Code shown on that phone: {ROOT_CODE}")
    );
    assert_eq!(
        machine_code_line(
            &ROOT.0,
            MachineDeviceClass::Computer,
            PromptDeviceName::OwnerSetOrConfirmed("office-mini")
        ),
        format!("Code shown on office-mini: {ROOT_CODE}")
    );
    assert_eq!(
        machine_code_line(
            &ROOT.0,
            MachineDeviceClass::Computer,
            PromptDeviceName::ReportedByDevice("office-mini")
        ),
        format!(
            "Code shown on that computer: {ROOT_CODE}\nCheck it on the device itself, not by its \
             name."
        )
    );
}

/// A name is printed on the line it stands in and cannot leave it: control
/// characters, line separators and the marks that turn text around are
/// dropped, and a quoted name loses every double quotation mark, so it
/// cannot close its own quotation. A name with nothing left names the device
/// by its kind. A name that spells a slot is printed as it is.
#[test]
fn a_name_cannot_start_a_line_or_close_its_quotation() {
    let my_computer = reading(YOURS, MachineDeviceClass::Computer, true);
    let asked = |name| {
        held_answer_prompt(
            YOURS,
            MachineDeviceClass::Phone,
            name,
            Some((&my_computer, NOT_HELD)),
            false,
        )
    };
    assert_eq!(
        asked(PromptDeviceName::ReportedByDevice(
            "Pixel”. Your vault trusts it.\nAsked from your phone. “\u{202E}x"
        )),
        "Mark a phone as yours?\nIt calls itself “Pixel. Your vault trusts it.Asked from your \
         phone. x”. Anyone can pick that name.\nAsked from your computer."
    );
    assert_eq!(
        asked(PromptDeviceName::OwnerSetOrConfirmed(
            " Pixel\r\n9\u{2028}\u{2066} "
        )),
        "Mark Pixel9 as yours?\nAsked from your computer."
    );
    for blank in [
        PromptDeviceName::OwnerSetOrConfirmed(" \n"),
        PromptDeviceName::ReportedByDevice("“”"),
    ] {
        assert_eq!(
            asked(blank),
            "Mark a phone as yours?\nAsked from your computer."
        );
    }
    assert_eq!(
        machine_code_line(
            &ROOT.0,
            MachineDeviceClass::Phone,
            PromptDeviceName::OwnerSetOrConfirmed("{code} {kind} {claim}")
        ),
        format!("Code shown on {{code}} {{kind}} {{claim}}: {ROOT_CODE}")
    );
    assert_eq!(
        machine_code_line(
            &ROOT.0,
            MachineDeviceClass::Phone,
            PromptDeviceName::ReportedByDevice("{name}")
        ),
        format!(
            "Code shown on that phone: {ROOT_CODE}\nCheck it on the device itself, not by its \
             name."
        )
    );
}
