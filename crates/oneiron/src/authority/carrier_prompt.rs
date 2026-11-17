//! The question an owner's surface asks before he confirms an act another
//! device carried: a pending pin of a recovery root (FIX
//! [CARRIED-PIN-CONFIRM-PROMPT]) and a held machine answer (FIX
//! [HELD-ANSWER-PROMPT-CLIENT-UI]). The engine composes it, so every surface
//! shows the same words (CARRIED-PIN-PROMPT-SURFACE = A).
//!
//! Every word is a constant of this file: a surface session rewords here and
//! nowhere else (CARRIED-PIN-PROMPT-WORDING = A). The words are the UI
//! session's (Engine TASK, 17 Nov 07:01): a question says "device", never
//! "machine". A question is one or more lines with a line feed between them:
//! what happens, then who asked.
//!
//! The slots: `{code}` is a code, `{kind}` a device class (`phone`,
//! `computer`), `{role}` a role's noun, `{name}` a name the owner set or
//! confirmed, `{reported}` a name the device reported for itself and
//! `{claim}` the line that quotes it ([`REPORTED_NAME_CLAIM`]).
//!
//! Who asked is read from [`CarrierReading`], this install's reading of the
//! key that signed the act, never from the machine id or the owner the act
//! names (CARRIED-PIN-PROMPT-HOSTED-CARRIER = A). A sentence says "your" only
//! for a key this install trusts as one of the owner's machines, and names no
//! device at all for a key its records tie to none.
//!
//! A device is named by a name only when the owner set or confirmed that
//! name ([`PromptDeviceName`]). A name the device reported for itself is
//! anyone's to pick, so the question names that device by its kind and quotes
//! the name as the device's own claim.

use super::*;

/// What this install holds as a device's name, as a question may use it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PromptDeviceName<'a> {
    /// A name the owner set, or confirmed when he marked the device as his:
    /// the question names the device by it.
    OwnerSetOrConfirmed(&'a str),
    /// A name the device reported for itself and the owner never confirmed:
    /// the question names the device by its kind and quotes the name as the
    /// device's claim.
    ReportedByDevice(&'a str),
    /// No name is held: the question names the device by its kind.
    NotHeld,
}

/// How a sentence names one device.
enum Naming {
    /// By the name the owner set or confirmed.
    Name(String),
    /// By its kind, with the name it reported quoted as its claim.
    Claim(String),
    /// By its kind alone.
    Kind,
}

impl PromptDeviceName<'_> {
    /// How a sentence names the device: a name nothing is left of once it is
    /// printed ([`printed_name`]) names it by its kind.
    fn naming(self) -> Naming {
        let (name, quoted) = match self {
            Self::OwnerSetOrConfirmed(name) => (name, false),
            Self::ReportedByDevice(name) => (name, true),
            Self::NotHeld => return Naming::Kind,
        };
        let name = printed_name(name, quoted);
        if name.is_empty() {
            Naming::Kind
        } else if quoted {
            Naming::Claim(name)
        } else {
            Naming::Name(name)
        }
    }
}

/// Characters a name is printed without, beside every control character:
/// the line and paragraph separators and the marks that turn text around on
/// its line. A name can then neither start a line of a question nor reorder
/// one.
const LINE_AND_DIRECTION_MARKS: [char; 14] = [
    '\u{061C}', '\u{200E}', '\u{200F}', '\u{2028}', '\u{2029}', '\u{202A}', '\u{202B}', '\u{202C}',
    '\u{202D}', '\u{202E}', '\u{2066}', '\u{2067}', '\u{2068}', '\u{2069}',
];

/// Double quotation marks. A quoted name is printed without them, so it
/// cannot close the quotation it stands in.
const DOUBLE_QUOTATION_MARKS: [char; 7] = [
    '"', '\u{201C}', '\u{201D}', '\u{201E}', '\u{201F}', '\u{2033}', '\u{FF02}',
];

/// `name` as a question prints it: trimmed, without control characters and
/// [`LINE_AND_DIRECTION_MARKS`], and inside a quotation (`quoted`) without
/// [`DOUBLE_QUOTATION_MARKS`]. The length is its store's to bound.
fn printed_name(name: &str, quoted: bool) -> String {
    let dropped = |mark: char| {
        mark.is_control()
            || LINE_AND_DIRECTION_MARKS.contains(&mark)
            || (quoted && DOUBLE_QUOTATION_MARKS.contains(&mark))
    };
    let printed: String = name.chars().filter(|mark| !dropped(*mark)).collect();
    printed.trim().to_owned()
}

/// One sentence in its three forms, by how it names its device.
#[derive(Clone, Copy)]
struct SentenceForms {
    /// With `{name}`: the owner set or confirmed the device's name.
    named: &'static str,
    /// With `{kind}` and `{reported}` or `{claim}`: the device reported its
    /// name itself.
    claimed: &'static str,
    /// With `{kind}`: no name is held.
    by_kind: &'static str,
}

impl SentenceForms {
    /// The sentence about a device of class `kind` that `name` names.
    /// `filled` is the sentence's own slot and its text. The name goes in
    /// last, so a name that spells a slot is printed as it is.
    fn say(
        self,
        kind: MachineDeviceClass,
        filled: Option<(&str, &str)>,
        name: PromptDeviceName<'_>,
    ) -> String {
        let naming = name.naming();
        let form = match naming {
            Naming::Name(_) => self.named,
            Naming::Claim(_) => self.claimed,
            Naming::Kind => self.by_kind,
        };
        let mut said = form
            .replace("{claim}", REPORTED_NAME_CLAIM)
            .replace("{kind}", kind.wire());
        if let Some((slot, text)) = filled {
            said = said.replace(slot, text);
        }
        match naming {
            Naming::Name(name) => said.replace("{name}", &name),
            Naming::Claim(reported) => said.replace("{reported}", &reported),
            Naming::Kind => said,
        }
    }
}

/// The question of a pending pin.
const USE_KIT: &str = "Use your recovery kit to get back in?";
/// The line under [`USE_KIT`]. The owner compares `{code}` with the code his
/// kit shows ([`recovery_root_code`]).
const KIT_CODE: &str = "Kit code: {code}";

/// The line that quotes the name a device reported for itself, under a
/// question about that device.
const REPORTED_NAME_CLAIM: &str = "It calls itself “{reported}”. Anyone can pick that name.";

/// The carrier is a machine this install trusts as the owner's.
const ASKED_BY_YOURS: SentenceForms = SentenceForms {
    named: "Asked from {name}, one of your devices.",
    claimed: "Asked from a {kind} that calls itself “{reported}”.",
    by_kind: "Asked from your {kind}.",
};
/// This install's records tie the signing key to a machine that is not the
/// owner's own.
const ASKED_BY_KNOWN: SentenceForms = SentenceForms {
    named: "Asked from {name}. It is {role}, not one of your devices.",
    claimed: "Asked from a {kind} that calls itself “{reported}”. It is {role}, not one of your \
              devices.",
    by_kind: "Asked from a {kind}. It is {role}, not one of your devices.",
};
/// The roster lists the signing key's machine as the owner's, and this
/// install does not trust it as his. No name is said: a name would lend the
/// listing a standing this install does not give it.
const ASKED_BY_LISTED_YOURS: &str = "Asked from a {kind} listed as yours. This device cannot check \
     that. Confirm only if you started this yourself.";
/// This install's records tie the signing key to no machine.
const ASKED_BY_UNKNOWN: &str = "This does not come from a device your vault knows. Confirm only if \
     you started this yourself.";

/// `{role}` of [`ASKED_BY_KNOWN`], for each role that is not the owner's own.
const HOSTED_SERVER: &str = "a server Oneiron hosts";
const EXECUTION_NODE: &str = "a server that runs work for this vault";
const WORK_SCHOOL_MACHINE: &str = "a work or school device";
const RENTED_MACHINE: &str = "a rented device";
const REMOVED_MACHINE: &str = "a device you removed";
const UNANSWERED_MACHINE: &str = "a device you have not marked yet";

/// The question of a held machine answer, by the role it asks for.
const ADD_AS_YOURS: SentenceForms = SentenceForms {
    named: "Mark {name} as yours?",
    claimed: "Mark a {kind} as yours?\n{claim}",
    by_kind: "Mark a {kind} as yours?",
};
const ADD_AS_WORK_SCHOOL: SentenceForms = SentenceForms {
    named: "Mark {name} as a work or school device?",
    claimed: "Mark a {kind} as a work or school device?\n{claim}",
    by_kind: "Mark a {kind} as a work or school device?",
};
const ADD_AS_RENTED: SentenceForms = SentenceForms {
    named: "Mark {name} as rented?",
    claimed: "Mark a {kind} as rented?\n{claim}",
    by_kind: "Mark a {kind} as rented?",
};
const REMOVE_MACHINE: SentenceForms = SentenceForms {
    named: "Remove {name} from this vault?",
    claimed: "Remove a {kind} that calls itself “{reported}”?",
    by_kind: "Remove a {kind} from this vault?",
};
/// A hosted node or an execution node: what the device will do, not a role
/// noun (HELD-MACHINE-PROMPT-WORDING = A).
const RUN_WORK: SentenceForms = SentenceForms {
    named: "Let {name} run work for this vault?",
    claimed: "Let a {kind} run work for this vault?\n{claim}",
    by_kind: "Let a {kind} run work for this vault?",
};
/// A role the wording ruling did not name (an answer back to unanswered).
const CHANGE_MACHINE: SentenceForms = SentenceForms {
    named: "Change how {name} is marked?",
    claimed: "Change how a {kind} is marked?\n{claim}",
    by_kind: "Change how a {kind} is marked?",
};
/// The line under a held answer's question: its machine key as a code
/// ([`machine_key_code`]), for the owner to compare with the code that
/// device shows.
const MACHINE_CODE: SentenceForms = SentenceForms {
    named: "Code shown on {name}: {code}",
    claimed: "Code shown on that {kind}: {code}\nCheck it on the device itself, not by its name.",
    by_kind: "Code shown on that {kind}: {code}",
};
/// The line under [`MACHINE_CODE`]: what the owner does with the code. A
/// surface draws it quiet. A device whose name is only its own report is
/// found by having it at hand, never by that name, so its form names no
/// device (the UI session's words, Engine TASK 17 Nov 08:32).
const MACHINE_CODE_CHECK: SentenceForms = SentenceForms {
    named: "It should match the code on {name}. If they differ, dismiss this.",
    claimed: "Check the code on the device itself, not by its name. If they differ, dismiss \
              this.",
    by_kind: "It should match the code on that {kind}. If they differ, dismiss this.",
};
/// In place of who asked, for a held answer a confirm refuses
/// ([`AuthorityFold::replaces_standing_keys`]).
const NAMES_OTHER_KEYS: &str =
    "This no longer matches the device. Dismiss it, then mark the device again.";

/// A recovery root's code, as the owner compares it between his kit and a
/// question: the first 128 bits of the root's id as 26 Crockford base32
/// symbols, the text form of a machine's request code. The code is all the
/// owner checks before he confirms, so it keeps 128 bits: nobody can make a
/// root whose code equals his kit's. The id in full stays the fingerprint the
/// pin door takes.
#[must_use]
pub fn recovery_root_code(root: &RecoveryRootId) -> String {
    first_128_bits_code(&root.0)
}

/// A machine key's code, in the form and by the derivation of a recovery
/// root's code ([`recovery_root_code`]): the key's first 128 bits as 26
/// symbols. The owner compares it with the code the machine itself shows
/// before he confirms a held answer about it.
#[must_use]
pub fn machine_key_code(machine_key: &[u8; 32]) -> String {
    first_128_bits_code(machine_key)
}

/// What a surface shows under a held answer's question: the answer's machine
/// key as its code, said of a device of `device_class` that `name` names. A
/// device named only by its own report gets a second line: the owner checks
/// the code on the device itself.
#[must_use]
pub fn machine_code_line(
    machine_key: &[u8; 32],
    device_class: MachineDeviceClass,
    name: PromptDeviceName<'_>,
) -> String {
    let code = machine_key_code(machine_key);
    MACHINE_CODE.say(device_class, Some(("{code}", &code)), name)
}

/// What a surface shows, quiet, under a held answer's code
/// ([`machine_code_line`]): that the code should match the one the device
/// shows, and to dismiss the answer when the two differ. Said of a device of
/// `device_class` that `name` names. A served field of its own, so every
/// surface says it in the same words.
#[must_use]
pub fn machine_code_check_line(
    device_class: MachineDeviceClass,
    name: PromptDeviceName<'_>,
) -> String {
    MACHINE_CODE_CHECK.say(device_class, None, name)
}

/// The first 128 bits of `id` as 26 Crockford base32 symbols.
fn first_128_bits_code(id: &[u8; 32]) -> String {
    let mut head = [0; 16];
    head.copy_from_slice(&id[..16]);
    super::machine_identity::code_text(&head)
}

/// `{role}` for `role`; `None` for the owner's own machine, which
/// [`ASKED_BY_KNOWN`] never names.
fn role_noun(role: MachineRole) -> Option<&'static str> {
    match role {
        MachineRole::Owned(MachineOwnership::Yours) => None,
        MachineRole::Owned(MachineOwnership::WorkSchool) => Some(WORK_SCHOOL_MACHINE),
        MachineRole::Owned(MachineOwnership::Rented) => Some(RENTED_MACHINE),
        MachineRole::HostedNode => Some(HOSTED_SERVER),
        MachineRole::ExecutionNode => Some(EXECUTION_NODE),
        MachineRole::Removed => Some(REMOVED_MACHINE),
        MachineRole::Unanswered => Some(UNANSWERED_MACHINE),
    }
}

impl CarrierReading {
    /// Who asked, as a question names them: the last line of a prompt.
    /// `name` is what this install holds as the name of the machine this
    /// reading ties the signing key to. It is said only for a machine the
    /// records know: never for a key they tie to no machine, whose machine
    /// id is the act's own word, and never for a machine the roster lists as
    /// the owner's that this install does not trust.
    #[must_use]
    pub fn asked_by(&self, name: PromptDeviceName<'_>) -> String {
        let Some((role, class)) = self.role.zip(self.device_class) else {
            return ASKED_BY_UNKNOWN.to_owned();
        };
        if self.is_mine {
            return ASKED_BY_YOURS.say(class, None, name);
        }
        match role_noun(role) {
            Some(noun) => ASKED_BY_KNOWN.say(class, Some(("{role}", noun)), name),
            None => ASKED_BY_LISTED_YOURS.replace("{kind}", class.wire()),
        }
    }
}

/// The question a surface asks before the owner pins `root` here for a
/// request `carrier` carried, as three lines: the question, the kit's code,
/// who asked. `carrier_name` is the carrier's name as
/// [`CarrierReading::asked_by`] takes it.
#[must_use]
pub fn pin_request_prompt(
    root: &RecoveryRootId,
    carrier: &CarrierReading,
    carrier_name: PromptDeviceName<'_>,
) -> String {
    format!(
        "{USE_KIT}\n{}\n{}",
        KIT_CODE.replace("{code}", &recovery_root_code(root)),
        carrier.asked_by(carrier_name)
    )
}

/// The question a surface asks about one held machine answer: the `role` it
/// asks for its device, said of a device of `device_class` that `name`
/// names, then on the last line who carried it. `carrier` is the reading of
/// the answer's carrier and that machine's name, `None` for an answer that
/// names no carrier. With `replaces_keys` the answer can only be dismissed,
/// and the last line says so in place of who asked.
#[must_use]
pub fn held_answer_prompt(
    role: MachineRole,
    device_class: MachineDeviceClass,
    name: PromptDeviceName<'_>,
    carrier: Option<(&CarrierReading, PromptDeviceName<'_>)>,
    replaces_keys: bool,
) -> String {
    let question = match role {
        MachineRole::Owned(MachineOwnership::Yours) => ADD_AS_YOURS,
        MachineRole::Owned(MachineOwnership::WorkSchool) => ADD_AS_WORK_SCHOOL,
        MachineRole::Owned(MachineOwnership::Rented) => ADD_AS_RENTED,
        MachineRole::Removed => REMOVE_MACHINE,
        MachineRole::HostedNode | MachineRole::ExecutionNode => RUN_WORK,
        MachineRole::Unanswered => CHANGE_MACHINE,
    };
    let asked_by = if replaces_keys {
        NAMES_OTHER_KEYS.to_owned()
    } else {
        carrier.map_or_else(
            || ASKED_BY_UNKNOWN.to_owned(),
            |(reading, carrier_name)| reading.asked_by(carrier_name),
        )
    };
    format!("{}\n{asked_by}", question.say(device_class, None, name))
}
