//! The question an owner's surface asks before he confirms an act another
//! machine carried: a pending pin of a recovery root (FIX
//! [CARRIED-PIN-CONFIRM-PROMPT]) and a held machine answer (FIX
//! [HELD-ANSWER-PROMPT-CLIENT-UI]). The engine composes it, so every surface
//! shows the same words (CARRIED-PIN-PROMPT-SURFACE = A).
//!
//! Every word is a constant of this file: a surface session rewords here and
//! nowhere else (CARRIED-PIN-PROMPT-WORDING = A; these are that ruling's
//! draft sentences). `{code}` is the root's code, `{machine}` a device class
//! and `{role}` a role's noun.
//!
//! Who asked is read from [`CarrierReading`], this install's reading of the
//! key that signed the act, never from the machine id or the owner the act
//! names (CARRIED-PIN-PROMPT-HOSTED-CARRIER = A). A sentence says "your" only
//! for a key this install trusts as one of the owner's machines, and names no
//! machine at all for a key its records tie to none.

use super::*;

/// The question of a pending pin. The owner compares `{code}` with the code
/// his kit shows ([`recovery_root_code`]).
const USE_KIT: &str = "Use the recovery kit with code {code}?";

/// The carrier is a machine this install trusts as the owner's.
const ASKED_BY_YOURS: &str = "Your {machine} asked for it.";
/// This install's records tie the signing key to a machine that is not the
/// owner's own.
const ASKED_BY_KNOWN: &str = "A {machine} ({role}, not one of your devices) asked for it.";
/// The roster lists the signing key's machine as the owner's, and this
/// install does not trust it as his.
const ASKED_BY_LISTED_YOURS: &str = "A {machine} this vault lists as yours asked for it, but this \
     device cannot verify that. Only confirm if you started it yourself.";
/// This install's records tie the signing key to no machine.
const ASKED_BY_UNKNOWN: &str = "This request doesn't come from any device this vault knows. Only \
     confirm if you started it yourself.";

/// `{role}` of [`ASKED_BY_KNOWN`], for each role that is not the owner's own.
const HOSTED_SERVER: &str = "a hosted server";
const EXECUTION_NODE: &str = "an execution node";
const WORK_SCHOOL_MACHINE: &str = "a work or school machine";
const RENTED_MACHINE: &str = "a rented machine";
const REMOVED_MACHINE: &str = "a machine you removed";
const UNANSWERED_MACHINE: &str = "a linked machine you have not answered for";

/// The question of a held machine answer, by the role it asks for.
const ADD_AS_YOURS: &str = "Add a {machine} as one of your devices?";
const ADD_AS_WORK_SCHOOL: &str = "Add a {machine} as a work or school machine?";
const ADD_AS_RENTED: &str = "Add a {machine} as a rented machine?";
const REMOVE_MACHINE: &str = "Remove a {machine} from this vault?";
/// A hosted node or an execution node: what the machine will do, not a role
/// noun (HELD-MACHINE-PROMPT-WORDING = A).
const RUN_WORK: &str = "Let a {machine} run work for this vault?";
/// A role the wording ruling did not name (an answer back to unanswered).
const CHANGE_MACHINE: &str = "Change what a {machine} is to this vault?";
/// The line under a held answer's question: its machine key as a code
/// ([`machine_key_code`]), for the owner to compare with the code that
/// machine shows.
const MACHINE_CODE: &str = "Code shown on that machine: {code}";
/// In place of who asked, for a held answer a confirm refuses
/// ([`AuthorityFold::replaces_standing_keys`]).
const NAMES_OTHER_KEYS: &str = "It names different keys than this machine has. Dismiss it.";

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

/// The line a surface shows under a held answer's question: the answer's
/// machine key as its code.
#[must_use]
pub fn machine_code_line(machine_key: &[u8; 32]) -> String {
    MACHINE_CODE.replace("{code}", &machine_key_code(machine_key))
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
    /// Who asked, as a question names them: the last sentence of a prompt.
    #[must_use]
    pub fn asked_by(&self) -> String {
        let Some((role, class)) = self.role.zip(self.device_class) else {
            return ASKED_BY_UNKNOWN.to_owned();
        };
        let machine = class.wire();
        if self.is_mine {
            return ASKED_BY_YOURS.replace("{machine}", machine);
        }
        match role_noun(role) {
            Some(noun) => ASKED_BY_KNOWN
                .replace("{machine}", machine)
                .replace("{role}", noun),
            None => ASKED_BY_LISTED_YOURS.replace("{machine}", machine),
        }
    }
}

/// The question a surface asks before the owner pins `root` here for a
/// request `carrier` carried.
#[must_use]
pub fn pin_request_prompt(root: &RecoveryRootId, carrier: &CarrierReading) -> String {
    format!(
        "{} {}",
        USE_KIT.replace("{code}", &recovery_root_code(root)),
        carrier.asked_by()
    )
}

/// The question a surface asks about one held machine answer: the `role`
/// it asks for its machine, a `device_class`, then who carried it. `carrier`
/// is `None` for an answer that names no carrier. With `replaces_keys` the
/// answer can only be dismissed, and the sentence says so in place of who
/// asked.
#[must_use]
pub fn held_answer_prompt(
    role: MachineRole,
    device_class: MachineDeviceClass,
    carrier: Option<&CarrierReading>,
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
        carrier.map_or_else(|| ASKED_BY_UNKNOWN.to_owned(), CarrierReading::asked_by)
    };
    format!(
        "{} {asked_by}",
        question.replace("{machine}", device_class.wire())
    )
}
