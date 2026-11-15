//! The owner's call-transcript choices (UNBUILT-02 PR 3 and 3B) and what a
//! phone line's agent can see while on a call (VOICE-PHONE-AGENT-REACH R2):
//! catalogue keys, set and read through the Setting primitive's own verbs.

use super::reach::{PhoneReach, reach_default, reach_tighter};
use crate::entity_id::EntityId;
use crate::setting::{ItemDomain, Kind, ScopeKind, SetBy};

fn keep() -> bool {
    true
}

fn keep_nothing() -> bool {
    false
}

fn announce() -> bool {
    true
}

/// Whether `item` names a phone line: a canonical 32-char lower hex
/// ChannelIdentity id. Shape only; "a live line" is not checked here.
fn phone_line_item(item: &str) -> bool {
    EntityId::from_hex(item).is_ok_and(|id| id.to_hex() == item)
}

crate::setting::setting_keys! {
    /// Keep transcripts of calls with other people. Each call is kept like any
    /// other conversation, the other speaker's words labelled as theirs, between
    /// a row where the call starts and one where it ends; with this off, only
    /// those two rows are kept. Recording-consent rules differ by place, and
    /// the vault's owner chooses.
    pub CALL_TRANSCRIPTS_KEEP: bool = "voice.call_transcripts.keep" {
        kind: Kind::new(keep).strictest(keep_nothing),
    };
    /// Announce at the start of a call that it is transcribed. The agent says
    /// so in its first words, as call recorders do; with this off it says
    /// nothing before the other person speaks. Recording-consent rules differ
    /// by place, and the vault's owner chooses.
    pub CALL_TRANSCRIPTS_ANNOUNCE: bool = "voice.call_transcripts.announce" {
        kind: Kind::new(announce).strictest(announce),
    };
    /// What the phone agent can see while on a call, one choice per phone line. By default it sees
    /// only this caller's own history and the documents you pick; or the whole vault; or a custom
    /// scope you define or an agent proposes. Under the whole vault, or a custom scope that
    /// includes other callers, the agent may repeat what other callers said. The line's agent may
    /// narrow its own reach; any widening asks you first.
    pub CALL_REACH: PhoneReach = "voice.phone.reach" {
        kind: Kind::new(reach_default).strictest(reach_default).tighter(reach_tighter),
        scopes: &[ScopeKind::Vault, ScopeKind::Agent],
        item: Some(ItemDomain { name: "phone lines", admits: phone_line_item }),
        set_by: SetBy::Subject,
    };
}
