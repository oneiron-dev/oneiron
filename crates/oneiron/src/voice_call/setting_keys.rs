//! The owner's call-transcript choices (UNBUILT-02 PR 3 and 3B): catalogue
//! keys, set and read through the Setting primitive's own verbs.

use crate::setting::Kind;

fn keep() -> bool {
    true
}

fn keep_nothing() -> bool {
    false
}

fn announce() -> bool {
    true
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
}
