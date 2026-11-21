//! The owner's call-transcript choice (UNBUILT-02 PR 3): a catalogue key,
//! set and read through the Setting primitive's own verbs.

use crate::setting::Kind;

fn keep() -> bool {
    true
}

fn keep_nothing() -> bool {
    false
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
}
