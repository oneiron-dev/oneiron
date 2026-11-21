//! Doors for `tests/voice_room_call.rs` (UNBUILT-02 PR 4): store a voice
//! session roster directly, without running a match pass. Compiled only
//! under `--cfg oneiron_test_support`; never API.

use crate::Vault;
use crate::conversation::voice_roster::VoiceSessionRosterV1;
use crate::error::Result;

/// Stores `roster` under the same digest and table the match run uses, so a
/// room call's kept turns label their speaker keys from it.
pub fn put_voice_session_roster(vault: &Vault, roster: &VoiceSessionRosterV1) -> Result<()> {
    crate::voice_identity::put_voice_roster_for_test(vault, roster)
}
