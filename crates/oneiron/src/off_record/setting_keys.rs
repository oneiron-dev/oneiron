//! Off-record sessions' owner Setting keys (DESIGN 15-setting-primitive): rows the setting
//! catalogue reads from this file.

use crate::setting::{Kind, lower_is_tighter};

/// Off: a stretch entered alone goes on record on the owner's proof alone.
fn flip_alone_by_owner_alone() -> bool {
    false
}

crate::setting::setting_keys! {
    /// Let the creator of a stretch entered alone put it on record. Off by default: a stretch
    /// with no room goes on record ("from here on") only on the vault owner's proof. On, the
    /// person or agent who entered it puts it on record on their own live, unattenuated write
    /// slip, as a holder of this vault's write grant puts a room's stretch on record (ARCH-0052
    /// #d5-save-grant); the slip and this setting are checked at the flip and again at every
    /// landing, so turning it off stops the saving at the next landing. It never reaches the
    /// owner's own stretch or another creator's. On is the looser value, so only the owner
    /// turns it on; an agent's change waits on the owner's answer.
    pub(crate) OFF_RECORD_FLIP_ALONE_BY_HOLDER: bool = "off_record.flip_alone.by_holder" {
        kind: Kind::new(flip_alone_by_owner_alone)
            .strictest(flip_alone_by_owner_alone)
            .tighter(lower_is_tighter::<bool>),
    };
}
