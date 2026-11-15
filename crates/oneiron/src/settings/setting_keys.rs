//! The catalogue keys `settings` declares (DESIGN 15-setting-primitive, stages 1 and 2): the
//! owner's choices that each had a table, a codec and a setter, some of them recorded as an owner
//! act. The owner sets each through `vault.settings.set`; every change is one `SETTING_CHANGE`
//! row.

use crate::setting::{Kind, ReadBy, SettingSync};

use super::CustomizationSettings;
use super::backup::BackupChoice;
use super::undo_send::UndoSendSetting;

fn no_backup_choice() -> BackupChoice {
    BackupChoice(None)
}

const fn off() -> bool {
    false
}

const fn on() -> bool {
    true
}

crate::setting::setting_keys! {
    /// The owner's backup setting (FIX 5621): whether a running server backs up on its own, the
    /// hours between and the newest kept, one value for the whole choice. Null is no choice, and
    /// the deployment's `[backup]` section decides. A choice about this machine.
    pub(crate) BACKUP_POLICY: BackupChoice = "backup.policy" {
        kind: Kind::new(no_backup_choice),
        sync: SettingSync::Install,
    };
    /// The client's four-layer customization profile (SET-03): accent, type, mode and world.
    /// Every member of the vault reads it.
    pub(crate) CUSTOMIZATION: CustomizationSettings = "client.customization" {
        kind: Kind::new(CustomizationSettings::default),
        read_by: ReadBy::Members,
    };
    /// The owner's Responses `store` switch (OF-602): on, a provider keeps each response and a
    /// reconnected socket resumes the chain. Off by default; a row that does not decode reads
    /// off.
    pub(crate) RESPONSES_STORE: bool = "models.responses_store" {
        kind: Kind::new(off).strictest(off),
    };
    /// The owner's dial over proactive Dreamer plugin suggestions (ONE-1707): on by default, so
    /// an untouched vault suggests with no seeding step. A row that does not decode reads off,
    /// never on: a disabled knob that read back as enabled would resume suggestions the owner
    /// switched off.
    pub(crate) PLUGIN_SUGGESTIONS: bool = "dreamer.plugin_suggestions" {
        kind: Kind::new(on).strictest(off),
    };
    /// The owner's switch over an Admin walking into a private room thread (owner ruling
    /// 2026-10-20, FIX 6382): off, an Admin may not walk in, from now on. On by default: a vault
    /// that never set it lets its Admins walk in. The Owner never depends on it.
    pub(crate) ROOM_THREADS_ADMIN_WALK_IN: bool = "rooms.private_threads.admin_walk_in" {
        kind: Kind::new(on),
    };
    /// The owner's switch over an Admin deleting a private room thread (owner ruling 2026-10-20,
    /// FIX 6382): off, an Admin may not delete one. On by default. The Owner never depends on it.
    pub(crate) ROOM_THREADS_ADMIN_DELETE: bool = "rooms.private_threads.admin_delete" {
        kind: Kind::new(on),
    };
    /// The owner's undo-send window (DEC-0006 #undo-send; REV-8 = B): the seconds every send
    /// waits on every outbound channel, and each channel's own length, before it goes. Off by
    /// default: every send goes at once.
    pub(crate) UNDO_SEND: UndoSendSetting = "outbound.undo_send" {
        kind: Kind::new(UndoSendSetting::default),
    };
}
