//! The catalogue keys `settings` declares (DESIGN 15-setting-primitive, stages 1 and 2): the
//! owner's choices that each had a table, a codec and a setter, some of them recorded as an owner
//! act. The owner sets each through `vault.settings.set`; every change is one `SETTING_CHANGE`
//! row.

use crate::federation::EngineControlClass;
use crate::setting::{ItemDomain, Kind, ReadBy, Restore, SetBy, SettingSync};

use super::CustomizationSettings;
use super::backup::BackupChoice;
use super::board_layout::{BoardLayoutSettings, check_agent_overrides_in_txn, drop_agent_override};
use super::models::is_offer_key;
use super::non_base_world_claim_fraction::NonBaseWorldClaimFraction;
use super::snapshot_read::{SnapshotReadSettings, bounds_at_most};
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

const fn no_model_fallback() -> Option<String> {
    None
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
    /// The owner's non-base world claim fraction (ARCH-0004 #world-scope): the most of a context
    /// pack's claims that worlds other than base may hold, from 0 (base reality alone) to 1 (no
    /// cap); 0.5 by default. The owner alone sets it. It is a dial: a holder of any
    /// `engine.controls` class reads it.
    pub(crate) NON_BASE_WORLD_CLAIM_FRACTION: NonBaseWorldClaimFraction = "recall.non_base_world_claim_fraction" {
        kind: Kind::new(NonBaseWorldClaimFraction::default),
        read_by: ReadBy::Dials,
    };
    /// The bounds on primitive A's snapshot handles (slice 6.4b): open handles per actor, the
    /// default and the most lifetime, rows and bytes per page, and rows per handle. A holder of
    /// `engine.controls.work_budget` tunes them at or below the owner's, or below the defaults
    /// while the owner set none; a lower bound is the tighter one. It is a dial, and it travels
    /// with a restore, as its table did.
    pub(crate) SNAPSHOT_READ_BOUNDS: SnapshotReadSettings = "snapshot_read.bounds" {
        kind: Kind::new(SnapshotReadSettings::default).tighter(bounds_at_most),
        set_by: SetBy::Class(EngineControlClass::WorkBudget),
        read_by: ReadBy::Dials,
        restore: Restore::Content,
    };
    /// The owner's board cap and layout layers (BOARD-LAYOUT = A): the cap, the default layout an
    /// agent's board renders under until it lays out its own, the override whose sections win
    /// over every agent's own, and one agent's override, which wins over both. Empty by default.
    /// An override set names an agent the vault holds; an erase of an agent takes its override
    /// out (FIX 3520).
    pub(crate) BOARD_LAYOUT: BoardLayoutSettings = "context_board.layout" {
        kind: Kind::new(BoardLayoutSettings::default).erase_mentions(drop_agent_override),
        on_change: Some(check_agent_overrides_in_txn),
    };
    /// The owner's standing quota fallback for one model offer (OF-305; item: the offer's key,
    /// 64 hex): the engine model id its calls go to while the offer is parked. Null names none.
    /// The engine applies the owner's `use_fallback` answer to a quota question.
    pub(crate) MODEL_OWNER_FALLBACK: Option<String> = "models.owner_fallback" {
        kind: Kind::new(no_model_fallback),
        item: Some(ItemDomain { name: "model offers", admits: is_offer_key }),
    };
}
