//! The machine policy keys (pass 34 DESIGN 2.4, and of 6.3 the cache budget, `placement.cache.*`,
//! and the readiness period, `jobs.readiness.every_secs`):
//! one row per machine (the item is its MACHINE id), or per machine and device, or per machine and
//! template (`<machine>/<name>`). An item-less row holds for every machine that has no row of its
//! own. Each is the owner's, travels with the vault as his signed act, and states what tighter is.

use super::{
    CachePolicy, DeviceOffer, DrainClearBy, ExecutionState, FreeForm, KeepHeadroom, MachineAccepts,
    MachineExecution, MachineWindows, READINESS_EVERY_SECS_DEFAULT, TemplateNetwork, WorkRoles,
    admits_machine, admits_machine_part, drain_clear_by_no_wider, free_form_no_wider,
};
use crate::setting::{ItemDomain, Kind};

const MACHINES: ItemDomain = ItemDomain {
    name: "machines",
    admits: admits_machine,
};

const MACHINE_DEVICES: ItemDomain = ItemDomain {
    name: "machine devices",
    admits: admits_machine_part,
};

const MACHINE_TEMPLATES: ItemDomain = ItemDomain {
    name: "machine templates",
    admits: admits_machine_part,
};

fn execution_draining() -> MachineExecution {
    MachineExecution {
        state: ExecutionState::Draining,
        until_ms: Some(0),
    }
}

fn accepts_any() -> MachineAccepts {
    MachineAccepts::Any
}

fn accepts_resumable_only() -> MachineAccepts {
    MachineAccepts::ResumableOnly
}

fn free_form_off() -> FreeForm {
    FreeForm::Off
}

fn clear_after_readiness_check() -> DrainClearBy {
    DrainClearBy::AfterReadinessCheck
}

fn clear_by_person_at_box() -> DrainClearBy {
    DrainClearBy::PersonAtBox
}

fn device_withheld() -> DeviceOffer {
    DeviceOffer {
        offered: false,
        max_claimants: 1,
    }
}

fn no_network() -> TemplateNetwork {
    TemplateNetwork::default()
}

fn cache_cap_gib() -> u64 {
    CachePolicy::DEFAULT.cap_gib
}

fn cache_idle_days() -> u32 {
    CachePolicy::DEFAULT.idle_days
}

fn cache_protect_hours() -> u32 {
    CachePolicy::DEFAULT.protect_hours
}

fn cache_wanted_hold_secs() -> u64 {
    CachePolicy::DEFAULT.wanted_hold_secs
}

fn cache_keys_max() -> u32 {
    CachePolicy::DEFAULT.keys_max
}

fn readiness_every_secs() -> u64 {
    READINESS_EVERY_SECS_DEFAULT
}

crate::setting::setting_keys! {
    /// Whether the machine takes work: `state` is `on`; `paused` (no new work, and running work
    /// goes on: the panel's "off"); or `draining` (no new work, and work with a task boundary is
    /// closed at its next one), whose optional `until_ms` is when the panel offers to stop the
    /// rest; nothing is stopped by a clock alone. Default `on`, once the machine's own box file
    /// enables the service. `paused` is tighter than `on`, `draining` tighter still, and a sooner
    /// time tighter: an agent you gave this key may pause or drain a machine at once, and needs
    /// you to turn it back on.
    pub(crate) EXECUTION: MachineExecution = "machines.execution" {
        kind: Kind::new(MachineExecution::on).strictest(execution_draining).each(),
        item: Some(MACHINES),
    };
    /// Which work the machine takes: `any` (the default), or `resumable_only`, work that can be
    /// closed at a boundary and continued on another machine. `resumable_only` is tighter.
    pub(crate) MACHINE_ACCEPTS: MachineAccepts = "machines.accepts" {
        kind: Kind::new(accepts_any).strictest(accepts_resumable_only).chain(),
        item: Some(MACHINES),
    };
    /// What work leaves free on the machine for your own use: CPU threads, memory in MiB and
    /// payload disk in GiB. Default nothing kept. The machine gives work the lesser of its box
    /// file's figure and its total less this; more kept free is tighter, field by field.
    pub(crate) KEEP_HEADROOM: KeepHeadroom = "machines.keep_headroom" {
        kind: Kind::new(KeepHeadroom::default).each(),
        item: Some(MACHINES),
    };
    /// When the machine takes new work: the hours of the week in UTC (0 is Monday 00:00 to 01:00
    /// UTC, 167 is Sunday 23:00 to 24:00), and whether only on mains power. Default every hour, on
    /// any power. Fewer hours, and mains power only, are tighter.
    pub(crate) WINDOWS: MachineWindows = "machines.windows" {
        kind: Kind::new(MachineWindows::always).each(),
        item: Some(MACHINES),
    };
    /// What the machine is for, in your words: `experiments`, `agents`, `builds`, `interactive`,
    /// `storage`, `spill`, or another lowercase word. Placement sends work to machines by role.
    /// Default none: the machine takes any work. It guards nothing, so it has no tighter side.
    pub(crate) WORK_ROLES: WorkRoles = "machines.work_roles" {
        kind: Kind::new(WorkRoles::default).neutral(),
        item: Some(MACHINES),
    };
    /// Whether one device of the machine is offered to work, and to how many claims at once
    /// (`max_claimants`, inside the box's own cap). One row per machine and device, its item
    /// `<machine>/<device id>`. Default offered, to one claim. Withheld, and fewer claims, are
    /// tighter.
    pub(crate) DEVICES_OFFERED: DeviceOffer = "machines.devices.offered" {
        kind: Kind::new(DeviceOffer::default).strictest(device_withheld).each(),
        item: Some(MACHINE_DEVICES),
    };
    /// The network modes open to one template on the machine, inside the template's own list:
    /// `none` (its own empty network) and `host`. One row per machine and template, its item
    /// `<machine>/<template name>`. Default `["none"]`: a template the box lets use the host's
    /// network gets it only once you open it here. Fewer modes are tighter.
    pub(crate) TEMPLATES_NETWORK: TemplateNetwork = "machines.templates.network" {
        kind: Kind::new(no_network).strictest(no_network).subset(),
        item: Some(MACHINE_TEMPLATES),
    };
    /// Who may start a free-form command on the machine: `off` (the default), `owner` (you, by
    /// your device key, one command at a time), or `grants` (you, and these Grants until
    /// `until_ms`). `owner` is tighter than `grants`, and `off` tighter still. No machine runs a
    /// free-form command before the free-form row lands.
    pub(crate) FREE_FORM: FreeForm = "machines.free_form" {
        kind: Kind::new(free_form_off)
            .strictest(free_form_off)
            .custom(free_form_no_wider),
        item: Some(MACHINES),
    };
    /// Who clears the machine's drain: `after_readiness_check` (the machine itself, once its
    /// readiness check passes; the default), `grants` (you, and these Grants), `owner` (you), or
    /// `person_at_box` (someone at the machine). Each is tighter than the one before it.
    pub(crate) DRAIN_CLEAR_BY: DrainClearBy = "machines.drain.clear_by" {
        kind: Kind::new(clear_after_readiness_check)
            .strictest(clear_by_person_at_box)
            .custom(drain_clear_by_no_wider),
        item: Some(MACHINES),
    };
    /// The most the template caches on the machine hold together, in GiB; above it the least
    /// recently used cache key goes first. Default 150. Smaller is tighter: an agent you gave
    /// this key may lower it at once, and needs you to raise it.
    pub(crate) CACHE_CAP_GIB: u64 = "placement.cache.cap_gib" {
        kind: Kind::new(cache_cap_gib).lower(),
        item: Some(MACHINES),
    };
    /// After how many days unused a cache key on the machine goes, whatever the total. Default 3.
    /// Fewer days are tighter.
    pub(crate) CACHE_IDLE_DAYS: u32 = "placement.cache.idle_days" {
        kind: Kind::new(cache_idle_days).lower(),
        item: Some(MACHINES),
    };
    /// For how many hours after its last use a cache key on the machine is never removed for the
    /// cap. Default 6. Fewer hours are tighter.
    pub(crate) CACHE_PROTECT_HOURS: u32 = "placement.cache.protect_hours" {
        kind: Kind::new(cache_protect_hours).lower(),
        item: Some(MACHINES),
    };
    /// For how many seconds a cache key that an open order of a live issuer last asked for is
    /// kept after that ask. Default 900. Fewer seconds are tighter.
    pub(crate) CACHE_WANTED_HOLD_SECS: u64 = "placement.cache.wanted_hold_secs" {
        kind: Kind::new(cache_wanted_hold_secs).lower(),
        item: Some(MACHINES),
    };
    /// The most warm keys the machine's execution node remembers; a key with no path is
    /// forgotten first. Default 256. Fewer keys are tighter.
    pub(crate) CACHE_KEYS_MAX: u32 = "placement.cache.keys_max" {
        kind: Kind::new(cache_keys_max).lower(),
        item: Some(MACHINES),
    };
    /// How often, in seconds, the machine's execution node checks itself while no work runs on
    /// it: its probes, its free disk, its template mirrors and its clock. A failed check drains
    /// the machine, and a passed one may clear the drain (`machines.drain.clear_by`). Default 900;
    /// 0 checks at every step of the node. Shorter is tighter: an agent you gave this key may
    /// shorten it at once, and needs you to lengthen it. The node checks at the shorter of this
    /// and its box file's `readiness_every_secs`.
    pub(crate) READINESS_EVERY_SECS: u64 = "jobs.readiness.every_secs" {
        kind: Kind::new(readiness_every_secs).lower(),
        item: Some(MACHINES),
    };
}
