//! The owner's policy for each of his machines (pass 34, `34-compute-general/DESIGN.md` section
//! 2.4; EM-17 = A): the switches of the control panel's "My machines", as setting rows of family
//! keys whose item is the machine.
//!
//! Every key is the owner's to set (`SetBy::Owner`), travels with the vault (`sync: vault`) and
//! holds a closed value, so in a rooted vault the owner's change is his signed act carrying the
//! value, and every machine writes the row from the acts its own fold counts
//! (`crate::setting::project`). A row a person, an agent or the engine changed on one install
//! stays on that install (RULING SETTING-7A-2-DECIDERS = A): another machine's engine never moves
//! a row here. A holder of a key's Grant line tightens it at once, and its loosening asks the owner
//! (the move rule, `crate::setting::set`).
//!
//! Each key declares what "tighter" means, so the stricter of two values is the order's own
//! answer, both for two surfaces that change one row at once and for the execution node, which
//! applies the stricter of its box file and these rows:
//! - [`MachineExecution`]: `on`, then `paused`, then `draining`, and a sooner `until_ms`;
//! - [`MachineAccepts`]: `any`, then `resumable_only`;
//! - [`KeepHeadroom`]: more kept free, field by field;
//! - [`MachineWindows`]: fewer hours, and mains power only;
//! - [`WorkRoles`]: neutral, it guards nothing;
//! - [`DeviceOffer`]: withheld, and fewer claimants;
//! - [`TemplateNetwork`]: fewer network modes;
//! - [`FreeForm`]: `grants`, then `owner`, then `off`;
//! - [`DrainClearBy`]: towards `person_at_box`;
//! - the five `placement.cache.*` keys of [`CachePolicy`]: a smaller figure;
//! - `jobs.readiness.every_secs`: a shorter period.
//!
//! [`Vault::machine_policy`] reads every key for one machine in one read, as this install's rows
//! give them.

pub(crate) mod setting_keys;

use std::collections::{BTreeMap, BTreeSet};

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::job_workload::NetworkMode;
use crate::setting::{ChainOrder, SettingValue};
use crate::vault::Vault;

/// The hours in a week: [`MachineWindows::hours`] holds a subset of `0..HOURS_PER_WEEK`.
pub const HOURS_PER_WEEK: u8 = 168;

/// The hour of the week of the Unix epoch, Thursday 00:00 UTC, counted from Monday 00:00 UTC.
const EPOCH_HOUR_OF_WEEK: u64 = 72;

/// The most Grants one [`FreeForm::Grants`] or [`DrainClearBy::Grants`] names.
pub const GRANTS_MAX: usize = 16;

/// The most work roles one machine holds.
pub const WORK_ROLES_MAX: usize = 16;

/// The longest work role, in bytes.
pub const WORK_ROLE_MAX_BYTES: usize = 32;

/// The default of `jobs.readiness.every_secs`: how often, in seconds, a machine's execution node
/// checks itself while no work runs on it (pass 34 DESIGN 6.3 and 7.3).
pub const READINESS_EVERY_SECS_DEFAULT: u64 = 900;

/// Whether a machine takes work: the state of `machines.execution`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ExecutionState {
    /// It takes new work.
    On,
    /// No new work; running work goes on (the panel's "off").
    Paused,
    /// No new work; work with a task boundary is closed at it (row P3), and work without one runs
    /// to its end.
    Draining,
}

impl ChainOrder for ExecutionState {
    const STRICTEST_FIRST: &'static [Self] = &[Self::Draining, Self::Paused, Self::On];
}

/// `machines.execution`: whether the machine takes work, and for a drain when the owner's panel
/// offers to stop the rest. Rows meet part by part (the stricter state, the sooner time), so a
/// holder may pause or drain over the owner's own `on` at once.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct MachineExecution {
    /// `on`, `paused` or `draining`.
    pub state: ExecutionState,
    /// A drain's time: when the owner's panel offers to stop what still runs. Nothing is stopped
    /// by a clock alone (DESIGN 4.6). Only a draining value names one; a sooner time is tighter.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub until_ms: Option<u64>,
}

oneiron_setting_contract::each_order!(MachineExecution {
    state: chain,
    until_ms: lower_or_absent(oneiron_setting_contract::AbsentEnd::Loosest),
});

impl MachineExecution {
    /// On: the default.
    #[must_use]
    pub const fn on() -> Self {
        Self {
            state: ExecutionState::On,
            until_ms: None,
        }
    }

    /// Whether the machine takes new work under this value.
    #[must_use]
    pub const fn takes_new_work(&self) -> bool {
        matches!(self.state, ExecutionState::On)
    }
}

impl SettingValue for MachineExecution {
    const CLOSED: bool = true;

    /// Only a draining value names a time.
    ///
    /// # Errors
    ///
    /// `InvalidConfig` for `until_ms` on `on` or `paused`.
    fn check(self) -> Result<Self> {
        if self.until_ms.is_some() && self.state != ExecutionState::Draining {
            return Err(Error::InvalidConfig(
                "machines.execution: only a draining machine names until_ms".into(),
            ));
        }
        Ok(self)
    }
}

/// `machines.accepts`: which work the machine takes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum MachineAccepts {
    /// Any work.
    Any,
    /// Only work that can be closed at a boundary and continued elsewhere.
    ResumableOnly,
}

impl ChainOrder for MachineAccepts {
    const STRICTEST_FIRST: &'static [Self] = &[Self::ResumableOnly, Self::Any];
}

impl SettingValue for MachineAccepts {
    const CLOSED: bool = true;
}

/// `machines.keep_headroom`: what placement and the execution node leave free on the machine for
/// its owner's own use. More kept free is tighter, field by field.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct KeepHeadroom {
    /// CPU threads kept free.
    #[serde(default)]
    pub threads: u32,
    /// Memory kept free, in MiB.
    #[serde(default)]
    pub memory_mib: u64,
    /// Payload disk kept free, in GiB.
    #[serde(default)]
    pub disk_gib: u64,
}

oneiron_setting_contract::each_order!(KeepHeadroom {
    threads: higher,
    memory_mib: higher,
    disk_gib: higher,
});

impl SettingValue for KeepHeadroom {
    const CLOSED: bool = true;
}

/// `machines.windows`: when the machine takes new work.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct MachineWindows {
    /// The hours of the week, in UTC, during which it takes new work: 0 is Monday 00:00 to 01:00
    /// UTC and 167 is Sunday 23:00 to 24:00. Every hour is "always"; fewer hours are tighter.
    pub hours: BTreeSet<u8>,
    /// It takes new work only while it runs on mains power; tighter when true.
    #[serde(default)]
    pub mains_only: bool,
}

oneiron_setting_contract::each_order!(MachineWindows {
    hours: subset,
    mains_only: higher,
});

impl MachineWindows {
    /// Every hour of the week, on any power: the default.
    #[must_use]
    pub fn always() -> Self {
        Self {
            hours: (0..HOURS_PER_WEEK).collect(),
            mains_only: false,
        }
    }

    /// Whether `unix_ms` falls in one of the hours.
    #[must_use]
    pub fn covers(&self, unix_ms: u64) -> bool {
        let hour = (unix_ms / 3_600_000 + EPOCH_HOUR_OF_WEEK) % u64::from(HOURS_PER_WEEK);
        u8::try_from(hour).is_ok_and(|hour| self.hours.contains(&hour))
    }
}

impl SettingValue for MachineWindows {
    const CLOSED: bool = true;

    /// Every hour is below [`HOURS_PER_WEEK`].
    ///
    /// # Errors
    ///
    /// `InvalidConfig` for an hour past the week.
    fn check(self) -> Result<Self> {
        if let Some(hour) = self.hours.iter().find(|hour| **hour >= HOURS_PER_WEEK) {
            return Err(Error::InvalidConfig(format!(
                "machines.windows: an hour of the week is 0 to 167, not {hour}"
            )));
        }
        Ok(self)
    }
}

/// `machines.work_roles`: what the machine is for, in the owner's words (`experiments`,
/// `agents`, `builds`, `interactive`, `storage`, `spill`, or another). Each role is one lowercase
/// word of `a-z`, `0-9` and `_`, as a catalogue name is, so the value is closed. An empty set takes
/// any work. Neutral: it routes work and guards nothing.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(transparent)]
pub struct WorkRoles(pub BTreeSet<String>);

impl SettingValue for WorkRoles {
    const CLOSED: bool = true;

    /// At most [`WORK_ROLES_MAX`] roles, each a word of 1 to [`WORK_ROLE_MAX_BYTES`] bytes of
    /// `a-z`, `0-9` and `_`.
    ///
    /// # Errors
    ///
    /// `InvalidConfig` naming the role that is not such a word, or the count past the cap.
    fn check(self) -> Result<Self> {
        if self.0.len() > WORK_ROLES_MAX {
            return Err(Error::InvalidConfig(format!(
                "machines.work_roles holds at most {WORK_ROLES_MAX} roles"
            )));
        }
        if let Some(role) = self.0.iter().find(|role| !role_word(role)) {
            return Err(Error::InvalidConfig(format!(
                "machines.work_roles: a role is 1 to {WORK_ROLE_MAX_BYTES} bytes of a-z, 0-9 and _, not `{role}`"
            )));
        }
        Ok(self)
    }
}

fn role_word(role: &str) -> bool {
    (1..=WORK_ROLE_MAX_BYTES).contains(&role.len())
        && role
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_')
}

/// `machines.devices.offered`, one row per machine and device: whether the device is offered to
/// work, and to how many claimants at once, inside the box's own cap.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DeviceOffer {
    /// Offered; withheld (false) is tighter.
    pub offered: bool,
    /// The most claims that hold it at once, at least 1; fewer is tighter. Counting shared claims
    /// comes with the first device whose owner raises it (pass 34 9.2, R3a (a)).
    pub max_claimants: u32,
}

oneiron_setting_contract::each_order!(DeviceOffer {
    offered: lower,
    max_claimants: lower,
});

impl Default for DeviceOffer {
    fn default() -> Self {
        Self {
            offered: true,
            max_claimants: 1,
        }
    }
}

impl SettingValue for DeviceOffer {
    const CLOSED: bool = true;

    /// `max_claimants` is at least 1: a device no claim may hold is withheld.
    ///
    /// # Errors
    ///
    /// `InvalidConfig` for a zero count.
    fn check(self) -> Result<Self> {
        if self.max_claimants == 0 {
            return Err(Error::InvalidConfig(
                "machines.devices.offered: max_claimants is at least 1; withhold the device with offered = false"
                    .into(),
            ));
        }
        Ok(self)
    }
}

/// `machines.templates.network`, one row per machine and template: the network modes the owner
/// opens to the template, inside the template's own list. Fewer is tighter.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(transparent)]
pub struct TemplateNetwork(pub BTreeSet<NetworkMode>);

impl Default for TemplateNetwork {
    /// No network.
    fn default() -> Self {
        Self(BTreeSet::from([NetworkMode::None]))
    }
}

impl oneiron_setting_contract::SetOrder for TemplateNetwork {
    type Member = NetworkMode;

    fn members(&self) -> BTreeSet<NetworkMode> {
        self.0.clone()
    }

    fn from_members(members: BTreeSet<NetworkMode>) -> Self {
        Self(members)
    }
}

impl SettingValue for TemplateNetwork {
    const CLOSED: bool = true;
}

/// `machines.free_form`: who may start a free-form command on the machine (row W2; every node
/// refuses free-form until it lands).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "mode", rename_all = "snake_case", deny_unknown_fields)]
pub enum FreeForm {
    /// Nobody.
    Off,
    /// The owner himself, by his device key, one command at a time.
    Owner,
    /// The owner, and these Grants until a time.
    Grants {
        /// The Grants permitted, at most [`GRANTS_MAX`].
        grants: BTreeSet<EntityId>,
        /// When the permit ends.
        until_ms: u64,
    },
}

impl FreeForm {
    /// The strictness rank: `grants` 0, `owner` 1, `off` 2.
    const fn rank(&self) -> u8 {
        match self {
            Self::Grants { .. } => 0,
            Self::Owner => 1,
            Self::Off => 2,
        }
    }
}

impl SettingValue for FreeForm {
    const CLOSED: bool = true;

    /// At most [`GRANTS_MAX`] Grants, and at least one.
    ///
    /// # Errors
    ///
    /// `InvalidConfig` for an empty or over-long list.
    fn check(self) -> Result<Self> {
        if let Self::Grants { grants, .. } = &self {
            check_grants("machines.free_form", grants)?;
        }
        Ok(self)
    }
}

/// The comparator of `machines.free_form`: a stricter mode, or the same Grants or fewer until the
/// same time or earlier.
pub(crate) fn free_form_no_wider(a: &FreeForm, b: &FreeForm) -> bool {
    match (a, b) {
        (
            FreeForm::Grants {
                grants: a_grants,
                until_ms: a_until,
            },
            FreeForm::Grants {
                grants: b_grants,
                until_ms: b_until,
            },
        ) => a_grants.is_subset(b_grants) && a_until <= b_until,
        _ => a.rank() >= b.rank(),
    }
}

/// `machines.drain.clear_by`: who clears the machine's drain.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "by", rename_all = "snake_case", deny_unknown_fields)]
pub enum DrainClearBy {
    /// The machine itself, once its readiness check passes.
    AfterReadinessCheck,
    /// The owner, and these Grants.
    Grants {
        /// The Grants that may clear it, at most [`GRANTS_MAX`].
        grants: BTreeSet<EntityId>,
    },
    /// The owner.
    Owner,
    /// A person at the box (`oneiron execution-node resume`).
    PersonAtBox,
}

impl DrainClearBy {
    /// The strictness rank: `after_readiness_check` 0, `grants` 1, `owner` 2, `person_at_box` 3.
    const fn rank(&self) -> u8 {
        match self {
            Self::AfterReadinessCheck => 0,
            Self::Grants { .. } => 1,
            Self::Owner => 2,
            Self::PersonAtBox => 3,
        }
    }
}

impl SettingValue for DrainClearBy {
    const CLOSED: bool = true;

    /// At most [`GRANTS_MAX`] Grants, and at least one.
    ///
    /// # Errors
    ///
    /// `InvalidConfig` for an empty or over-long list.
    fn check(self) -> Result<Self> {
        if let Self::Grants { grants } = &self {
            check_grants("machines.drain.clear_by", grants)?;
        }
        Ok(self)
    }
}

/// The comparator of `machines.drain.clear_by`: nearer to `person_at_box`, or the same Grants or
/// fewer.
pub(crate) fn drain_clear_by_no_wider(a: &DrainClearBy, b: &DrainClearBy) -> bool {
    match (a, b) {
        (DrainClearBy::Grants { grants: a_grants }, DrainClearBy::Grants { grants: b_grants }) => {
            a_grants.is_subset(b_grants)
        }
        _ => a.rank() >= b.rank(),
    }
}

fn check_grants(key: &str, grants: &BTreeSet<EntityId>) -> Result<()> {
    if grants.is_empty() || grants.len() > GRANTS_MAX {
        return Err(Error::InvalidConfig(format!(
            "{key}: grants names 1 to {GRANTS_MAX} Grants"
        )));
    }
    Ok(())
}

/// The owner's budget for the template caches on one machine (`placement.cache.*`, pass 34 6.3):
/// what the execution node's cache pass may keep on the machine's disk. Each figure is its own
/// key, and a smaller figure is tighter: less is kept. The node applies the smaller of each figure
/// and its box file's.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CachePolicy {
    /// `placement.cache.cap_gib`: the most the machine's template caches hold together, in GiB;
    /// above it the least recently used key goes first.
    pub cap_gib: u64,
    /// `placement.cache.idle_days`: a cache key unused this many days goes, whatever the total.
    pub idle_days: u32,
    /// `placement.cache.protect_hours`: a cache key used within this many hours is never removed
    /// for the cap.
    pub protect_hours: u32,
    /// `placement.cache.wanted_hold_secs`: how long a key that an open order of a live issuer last
    /// asked for is kept after that ask, in seconds.
    pub wanted_hold_secs: u64,
    /// `placement.cache.keys_max`: the most warm keys the node's table remembers; a key with no
    /// path is forgotten first.
    pub keys_max: u32,
}

impl CachePolicy {
    /// Every figure's default: 150 GiB, 3 days, 6 hours, 900 s and 256 keys.
    pub const DEFAULT: Self = Self {
        cap_gib: 150,
        idle_days: 3,
        protect_hours: 6,
        wanted_hold_secs: 900,
        keys_max: 256,
    };
}

impl Default for CachePolicy {
    fn default() -> Self {
        Self::DEFAULT
    }
}

/// The item of a machine's row: its MACHINE id, 32 lower hex.
#[must_use]
pub fn machine_item(machine: EntityId) -> String {
    machine.to_hex()
}

/// The item of a row for one device or one template of a machine: `<machine>/<name>`.
#[must_use]
pub fn machine_part_item(machine: EntityId, name: &str) -> String {
    format!("{}/{name}", machine.to_hex())
}

/// Whether `item` is a canonical MACHINE id.
pub(crate) fn admits_machine(item: &str) -> bool {
    EntityId::from_lower_hex(item).is_ok()
}

/// Whether `item` is `<machine>/<name>`: a canonical MACHINE id, a `/`, and a non-empty name.
pub(crate) fn admits_machine_part(item: &str) -> bool {
    item.split_once('/')
        .is_some_and(|(machine, name)| admits_machine(machine) && !name.is_empty())
}

/// The owner's policy for one machine, as this install reads it now: every key of section 2.4,
/// each the value in force (the key's default where no row decides).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MachinePolicy {
    /// `machines.execution`.
    pub execution: MachineExecution,
    /// `machines.accepts`.
    pub accepts: MachineAccepts,
    /// `machines.keep_headroom`.
    pub keep_headroom: KeepHeadroom,
    /// `machines.windows`.
    pub windows: MachineWindows,
    /// `machines.work_roles`.
    pub work_roles: WorkRoles,
    /// `machines.free_form`.
    pub free_form: FreeForm,
    /// `machines.drain.clear_by`.
    pub drain_clear_by: DrainClearBy,
    /// The five `placement.cache.*` keys.
    pub cache: CachePolicy,
    /// `jobs.readiness.every_secs`.
    pub readiness_every_secs: u64,
    /// `machines.devices.offered` for each device asked for, by its id.
    pub devices: BTreeMap<String, DeviceOffer>,
    /// `machines.templates.network` for each template asked for, by its name.
    pub template_network: BTreeMap<String, TemplateNetwork>,
}

impl Vault {
    /// The owner's policy for `machine`, as this install's rows give it, read in one snapshot:
    /// the machine's keys, and `machines.devices.offered` for each of `devices` and
    /// `machines.templates.network` for each of `templates`. A row reads as the setting read
    /// reads it: an unreadable deciding row reads the key's strictest value.
    ///
    /// # Errors
    ///
    /// Storage errors; a device id or a template name that makes no item (empty, past 256
    /// bytes with the machine, or a control character).
    pub fn machine_policy(
        &self,
        machine: EntityId,
        devices: &[&str],
        templates: &[&str],
    ) -> Result<MachinePolicy> {
        self.with_read_snapshot(|txn| machine_policy_in_txn(self, txn, machine, devices, templates))
    }
}

/// [`Vault::machine_policy`] in `txn`.
///
/// # Errors
///
/// As [`Vault::machine_policy`].
pub fn machine_policy_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    machine: EntityId,
    devices: &[&str],
    templates: &[&str],
) -> Result<MachinePolicy> {
    use setting_keys::{
        CACHE_CAP_GIB, CACHE_IDLE_DAYS, CACHE_KEYS_MAX, CACHE_PROTECT_HOURS,
        CACHE_WANTED_HOLD_SECS, DEVICES_OFFERED, DRAIN_CLEAR_BY, EXECUTION, FREE_FORM,
        KEEP_HEADROOM, MACHINE_ACCEPTS, READINESS_EVERY_SECS, TEMPLATES_NETWORK, WINDOWS,
        WORK_ROLES,
    };
    let item = machine_item(machine);
    let item = Some(item.as_str());
    let cache = CachePolicy {
        cap_gib: CACHE_CAP_GIB.read_in_txn(vault, txn, &[], item)?.value,
        idle_days: CACHE_IDLE_DAYS.read_in_txn(vault, txn, &[], item)?.value,
        protect_hours: CACHE_PROTECT_HOURS
            .read_in_txn(vault, txn, &[], item)?
            .value,
        wanted_hold_secs: CACHE_WANTED_HOLD_SECS
            .read_in_txn(vault, txn, &[], item)?
            .value,
        keys_max: CACHE_KEYS_MAX.read_in_txn(vault, txn, &[], item)?.value,
    };
    let mut policy = MachinePolicy {
        execution: EXECUTION.read_in_txn(vault, txn, &[], item)?.value,
        accepts: MACHINE_ACCEPTS.read_in_txn(vault, txn, &[], item)?.value,
        keep_headroom: KEEP_HEADROOM.read_in_txn(vault, txn, &[], item)?.value,
        windows: WINDOWS.read_in_txn(vault, txn, &[], item)?.value,
        work_roles: WORK_ROLES.read_in_txn(vault, txn, &[], item)?.value,
        free_form: FREE_FORM.read_in_txn(vault, txn, &[], item)?.value,
        drain_clear_by: DRAIN_CLEAR_BY.read_in_txn(vault, txn, &[], item)?.value,
        cache,
        readiness_every_secs: READINESS_EVERY_SECS
            .read_in_txn(vault, txn, &[], item)?
            .value,
        devices: BTreeMap::new(),
        template_network: BTreeMap::new(),
    };
    for device in devices {
        let item = machine_part_item(machine, device);
        let offer = DEVICES_OFFERED
            .read_in_txn(vault, txn, &[], Some(&item))?
            .value;
        policy.devices.insert((*device).to_owned(), offer);
    }
    for template in templates {
        let item = machine_part_item(machine, template);
        let network = TEMPLATES_NETWORK
            .read_in_txn(vault, txn, &[], Some(&item))?
            .value;
        policy
            .template_network
            .insert((*template).to_owned(), network);
    }
    Ok(policy)
}
