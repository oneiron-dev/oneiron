//! The job unit's two networks (row NODE-NETWORK-HOST-UNIT): the private
//! unit `oneiron-job@.service` (`PrivateNetwork=yes`) and the host network
//! unit `oneiron-job-host-network@.service`, the same unit in the machine's
//! own network namespace. `install` writes both.
//!
//! A unit's network namespace is fixed when it starts, so its prepare step
//! cannot change it: the unit is picked before the start. The root control
//! handler reads the key's `launch.json` and starts the host network unit
//! only for a pin that asks `host` ([`start_unit_network`]); the prepare
//! step then refuses a pin whose network is not its unit's
//! ([`unit_admits_pin_network`]). Before either, the template's `network`
//! list (default `["none"]`) and the owner's `machines.templates.network`
//! row (default `{none}`) must both open `host`, and a host pin under a
//! template whose `require` lists `network_closed` is refused at admission.
//!
//! Every step that names a key's unit by its id alone (the stop, the
//! checkpoint notice, the cutoff, a renewal, the engine's status and its
//! list of live units) names it under each installed template
//! ([`installed_unit_names`]); the handler never starts one key in both.

use std::path::Path;

use super::super::jobs::JobKeyId;
use super::super::jobs::job_unit::{
    JOB_UNIT_SUFFIX, JOB_UNIT_TEMPLATE_PREFIX, JobUnitPhase, JobUnitStatus,
};
use super::super::wire::NetworkMode;
use super::UNIT_TEMPLATE_PATH;

/// The host network unit's template, as `install` writes it.
pub const HOST_NETWORK_UNIT_TEMPLATE_PATH: &str =
    "/etc/systemd/system/oneiron-job-host-network@.service";

/// The name every host network unit instance starts with.
pub const HOST_NETWORK_UNIT_TEMPLATE_PREFIX: &str = "oneiron-job-host-network@";

/// The flag the host network unit gives each of its root steps.
pub const HOST_NETWORK_STEP_FLAG: &str = "--host-network";

/// The socket address families a job in the host network unit may open
/// (`RestrictAddressFamilies=`): local sockets, IPv4 and IPv6, which git,
/// curl and the web clients use, and netlink, which the C library's resolver
/// reads the machine's interfaces with. Chosen for this row: every other
/// family (vsock, packet, Bluetooth, the kernel's crypto sockets) stays
/// closed, as it is in the private unit's empty namespace.
pub const HOST_NETWORK_ADDRESS_FAMILIES: &str = "AF_UNIX AF_INET AF_INET6 AF_NETLINK";

/// Which of the two job units a key runs in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UnitNetwork {
    /// `oneiron-job@.service`: its own network namespace, loopback alone.
    Private,
    /// `oneiron-job-host-network@.service`: the machine's own network.
    Host,
}

impl UnitNetwork {
    /// The unit a root step runs in, from its [`HOST_NETWORK_STEP_FLAG`].
    #[must_use]
    pub const fn from_step_flag(host_network: bool) -> Self {
        if host_network {
            Self::Host
        } else {
            Self::Private
        }
    }

    /// The template's instance prefix.
    #[must_use]
    pub const fn template_prefix(self) -> &'static str {
        match self {
            Self::Private => JOB_UNIT_TEMPLATE_PREFIX,
            Self::Host => HOST_NETWORK_UNIT_TEMPLATE_PREFIX,
        }
    }

    /// The template's file, as `install` writes it.
    #[must_use]
    pub const fn template_path(self) -> &'static str {
        match self {
            Self::Private => UNIT_TEMPLATE_PATH,
            Self::Host => HOST_NETWORK_UNIT_TEMPLATE_PATH,
        }
    }

    /// The unit of the key whose id is `instance`.
    #[must_use]
    pub fn unit_name(self, instance: &str) -> String {
        format!("{}{instance}{JOB_UNIT_SUFFIX}", self.template_prefix())
    }
}

/// Whether `install` wrote the host network unit's template on this
/// machine. An engine and a handler from before this row find none.
#[must_use]
pub fn host_network_unit_installed() -> bool {
    Path::new(HOST_NETWORK_UNIT_TEMPLATE_PATH).is_file()
}

/// The units a key may run in on this machine: the private one always, the
/// host network one when its template is installed.
#[must_use]
pub fn installed_networks(host_unit_installed: bool) -> Vec<UnitNetwork> {
    if host_unit_installed {
        vec![UnitNetwork::Private, UnitNetwork::Host]
    } else {
        vec![UnitNetwork::Private]
    }
}

/// The key's unit under each installed template, the private one first.
#[must_use]
pub fn installed_unit_names(instance: &str, host_unit_installed: bool) -> Vec<String> {
    installed_networks(host_unit_installed)
        .into_iter()
        .map(|network| network.unit_name(instance))
        .collect()
}

/// The unit the root control handler starts for a pin of `pin`: the host
/// network unit only for a host pin, and only where its template is
/// installed. Everything else starts the private unit, whose prepare step
/// then refuses a host pin ([`unit_admits_pin_network`]).
#[must_use]
pub const fn start_unit_network(pin: NetworkMode, host_unit_installed: bool) -> UnitNetwork {
    match pin {
        NetworkMode::Host if host_unit_installed => UnitNetwork::Host,
        NetworkMode::Host | NetworkMode::None => UnitNetwork::Private,
    }
}

/// The prepare step's check of the unit it runs in against the pin's
/// network.
///
/// # Errors
///
/// `network_host_unit_not_installed` for a host pin in the private unit,
/// `network_unit_not_private` for a pin of no network in the host network
/// unit.
pub fn unit_admits_pin_network(unit: UnitNetwork, pin: NetworkMode) -> Result<(), String> {
    match (unit, pin) {
        (UnitNetwork::Private, NetworkMode::None)
        | (UnitNetwork::Host, NetworkMode::Host)
        | (UnitNetwork::Host, NetworkMode::None) => Ok(()),
        (UnitNetwork::Private, NetworkMode::Host) => Err(
            "network_host_unit_not_installed: the pin asks the host network and this unit has a private one: run `oneiron execution-node install` again"
                .to_owned(),
        ),
        (UnitNetwork::Host, NetworkMode::None) => Err(
            "network_unit_not_private: the pin asks no network and this unit has the machine's"
                .to_owned(),
        ),
    }
}

/// The job units in a `systemctl list-units --plain --no-legend` listing,
/// under either template, each with its key's id, in the listing's order.
#[must_use]
pub fn listed_job_units(listing: &str) -> Vec<(JobKeyId, UnitNetwork)> {
    listing
        .lines()
        .filter_map(|line| line.split_whitespace().next())
        .filter_map(|name| {
            [UnitNetwork::Private, UnitNetwork::Host]
                .into_iter()
                .find_map(|network| {
                    name.strip_prefix(network.template_prefix())
                        .and_then(|rest| rest.strip_suffix(JOB_UNIT_SUFFIX))
                        .and_then(JobKeyId::parse)
                        .map(|id| (id, network))
                })
        })
        .collect()
}

/// A key's status from the statuses of its units under each template: the
/// phase of the first that is not inactive (the handler never starts one key
/// in both), and empty only when every unit's control group is.
#[must_use]
pub fn key_status(units: &[JobUnitStatus]) -> JobUnitStatus {
    JobUnitStatus {
        phase: units
            .iter()
            .map(|unit| unit.phase)
            .find(|phase| *phase != JobUnitPhase::Inactive)
            .unwrap_or(JobUnitPhase::Inactive),
        cgroup_empty: units.iter().all(|unit| unit.cgroup_empty),
    }
}
