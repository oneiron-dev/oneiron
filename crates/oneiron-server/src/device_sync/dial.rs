//! What a device dials ([`Dial`]): the home its `[device_sync]` section
//! names by hand, else the one `oneiron device enrol` recorded.

use crate::config::{DeviceSyncConfig, ServeConfig};
use crate::server::SyncServer;

use super::enrolment::{DeviceEnrolment, EnrolmentFiles, EnrolmentSource};

/// What this machine dials: the home `[device_sync]` names by hand, else the
/// one it enrolled with, and the worlds the section follows.
#[cfg_attr(not(feature = "mesh"), allow(dead_code))]
pub(super) struct Dial {
    pub(super) home: oneiron::EntityId,
    pub(super) url: String,
    pub(super) credential_file: std::path::PathBuf,
    pub(super) worlds: Vec<oneiron::EntityId>,
    pub(super) home_node: Option<u64>,
    pub(super) pin: Option<oneiron::authority::AuthorityCheckpointPin>,
    /// Enrolled by `oneiron device enrol`: the home holds this machine's
    /// profile, which reaches this vault on the first authority catch-up.
    pub(super) enrolled: bool,
    /// The section's `always_on` and `primary` flags: what this machine's
    /// MACRO home candidacy declares (FIX 4898).
    pub(super) always_on: bool,
    pub(super) primary: bool,
}

impl Dial {
    /// `None` when this machine has no home: no section and no enrolment.
    /// Its enrolment is looked for where `source` says.
    pub(super) fn resolve(
        server: &SyncServer,
        config: &ServeConfig,
        source: EnrolmentSource,
    ) -> anyhow::Result<Option<Self>> {
        let section = config.device_sync.as_ref();
        // No directory to look in means `device enrol` wrote nothing either.
        let enrolment = match EnrolmentFiles::for_serve(&config.keystore, &server.vault, source) {
            Ok(Some(files)) => files.read()?.map(|record| (files, record)),
            Ok(None) | Err(_) => None,
        };
        let worlds = section
            .map(DeviceSyncConfig::followed_worlds)
            .transpose()?
            .unwrap_or_default();
        let node = section.and_then(|section| section.home_node_id);
        let (always_on, primary) = section.map_or((false, false), |section| {
            (section.always_on, section.primary)
        });
        if let Some(named) = section
            .map(DeviceSyncConfig::named_home)
            .transpose()?
            .flatten()
        {
            // An enrolment's pins are its own home's only.
            let enrolment = enrolment.filter(|(_, record)| {
                crate::config::device_sync::parse_machine(&record.home_machine).ok()
                    == Some(named.machine)
            });
            pin_mesh(server, enrolment.as_ref().map(|(_, record)| record));
            let pin = enrolment.and_then(|(_, record)| record.authority_checkpoint_pin);
            return Ok(Some(Self {
                home: named.machine,
                url: named.url.to_owned(),
                credential_file: named.credential_file.to_owned(),
                worlds,
                home_node: node,
                pin,
                enrolled: false,
                always_on,
                primary,
            }));
        }
        let Some((files, record)) = enrolment else {
            anyhow::ensure!(
                section.is_none(),
                "[device_sync] names no home and this machine is not enrolled; run `oneiron \
                 device enrol` with the vault stopped"
            );
            return Ok(None);
        };
        pin_mesh(server, Some(&record));
        Ok(Some(Self {
            home: crate::config::device_sync::parse_machine(&record.home_machine)?,
            url: record.home_url,
            credential_file: files.credential,
            worlds,
            home_node: Some(node.unwrap_or(record.home_node_id)),
            pin: record.authority_checkpoint_pin,
            enrolled: true,
            always_on,
            primary,
        }))
    }
}

/// Pins the home `record` names, at the mesh address that home answered at
/// enrolment, on this install's mesh listener (FIX 3374): the listener admits
/// it on sync, and the dial goes over the mesh first. A record with no mesh
/// address, or an install with no MACHINE yet, pins nothing.
#[cfg(feature = "mesh")]
fn pin_mesh(server: &SyncServer, record: Option<&DeviceEnrolment>) {
    let Some(record) = record else {
        return;
    };
    let (Some(address), Ok(home)) = (
        record.home_mesh.clone(),
        crate::config::device_sync::parse_machine(&record.home_machine),
    ) else {
        return;
    };
    if let Ok(Some(local)) = server.vault.local_machine() {
        crate::handler::mesh::pin_home(local.id, home, address);
    }
}

/// A build without the `mesh` feature runs no listener to pin a home on.
#[cfg(not(feature = "mesh"))]
fn pin_mesh(_server: &SyncServer, _record: Option<&DeviceEnrolment>) {}
