//! The host's half of a vault VM's guest network (FIX 6808,
//! [`oneiron_vault_contract::vm::VmTapAttachment`]): the profile's TAP,
//! attached as the guest's one NIC before the instance starts.
//!
//! The supervisor makes the TAP, brings it up and installs its forwarding,
//! masquerade and ingress drops before it runs this driver, and writes the
//! guest's view of the same plan to the config drive. This only checks the
//! attachment and hands it to the VMM on every boot: an open's, a restore's
//! and an inspection's. A RAM snapshot keeps the attachment, so a resume
//! opens the same TAP by its name again. Nothing here runs `ip` or `nft`,
//! changes a host sysctl, or adds a port forward or a listener: every host
//! surface stays on vsock.

use super::{VaultVm, VaultVmConfig};
use serde_json::json;

/// The guest NIC's interface id in the VMM.
const VM_NETWORK_INTERFACE_ID: &str = "vault-egress";

/// Refuses a profile whose `network` is not in its form, or that names a NIC
/// without the config drive that carries the guest's view of it.
pub(super) fn validate(config: &VaultVmConfig) -> anyhow::Result<()> {
    let Some(network) = &config.network else {
        return Ok(());
    };
    if let Err(fault) = network.validate() {
        anyhow::bail!("the VM profile's network: {fault}");
    }
    anyhow::ensure!(
        config.config_disk.is_some(),
        "the VM profile's network needs a config_disk, which carries the guest's view of it"
    );
    Ok(())
}

impl VaultVm {
    /// Attaches the profile's TAP as the guest's NIC, with the plan's MAC,
    /// before the instance starts; nothing for a profile with no `network`.
    pub(super) async fn attach_network(&self) -> anyhow::Result<()> {
        let Some(network) = &self.config.network else {
            return Ok(());
        };
        self.api(
            "PUT",
            &format!("/network-interfaces/{VM_NETWORK_INTERFACE_ID}"),
            json!({
                "iface_id": VM_NETWORK_INTERFACE_ID, "host_dev_name": network.tap_name,
                "guest_mac": network.guest_mac,
            }),
        )
        .await
    }
}
