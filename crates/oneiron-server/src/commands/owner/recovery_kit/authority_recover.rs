//! Lost-owner recovery uses the kit's pre-enrolled key, never this host's owner key.

use std::fs::File;

use crate::cli::RecoveryKitRecoverAuthorityArgs;
use crate::config::resolve_serve_config;
use crate::owner::recovery_kit::authority_recovery::{DeviceAuthorityInput, RecoveryReceipt};

use super::authority_recovery::open_material;
use super::emit;

pub(super) fn recover(args: RecoveryKitRecoverAuthorityArgs) -> anyhow::Result<()> {
    let file = File::open(&args.new_device)?;
    let input: DeviceAuthorityInput = serde_json::from_reader(file).map_err(|_| {
        anyhow::anyhow!("--new-device must contain a complete device authority JSON envelope")
    })?;
    let new_device = input.into_native()?;
    let config = resolve_serve_config(&args.serve)?;
    let (vault, secret) = open_material(&config, &args.kit, &args.unlock)?;
    let entry = vault.recover_owner_authority_from_kit(secret, new_device)?;
    emit(&RecoveryReceipt::committed(&entry)?)
}
