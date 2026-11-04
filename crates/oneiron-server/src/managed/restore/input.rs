//! The restore's two pipes and the plan on the input pipe: each descriptor
//! proven the right end of a pipe before either is taken over (FIX 6580,
//! [`crate::pipe_proof::pipe_end`]), the plan read to EOF and parsed strictly,
//! and every binding it names checked against this start's argv, and in a
//! vault VM its carrier, before anything is touched.

use std::io::{ErrorKind, Read as _};
use std::os::fd::{FromRawFd as _, RawFd};
use std::path::PathBuf;

use oneiron_vault_contract::restore::framing::identity_fits;
use oneiron_vault_contract::restore::{
    EscrowRole, FreshRecipient, ManagedRestoreIdentity, ManagedRestoreInput, ManagedRestorePlan,
    RESTORE_INPUT_SCHEMA_VERSION,
};

use crate::managed::ManagedArgs;
#[cfg(target_os = "linux")]
use crate::managed::state_serve::carrier_recipient;

/// An SLH-DSA-SHA2-256s public key's length in bytes.
const SLHDSA_PUBLIC_LEN: usize = 64;

/// Takes `fd` over, once, after [`pipe_end`](crate::pipe_proof::pipe_end)
/// proved it.
pub(in crate::managed) fn adopt(fd: RawFd) -> std::fs::File {
    // SAFETY: `fd` arrives on argv from the supervisor and is this process's
    // to own; `pipe_end` proved it open, and nothing else takes it over.
    // The `File` closes it on drop, which is the EOF its reader waits for.
    unsafe { std::fs::File::from_raw_fd(fd) }
}

/// Reads the input pipe to EOF and parses its one object.
pub(super) fn read(mut pipe: std::fs::File) -> Result<ManagedRestoreInput, &'static str> {
    let mut bytes = Vec::new();
    pipe.read_to_end(&mut bytes)
        .map_err(|_| "the input pipe did not read to its end")?;
    let input: ManagedRestoreInput = serde_json::from_slice(&bytes)
        .map_err(|_| "the input is not one restore input object with nothing after it")?;
    if input.schema_version != RESTORE_INPUT_SCHEMA_VERSION {
        return Err("the input's schema version is not one this build reads");
    }
    Ok(input)
}

/// The argv escrow recipient bytes a cold restore's begin-check read and
/// verified against the plan (FIX 11988): the start seals these, never the
/// files again, so a file swapped in between is not sealed unchecked. A
/// role argv names no file for holds none; a vault VM's carrier bytes are
/// not carried, since the carrier watch re-runs the plan check at its
/// first look before it seals (FIX 11851).
pub(in crate::managed) struct CheckedRecipients {
    pub(in crate::managed) managed: Option<Vec<u8>>,
    pub(in crate::managed) break_glass: Option<Vec<u8>>,
}

/// Checks each binding the plan names against this start: its vault and
/// owners, its tier, the artifact's path, its signer pins, that its
/// identity rides a result frame, and that each escrow recipient argv names
/// is one of the plan's fresh recipients of that role, never a released
/// one or one the plan did not authorize. In a vault VM a role argv names
/// no file for is checked the same way against the carrier's file for it,
/// as it stands now ([`vm_carrier_recipient`]). Returns the argv bytes it
/// read and verified, for the start to seal (FIX 11988).
pub(super) fn check(
    plan: &ManagedRestorePlan,
    managed: &ManagedArgs,
    maximum_tier: bool,
) -> Result<CheckedRecipients, &'static str> {
    let checks = [
        (
            plan.vault_name == managed.vault_name,
            "its vault_name is not --vault-name",
        ),
        (
            plan.source.registry_id == managed.vault_name,
            "its source registry_id is not --vault-name",
        ),
        (
            plan.derivation_owner == managed.derivation_owner.0,
            "its derivation_owner is not --derivation-owner",
        ),
        (
            plan.organization_owner == managed.organization_owner.map(|owner| owner.0),
            "its organization_owner is not --organization-owner",
        ),
        (
            plan.member_vault == managed.member_vault,
            "its member_vault is not --member-vault",
        ),
        (
            plan.maximum_tier == maximum_tier,
            "its maximum_tier is not the tier this start settled",
        ),
        (
            plan.artifact.is_absolute(),
            "its artifact is not an absolute path",
        ),
        (
            plan.source
                .signer_pins
                .iter()
                .all(|pin| pin.slhdsa.len() == SLHDSA_PUBLIC_LEN),
            "a signer pin's SLH-DSA key is not 64 bytes",
        ),
        (
            identity_fits(&ManagedRestoreIdentity::of(&plan.request)),
            "its identity does not fit a result frame",
        ),
    ];
    if let Some((_, refusal)) = checks.into_iter().find(|(holds, _)| !holds) {
        return Err(refusal);
    }
    let mut checked = CheckedRecipients {
        managed: None,
        break_glass: None,
    };
    for (role, file) in [
        (EscrowRole::Managed, &managed.escrow_recipient),
        (EscrowRole::BreakGlass, &managed.break_glass_recipient),
    ] {
        let (public_key, from_carrier) = if let Some(file) = file {
            (
                std::fs::read(file)
                    .map_err(|_| "an escrow recipient file argv names did not read")?,
                false,
            )
        } else if let Some(file) = vm_carrier_recipient(managed, role) {
            match std::fs::read(file) {
                Ok(public_key) => (public_key, true),
                Err(error) if error.kind() == ErrorKind::NotFound => continue,
                Err(_) => return Err("the carrier's escrow recipient file did not read"),
            }
        } else {
            continue;
        };
        if !fresh_authorizes(&plan.request.fresh, role, &public_key) {
            return Err(if from_carrier {
                "the carrier's escrow recipient is not one of the plan's fresh recipients"
            } else {
                "an escrow recipient argv names is not one of the plan's fresh recipients"
            });
        }
        if !from_carrier {
            let slot = match role {
                EscrowRole::Managed => &mut checked.managed,
                EscrowRole::BreakGlass => &mut checked.break_glass,
            };
            *slot = Some(public_key);
        }
    }
    Ok(checked)
}

/// Whether the plan authorizes `public_key` as a fresh escrow recipient of
/// `role`: one of the plan's fresh recipients of that role, never a
/// released one or one the plan did not authorize. The carrier watch's
/// first look runs this same check again before it seals (FIX 11851).
pub(in crate::managed) fn fresh_authorizes(
    fresh: &[FreshRecipient],
    role: EscrowRole,
    public_key: &[u8],
) -> bool {
    fresh
        .iter()
        .any(|fresh| fresh.role == role && fresh.public_key.as_slice() == public_key)
}

/// The file a vault VM's carrier delivers `role`'s escrow recipient in, for
/// a role argv names no file for: the host may send one after this start's
/// argv was built, and the carrier watch seals to it once the vault serves
/// (FIX 11078). `None` outside a vault VM.
fn vm_carrier_recipient(managed: &ManagedArgs, role: EscrowRole) -> Option<PathBuf> {
    #[cfg(target_os = "linux")]
    if managed.vsock_guest {
        return Some(carrier_recipient(role));
    }
    #[cfg(not(target_os = "linux"))]
    let _ = (managed, role);
    None
}
