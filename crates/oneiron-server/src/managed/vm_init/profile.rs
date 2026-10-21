//! The vault's managed profile as the config drive carries it into a VM
//! (FIX 6809): five typed files, one value each, which the root bootstrap
//! reads with the drive's other typed files ([`super::config_drive`]) and
//! turns into the engine's own managed-profile flags, the ones a supervisor
//! passes a node's child. An open and a cold restore get the same flags.
//!
//! Each file is the whole of its value, with at most one final LF and no
//! other byte. One that is not there gives the engine no flag, so the
//! engine's own default stands; it is never read as `false`. An explicit
//! `false` is kept: a member-vault `false` is the engine's own false, no
//! flag, and a failure-signal `false` is passed as `false`. What the values
//! mean (the tenancy they select, the width's bound against the vault's
//! dimensions) stays the engine's to check, as on a node.

use super::config_drive::{VmConfigFileError, read_known};
use oneiron_vault_contract::vm::{
    VM_GUEST_FAILURE_SIGNAL_EXPORT_FILE, VM_GUEST_FAILURE_SIGNAL_TRAINING_FILE,
    VM_GUEST_FAST_DIMS_FILE, VM_GUEST_MEMBER_VAULT_FILE, VM_GUEST_ORGANIZATION_OWNER_FILE,
};
use std::ffi::OsString;

/// What the guest's form says an organization file is, for a refusal.
const ORGANIZATION_FORM: &str = "not 64 hex digits";
/// What the guest's form says a choice file is, for a refusal.
const CHOICE_FORM: &str = "not true or false";
/// What the guest's form says a width file is, for a refusal.
const WIDTH_FORM: &str = "not a nonzero width in decimal digits that a u16 holds";

/// The managed profile the config drive's files carry, each `None` when its
/// file is not there.
#[derive(Default)]
pub(super) struct VmManagedProfile {
    /// [`VM_GUEST_ORGANIZATION_OWNER_FILE`]: the organization hosting id, as
    /// the file spells it.
    organization_owner: Option<String>,
    /// [`VM_GUEST_MEMBER_VAULT_FILE`]: whether this is the organization's
    /// member vault.
    member_vault: Option<bool>,
    /// [`VM_GUEST_FAILURE_SIGNAL_EXPORT_FILE`]: "Help improve Oneiron".
    failure_signal_export: Option<bool>,
    /// [`VM_GUEST_FAILURE_SIGNAL_TRAINING_FILE`]: training on what that
    /// sends, a choice of its own.
    failure_signal_training: Option<bool>,
    /// [`VM_GUEST_FAST_DIMS_FILE`]: the measured MRL prefix width.
    fast_dims: Option<u16>,
}

impl VmManagedProfile {
    /// Reads each of the five files once, each strictly in its form.
    pub(super) fn load() -> Result<Self, VmConfigFileError> {
        Ok(Self {
            organization_owner: scalar(
                VM_GUEST_ORGANIZATION_OWNER_FILE,
                ORGANIZATION_FORM,
                organization,
            )?,
            member_vault: scalar(VM_GUEST_MEMBER_VAULT_FILE, CHOICE_FORM, choice)?,
            failure_signal_export: scalar(
                VM_GUEST_FAILURE_SIGNAL_EXPORT_FILE,
                CHOICE_FORM,
                choice,
            )?,
            failure_signal_training: scalar(
                VM_GUEST_FAILURE_SIGNAL_TRAINING_FILE,
                CHOICE_FORM,
                choice,
            )?,
            fast_dims: scalar(VM_GUEST_FAST_DIMS_FILE, WIDTH_FORM, width)?,
        })
    }

    /// The engine's flags for the profile, each flag and each value its own
    /// argument: none for a file that is not there, and none for a
    /// member-vault `false`.
    pub(super) fn engine_flags(&self) -> Vec<OsString> {
        let mut flags: Vec<OsString> = Vec::new();
        if let Some(organization) = &self.organization_owner {
            flags.push("--organization-owner".into());
            flags.push(organization.into());
        }
        if self.member_vault == Some(true) {
            flags.push("--member-vault".into());
        }
        for (flag, choice) in [
            ("--failure-signal-export", self.failure_signal_export),
            ("--failure-signal-training", self.failure_signal_training),
        ] {
            if let Some(choice) = choice {
                flags.push(flag.into());
                flags.push(choice.to_string().into());
            }
        }
        if let Some(width) = self.fast_dims {
            flags.push("--fast-dims".into());
            flags.push(width.to_string().into());
        }
        flags
    }
}

/// One profile file's value, or `None` when the file is not there: its
/// bytes less at most one final LF are the whole value, which `parse` takes
/// or refuses as not in `form`.
fn scalar<T>(
    path: &'static str,
    form: &'static str,
    parse: fn(&str) -> Option<T>,
) -> Result<Option<T>, VmConfigFileError> {
    let Some(bytes) = read_known(path)? else {
        return Ok(None);
    };
    let body = bytes.strip_suffix(b"\n").unwrap_or(&bytes[..]);
    std::str::from_utf8(body)
        .ok()
        .and_then(parse)
        .map(Some)
        .ok_or_else(|| VmConfigFileError::Malformed {
            path: path.into(),
            fault: form,
        })
}

/// An organization hosting id: exactly 64 hex digits, either case, kept as
/// written.
fn organization(id: &str) -> Option<String> {
    (id.len() == 64 && id.bytes().all(|byte| byte.is_ascii_hexdigit())).then(|| id.to_owned())
}

/// `true` or `false`, and nothing else.
fn choice(value: &str) -> Option<bool> {
    match value {
        "true" => Some(true),
        "false" => Some(false),
        _ => None,
    }
}

/// A width: decimal digits only, with no sign, space or prefix, that a u16
/// holds and that is not zero.
fn width(value: &str) -> Option<u16> {
    if !value.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    value.parse().ok().filter(|width| *width != 0)
}
