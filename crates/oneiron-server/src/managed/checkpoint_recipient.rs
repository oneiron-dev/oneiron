//! Supervisor-delivered public recipients for checkpoint host-order members.

use std::fs::File;
use std::os::fd::{AsRawFd as _, FromRawFd as _, RawFd};

use base64::Engine as _;
use oneiron_store::checkpoint_host_recipient::HostHoldsRecipient;
use oneiron_vault_contract::checkpoint_recipient::CheckpointHostHoldsRecipient;

/// Owns a distinct supervisor descriptor after the argument and listener
/// alias checks. It closes on every later startup exit and never reaches a
/// subprocess: the public frame is consumed before storage or workers open.
pub(super) fn adopt(fd: Option<RawFd>) -> Option<File> {
    let fd = fd?;
    // SAFETY: F_GETFD reads no pointer and asks the kernel whether this raw
    // number is open. A missing optional pipe must not become an invalid
    // owned descriptor whose drop could abort the process.
    if unsafe { libc::fcntl(fd, libc::F_GETFD) } < 0 {
        tracing::warn!("checkpoint host-order recipient pipe is not open; vault start continues");
        return None;
    }
    // SAFETY: managed resolution proved this non-negative inherited
    // descriptor distinct from every other delivered descriptor. This is
    // its only adoption, and the returned file owns its lifetime.
    let file = unsafe { File::from_raw_fd(fd) };
    if rustix::io::fcntl_setfd(&file, rustix::io::FdFlags::CLOEXEC).is_err() {
        tracing::warn!(
            "checkpoint host-order recipient pipe could not be retained; vault start continues"
        );
        return None;
    }
    Some(file)
}

/// Consumes the one public object followed by EOF. The supervisor closes
/// the same pipe's writer before starting the child. Invalid material
/// leaves the recipient missing, never stops the hosted vault.
pub(super) fn read(file: Option<File>) -> Option<HostHoldsRecipient> {
    let file = file?;
    let decoded = crate::pipe_proof::pipe_end(file.as_raw_fd(), false)
        .map_err(|_| "the public recipient did not arrive on a pipe")
        .and_then(|()| {
            serde_json::from_reader::<_, CheckpointHostHoldsRecipient>(file)
                .map_err(|_| "the public recipient is not its one JSON object followed by EOF")
        })
        .and_then(|wire| decode(&wire));
    match decoded {
        Ok(recipient) => Some(recipient),
        Err(reason) => {
            tracing::warn!(
                reason,
                "checkpoint host-order recipient unavailable; vault start continues"
            );
            None
        }
    }
}

/// Normalize the optional host-profile material before framing it. Invalid
/// strings must not make an otherwise valid VM start fail its frame bound;
/// the exact normalized object is what the guest must echo back.
pub(super) fn normalized(
    wire: Option<&CheckpointHostHoldsRecipient>,
) -> Option<CheckpointHostHoldsRecipient> {
    let wire = wire?;
    match decode(wire) {
        Ok(_) => Some(wire.clone()),
        Err(reason) => {
            tracing::warn!(
                reason,
                "checkpoint host-order recipient unavailable; VM start continues"
            );
            None
        }
    }
}

/// The epoch belongs to the actual ONHB frame, not a local default. The
/// native constructor validates its complete format and public key; the
/// delivered fingerprint must name those exact bytes.
pub(super) fn decode(
    wire: &CheckpointHostHoldsRecipient,
) -> Result<HostHoldsRecipient, &'static str> {
    let bundle = base64::engine::general_purpose::STANDARD
        .decode(&wire.bundle_b64)
        .map_err(|_| "the public recipient bundle is not standard base64")?;
    let epoch = bundle
        .get(8..16)
        .and_then(|bytes| <[u8; 8]>::try_from(bytes).ok())
        .map(u64::from_be_bytes)
        .ok_or("the public recipient bundle has no epoch")?;
    let recipient = HostHoldsRecipient::new(&bundle, epoch)
        .map_err(|_| "the public recipient bundle is invalid")?;
    let fingerprint = oneiron_vault_contract::from_hex(&wire.fingerprint)
        .ok_or("the public recipient fingerprint is not 32 hexadecimal bytes")?;
    if fingerprint != recipient.id() {
        return Err("the public recipient fingerprint does not match its bundle");
    }
    Ok(recipient)
}
