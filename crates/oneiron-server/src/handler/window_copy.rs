//! The masked repo copy generation each socket was last sent of a window
//! (FIX 7608 slice 4, C3 of the s4 soundness read), and the answer to a
//! device's copy edit held on its ruled cause (FIX 10598).
//!
//! A copy's generation is its stamp, never a version vector: a later mark
//! (or a mask that changes spans under the same mark ids) changes what a
//! peer must hold while the window's version vector stays equal. A socket
//! that was last sent another generation of a window, or none yet, gets the
//! window's replacement on its next version exchange, so a stale copy is not
//! kept on. A window that carries no marked repo item answers as today.

use std::ops::ControlFlow;

use loro::{LoroDoc, VersionVector};
use oneiron::Vault;
use oneiron::sync::WindowKey;
use oneiron::sync::transport::WindowPadReceipt;
use oneiron::sync::window::WindowExport;

use super::conn_state::ConnState;
use crate::protocol::ProtocolError;

/// `export`, this socket's answer to `remote` for window `key`, bound to
/// the generation of `doc`'s masked repo copies: the replacement
/// `replacement` cuts when the socket was last sent another one and can
/// install it (`replaces`).
///
/// # Errors
/// A store failure reading the copies, or the replacement's own.
#[expect(
    clippy::too_many_arguments,
    reason = "the socket, its window, its answer and how a replacement is cut"
)]
pub(super) fn bind_generation<F>(
    vault: &Vault,
    conn_state: &ConnState,
    key: &WindowKey,
    doc: &LoroDoc,
    remote: &VersionVector,
    export: WindowExport,
    replaces: bool,
    replacement: F,
) -> oneiron::Result<WindowExport>
where
    F: FnOnce() -> oneiron::Result<Option<Vec<u8>>>,
{
    let generation = oneiron::sync::selector::repo_copy_generation(vault, doc)?;
    let mut sent = conn_state
        .repo_copy_generations
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let Some(generation) = generation else {
        sent.remove(key);
        return Ok(export);
    };
    let whole = remote.is_empty() || matches!(export, WindowExport::Replacement(_));
    if whole || sent.get(key) == Some(&generation) {
        sent.insert(key.clone(), generation);
        return Ok(export);
    }
    // A peer on a protocol that cannot install a replacement keeps today's
    // answer; its masked copies refresh only where new operations reach it.
    if !replaces {
        return Ok(export);
    }
    match replacement()? {
        Some(snapshot) => {
            sent.insert(key.clone(), generation);
            Ok(WindowExport::Replacement(snapshot))
        }
        None => Ok(export),
    }
}

/// The answer to a device's update of window `window_key`, sent under
/// `sub_tag` with its pads admitted as `receipt`, whose copy edit the
/// admission held on its ruled cause and recorded (FIX 10598): the
/// acknowledgment a landed update gets (a residence update's, `residence_seq`,
/// or an owner-lane update's receipt), so the device retires it from its
/// queue and stops sending it. Nothing of it persisted, imported or relayed,
/// and its edit is never applied; the device keeps its operations in its own
/// window.
///
/// # Errors
/// The receipt's encoding, or a closed reply channel.
pub(super) fn acknowledge_held(
    window_key: &str,
    sub_tag: u8,
    residence_seq: Option<u64>,
    receipt: &WindowPadReceipt,
    direct_tx: &tokio::sync::mpsc::UnboundedSender<Vec<u8>>,
) -> Result<ControlFlow<()>, ProtocolError> {
    if residence_seq.is_some() || receipt.binding.sidecar_digest.is_some() {
        let frame = super::window_pads::receipt_frame(window_key, sub_tag, receipt)?;
        direct_tx.send(frame).map_err(|_| {
            ProtocolError::Persistence("held copy edit acknowledgment channel closed".into())
        })?;
    }
    Ok(ControlFlow::Continue(()))
}
