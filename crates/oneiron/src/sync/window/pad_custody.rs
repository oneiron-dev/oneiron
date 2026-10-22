//! A window pad envelope's two engine doors (KS-5, FIX 7107), one for each
//! side of the wire and both crates' sockets.
//!
//! The send door ([`prepare_window_pads`]) projects a window blob through the
//! pad projector and seals the pads its references name, gathered from
//! current custody here or else the rows that hold them, to the one machine
//! the frame goes to: the machine its socket proved, when the world's pad
//! recipients name it. Never another machine's capsule, never a wider set.
//! The receive door ([`admit_window_pads`]) opens what came sealed to this
//! machine, installs it into current custody, commits and reads it back,
//! and checks that every pad the payload owes is held, all before the
//! payload is persisted or imported.
//!
//! KEEP TODAY (Engine 10-22): a blob the send door cannot project, a machine
//! it may not seal to or pads it cannot gather go as today's carrier under
//! the same envelope, warned value-free. A receive that cannot install
//! answers `NotReady` and its caller imports nothing; the sender sends the
//! same bytes again as the carrier. Nothing waits, nothing new is refused,
//! and no ready is claimed for a pad not installed here.

mod inflate;
mod persist;

use std::collections::BTreeSet;

use loro::LoroDoc;

use crate::Vault;
use crate::authority::PeerMachine;
use crate::store::custody_protocol::CustodyPosition;
use crate::store::{PadRecipients, SealedWorldPads, open_world_pad_compartment};
use crate::sync::transport::{
    TransportError, WindowPadBinding, WindowPadEnvelope, WindowPadForm, WindowPadKind,
    WindowPadReadiness, WindowPadReceipt, WindowPadSidecar,
};
use crate::sync::types::WindowKey;
use crate::world_keys::{
    WindowPadProjection, WrapRecipient, project_window_pad_refs, row_pad_in_txn,
    world_pad_recipients_in_txn,
};

pub use self::persist::persisted_window_pads;
pub(super) use self::persist::window_row_holds;

/// What becomes of an envelope's capsule that did not arrive whole or did
/// not install (CALLS: WINDOW_PAD_PART_REPAIR, lead 10-22 14:3x).
pub enum WindowPadPartRepair {
    /// Parts stream in order on the frame's own socket, the sealed bytes
    /// held in memory for that send alone. A delivery whose parts did not
    /// arrive is a lost frame: it goes again, and the pads it owed come in a
    /// fresh exact-key capsule (`residence.pad.fetch`) bound to its own
    /// position and digest. A capsule that did not install is answered
    /// `NotReady`, and its sender sends the same bytes again as the carrier.
    FreshCapsuleRebind,
}

pub const WINDOW_PAD_PART_REPAIR: WindowPadPartRepair = WindowPadPartRepair::FreshCapsuleRebind;

/// A window blob made ready for one machine: projected and sealed for it,
/// pad-free, or kept as today's carrier.
pub struct PreparedWindowPads {
    form: WindowPadForm,
    payload: Vec<u8>,
    refs: Vec<[u8; 40]>,
    sidecar: Option<WindowPadSidecar>,
}

impl PreparedWindowPads {
    /// `payload` as it is, today's carrier: what a send that may not seal
    /// sends, and what a sender sends again after a `NotReady`.
    pub fn carrier(payload: &[u8]) -> Self {
        Self::bare(WindowPadForm::Carrier, payload)
    }

    fn bare(form: WindowPadForm, payload: &[u8]) -> Self {
        Self {
            form,
            payload: payload.to_vec(),
            refs: Vec::new(),
            sidecar: None,
        }
    }

    pub fn form(&self) -> WindowPadForm {
        self.form
    }

    /// The envelope of kind `kind`, under `queue_seq`.
    pub fn envelope(&self, kind: WindowPadKind, queue_seq: Option<u64>) -> WindowPadEnvelope {
        WindowPadEnvelope {
            kind,
            form: self.form,
            queue_seq,
            payload: self.payload.clone(),
            refs: self.refs.clone(),
            sidecar: self.sidecar.clone(),
        }
    }

    /// The frames the envelope for `sub_tag` goes as, under `queue_seq`, and
    /// what its receipt must bind.
    ///
    /// # Errors
    ///
    /// A sub-tag that carries no window bytes; the envelope's own encoding
    /// faults.
    pub fn frames(
        &self,
        window_key: &str,
        sub_tag: u8,
        queue_seq: Option<u64>,
    ) -> Result<(Vec<Vec<u8>>, WindowPadBinding), TransportError> {
        let kind = WindowPadKind::of_sub_tag(sub_tag).ok_or(TransportError::InvalidPayload(
            "window frame carries no window bytes",
        ))?;
        let envelope = self.envelope(kind, queue_seq);
        Ok((
            envelope.encode_frames(window_key, sub_tag)?,
            envelope.binding(),
        ))
    }
}

/// `payload`, window `window`'s blob, as today's carrier for a send that may
/// not seal: each pad reference its blob holds whose pad is here inflated
/// back into its carrier, the blob otherwise as it is. `context` holds an
/// update's dependencies.
pub fn carrier_window_pads(
    vault: &Vault,
    window: &WindowKey,
    payload: &[u8],
    context: Option<&LoroDoc>,
) -> PreparedWindowPads {
    let inflated = window
        .world()
        .and_then(|_| inflate::inflate_window_pad_refs(&vault.store, payload, context));
    PreparedWindowPads::carrier(inflated.as_deref().unwrap_or(payload))
}

/// A send that keeps today's carrier for a fault, told value-free.
fn keep(
    vault: &Vault,
    window: &WindowKey,
    payload: &[u8],
    context: Option<&LoroDoc>,
    why: &'static str,
) -> PreparedWindowPads {
    tracing::warn!(%window, why, "window pads not sealed; the carrier goes as today");
    carrier_window_pads(vault, window, payload, context)
}

/// `payload`, window `window`'s blob, made ready for `recipient`, the machine
/// the frame's socket proved. A window of no world holds no pad: it goes as
/// it is. `context` is a document holding an update's dependencies (the
/// projector copies it). A blob with no pad goes pad-free; one whose pads
/// all seal to `recipient` alone goes as bare references with its capsule;
/// any other goes as today's carrier ([`carrier_window_pads`]).
pub fn prepare_window_pads(
    vault: &Vault,
    window: &WindowKey,
    payload: &[u8],
    context: Option<&LoroDoc>,
    recipient: PeerMachine,
) -> PreparedWindowPads {
    // A live pad rides its world's windows alone (`types::entity_world`).
    let Some(world) = window.world() else {
        return PreparedWindowPads::bare(WindowPadForm::PadFree, payload);
    };
    // A machine the world's pads do not go to takes the carrier, as before.
    let PeerMachine::Proven { machine, .. } = recipient else {
        return carrier_window_pads(vault, window, payload, context);
    };
    let to = match vault
        .store
        .env
        .read_txn()
        .map_err(crate::Error::from)
        .and_then(|txn| world_pad_recipients_in_txn(vault, &txn, world))
    {
        Ok(mut all) => {
            let recipient = WrapRecipient::Machine(machine);
            let Some(public) = all.remove(&recipient) else {
                return carrier_window_pads(vault, window, payload, context);
            };
            PadRecipients::from([(recipient, public)])
        }
        Err(error) => {
            tracing::warn!(%window, kind = ?error.kind(), "window pad recipients not read");
            return carrier_window_pads(vault, window, payload, context);
        }
    };
    let Some(namespace) = vault.store.world_pad_namespace() else {
        return keep(vault, window, payload, context, "no current custody here");
    };
    let (bytes, required) = match project_window_pad_refs(window, payload, context, &namespace) {
        Ok(WindowPadProjection::NothingToProject) => {
            return PreparedWindowPads::bare(WindowPadForm::PadFree, payload);
        }
        Ok(WindowPadProjection::Projected {
            bytes,
            required_refs,
        }) => (bytes, required_refs),
        Err(error) => {
            tracing::warn!(%window, kind = ?error.kind(), "window blob not projected");
            return keep(vault, window, payload, context, "projection fault");
        }
    };
    let items: BTreeSet<[u8; 40]> = required
        .iter()
        .map(|reference| reference.key.envelope_key_id())
        .collect();
    let exported = vault
        .store
        .env
        .read_txn()
        .map_err(crate::Error::from)
        .and_then(|txn| {
            let row_pad = |item: &[u8; 40]| row_pad_in_txn(&vault.store, &txn, item);
            vault
                .store
                .export_current_world_pads(&txn, world, &items, &row_pad, &to)
        });
    let sealed = match exported {
        Ok(Some(exported)) => {
            // Every pad the blob owes goes live; one retired at the source
            // or held by no source here keeps the carrier.
            let live: BTreeSet<[u8; 40]> = exported
                .sealed
                .required_keys
                .iter()
                .map(crate::world_keys::WorldKeyId::envelope_key_id)
                .filter(|item| !exported.retired.contains(item))
                .collect();
            if !items.is_subset(&live) {
                return keep(
                    vault,
                    window,
                    payload,
                    context,
                    "a pad the blob owes is not live here",
                );
            }
            exported.sealed
        }
        Ok(None) => {
            return keep(
                vault,
                window,
                payload,
                context,
                "nothing to seal the blob's pads under",
            );
        }
        Err(error) => {
            tracing::warn!(%window, kind = ?error.kind(), "window pads not gathered");
            return keep(vault, window, payload, context, "custody fault");
        }
    };
    PreparedWindowPads {
        form: WindowPadForm::Sealed,
        payload: bytes,
        refs: items.into_iter().collect(),
        sidecar: Some(WindowPadSidecar {
            recipient: *machine.as_bytes(),
            source_position: sealed.position.to_bytes(),
            digest: sealed.digest,
            capsule: sealed.bytes,
        }),
    }
}

/// A promotion's snapshot of `window` for the machine `peer` proved, as the
/// whole envelope its reply carries.
///
/// # Errors
///
/// The envelope's own encoding faults.
pub fn promotion_window_pads(
    vault: &Vault,
    peer: PeerMachine,
    window: &WindowKey,
    snapshot: &[u8],
) -> Result<Vec<u8>, TransportError> {
    prepare_window_pads(vault, window, snapshot, None, peer)
        .envelope(WindowPadKind::Promotion, None)
        .encode()
}

/// What this machine did with `envelope`'s pads, a frame of `window` that
/// passed its admission: a sealed envelope's capsule opened as this machine,
/// installed into current custody and read back, each pad it owes held. The
/// caller persists and imports the payload only when the readiness is not
/// `NotReady`.
pub fn admit_window_pads(
    vault: &Vault,
    window: &WindowKey,
    envelope: &WindowPadEnvelope,
) -> WindowPadReceipt {
    let readiness = match envelope.form {
        WindowPadForm::PadFree => WindowPadReadiness::PadFree,
        WindowPadForm::Carrier => WindowPadReadiness::KeptCarrier,
        WindowPadForm::Sealed => match install(vault, window, envelope) {
            Ok(true) => WindowPadReadiness::Ready,
            Ok(false) => {
                tracing::warn!(%window, "window pads not all installed here");
                WindowPadReadiness::NotReady
            }
            Err(error) => {
                tracing::warn!(%window, kind = ?error.kind(), "window pads not installed");
                WindowPadReadiness::NotReady
            }
        },
    };
    WindowPadReceipt {
        binding: envelope.binding(),
        readiness,
    }
}

/// Opens, installs, commits and reads back `envelope`'s capsule; whether
/// every pad it owes is then held here.
fn install(vault: &Vault, window: &WindowKey, envelope: &WindowPadEnvelope) -> crate::Result<bool> {
    let corrupt = || crate::Error::CorruptedIndex("window pad envelope");
    let sidecar = envelope.sidecar.as_ref().ok_or_else(corrupt)?;
    let world = window.world().ok_or_else(corrupt)?;
    let machine = vault.machine_secret_outside_txn()?;
    if *machine.machine.as_bytes() != sidecar.recipient {
        return Ok(false);
    }
    let position = CustodyPosition::from_bytes(&sidecar.source_position).ok_or_else(corrupt)?;
    let sealed = SealedWorldPads::parse(sidecar.capsule.clone())?;
    let named: BTreeSet<[u8; 40]> = sealed
        .required_keys
        .iter()
        .map(crate::world_keys::WorldKeyId::envelope_key_id)
        .collect();
    if sealed.world != world || !envelope.refs.iter().all(|item| named.contains(item)) {
        return Ok(false);
    }
    let opened = open_world_pad_compartment(
        &sealed,
        &position,
        &sidecar.digest,
        WrapRecipient::Machine(machine.machine),
        &machine.secret,
    )?;
    let installed = vault.with_write_txn_grouped(|wtxn| {
        vault.store.install_current_world_pads_in_txn(wtxn, &opened)
    })?;
    if !vault
        .store
        .read_back_current_world_pads(&opened, &installed)?
    {
        return Ok(false);
    }
    let held: BTreeSet<&[u8; 40]> = installed.held.iter().collect();
    Ok(envelope.refs.iter().all(|item| held.contains(item)))
}
