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
use crate::{EntityId, Vault};

pub use self::persist::persisted_window_pads;
pub(super) use self::persist::window_row_holds;
pub(crate) use self::persist::{PersistedWindowPads, persisted_window_pads_form};

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

/// Whether an owner-lane window's convergence waits for the receipt of its
/// sealed sends (CALLS: WINDOW_PAD_RECEIPT_WITNESS, Engine 10-22 on FIX
/// 10479). No owner-lane update waited on an answer before the envelope, so
/// the wait is the owner's to turn on.
pub enum WindowPadReceiptWitness {
    /// Convergence is the version vectors' alone, as before: a receipt still
    /// answers its send, and a `NotReady` still sends the carrier again.
    Off,
    /// A window stays pending while a sealed send of it has no receipt; the
    /// re-bootstrap after `MAX_CONVERGENCE_ROUNDS` stands as it is.
    On,
}

pub const WINDOW_PAD_RECEIPT_WITNESS: WindowPadReceiptWitness = WindowPadReceiptWitness::Off;

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

    /// `payload` as it is, holding no pad: a shared release's pad-free form.
    pub(super) fn pad_free(payload: &[u8]) -> Self {
        Self::bare(WindowPadForm::PadFree, payload)
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

/// `payload`, window `window`'s blob, with each pad reference whose pad is
/// here inflated back into its carrier, the blob otherwise as it is: the
/// bytes a carrier send goes as, made once for a shared release (FIX
/// 10477). `context` holds an update's dependencies.
pub(super) fn inflate_window_carrier(
    vault: &Vault,
    window: &WindowKey,
    payload: &[u8],
    context: Option<&LoroDoc>,
) -> Vec<u8> {
    let inflated = window
        .world()
        .and_then(|_| inflate::inflate_window_pad_refs(&vault.store, payload, context));
    inflated.unwrap_or_else(|| payload.to_vec())
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
    PreparedWindowPads::carrier(&inflate_window_carrier(vault, window, payload, context))
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

/// What projecting one blob makes of it, the same for every machine it may
/// go to (FIX 10477): the shared half of the send door, before any seal.
pub(super) enum SharedPadProjection {
    /// No pad anywhere in the blob: it goes as it is.
    PadFree,
    /// Reference-only bytes and the pads they name, by full id, sorted.
    Projected {
        bytes: Vec<u8>,
        items: Vec<[u8; 40]>,
    },
    /// No projection here: the carrier goes, told by this static reason.
    Keep(&'static str),
}

/// Why a projected blob was not sealed for one machine, told value-free.
pub(super) enum SealFallback {
    /// The machine takes the carrier, as before, with no fault to tell.
    Carrier,
    /// The carrier goes for this static reason.
    Keep(&'static str),
}

/// `payload`, window `window`'s blob, projected under `namespace`, this
/// vault's current pad namespace when it has one: the half of the send
/// door no recipient chooses. `context` holds an update's dependencies.
pub(super) fn project_window_shared(
    window: &WindowKey,
    payload: &[u8],
    context: Option<&LoroDoc>,
    namespace: Option<[u8; 16]>,
) -> SharedPadProjection {
    // A live pad rides its world's windows alone (`types::entity_world`).
    if window.world().is_none() {
        return SharedPadProjection::PadFree;
    }
    let Some(namespace) = namespace else {
        return SharedPadProjection::Keep("no current custody here");
    };
    match project_window_pad_refs(window, payload, context, &namespace) {
        Ok(WindowPadProjection::NothingToProject) => SharedPadProjection::PadFree,
        Ok(WindowPadProjection::Projected {
            bytes,
            required_refs,
        }) => {
            let items: BTreeSet<[u8; 40]> = required_refs
                .iter()
                .map(|reference| reference.key.envelope_key_id())
                .collect();
            SharedPadProjection::Projected {
                bytes,
                items: items.into_iter().collect(),
            }
        }
        Err(error) => {
            tracing::warn!(%window, kind = ?error.kind(), "window blob not projected");
            SharedPadProjection::Keep("projection fault")
        }
    }
}

/// The one machine `recipient` proved, with its pad key alone, when the
/// pads of `world` go to it: the recipient half of the seal, read fresh
/// for each send. Any other machine takes the carrier.
pub(super) fn seal_recipient(
    vault: &Vault,
    window: &WindowKey,
    world: EntityId,
    recipient: PeerMachine,
) -> Result<(EntityId, PadRecipients), SealFallback> {
    // A machine the world's pads do not go to takes the carrier, as before.
    let PeerMachine::Proven { machine, .. } = recipient else {
        return Err(SealFallback::Carrier);
    };
    match vault
        .store
        .env
        .read_txn()
        .map_err(crate::Error::from)
        .and_then(|txn| world_pad_recipients_in_txn(vault, &txn, world))
    {
        Ok(mut all) => {
            let recipient = WrapRecipient::Machine(machine);
            let Some(public) = all.remove(&recipient) else {
                return Err(SealFallback::Carrier);
            };
            Ok((machine, PadRecipients::from([(recipient, public)])))
        }
        Err(error) => {
            tracing::warn!(%window, kind = ?error.kind(), "window pad recipients not read");
            Err(SealFallback::Carrier)
        }
    }
}

/// The projected `bytes`, naming `items`, sealed to `machine` alone under
/// `to`, its pad key: the gathered pads and sidecar of one send, never
/// shared with another machine's.
pub(super) fn seal_projected_to(
    vault: &Vault,
    window: &WindowKey,
    world: EntityId,
    bytes: Vec<u8>,
    items: &[[u8; 40]],
    machine: EntityId,
    to: &PadRecipients,
) -> Result<PreparedWindowPads, SealFallback> {
    let items: BTreeSet<[u8; 40]> = items.iter().copied().collect();
    let exported = vault
        .store
        .env
        .read_txn()
        .map_err(crate::Error::from)
        .and_then(|txn| {
            let row_pad = |item: &[u8; 40]| row_pad_in_txn(&vault.store, &txn, item);
            vault
                .store
                .export_current_world_pads(&txn, world, &items, &row_pad, to)
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
                return Err(SealFallback::Keep("a pad the blob owes is not live here"));
            }
            exported.sealed
        }
        Ok(None) => {
            return Err(SealFallback::Keep("nothing to seal the blob's pads under"));
        }
        Err(error) => {
            tracing::warn!(%window, kind = ?error.kind(), "window pads not gathered");
            return Err(SealFallback::Keep("custody fault"));
        }
    };
    Ok(PreparedWindowPads {
        form: WindowPadForm::Sealed,
        payload: bytes,
        refs: items.into_iter().collect(),
        sidecar: Some(WindowPadSidecar {
            recipient: *machine.as_bytes(),
            source_position: sealed.position.to_bytes(),
            digest: sealed.digest,
            capsule: sealed.bytes,
        }),
    })
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
    let Some(world) = window.world() else {
        return PreparedWindowPads::bare(WindowPadForm::PadFree, payload);
    };
    let (machine, to) = match seal_recipient(vault, window, world, recipient) {
        Ok(seal) => seal,
        Err(SealFallback::Carrier) => return carrier_window_pads(vault, window, payload, context),
        Err(SealFallback::Keep(why)) => return keep(vault, window, payload, context, why),
    };
    let namespace = vault.store.world_pad_namespace();
    let (bytes, items) = match project_window_shared(window, payload, context, namespace) {
        SharedPadProjection::PadFree => {
            return PreparedWindowPads::bare(WindowPadForm::PadFree, payload);
        }
        SharedPadProjection::Projected { bytes, items } => (bytes, items),
        SharedPadProjection::Keep(why) => return keep(vault, window, payload, context, why),
    };
    match seal_projected_to(vault, window, world, bytes, &items, machine, &to) {
        Ok(prepared) => prepared,
        Err(SealFallback::Carrier) => carrier_window_pads(vault, window, payload, context),
        Err(SealFallback::Keep(why)) => keep(vault, window, payload, context, why),
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
    // FIX 7608 slice 4: the masked copy, made before any pad is.
    let masked = crate::sync::selector::prepare_repo_sync_frame(vault, snapshot, None)
        .map_err(|error| TransportError::Storage(error.to_string()))?;
    prepare_window_pads(
        vault,
        window,
        masked.as_deref().unwrap_or(snapshot),
        None,
        peer,
    )
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
