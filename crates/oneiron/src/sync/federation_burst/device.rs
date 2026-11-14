//! One of this vault's own devices as a burst peer (L7-41). A device's
//! window update at its home gets the same relative response a federated
//! peer's does (arch-0023b `#decision-federation-26`: allow,
//! isolate-and-propose or defer, against the peer's own baseline and the
//! vault's size; never a plain block, never a pause for a human).

use loro::LoroDoc;

use super::{
    BurstPeer, DeferredWork, FederationBurstDecision, FederationBurstPeerRef, WorkKind, admit_work,
    corrupt,
};
use crate::authority::PeerMachine;
use crate::sync::WindowKey;
use crate::{EntityId, Error, Result, Vault};

/// An own device as its connection proved it, in the order its home reads
/// it: the machine the connection proved, else the paired app's slip that
/// bound its Write credential, else one shared bucket for connections that
/// proved neither. It names whose baseline a write counts against; it grants
/// and refuses nothing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DevicePeer {
    /// A machine that proved, on its connection, the key it stands on here.
    Machine { machine: EntityId, key: [u8; 32] },
    /// The id of the slip that bound the connection's Write credential.
    Slip { slip: [u8; 32] },
    /// A connection that proved neither.
    Unproven,
}

impl DevicePeer {
    /// The device a connection proved: its machine when it is
    /// [`PeerMachine::Proven`], else the slip of its Write credential, else
    /// [`Self::Unproven`].
    #[must_use]
    pub fn of_connection(machine: PeerMachine, slip: Option<[u8; 32]>) -> Self {
        match (machine, slip) {
            (PeerMachine::Proven { machine, key }, _) => Self::Machine { machine, key },
            (PeerMachine::Unknown, Some(slip)) => Self::Slip { slip },
            (PeerMachine::Unknown, None) => Self::Unproven,
        }
    }

    /// The baseline its writes count against. A machine keeps its baseline
    /// across a new key.
    pub(super) fn digest(&self) -> [u8; 32] {
        let mut hash = blake3::Hasher::new();
        hash.update(b"oneiron/device-peer/v1");
        match self {
            Self::Machine { machine, .. } => {
                hash.update(b"machine");
                hash.update(machine.as_bytes());
            }
            Self::Slip { slip } => {
                hash.update(b"slip");
                hash.update(slip);
            }
            Self::Unproven => {
                hash.update(b"unproven");
            }
        }
        *hash.finalize().as_bytes()
    }

    /// The bytes that bind its retained work to it: the device as its
    /// connection proved it, a machine's key included.
    pub(super) fn encode(&self) -> Vec<u8> {
        match self {
            Self::Machine { machine, key } => {
                let mut bytes = vec![0];
                bytes.extend_from_slice(machine.as_bytes());
                bytes.extend_from_slice(key);
                bytes
            }
            Self::Slip { slip } => {
                let mut bytes = vec![1];
                bytes.extend_from_slice(slip);
                bytes
            }
            Self::Unproven => vec![2],
        }
    }

    /// The device [`Self::encode`] wrote.
    pub(super) fn decode(bytes: &[u8]) -> Result<Self> {
        match bytes {
            [0, rest @ ..] => {
                let (machine, key) = rest.split_first_chunk::<16>().ok_or_else(corrupt)?;
                Ok(Self::Machine {
                    machine: EntityId::from_bytes(*machine).map_err(|_| corrupt())?,
                    key: key.try_into().map_err(|_| corrupt())?,
                })
            }
            [1, slip @ ..] => Ok(Self::Slip {
                slip: slip.try_into().map_err(|_| corrupt())?,
            }),
            [2] => Ok(Self::Unproven),
            _ => Err(corrupt()),
        }
    }

    /// What its retained work is held under: whether it still stands here as
    /// its connection proved it (a machine on the same proof key, a slip
    /// still live). A machine removed or proving another key since, or a
    /// slip revoked since, ends that work `StaleAuthority` (FIX 7999).
    pub(super) fn authority_digest_in_txn(
        &self,
        vault: &Vault,
        txn: &heed::RoTxn<'_>,
    ) -> Result<[u8; 32]> {
        let stands = match self {
            Self::Machine { machine, key } => {
                vault
                    .authority_view_readonly_in_txn(txn)?
                    .machine_proof_key(*machine)
                    == Some(*key)
            }
            Self::Slip { slip } => vault
                .authority_view_readonly_in_txn(txn)?
                .slip_is_live(slip),
            Self::Unproven => true,
        };
        let mut hash = blake3::Hasher::new();
        hash.update(b"oneiron/device-peer-authority/v1");
        hash.update(&self.encode());
        hash.update(&[u8::from(stands)]);
        Ok(*hash.finalize().as_bytes())
    }

    /// The device as its receipts name it.
    pub(super) fn receipt_peer(&self) -> FederationBurstPeerRef {
        match self {
            Self::Machine { machine, .. } => FederationBurstPeerRef::Machine { machine: *machine },
            Self::Slip { slip } => FederationBurstPeerRef::Slip {
                slip: blake3::Hash::from(*slip).to_hex().to_string(),
            },
            Self::Unproven => FederationBurstPeerRef::Unproven,
        }
    }
}

/// What the home does with an own device's window update.
#[derive(Debug)]
pub enum DeviceBurstAdmission {
    /// Land it now through the home's ordinary doors, then
    /// [`DeviceBurstWork::complete`] it.
    Allow(DeviceBurstWork),
    /// Retained whole: [`ready_device_work`] hands it back once the device's
    /// rate is at its baseline again.
    Defer { batch_ref: String },
    /// Retained apart in the device's review bundle and proposed to the
    /// owner; [`ready_device_work`] hands it back as it does a deferred one.
    IsolateAndPropose {
        batch_ref: String,
        bundle_ref: String,
    },
}

/// An own device's update the burst core holds until it lands.
#[derive(Debug)]
pub struct DeviceBurstWork {
    peer: DevicePeer,
    work: Box<DeferredWork>,
}

impl DeviceBurstWork {
    /// The device whose update it is.
    #[must_use]
    pub fn peer(&self) -> DevicePeer {
        self.peer
    }

    /// The window the update names.
    #[must_use]
    pub fn window_key(&self) -> &str {
        &self.work.window
    }

    /// The update's bytes, as the device sent them.
    #[must_use]
    pub fn update(&self) -> &[u8] {
        self.work.payload.as_slice()
    }

    /// The address of its receipt.
    #[must_use]
    pub fn batch_ref(&self) -> String {
        blake3::Hash::from(self.work.id).to_hex().to_string()
    }

    /// Ends the batch landed: its receipt reads `Imported`.
    ///
    /// # Errors
    /// A store error, or a batch that is not this device's.
    pub fn complete(&self, vault: &Vault) -> Result<()> {
        self.work.complete(vault, BurstPeer::Device(&self.peer))
    }

    /// Ends the batch the home's doors refused as the device's own bytes:
    /// its receipt reads `Rejected`, and it counts as a structural failure.
    ///
    /// # Errors
    /// A store error, or a batch that is not this device's.
    pub fn reject(&self, vault: &Vault) -> Result<()> {
        self.work.reject(vault, BurstPeer::Device(&self.peer))
    }
}

/// Judges an own device's window `update` to `key` at its home, before the
/// home persists or relays it (L7-41). Its writes are the operations the
/// update carries, counted against the device's own baseline and the vault's
/// size. Its rows and `carried`, the rows the home's admission lands it as,
/// are named, so an erase of any scrubs the retained bytes (FIX 7998).
///
/// # Errors
/// [`Error::InvalidConfig`] for bytes that are no Loro update or that pass
/// the transport bound; a store error.
pub fn admit_device_window_update(
    vault: &Vault,
    peer: &DevicePeer,
    key: &WindowKey,
    update: &[u8],
    carried: &[EntityId],
) -> Result<DeviceBurstAdmission> {
    let writes = update_operations(update)?;
    let mut rows = crate::sync::ingest::payload_rows(key, update);
    rows.extend(carried.iter().copied());
    let carried = rows.into_iter().collect::<Vec<_>>();
    let parts = [(key.as_str(), update)];
    let (decision, work) = admit_work(
        vault,
        BurstPeer::Device(peer),
        key,
        WorkKind::DeviceUpdate,
        update,
        (writes, carried.as_slice()),
        Some(parts.as_slice()),
    )?;
    let work = work.ok_or_else(corrupt)?;
    let batch_ref = blake3::Hash::from(work.id).to_hex().to_string();
    Ok(match decision {
        FederationBurstDecision::Allow(_) => DeviceBurstAdmission::Allow(DeviceBurstWork {
            peer: *peer,
            work: Box::new(work),
        }),
        FederationBurstDecision::Defer { .. } => DeviceBurstAdmission::Defer { batch_ref },
        FederationBurstDecision::IsolateAndPropose { bundle_id, .. } => {
            DeviceBurstAdmission::IsolateAndPropose {
                batch_ref,
                bundle_ref: format!(
                    "federation-review:{}",
                    blake3::Hash::from(bundle_id).to_hex()
                ),
            }
        }
    })
}

/// Every own device's oldest retained update that is due now, for its home
/// to land and then complete (L7-41). A retained update is due once its
/// device's rate is back at its baseline, with no human step; the owner's
/// release of an isolated one lifts only its isolation. A batch held under a
/// standing that has changed since ends `StaleAuthority`, and one past its
/// wait `Expired`, each with its receipt (FIX 7997, 7999).
///
/// # Errors
/// A store error, or a retained row that does not decode.
pub fn ready_device_work(vault: &Vault) -> Result<Vec<DeviceBurstWork>> {
    let mut due = Vec::new();
    for peer in super::queue::retained_device_peers(vault)? {
        if let Some(work) = DeferredWork::next_update(vault, BurstPeer::Device(&peer))? {
            due.push(DeviceBurstWork {
                peer,
                work: Box::new(work),
            });
        }
    }
    Ok(due)
}

/// The operations an update carries: what its end version adds to its
/// start, over every peer it names.
fn update_operations(update: &[u8]) -> Result<u64> {
    let meta = LoroDoc::decode_import_blob_meta(update, true)
        .map_err(|_| Error::InvalidConfig("device window update is no Loro update".into()))?;
    Ok(
        u64::try_from(meta.partial_end_vv.distance_between(&meta.partial_start_vv))
            .unwrap_or(u64::MAX),
    )
}
