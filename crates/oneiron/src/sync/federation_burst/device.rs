//! One of this vault's own devices as a burst peer (L7-41). A device's
//! window update at its home gets the same relative response a federated
//! peer's does (arch-0023b `#decision-federation-26`: allow,
//! isolate-and-propose or defer, against the peer's own baseline and the
//! vault's size; never a plain block, never a pause for a human).

use std::collections::BTreeSet;

use loro::LoroDoc;

use super::{
    BurstPeer, DeferredWork, FederationBurstDecision, FederationBurstPeerRef, WorkKind, admit_work,
    corrupt, hash_grant_pacts,
};
use crate::authority::{PeerMachine, WorldPrivacyView};
use crate::federation::decode_federation_grant_body;
use crate::registry::ENTITY_TYPE_FEDERATION_GRANT;
use crate::sync::WindowKey;
use crate::vault::{LiveEntityRow, live_entity_row_in_txn};
use crate::{EntityId, Error, Result, Vault};

/// An own device as its connection proved it, in the order its home reads
/// it: the machine the connection proved, else the paired app's slip that
/// bound its Write credential, else one shared bucket for connections that
/// proved neither. It names whose baseline a write counts against; it grants
/// and refuses nothing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DevicePeer {
    /// A machine that proved, on its connection, the key it stands on here,
    /// with the id of the slip that bound the connection's Write credential,
    /// if one did.
    Machine {
        machine: EntityId,
        key: [u8; 32],
        slip: Option<[u8; 32]>,
    },
    /// The id of the slip that bound the connection's Write credential.
    Slip { slip: [u8; 32] },
    /// A connection that proved neither.
    Unproven,
}

impl DevicePeer {
    /// The device a connection proved: its machine when it is
    /// [`PeerMachine::Proven`], with the slip of its Write credential, else
    /// that slip, else [`Self::Unproven`].
    #[must_use]
    pub fn of_connection(machine: PeerMachine, slip: Option<[u8; 32]>) -> Self {
        match (machine, slip) {
            (PeerMachine::Proven { machine, key }, slip) => Self::Machine { machine, key, slip },
            (PeerMachine::Unknown, Some(slip)) => Self::Slip { slip },
            (PeerMachine::Unknown, None) => Self::Unproven,
        }
    }

    /// The machine its connection proved, as the home's own-device import
    /// reads it; [`PeerMachine::Unknown`] for a slip or an unproven device.
    #[must_use]
    pub fn machine(&self) -> PeerMachine {
        match *self {
            Self::Machine { machine, key, .. } => PeerMachine::Proven { machine, key },
            Self::Slip { .. } | Self::Unproven => PeerMachine::Unknown,
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
    /// connection proved it, a machine's key and slip included.
    pub(super) fn encode(&self) -> Vec<u8> {
        match self {
            Self::Machine { machine, key, slip } => {
                let mut bytes = vec![0];
                bytes.extend_from_slice(machine.as_bytes());
                bytes.extend_from_slice(key);
                if let Some(slip) = slip {
                    bytes.extend_from_slice(slip);
                }
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
                let (machine, rest) = rest.split_first_chunk::<16>().ok_or_else(corrupt)?;
                let (key, slip) = rest.split_first_chunk::<32>().ok_or_else(corrupt)?;
                Ok(Self::Machine {
                    machine: EntityId::from_bytes(*machine).map_err(|_| corrupt())?,
                    key: *key,
                    slip: match slip {
                        [] => None,
                        slip => Some(slip.try_into().map_err(|_| corrupt())?),
                    },
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
    /// its connection proved it (a machine on the same proof key, and the
    /// slip of its Write credential standing as the home's persist recheck
    /// reads one: unexpired, unrevoked, its grant and member scope standing),
    /// and, under a slip, the write authority the home's residence arm
    /// admitted its update under ([`Self::hash_write_authority_in`]). A
    /// machine removed or proving another key since, a slip that has expired
    /// or been revoked since (FIX 7999), and any change of that write
    /// authority since (BURST-REPLAY-SKIPS-ROW-ADMISSION) end that work
    /// `StaleAuthority`. The UPDATE arm held it only past that same
    /// credential's live check and that same row admission.
    pub(super) fn authority_digest_in_txn(
        &self,
        vault: &Vault,
        txn: &heed::RoTxn<'_>,
    ) -> Result<[u8; 32]> {
        let (machine_stands, slip) = match self {
            Self::Machine { machine, key, slip } => (
                vault
                    .authority_view_readonly_in_txn(txn)?
                    .machine_proof_key(*machine)
                    == Some(*key),
                slip.as_ref(),
            ),
            Self::Slip { slip } => (true, Some(slip)),
            Self::Unproven => (true, None),
        };
        let slip_stands = match slip {
            Some(slip) => vault.folded_slip_stands_in_txn(txn, slip)?,
            None => true,
        };
        let mut hash = blake3::Hasher::new();
        hash.update(b"oneiron/device-peer-authority/v2");
        hash.update(&self.encode());
        hash.update(&[u8::from(machine_stands), u8::from(slip_stands)]);
        if let Some(slip) = slip {
            self.hash_write_authority_in(&mut hash, vault, txn, slip)?;
        }
        Ok(*hash.finalize().as_bytes())
    }

    /// Hashes into `hash` the write authority the home's residence arm
    /// admitted an update of this device's under, the slip `slip` bound to
    /// its connection: the live row of each grant the arm may have judged it
    /// under (the slip's own grant, and every grant of the slip's holder
    /// under the residence selector's scope, which the selector names), with
    /// whether it confers now as the arm judges a grant's end, the pacts that
    /// bind each, and the worlds kept off the device's machine. The held work
    /// keeps no selector, so the drain cannot judge its rows again; any edit
    /// of one of these since, a narrowing in place included, and any of those
    /// grants expired since end the work `StaleAuthority` before it lands. A
    /// widening ends it too, and the device sends its update again.
    fn hash_write_authority_in(
        &self,
        hash: &mut blake3::Hasher,
        vault: &Vault,
        txn: &heed::RoTxn<'_>,
        slip: &[u8; 32],
    ) -> Result<()> {
        let fold = vault.authority_view_readonly_in_txn(txn)?;
        let Some(mint) = fold.slips.mints.get(slip) else {
            hash.update(b"no-mint");
            return Ok(());
        };
        let claims = &mint.action.claims;
        let mut grants = vault
            .residence_scope_grants_in_txn(txn, &claims.holder_ref)?
            .into_iter()
            .collect::<BTreeSet<_>>();
        match claims.grant_ref.as_deref().map(EntityId::from_hex) {
            Some(Ok(grant)) => {
                grants.insert(grant);
            }
            Some(Err(_)) => {
                hash.update(b"unreadable-grant-ref");
            }
            None => {}
        }
        // A grant's end is judged on the grant clock, as the slip's own
        // grant is (`folded_slip_stands_in_txn`): its expiry passing changes
        // no row, so whether it confers is hashed too (#9226 review).
        let now = vault.grant_judgement_secs_in_txn(txn)?;
        hash.update(b"grants");
        hash.update(&(grants.len() as u64).to_be_bytes());
        for grant in grants {
            hash.update(grant.as_bytes());
            let row = live_entity_row_in_txn(&vault.store, txn, &grant)?;
            match vault.get_raw_in(txn, &grant)?.filter(|_| row.is_live()) {
                Some(raw) => {
                    hash.update(b"live");
                    hash.update(&(raw.len() as u64).to_be_bytes());
                    hash.update(&raw);
                    let confers = match &row {
                        LiveEntityRow::Live {
                            entity_type: ENTITY_TYPE_FEDERATION_GRANT,
                            body,
                        } => decode_federation_grant_body(body)?.confers_at(now),
                        _ => false,
                    };
                    hash.update(&[u8::from(confers)]);
                }
                None => {
                    hash.update(b"gone");
                }
            }
            hash_grant_pacts(hash, &fold, grant)?;
        }
        match WorldPrivacyView::load_unless_conflicted_in(vault, txn)? {
            Some(view) => {
                let withheld = view.withheld_for_peer(self.machine())?;
                hash.update(b"withheld");
                hash.update(&(withheld.len() as u64).to_be_bytes());
                for world in withheld {
                    hash.update(world.as_bytes());
                }
            }
            None => {
                hash.update(b"conflicted");
            }
        }
        Ok(())
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

    /// Whether the batch still stands in `txn` as [`ready_device_work`]
    /// handed it back: still held under its key, and its device's authority
    /// digest the one it was held under. The drain judged both in its own
    /// read, before its home loaded the window; the home judges them again
    /// in the writer that persists the update's bytes, so a grant narrowed,
    /// expired or revoked, a world kept off the device, or the batch ended or
    /// erased in between lands nothing (#9226 review).
    ///
    /// # Errors
    /// A store error, or a held row that does not decode.
    pub fn stands_in_txn(&self, vault: &Vault, txn: &heed::RoTxn<'_>) -> Result<bool> {
        let held = match vault.store.sync_queue.get(txn, &self.work.key())? {
            Some(value) => DeferredWork::decode(&value)?.id == self.work.id,
            None => false,
        };
        Ok(held
            && BurstPeer::Device(&self.peer).authority_digest_in_txn(vault, txn)?
                == self.work.authority_digest)
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

/// Counts an own device's window update its home refused as the device's
/// own bytes before the burst core judged it: a structural failure on the
/// device's streak, as a federated peer's refused update is one on its own
/// (arch-0023b `#decision-federation-26`: rate and streak; L7-41).
///
/// # Errors
/// A store error.
pub fn record_device_refusal(vault: &Vault, peer: &DevicePeer) -> Result<()> {
    super::record_outcome(vault, BurstPeer::Device(peer), true)
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
