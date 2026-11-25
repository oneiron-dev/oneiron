//! The home's host-signed mesh bindings carried to the owner's other machines
//! (MESH-AUTHORITY-REPLICATION, R6 P0, Engine 26 Nov 02:16).
//!
//! A binding (`AUTHORITY_MESH_MACHINE`) and the MACHINE address row it binds
//! are this install's own rows: device sync carries neither. The authority log
//! carries the pairing and grant mints a binding names, but no peer sends a
//! MACHINE row and no window holds a binding. A joined replica holds no host
//! issuer (FIX 10770), so it cannot sign a binding of its own either, and a
//! node on such a replica could prove no peer the owner bound on the home.
//!
//! The reader already trusts a binding signed by any live owner host of its
//! own fold (`verified_mesh_authority`). So the home serves its bindings as
//! it stores them, each with the address its MACHINE row holds
//! ([`Vault::mesh_authority_page`]). A machine of the owner's imports each one
//! ([`Vault::import_mesh_authority_rows`]): the signature and the live owner
//! host are checked against its own fold, and the row is written as it was
//! signed, never re-signed. Every other check stays where it is, on the read:
//! the pairing, the grants, the machine's proof key and its removal are judged
//! against this replica's fold each time a peer is proven.
//!
//! An import never widens what a replica holds:
//! - a row another host signed is never replaced;
//! - a revoked binding stays revoked;
//! - a binding never moves to another endpoint or machine key;
//! - this install's own MACHINE row stays its own to write.
//!
//! An older row from the same host can only name fewer live grants: a grant's
//! withdrawal is a revoke in the authority log, which every replica folds.

use super::*;
use crate::ports::{EntityRecord, TombstoneStoreRead};
use crate::scan_check::EngineScan;
use crate::temporal::TimeRange;
use std::ops::Bound;

/// The most bindings one page of [`Vault::mesh_authority_page`] carries.
pub const MESH_AUTHORITY_PAGE_MAX: usize = 32;

/// The bytes past which a page stops taking rows, once it holds one: a
/// quarter of the residence reply bound, since a binding keeps every direct
/// address its MACHINE names (FIX 7922).
const MESH_AUTHORITY_PAGE_BYTES: usize = crate::sync::residence::RESIDENCE_PAGE_REPLY_BYTES / 4;

/// One host-signed binding as a home holds it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MeshAuthorityRow {
    /// The MACHINE the binding names.
    pub machine: EntityId,
    /// The signed binding, as the home stores it.
    pub authority: Vec<u8>,
    /// The MACHINE row's address envelope, as the home stores it.
    pub address: Vec<u8>,
}

/// One page of the bindings a home holds, in MACHINE id order.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct MeshAuthorityPage {
    /// The bindings, each after the one before it.
    pub rows: Vec<MeshAuthorityRow>,
    /// Whether the home holds a binding past the last one here.
    pub more: bool,
}

/// What one import did with each binding a home served.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct MeshAuthorityImport {
    /// The bindings written here.
    pub written: BTreeSet<EntityId>,
    /// The bindings already held here exactly as served.
    pub held: BTreeSet<EntityId>,
    /// The bindings refused: a row that does not decode or verify here, an
    /// address that is not the one it binds, or a row this replica keeps
    /// instead (another host's, a revoked one, another endpoint or key, or
    /// a MACHINE row it cannot take).
    pub refused: BTreeSet<EntityId>,
    /// This install's own MACHINE, left to this install.
    pub own: BTreeSet<EntityId>,
}

/// Whether `stored`, the binding this replica holds, gives way to `served`,
/// both signed for the same MACHINE: the same host, still unrevoked, at the
/// same endpoint under the same machine key.
fn replaces(stored: &MeshAuthorityClaims, served: &MeshAuthorityClaims) -> bool {
    !stored.revoked
        && stored.host_key == served.host_key
        && stored.endpoint_key == served.endpoint_key
        && stored.device_key == served.device_key
}

/// Whether `served` withdraws something `stored` held: the binding revoked,
/// or a grant it named dropped. Live streams recheck their grants then.
fn narrows(stored: Option<&MeshAuthorityClaims>, served: &MeshAuthorityClaims) -> bool {
    stored.is_some_and(|stored| {
        (served.revoked && !stored.revoked)
            || stored
                .alpns
                .iter()
                .any(|(alpn, grant)| served.alpns.get(alpn) != Some(grant))
    })
}

impl Vault {
    /// The bindings this vault holds after MACHINE `after`, at most
    /// [`MESH_AUTHORITY_PAGE_MAX`], each as stored with its MACHINE row's
    /// address. A binding that does not verify here, and one whose MACHINE
    /// carries no address, is left out. The caller has already admitted the
    /// machine it serves (`residence.authority.mesh`).
    ///
    /// # Errors
    ///
    /// An authority history this vault cannot fold; storage errors.
    pub fn mesh_authority_page(&self, after: Option<EntityId>) -> Result<MeshAuthorityPage> {
        let txn = self.store.env.read_txn()?;
        let fold = self.authority_fold_readonly_in_txn(&txn)?;
        let start = after.map(HexId);
        let rows = MESH_AUTHORITY.iter_raw_range(
            &self.store,
            &txn,
            start.as_ref().map_or(Bound::Unbounded, Bound::Excluded),
            Bound::Unbounded,
        )?;
        let mut page = MeshAuthorityPage::default();
        let mut bytes = 0usize;
        for row in rows {
            let (HexId(machine), authority) = row?;
            if page.rows.len() >= MESH_AUTHORITY_PAGE_MAX
                || (!page.rows.is_empty() && bytes >= MESH_AUTHORITY_PAGE_BYTES)
            {
                page.more = true;
                break;
            }
            let Ok(signed) = MESH_AUTHORITY.decode_value(&authority) else {
                continue;
            };
            if !matches!(
                verified_mesh_authority(&fold, machine, &signed),
                Ok(Some(_))
            ) {
                continue;
            }
            let Some(address) = self.mesh_machine_in_txn(&txn, machine)? else {
                continue;
            };
            let address = rmp_serde::to_vec_named(&MeshMachineAddressEnvelope::new(address))
                .map_err(|_| invalid_authority())?;
            bytes = bytes.saturating_add(authority.len() + address.len());
            page.rows.push(MeshAuthorityRow {
                machine,
                authority,
                address,
            });
        }
        Ok(page)
    }

    /// Imports the bindings a home served (`rows`, one page): each one a live
    /// owner host of this vault's fold signed, written as signed with its
    /// MACHINE address row, in one write. A row this replica cannot take is
    /// refused alone; the rest land. Never signs anything.
    ///
    /// # Errors
    ///
    /// An authority history this vault cannot fold; storage errors.
    pub fn import_mesh_authority_rows(
        &self,
        rows: Vec<MeshAuthorityRow>,
    ) -> Result<MeshAuthorityImport> {
        let mut import = MeshAuthorityImport::default();
        let mut narrowed = false;
        let mut txn = self.store.env.write_txn()?;
        let own = crate::identity::read_machine_id_in_txn(self, &txn)?;
        // Nothing an import writes changes the authority log, so one fold
        // judges every row.
        let fold = self.authority_fold_readonly_in_txn(&txn)?;
        let mut count = ScanCount::start(&self.store, &txn, EngineScan::MachineRows, &[])?;
        for row in rows {
            let machine = row.machine;
            if own == Some(machine) {
                import.own.insert(machine);
                continue;
            }
            match self.import_mesh_authority_row_in_txn(&mut txn, &fold, row, &mut count)? {
                RowOutcome::Written { narrowed: withdrew } => {
                    narrowed |= withdrew;
                    import.written.insert(machine);
                }
                RowOutcome::Held => {
                    import.held.insert(machine);
                }
                RowOutcome::Refused => {
                    import.refused.insert(machine);
                }
            }
        }
        txn.commit()?;
        count.finish(self);
        if narrowed {
            self.store.notify_credential_revocations();
        }
        Ok(import)
    }

    /// One served binding into `txn`, as [`Self::import_mesh_authority_rows`]
    /// takes it: verified, at the address it binds, over no binding this
    /// replica keeps instead ([`replaces`]), on a MACHINE row that can take
    /// it ([`Self::machine_row_takes_in_txn`]).
    fn import_mesh_authority_row_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        fold: &AuthorityFold,
        row: MeshAuthorityRow,
        count: &mut ScanCount,
    ) -> Result<RowOutcome> {
        // RED STUB: the replica refuses every binding the home serves.
        if !row.machine.as_bytes().is_empty() {
            return Ok(RowOutcome::Refused);
        }
        let MeshAuthorityRow {
            machine,
            authority,
            address,
        } = row;
        let Ok(signed) = MESH_AUTHORITY.decode_value(&authority) else {
            return Ok(RowOutcome::Refused);
        };
        let Ok(Some(served)) = verified_mesh_authority(fold, machine, &signed) else {
            return Ok(RowOutcome::Refused);
        };
        let Some(address) = parse_address(&address) else {
            return Ok(RowOutcome::Refused);
        };
        if address.endpoint_key != served.endpoint_key {
            return Ok(RowOutcome::Refused);
        }
        // Every direct address and grant is kept (FIX 7921, 7922): measured,
        // never refused for its count.
        self.measure_authority_items(address.direct_addrs.len() + served.alpns.len());
        let encoded = rmp_serde::to_vec_named(&MeshMachineAddressEnvelope::new(address.clone()))
            .map_err(|_| invalid_authority())?;
        let stored = match MESH_AUTHORITY.get_bytes(&self.store, txn, &HexId(machine))? {
            Some(bytes) => match MESH_AUTHORITY.decode_value(&bytes) {
                Ok(stored) => Some((bytes, stored.claims)),
                Err(_) => return Ok(RowOutcome::Refused),
            },
            None => None,
        };
        if let Some((_, claims)) = &stored
            && !replaces(claims, &served)
        {
            return Ok(RowOutcome::Refused);
        }
        let Some(address_held) =
            self.machine_row_takes_in_txn(txn, machine, &address, &encoded, count)?
        else {
            return Ok(RowOutcome::Refused);
        };
        if address_held
            && stored
                .as_ref()
                .is_some_and(|(bytes, _)| *bytes == authority)
        {
            return Ok(RowOutcome::Held);
        }
        if !address_held {
            let now = self.instant_in_txn(txn)?.secs();
            EntityStore::port_entity_put(
                self,
                txn,
                &machine,
                &EntityRecord {
                    entity_type: ENTITY_TYPE_MACHINE,
                    occurred: TimeRange {
                        start: now,
                        end: now,
                    },
                    learned_at: now,
                    row_version: 0,
                    body: encoded,
                },
            )?;
        }
        let narrowed = narrows(stored.as_ref().map(|(_, claims)| claims), &served);
        MESH_AUTHORITY.put(&self.store, txn, &HexId(machine), &signed)?;
        Ok(RowOutcome::Written { narrowed })
    }

    /// Whether `machine`'s MACHINE row here can take `encoded`, the envelope
    /// of `address`, as the bind judges it ([`Self::bind_mesh_machine_in_txn`]):
    /// `None` when another kind, a deleted or stale holder, a mesh address at
    /// another endpoint, or another MACHINE at this endpoint refuses it; else
    /// whether the row holds that envelope already. An absent row takes it:
    /// no peer sends a MACHINE row.
    fn machine_row_takes_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        machine: EntityId,
        address: &MeshMachineAddress,
        encoded: &[u8],
        count: &mut ScanCount,
    ) -> Result<Option<bool>> {
        let visibility = TombstoneStoreRead::port_deletion_state(&self.store, txn, &machine)?;
        if visibility.deleted || visibility.archived || visibility.stale {
            return Ok(None);
        }
        let existing = EntityStoreRead::port_entity_record(&self.store, txn, &machine)?;
        if let Some(existing) = &existing {
            if existing.entity_type != ENTITY_TYPE_MACHINE
                || EntityStore::port_entity_get(self, txn, &machine)?.is_none()
            {
                return Ok(None);
            }
            if let Ok(prior) = rmp_serde::from_slice::<MeshMachineAddressEnvelope>(&existing.body)
                && prior.domain == DOMAIN
                && (prior.version != 1
                    || parse_address(&existing.body).is_none()
                    || prior.address.endpoint_key != address.endpoint_key)
            {
                return Ok(None);
            }
        }
        if self
            .mesh_machine_by_endpoint_in_txn(txn, address.endpoint_key, Some(count))?
            .is_some_and(|(id, _)| id != machine)
        {
            return Ok(None);
        }
        Ok(Some(existing.is_some_and(|row| row.body == encoded)))
    }
}

/// What one import did with one binding.
enum RowOutcome {
    /// Written here; `narrowed` when it withdrew a grant or the binding.
    Written { narrowed: bool },
    /// Already held exactly as served.
    Held,
    /// Refused; this replica keeps what it held.
    Refused,
}
