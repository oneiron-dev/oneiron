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
//! - a row replaces only an older row of the same host: its signed revision
//!   is higher (REVIEW-10536 P1: a replayed row from before a rebind must not
//!   bring back the older pairing);
//! - a revoked binding stays revoked;
//! - a binding never moves to another endpoint or machine key;
//! - this install's own MACHINE row stays its own to write.

use super::*;
use crate::ports::{EntityRecord, TombstoneStoreRead};
use crate::scan_check::EngineScan;
use crate::temporal::TimeRange;
use std::ops::Bound;

/// The most bindings one page of [`Vault::mesh_authority_page`] carries.
pub const MESH_AUTHORITY_PAGE_MAX: usize = 32;

/// The base64 bytes one page's rows may take: half the 16 MiB a residence
/// page reply may carry, so the reply's framing stays well inside it.
const MESH_AUTHORITY_PAGE_BYTES: usize = 8 * 1024 * 1024;

/// One host-signed binding as a home holds it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MeshAuthorityRow {
    /// The MACHINE the binding names.
    pub machine: EntityId,
    /// The signed binding, as the home stores it.
    pub authority: Vec<u8>,
    /// The MACHINE row's address envelope.
    pub address: Vec<u8>,
}

/// One page of the bindings a home holds, in MACHINE id order.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct MeshAuthorityPage {
    /// The bindings, each after the one before it.
    pub rows: Vec<MeshAuthorityRow>,
    /// The MACHINE the next page starts after, while the home holds bindings
    /// past this page; `None` once this page reached the last one. A row the
    /// page left out is behind it too, so no row holds the scan back.
    pub next: Option<EntityId>,
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
    /// instead (another host's, an older or equal revision, a revoked one,
    /// another endpoint or key, or a MACHINE row it cannot take).
    pub refused: BTreeSet<EntityId>,
    /// This install's own MACHINE, left to this install.
    pub own: BTreeSet<EntityId>,
}

/// The claims of `signed`, the binding row of `machine`, when a live owner
/// host of `fold` signed it: well formed, the vault root not conflicted, its
/// host a live owner in the roster, and the signature that host's. A row
/// that does not check refuses; a host that is not a live owner answers
/// `None`. A stored row and one a home serves are judged alike
/// (MESH-AUTHORITY-REPLICATION).
pub(super) fn verified_mesh_authority(
    fold: &AuthorityFold,
    machine: EntityId,
    signed: &SignedMeshAuthority,
) -> Result<Option<MeshAuthorityClaims>> {
    // Every ALPN grant the host signed is read, however many (FIX 7921);
    // each must still be a valid ALPN.
    let claims = &signed.claims;
    if claims.version != 1
        || claims.machine != machine
        || claims.alpns.keys().any(|alpn| !valid_alpn(alpn))
    {
        return Err(invalid_authority());
    }
    if fold.vault_root_is_conflicted()
        || !roster_has_live_owner(&fold.roster, &AuthorityKey::Ed25519(claims.host_key))
    {
        return Ok(None);
    }
    let host = super::super::strong_ed25519_key(&claims.host_key)?;
    let sig = Signature::from_slice(&signed.signature).map_err(|_| invalid_authority())?;
    host.verify_strict(&transcript(claims)?, &sig)
        .map_err(|_| invalid_authority())?;
    Ok(Some(claims.clone()))
}

/// The length of `bytes` bytes in standard base64, as a reply carries them.
fn base64_len(bytes: usize) -> usize {
    bytes.div_ceil(3).saturating_mul(4)
}

/// Whether `stored`, the binding this replica holds, gives way to `served`,
/// both signed for the same MACHINE: the same host wrote `served` later
/// (a higher revision), the stored one is unrevoked, and both name the same
/// endpoint under the same machine key.
fn replaces(stored: &MeshAuthorityClaims, served: &MeshAuthorityClaims) -> bool {
    !stored.revoked
        && served.revision > stored.revision
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

/// Whether `error` is the authority refusal a lookup answers for an endpoint
/// two MACHINE rows name, as opposed to a storage error.
fn is_authority_refusal(error: &crate::Error) -> bool {
    matches!(
        error,
        crate::Error::Record(crate::error::RecordError::InvalidAuthorityLogBody(_))
    )
}

impl Vault {
    /// The bindings this vault holds after MACHINE `after`, at most
    /// [`MESH_AUTHORITY_PAGE_MAX`] and as many as fit the page's encoded
    /// bytes, each as stored with its MACHINE row's address. A binding that
    /// does not verify here, one whose MACHINE carries no address, and one
    /// whose signed row alone passes the page's bytes, is left out. An
    /// address that alone passes them is served without its direct
    /// addresses: the binding's signature covers only its endpoint key. The
    /// caller has already admitted the machine it serves
    /// (`residence.authority.mesh`).
    ///
    /// # Errors
    ///
    /// An authority history this vault cannot fold; storage errors.
    pub fn mesh_authority_page(&self, after: Option<EntityId>) -> Result<MeshAuthorityPage> {
        self.mesh_authority_page_within(after, MESH_AUTHORITY_PAGE_BYTES)
    }

    /// [`Self::mesh_authority_page`] within `budget` base64 bytes.
    pub(crate) fn mesh_authority_page_within(
        &self,
        after: Option<EntityId>,
        budget: usize,
    ) -> Result<MeshAuthorityPage> {
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
        let mut last = None;
        for row in rows {
            let (HexId(machine), authority) = row?;
            if page.rows.len() >= MESH_AUTHORITY_PAGE_MAX {
                page.next = last;
                break;
            }
            let Some(address) = self.servable_mesh_row_in_txn(&txn, &fold, machine, &authority)?
            else {
                last = Some(machine);
                continue;
            };
            let Some(encoded) = served_address(&address, authority.len(), budget)? else {
                last = Some(machine);
                continue;
            };
            let size = base64_len(authority.len()) + base64_len(encoded.len());
            if bytes.saturating_add(size) > budget {
                page.next = last;
                break;
            }
            bytes += size;
            last = Some(machine);
            page.rows.push(MeshAuthorityRow {
                machine,
                authority,
                address: encoded,
            });
        }
        Ok(page)
    }

    /// The address `machine`'s stored binding `authority` is served with:
    /// its MACHINE row's, when the binding decodes and verifies here; `None`
    /// when it does not, or the MACHINE carries no address.
    fn servable_mesh_row_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        fold: &AuthorityFold,
        machine: EntityId,
        authority: &[u8],
    ) -> Result<Option<MeshMachineAddress>> {
        let Ok(signed) = MESH_AUTHORITY.decode_value(authority) else {
            return Ok(None);
        };
        if !matches!(verified_mesh_authority(fold, machine, &signed), Ok(Some(_))) {
            return Ok(None);
        }
        self.mesh_machine_in_txn(txn, machine)
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
        let same_row = stored
            .as_ref()
            .is_some_and(|(bytes, _)| *bytes == authority);
        if let Some((_, claims)) = &stored
            && !same_row
            && !replaces(claims, &served)
        {
            return Ok(RowOutcome::Refused);
        }
        let Some(address_held) =
            self.machine_row_takes_in_txn(txn, machine, &address, &encoded, count)?
        else {
            return Ok(RowOutcome::Refused);
        };
        if address_held && same_row {
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
        if same_row {
            return Ok(RowOutcome::Written { narrowed: false });
        }
        let narrowed = narrows(stored.as_ref().map(|(_, claims)| claims), &served);
        MESH_AUTHORITY.put(&self.store, txn, &HexId(machine), &signed)?;
        Ok(RowOutcome::Written { narrowed })
    }

    /// Whether `machine`'s MACHINE row here can take `encoded`, the envelope
    /// of `address`, as the bind judges it ([`Self::bind_mesh_machine_in_txn`]):
    /// `None` when another kind, a deleted or stale holder, a mesh address at
    /// another endpoint, or another MACHINE at this endpoint refuses it, two
    /// MACHINE rows here naming that endpoint included; else whether the row
    /// holds that envelope already. An absent row takes it: no peer sends a
    /// MACHINE row.
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
        // An endpoint two MACHINE rows here name refuses this row alone, so
        // the rest of the page still lands (REVIEW-10536 P1).
        match self.mesh_machine_by_endpoint_in_txn(txn, address.endpoint_key, Some(count)) {
            Ok(Some((id, _))) if id != machine => return Ok(None),
            Ok(_) => {}
            Err(error) if is_authority_refusal(&error) => return Ok(None),
            Err(error) => return Err(error),
        }
        Ok(Some(existing.is_some_and(|row| row.body == encoded)))
    }
}

/// The envelope a page serves `address` in, beside a signed row of
/// `authority_len` bytes, within `budget` base64 bytes: whole when it fits,
/// else without its direct addresses (the signature covers only the endpoint
/// key, REVIEW-10536 P1). `None` when even that does not fit.
fn served_address(
    address: &MeshMachineAddress,
    authority_len: usize,
    budget: usize,
) -> Result<Option<Vec<u8>>> {
    let fits = |encoded: &[u8]| base64_len(authority_len) + base64_len(encoded.len()) <= budget;
    let whole = rmp_serde::to_vec_named(&MeshMachineAddressEnvelope::new(address.clone()))
        .map_err(|_| invalid_authority())?;
    if fits(&whole) {
        return Ok(Some(whole));
    }
    let bare = rmp_serde::to_vec_named(&MeshMachineAddressEnvelope::new(MeshMachineAddress {
        direct_addrs: Vec::new(),
        ..address.clone()
    }))
    .map_err(|_| invalid_authority())?;
    Ok(fits(&bare).then_some(bare))
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
