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
//! - an address served bare, without its direct addresses, never takes the
//!   one this replica holds at that endpoint;
//! - this install's own binding lands only when it names this install's
//!   machine key and the endpoint this install serves under, the key it
//!   derives from that machine key ([`OwnMeshKeys`]); those keys come only
//!   from the install signer already loaded on this handle, so an import
//!   reads no keystore slot and never mints or forgets this install's machine
//!   identity or keys (REVIEW-10537 P1, round 2 P1);
//! - this install's own MACHINE row is filled only where it is absent or
//!   holds the empty body its enrolment wrote. Any other body stays as it
//!   is, and the own binding lands beside it only when that body is a mesh
//!   address at the endpoint the binding names (REVIEW-10537 round 2 P1).
//!
//! A replica takes its own binding as it takes any other
//! (MESH-AUTHORITY-OWN-BINDING, R6 P0, Engine 26 Nov 12:35): it holds no host
//! issuer to sign one, so a node on it could never prove its own job grant
//! (`own_grant_ended`). Nothing on a joined replica writes its own MACHINE
//! address either (device sync sends no MACHINE row), so the served address
//! fills it when it is absent.

use super::*;
use crate::ports::{EntityRecord, TombstoneStoreRead};
use crate::scan_check::EngineScan;
use crate::temporal::TimeRange;
use std::ops::Bound;

/// The most bindings one page of [`Vault::mesh_authority_page`] carries.
pub const MESH_AUTHORITY_PAGE_MAX: usize = 32;

/// The base64 bytes one page's rows may take: a quarter of the 32 MiB a
/// residence RPC reply may carry, so the reply's framing stays well inside it.
const MESH_AUTHORITY_PAGE_BYTES: usize = 8 * 1024 * 1024;

/// The base64 bytes a page's first row may take alone: three quarters of
/// that reply, room for the 26,000 grants of 255-byte ALPNs review round 2 of
/// #10536 measured, twice over. A signed row past it is named by reference
/// and read in parts (`parts`, MESH-AUTHORITY-ROW-PARTS).
const MESH_AUTHORITY_LONE_ROW_BYTES: usize = 24 * 1024 * 1024;

mod parts;
pub use parts::{
    MESH_AUTHORITY_PART_MAX, MESH_AUTHORITY_ROW_MAX, MeshAuthorityPart, MeshAuthorityRowJoin,
    MeshAuthorityRowRef,
};

/// One host-signed binding as a home holds it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MeshAuthorityRow {
    /// The MACHINE the binding names.
    pub machine: EntityId,
    /// The signed binding, as the home stores it.
    pub authority: Vec<u8>,
    /// The MACHINE row's address envelope.
    pub address: Vec<u8>,
    /// The envelope was served without its direct addresses, to fit the
    /// page: an importer keeps the address it holds at that endpoint.
    pub bare: bool,
}

/// One page of the bindings a home holds, in MACHINE id order.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct MeshAuthorityPage {
    /// The bindings carried whole, each after the one before it.
    pub rows: Vec<MeshAuthorityRow>,
    /// The bindings named by reference, each after the one before it, for
    /// the machine to read in parts ([`Vault::mesh_authority_part`]): a
    /// signed row that passes the lone row's bytes beside its address. A
    /// machine older than MESH-AUTHORITY-ROW-PARTS reads `rows` alone and
    /// misses only these, as it did when the page left them out.
    pub parted: Vec<MeshAuthorityRowRef>,
    /// The MACHINE the next page starts after, while the home holds bindings
    /// past this page; `None` once this page reached the last one. A row the
    /// page left out is behind it too, so no row holds the scan back.
    pub next: Option<EntityId>,
}

impl MeshAuthorityPage {
    /// How many bindings the page serves, whole and by reference.
    fn served(&self) -> usize {
        self.rows.len() + self.parted.len()
    }
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
    /// another endpoint or key, or a MACHINE row it cannot take); and this
    /// install's own binding when it names another machine key or endpoint
    /// than this install's own (`OwnMeshKeys`), when this handle has no
    /// signing keys loaded for this install, or when this install's MACHINE
    /// row holds a body of its own that is not a mesh address at that
    /// endpoint.
    pub refused: BTreeSet<EntityId>,
}

/// The keys this install's own binding must name: its machine key and the
/// mesh endpoint key it serves under, derived from that machine key as its
/// transport derives it ([`mesh_transport_seed_of`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct OwnMeshKeys {
    device_key: [u8; 32],
    endpoint_key: [u8; 32],
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

/// The seed of the mesh transport key an install serves under, derived from
/// its machine key `machine_key` under the transport domain
/// `oneiron-mesh-transport` derives with (`oneiron/mesh-transport-ed25519/v1`):
/// the one derivation [`Vault::mesh_transport_seed`] and an import's own keys
/// ([`OwnMeshKeys`]) share.
pub(super) fn mesh_transport_seed_of(
    machine_key: &ed25519_dalek::SigningKey,
) -> zeroize::Zeroizing<[u8; 32]> {
    // FIX 6669: derive straight into the guard.
    crate::world_keys::derive_guarded(
        "oneiron/mesh-transport-ed25519/v1",
        &[&machine_key.as_bytes()[..]],
    )
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
    /// bytes, each as stored with its MACHINE row's address. A row past
    /// them starts a page of its own, which it may fill alone up to the
    /// lone row's bytes. A signed row that passes the lone row's bytes beside
    /// its address is named by reference (`parted`), its address inline, and
    /// read in parts ([`Vault::mesh_authority_part`]). A binding that does
    /// not verify here, and one whose MACHINE carries no address, is left
    /// out. An address that passes the bytes left beside its row or
    /// reference is served bare, without its direct addresses: the binding's
    /// signature covers only its endpoint key. The caller has already
    /// admitted the machine it serves (`residence.authority.mesh`).
    ///
    /// # Errors
    ///
    /// An authority history this vault cannot fold; storage errors.
    pub fn mesh_authority_page(&self, after: Option<EntityId>) -> Result<MeshAuthorityPage> {
        self.mesh_authority_page_within(
            after,
            MESH_AUTHORITY_PAGE_BYTES,
            MESH_AUTHORITY_LONE_ROW_BYTES,
        )
    }

    /// [`Self::mesh_authority_page`] within `budget` base64 bytes, or `lone`
    /// for a page's first row.
    pub(crate) fn mesh_authority_page_within(
        &self,
        after: Option<EntityId>,
        budget: usize,
        lone: usize,
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
            if page.served() >= MESH_AUTHORITY_PAGE_MAX {
                page.next = last;
                break;
            }
            let Some(address) = self.servable_mesh_row_in_txn(&txn, &fold, machine, &authority)?
            else {
                last = Some(machine);
                continue;
            };
            // Whole while the row and its address fit a page's first row;
            // by reference otherwise, its address beside the reference.
            let (encoded, bare, size, parted) =
                match served_address(&address, authority.len(), lone.max(budget))? {
                    Some((encoded, bare)) => {
                        let size = base64_len(authority.len()) + base64_len(encoded.len());
                        (encoded, bare, size, false)
                    }
                    None => match served_address(&address, 0, budget)? {
                        Some((encoded, bare)) => {
                            let size = base64_len(encoded.len());
                            (encoded, bare, size, true)
                        }
                        None => {
                            last = Some(machine);
                            continue;
                        }
                    },
                };
            if page.served() > 0 && bytes.saturating_add(size) > budget {
                page.next = last;
                break;
            }
            bytes = bytes.saturating_add(size);
            last = Some(machine);
            if parted {
                page.parted
                    .push(MeshAuthorityRowRef::of(machine, &authority, encoded, bare));
            } else {
                page.rows.push(MeshAuthorityRow {
                    machine,
                    authority,
                    address: encoded,
                    bare,
                });
            }
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
    /// refused alone; the rest land. This install's own binding lands the
    /// same way, when it names this install's own machine key and the
    /// endpoint it serves under. Never signs anything, and never loads, mints
    /// or forgets this install's keys or machine identity.
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
        // Only for a page that carries this install's own row, and from the
        // keys loaded on this handle alone: no keystore read.
        let own_keys = own
            .filter(|own| rows.iter().any(|row| row.machine == *own))
            .and_then(|own| self.own_mesh_keys(own));
        // Nothing an import writes changes the authority log, so one fold
        // judges every row.
        let fold = self.authority_fold_readonly_in_txn(&txn)?;
        let mut count = ScanCount::start(&self.store, &txn, EngineScan::MachineRows, &[])?;
        for row in rows {
            let machine = row.machine;
            let whose = if own == Some(machine) {
                match own_keys {
                    Some(keys) => Whose::Own(keys),
                    None => {
                        import.refused.insert(machine);
                        continue;
                    }
                }
            } else {
                Whose::Other
            };
            let outcome =
                self.import_mesh_authority_row_in_txn(&mut txn, &fold, row, whose, &mut count)?;
            match outcome {
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

    /// The [`OwnMeshKeys`] of `own`, this install's machine, derived from the
    /// install signer already loaded on this handle
    /// ([`Vault::loaded_install_signer`]); `None`, logged at debug, when no
    /// signer for `own` is loaded. A serving replica loads it as its keystore
    /// installs, before its first sync round: its machine proof to the home
    /// and its mesh listener's transport key sign with the same keys. No
    /// keystore slot or key selector is read, so an import never mints a
    /// machine id, a seed or a sealing key, and never forgets a machine, with
    /// its pin and its choices (REVIEW-10537 P1, round 2 P1; on mel a new
    /// machine identity would cut it off from its home again). Without the
    /// keys its own binding is refused and every other row still lands.
    fn own_mesh_keys(&self, own: EntityId) -> Option<OwnMeshKeys> {
        let Some(signer) = self
            .loaded_install_signer()
            .filter(|signer| signer.machine == own)
        else {
            tracing::debug!(
                "this install's signing keys are not loaded; its own mesh binding is refused"
            );
            return None;
        };
        let seed = mesh_transport_seed_of(&signer.machine_key);
        Some(OwnMeshKeys {
            device_key: signer.machine_key.verifying_key().to_bytes(),
            endpoint_key: ed25519_dalek::SigningKey::from_bytes(&seed)
                .verifying_key()
                .to_bytes(),
        })
    }

    /// One served binding into `txn`, as [`Self::import_mesh_authority_rows`]
    /// takes it: verified, at the address it binds, over no binding this
    /// replica keeps instead ([`replaces`]), on a MACHINE row that can take
    /// it ([`Self::machine_row_takes_in_txn`]). This install's own binding
    /// (`whose`) must also name its own machine key and endpoint, and keeps
    /// any MACHINE body this install holds for itself.
    fn import_mesh_authority_row_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        fold: &AuthorityFold,
        row: MeshAuthorityRow,
        whose: Whose,
        count: &mut ScanCount,
    ) -> Result<RowOutcome> {
        let MeshAuthorityRow {
            machine,
            authority,
            address,
            bare,
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
        // This install's own binding names the key this install pairs with and
        // the endpoint it serves under, or it is not this install's to prove.
        if let Whose::Own(keys) = whose
            && (served.device_key != keys.device_key || served.endpoint_key != keys.endpoint_key)
        {
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
            self.machine_row_takes_in_txn(txn, machine, &address, &encoded, bare, whose, count)?
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
    /// keeps what it holds: that envelope already, or, for a `bare` row or
    /// this install's own (`whose`), a mesh address at that endpoint. A bare
    /// row keeps it because its direct addresses may be this replica's only
    /// route (REVIEW-10536 round 2). Another machine's row with no mesh
    /// address takes it: no peer sends a MACHINE row. This install's own row
    /// is this install's own to write: only an absent one, or the empty body
    /// its enrolment wrote (`EMPTY_MACHINE_BODY`), takes it, and any other
    /// body refuses it and stays (REVIEW-10537 round 2 P1).
    #[expect(
        clippy::too_many_arguments,
        reason = "one served row's address, its envelope, whether it came bare, whose row it is, and the import's scan count"
    )]
    fn machine_row_takes_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        machine: EntityId,
        address: &MeshMachineAddress,
        encoded: &[u8],
        bare: bool,
        whose: Whose,
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
        let Some(existing) = existing else {
            return Ok(Some(false));
        };
        let own = matches!(whose, Whose::Own(_));
        let held = existing.body == encoded
            || ((bare || own)
                && parse_address(&existing.body)
                    .is_some_and(|held| held.endpoint_key == address.endpoint_key));
        if own && !held && existing.body != super::super::machine_identity::EMPTY_MACHINE_BODY {
            return Ok(None);
        }
        Ok(Some(held))
    }
}

/// The envelope a page serves `address` in, beside a signed row of
/// `authority_len` bytes, within `budget` base64 bytes, and whether it is
/// bare: whole when it fits, else without its direct addresses (the
/// signature covers only the endpoint key, REVIEW-10536 P1). `None` when even
/// that does not fit.
fn served_address(
    address: &MeshMachineAddress,
    authority_len: usize,
    budget: usize,
) -> Result<Option<(Vec<u8>, bool)>> {
    let fits = |encoded: &[u8]| base64_len(authority_len) + base64_len(encoded.len()) <= budget;
    let whole = rmp_serde::to_vec_named(&MeshMachineAddressEnvelope::new(address.clone()))
        .map_err(|_| invalid_authority())?;
    if fits(&whole) {
        return Ok(Some((whole, false)));
    }
    let bare = rmp_serde::to_vec_named(&MeshMachineAddressEnvelope::new(MeshMachineAddress {
        direct_addrs: Vec::new(),
        ..address.clone()
    }))
    .map_err(|_| invalid_authority())?;
    Ok(fits(&bare).then_some((bare, true)))
}

/// Whose binding one served row is.
#[derive(Clone, Copy)]
enum Whose {
    /// Another machine's.
    Other,
    /// This install's own, with the keys it must name.
    Own(OwnMeshKeys),
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
