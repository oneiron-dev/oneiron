//! A binding past one page, read in parts (MESH-AUTHORITY-ROW-PARTS, review
//! round 2 of #10536).
//!
//! The grant door never refuses a binding for its count (FIX 7921), so a
//! signed row can pass the bytes a page's first row may take alone
//! ([`MESH_AUTHORITY_LONE_ROW_BYTES`], about 60,000 grants at the longest
//! ALPN). The page names such a row by reference ([`MeshAuthorityRowRef`]:
//! its MACHINE, its length and its content hash, its address inline), and
//! the machine reads it a part at a time ([`Vault::mesh_authority_part`],
//! `residence.authority.mesh.part`), as it reads an authority entry past one
//! frame (FIX 8246). It joins the parts ([`MeshAuthorityRowJoin`]), checks
//! the length against [`MESH_AUTHORITY_ROW_MAX`] and the content hash, and
//! imports the row as one a page carried whole: nothing served is trusted
//! until its signature checks there.

use super::*;
use oneiron_contracts::fingerprint::ContentHash;

/// The most bytes one part carries: their base64 is one page's bytes.
pub const MESH_AUTHORITY_PART_MAX: usize = MESH_AUTHORITY_PAGE_BYTES / 4 * 3;

/// The longest signed row a machine joins from parts: 256 MiB, about
/// 850,000 grants at the longest ALPN. A reference past it is refused alone.
pub const MESH_AUTHORITY_ROW_MAX: usize = 256 * 1024 * 1024;

/// A binding a page names by reference, its signed row read in parts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MeshAuthorityRowRef {
    /// The MACHINE the binding names.
    pub machine: EntityId,
    /// The signed row's length in bytes.
    pub total: u64,
    /// The signed row's content hash ([`ContentHash`], BLAKE3); the wire
    /// spells it as [`Self::digest_text`] does.
    pub digest: [u8; 32],
    /// The MACHINE row's address envelope, as [`MeshAuthorityRow::address`].
    pub address: Vec<u8>,
    /// As [`MeshAuthorityRow::bare`].
    pub bare: bool,
}

impl MeshAuthorityRowRef {
    /// The reference to `authority`, the signed row of `machine`, served
    /// with the address envelope `address`.
    pub(super) fn of(machine: EntityId, authority: &[u8], address: Vec<u8>, bare: bool) -> Self {
        Self {
            machine,
            total: authority.len() as u64,
            digest: ContentHash::of(authority).into_bytes(),
            address,
            bare,
        }
    }

    /// The content hash as the wire spells it: `blake3:` and 64 lower-case
    /// hex digits, the hash named so that a later change of hash shows there.
    #[must_use]
    pub fn digest_text(&self) -> String {
        format!("blake3:{}", oneiron_hex::encode(&self.digest))
    }

    /// The content hash `text` spells as [`Self::digest_text`] does; `None`
    /// for any other hash or spelling.
    #[must_use]
    pub fn digest_from_text(text: &str) -> Option<[u8; 32]> {
        oneiron_hex::decode::<32>(text.strip_prefix("blake3:")?)
    }
}

/// One part of a signed row ([`Vault::mesh_authority_part`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MeshAuthorityPart {
    /// The whole row's length in bytes.
    pub total: u64,
    /// Its bytes from the part's offset.
    pub part: Vec<u8>,
}

/// A signed row joined from its parts, each after the one before it.
#[derive(Debug)]
pub struct MeshAuthorityRowJoin {
    reference: MeshAuthorityRowRef,
    authority: Vec<u8>,
}

impl MeshAuthorityRowJoin {
    /// A join of the row `reference` names; `None` for an empty row and one
    /// past [`MESH_AUTHORITY_ROW_MAX`].
    #[must_use]
    pub fn start(reference: MeshAuthorityRowRef) -> Option<Self> {
        let total = usize::try_from(reference.total)
            .ok()
            .filter(|total| (1..=MESH_AUTHORITY_ROW_MAX).contains(total))?;
        Some(Self {
            authority: Vec::with_capacity(total.min(MESH_AUTHORITY_PART_MAX)),
            reference,
        })
    }

    /// The MACHINE the binding names.
    #[must_use]
    pub fn machine(&self) -> EntityId {
        self.reference.machine
    }

    /// The offset the next part starts at.
    #[must_use]
    pub fn offset(&self) -> u64 {
        self.authority.len() as u64
    }

    /// Whether every byte of the row has come.
    #[must_use]
    pub fn is_whole(&self) -> bool {
        self.offset() == self.reference.total
    }

    /// Takes `part`, the next part of the row. `false`, taking nothing, for a
    /// part that does not continue it: one of another row's length, an empty
    /// one, one past [`MESH_AUTHORITY_PART_MAX`] and one past the row's end.
    pub fn take(&mut self, part: MeshAuthorityPart) -> bool {
        let continues = part.total == self.reference.total
            && !part.part.is_empty()
            && part.part.len() <= MESH_AUTHORITY_PART_MAX
            && self.offset().saturating_add(part.part.len() as u64) <= self.reference.total;
        if continues {
            self.authority.extend_from_slice(&part.part);
        }
        continues
    }

    /// The row as a page would carry it whole, once every byte has come and
    /// their content hash is the one the page named; `None` otherwise.
    #[must_use]
    pub fn finish(self) -> Option<MeshAuthorityRow> {
        (self.is_whole() && ContentHash::of(&self.authority).into_bytes() == self.reference.digest)
            .then(|| MeshAuthorityRow {
                machine: self.reference.machine,
                authority: self.authority,
                address: self.reference.address,
                bare: self.reference.bare,
            })
    }
}

impl Vault {
    /// One part of the signed binding of `machine`, at most
    /// [`MESH_AUTHORITY_PART_MAX`] bytes from `offset`, with its whole
    /// length. Only a row a page serves is served: one that verifies here
    /// and whose MACHINE carries an address. `None` for any other row and
    /// for an offset at or past its end. The caller has already admitted the
    /// machine it serves (`residence.authority.mesh.part`).
    ///
    /// # Errors
    ///
    /// An authority history this vault cannot fold; storage errors.
    pub fn mesh_authority_part(
        &self,
        machine: EntityId,
        offset: u64,
    ) -> Result<Option<MeshAuthorityPart>> {
        let txn = self.store.env.read_txn()?;
        let Some(authority) = MESH_AUTHORITY.get_borrowed(&self.store, &txn, &HexId(machine))?
        else {
            return Ok(None);
        };
        let fold = self.authority_fold_readonly_in_txn(&txn)?;
        if self
            .servable_mesh_row_in_txn(&txn, &fold, machine, &authority)?
            .is_none()
        {
            return Ok(None);
        }
        let Some(rest) = usize::try_from(offset)
            .ok()
            .and_then(|offset| authority.get(offset..))
            .filter(|rest| !rest.is_empty())
        else {
            return Ok(None);
        };
        Ok(Some(MeshAuthorityPart {
            total: authority.len() as u64,
            part: rest[..rest.len().min(MESH_AUTHORITY_PART_MAX)].to_vec(),
        }))
    }

    /// Test door (MESH-AUTHORITY-ROW-PARTS): signs the binding of `machine`
    /// again, once, with `grants` (ALPN to grant id) beside the ones it
    /// names, minting no grant slip. The grant door writes one grant at a
    /// time, signing the whole row again each time, so a binding of 70,000
    /// grants would encode about 700 GB.
    #[cfg(test)]
    pub(crate) fn add_unminted_mesh_grants(
        &self,
        issuer: &HostSlipIssuer,
        machine: EntityId,
        grants: impl IntoIterator<Item = (Vec<u8>, [u8; 32])>,
    ) -> Result<()> {
        let mut txn = self.store.env.write_txn()?;
        let mut claims = self
            .mesh_authority_in_txn(&txn, machine)?
            .ok_or_else(invalid_authority)?;
        claims.alpns.extend(grants);
        self.write_mesh_authority_in_txn(&mut txn, issuer, claims)?;
        txn.commit()?;
        Ok(())
    }
}
