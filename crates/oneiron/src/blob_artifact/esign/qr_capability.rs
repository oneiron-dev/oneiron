//! The QR capability a sealed document's certificate page prints
//! (ARCH-0064a section 6 "QR capability-URL", [SGN-05]).
//!
//! The seal mints one per seal pass, before it prepares the PDFs: 256 fresh
//! random bits, named as the fragment of the QR page's URL
//! ([`certificate_url`]), so the QR and the certificate's `canonical_url:`
//! line carry it and no request path, server log or Referer does. Every item
//! of the pass prints the same one. Only its SHA-256 digest is kept, written
//! in the sealed commit's own transaction and bound to the document and the
//! sealed manifest it was printed in: a seal that never commits leaves a
//! token that never worked, and a reseal mints a fresh one while the earlier
//! one keeps answering for the version it was printed in.
//!
//! Whoever holds the capability reads [`EsignQrPage`]: the document's
//! metadata, each item's hash and its seal-time validation. Never an email,
//! an IP, a user agent or the PDF itself. An unknown, revoked, expired or
//! erased capability gets one refusal, so the answer tells nothing about
//! which. No read is refused for its rate, and no read is logged as a view.
//! The owner revokes a document's QR capabilities or sets their expiry
//! ([`Vault::revoke_esign_qr_capabilities`],
//! [`Vault::set_esign_qr_capability_expiry`]); a revoked one stays revoked.
//!
//! The PDF stays behind a separate possession factor, each party's own
//! signing link (ARCH-0064a section 6, "for sensitive envelopes"). Every
//! envelope counts as sensitive until the vault owner turns on its QR PDF
//! download (`qr_pdf_download` at drafting, or
//! [`Vault::set_esign_qr_pdf_download`] at any time): then a usable QR
//! capability also reads the sealed PDF it was printed in
//! ([`Vault::esign_qr_sealed_pdf`]). The switch is read live on each read,
//! so turning it off closes the download at once; without it the download
//! answers the one refusal.
use super::{
    ledger::{events_in, state_in},
    model::*,
    principals::verify_owner,
    seal::SealedDocument,
    sealer::{SealProfileEvidence, SealVerdict},
};
use crate::consent::AuthenticatedOwner;
use crate::side_table::{self, CodecError, Named, Raw, RawValue, SideTable};
use crate::{EntityId, Result, Vault};
use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// QR capability row. Key: bytes32 (the capability's SHA-256 digest).
const QR_TOKENS: SideTable<[u8; 32], QrCapabilityBinding, Named> =
    SideTable::new(&side_table::ESIGN_QR_CAPABILITY);
/// Every QR capability digest a document's seals printed, in mint order.
/// Key: id16 (document).
const DOCUMENT_QR: SideTable<EntityId, QrDigests, Raw> =
    SideTable::new(&side_table::ESIGN_DOCUMENT_QR_CAPABILITY_INDEX);

/// The documents whose QR capabilities download the sealed PDF: a row
/// means the vault owner turned the download on. Key: id16 (document).
const DOCUMENT_QR_PDF_DOWNLOAD: SideTable<EntityId, QrPdfDownload, Raw> =
    SideTable::new(&side_table::ESIGN_DOCUMENT_QR_PDF_DOWNLOAD);

/// The digests one document's QR capabilities go by, stored as
/// concatenated 32-byte digests.
struct QrDigests(Vec<[u8; 32]>);

/// The QR PDF download switch's row: one byte, 1.
struct QrPdfDownload;

impl RawValue for QrPdfDownload {
    fn to_raw(&self) -> std::result::Result<Vec<u8>, CodecError> {
        Ok(vec![1])
    }

    fn from_raw(bytes: &[u8]) -> std::result::Result<Self, CodecError> {
        if bytes != [1_u8].as_slice() {
            return Err(crate::Error::CorruptedIndex("esign document QR PDF download").into());
        }
        Ok(Self)
    }
}

/// Turns `document`'s QR PDF download on or off in `txn`, and answers
/// whether it was on before.
///
/// # Errors
/// The store's.
pub(super) fn set_pdf_download_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    document: EntityId,
    on: bool,
) -> Result<bool> {
    if on {
        let was = DOCUMENT_QR_PDF_DOWNLOAD.contains(&vault.store, txn, &document)?;
        DOCUMENT_QR_PDF_DOWNLOAD.put(&vault.store, txn, &document, &QrPdfDownload)?;
        Ok(was)
    } else {
        DOCUMENT_QR_PDF_DOWNLOAD.delete(&vault.store, txn, &document)
    }
}

impl RawValue for QrDigests {
    fn to_raw(&self) -> std::result::Result<Vec<u8>, CodecError> {
        Ok(self.0.concat())
    }

    fn from_raw(bytes: &[u8]) -> std::result::Result<Self, CodecError> {
        if bytes.is_empty() || !bytes.len().is_multiple_of(32) {
            return Err(crate::Error::CorruptedIndex("esign document QR capability index").into());
        }
        Ok(Self(
            bytes
                .chunks_exact(32)
                .map(|chunk| {
                    let mut digest = [0u8; 32];
                    digest.copy_from_slice(chunk);
                    digest
                })
                .collect(),
        ))
    }
}

/// A QR capability's raw value: 64 lower-hex characters, 256 random bits.
/// Not serializable, and redacted in `Debug`. Its raw value leaves the vault
/// once, printed in the sealed PDFs of the pass that minted it.
pub struct EsignQrCapability(String);

impl std::fmt::Debug for EsignQrCapability {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("EsignQrCapability([redacted])")
    }
}

impl EsignQrCapability {
    /// Reads a capability as a QR page's fragment carries it. Anything but
    /// 64 lower-hex characters gets the same refusal as an unknown one.
    ///
    /// # Errors
    /// The refusal every unusable capability gets.
    pub fn parse(raw: &str) -> Result<Self> {
        if raw.len() != 64
            || !raw
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            return Err(refused());
        }
        Ok(Self(raw.into()))
    }

    fn digest(&self) -> [u8; 32] {
        Sha256::digest(self.0.as_bytes()).into()
    }

    /// 256 fresh random bits as 64 lower-hex characters.
    pub(super) fn mint() -> Result<Self> {
        let mut entropy = [0u8; 32];
        OsRng
            .try_fill_bytes(&mut entropy)
            .map_err(|_| invalid("QR capability entropy unavailable"))?;
        Ok(Self(crate::entity_id::bytes_to_hex_lower(&entropy)))
    }
}

/// The URL a certificate page prints for `token`: the QR page `page`, with
/// the capability as its fragment. A `page` that already carries a fragment
/// fails the certificate's URL grammar, so its seal fails and is retried.
pub(super) fn certificate_url(page: &str, token: &EsignQrCapability) -> String {
    format!("{page}#{}", token.0)
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct QrCapabilityBinding {
    /// The sealed manifest the capability was printed in.
    sealed: SealedDocument,
    /// When that seal committed.
    sealed_at: u64,
    /// The owner's expiry: no read at or past it.
    expires_at: Option<u64>,
    /// When the owner revoked it.
    revoked_at: Option<u64>,
}

impl QrCapabilityBinding {
    fn usable_at(&self, now: u64) -> bool {
        self.revoked_at.is_none() && self.expires_at.is_none_or(|expires_at| now < expires_at)
    }
}

/// The refusal every unusable QR capability gets: unknown, revoked, expired
/// or erased alike.
fn refused() -> crate::Error {
    invalid("invalid QR capability")
}

/// Records the QR capability a seal printed, in the seal's sealed commit
/// transaction, bound to its `sealed` manifest.
///
/// # Errors
/// The store's, or a digest some earlier capability already holds.
pub(super) fn bind_sealed_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    token: &EsignQrCapability,
    document: EntityId,
    sealed: &SealedDocument,
    sealed_at: u64,
) -> Result<()> {
    let digest = token.digest();
    if QR_TOKENS.contains(&vault.store, txn, &digest)? {
        return Err(invalid("QR capability collision"));
    }
    QR_TOKENS.put(
        &vault.store,
        txn,
        &digest,
        &QrCapabilityBinding {
            sealed: sealed.clone(),
            sealed_at,
            expires_at: None,
            revoked_at: None,
        },
    )?;
    let mut digests = DOCUMENT_QR
        .get(&vault.store, txn, &document)?
        .map_or_else(Vec::new, |QrDigests(digests)| digests);
    digests.push(digest);
    DOCUMENT_QR.put(&vault.store, txn, &document, &QrDigests(digests))?;
    Ok(())
}

/// Applies `change` to every QR capability `document`'s seals printed, and
/// counts the ones it changed.
fn update_document_capabilities_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    document: EntityId,
    change: &dyn Fn(&mut QrCapabilityBinding) -> bool,
) -> Result<usize> {
    let Some(QrDigests(digests)) = DOCUMENT_QR.get(&vault.store, txn, &document)? else {
        return Ok(0);
    };
    let mut changed = 0;
    for digest in digests {
        let mut binding =
            QR_TOKENS
                .get(&vault.store, txn, &digest)?
                .ok_or(crate::Error::CorruptedIndex(
                    "esign document QR capability index",
                ))?;
        if change(&mut binding) {
            QR_TOKENS.put(&vault.store, txn, &digest, &binding)?;
            changed += 1;
        }
    }
    Ok(changed)
}

/// The public QR page: a projection of what the seal proved, never the PDF.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct EsignQrPage {
    pub document_ref: String,
    pub title: String,
    pub outcome: EsignQrOutcome,
    /// When the seal the QR was printed in committed.
    pub sealed_at: u64,
    /// The per-document audit hash chain's head the certificate names.
    pub audit_chain_sha256: String,
    /// Who signed, and when, in signing order. Names and roles only.
    pub signers: Vec<EsignQrSigner>,
    pub items: Vec<EsignQrItem>,
    /// Whether the vault owner lets this capability download the sealed
    /// PDF ([`Vault::esign_qr_sealed_pdf`]): off unless the owner turned it
    /// on, so each party's own signing link stays the possession factor.
    pub pdf_download: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EsignQrOutcome {
    Completed,
    Rejected,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct EsignQrSigner {
    pub name: String,
    pub role: RecipientRole,
    pub signed_at: u64,
}

/// One sealed item as the QR page shows it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct EsignQrItem {
    pub item: u32,
    pub sealed_artifact: String,
    pub sealed_version: u64,
    /// The sealed file's SHA-256, a file identifier: a lawful renewal
    /// append changes it.
    pub sha256: String,
    /// The profile asked for, the one reached, and each shortfall's reason:
    /// what the seal could not do.
    pub profile: SealProfileEvidence,
    /// The seal's own verification of these bytes before it committed. Only
    /// a seal that passed it commits.
    pub self_verify: SealVerdict,
}

impl Vault {
    /// The binding of `token` when it may be read now, and the document it
    /// names: unknown, revoked, expired and erased all get the one refusal.
    fn usable_qr_binding_in(
        &self,
        txn: &heed::RoTxn<'_>,
        token: &EsignQrCapability,
    ) -> Result<(QrCapabilityBinding, EntityId)> {
        let binding = QR_TOKENS
            .get(&self.store, txn, &token.digest())?
            .ok_or_else(refused)?;
        if !binding.usable_at(self.now_recorded_at()) {
            return Err(refused());
        }
        let document = EntityId::from_hex(&binding.sealed.document)?;
        // Sealed artifacts and the audit survive erasure; the bearer
        // authority to read them does not.
        if self.get_blob_artifact_in_txn(txn, &document)?.is_none() {
            return Err(refused());
        }
        Ok((binding, document))
    }

    /// The QR page `token` opens: the projection of the seal it was printed
    /// in. Reads only; refuses nothing for its rate.
    ///
    /// # Errors
    /// One refusal for an unknown, revoked, expired or erased capability;
    /// otherwise the store's.
    pub fn esign_qr_page(&self, token: &EsignQrCapability) -> Result<EsignQrPage> {
        let txn = self.store.env.read_txn()?;
        let (binding, document) = self.usable_qr_binding_in(&txn, token)?;
        let pdf_download = DOCUMENT_QR_PDF_DOWNLOAD.contains(&self.store, &txn, &document)?;
        let state = state_in(self, &txn, document)?;
        let signers = events_in(self, &txn, document)?
            .into_iter()
            .filter_map(|row| match row.event {
                EsignEvent::Signed { recipient, .. } => state
                    .document
                    .recipients
                    .iter()
                    .find(|known| known.id == recipient)
                    .map(|known| EsignQrSigner {
                        name: known.name.clone(),
                        role: known.role,
                        signed_at: row.at,
                    }),
                _ => None,
            })
            .collect();
        let hex = crate::entity_id::bytes_to_hex_lower;
        Ok(EsignQrPage {
            document_ref: binding.sealed.document.clone(),
            title: state.document.title,
            outcome: if binding.sealed.rejected {
                EsignQrOutcome::Rejected
            } else {
                EsignQrOutcome::Completed
            },
            sealed_at: binding.sealed_at,
            audit_chain_sha256: hex(&binding.sealed.audit_chain_sha256),
            signers,
            items: binding
                .sealed
                .items
                .iter()
                .enumerate()
                .map(|(index, item)| EsignQrItem {
                    item: index as u32,
                    sealed_artifact: item.sealed_artifact.clone(),
                    sealed_version: item.sealed_version,
                    sha256: hex(&item.sha256),
                    profile: item.profile.clone(),
                    self_verify: SealVerdict::Passed,
                })
                .collect(),
            pdf_download,
        })
    }

    /// The sealed PDF of `item` that `token` was printed in, hash-checked,
    /// when the vault owner turned on the document's QR PDF download. The
    /// switch is read in the same snapshot as the capability, so turning it
    /// off closes the next read. Reads only; refuses nothing for its rate.
    ///
    /// # Errors
    /// The one refusal for an unknown, revoked, expired or erased
    /// capability, a document whose download is off, or an item the seal
    /// did not print; a sealed file whose hash no longer matches; otherwise
    /// the store's.
    pub fn esign_qr_sealed_pdf(&self, token: &EsignQrCapability, item: usize) -> Result<Vec<u8>> {
        let txn = self.store.env.read_txn()?;
        let (binding, document) = self.usable_qr_binding_in(&txn, token)?;
        if !DOCUMENT_QR_PDF_DOWNLOAD.contains(&self.store, &txn, &document)? {
            return Err(refused());
        }
        let sealed = binding.sealed.items.get(item).ok_or_else(refused)?;
        let artifact = EntityId::from_hex(&sealed.sealed_artifact)?;
        let bytes = self
            .read_blob_artifact_version_in_txn(&txn, &artifact, sealed.sealed_version)?
            .ok_or_else(|| invalid("sealed artifact version missing"))?;
        if <[u8; 32]>::from(Sha256::digest(&bytes)) != sealed.sha256 {
            return Err(invalid("sealed artifact hash mismatch"));
        }
        Ok(bytes)
    }

    /// Turns `document`'s QR PDF download on or off: with it on, each usable
    /// QR capability its seals printed also reads the sealed PDF; off, the
    /// signing links stay the only way to the PDF. Answers whether it was
    /// on before.
    ///
    /// # Errors
    /// Not the live owner, no signing document `document`, or the store's.
    pub fn set_esign_qr_pdf_download(
        &self,
        owner: &AuthenticatedOwner,
        document: EntityId,
        on: bool,
    ) -> Result<bool> {
        self.with_write_txn_grouped(|txn| {
            verify_owner(self, txn, owner)?;
            if events_in(self, txn, document)?.is_empty() {
                return Err(invalid("no such signing document"));
            }
            set_pdf_download_in_txn(self, txn, document, on)
        })
    }

    /// Revokes every QR capability `document`'s seals printed: its QR page
    /// answers the refusal from now on, whatever expiry it had. Answers how
    /// many it revoked now; one already revoked keeps its first time.
    ///
    /// # Errors
    /// Not the live owner, or the store's.
    pub fn revoke_esign_qr_capabilities(
        &self,
        owner: &AuthenticatedOwner,
        document: EntityId,
    ) -> Result<usize> {
        self.with_write_txn_grouped(|txn| {
            verify_owner(self, txn, owner)?;
            let now = self.now_recorded_at();
            update_document_capabilities_in_txn(self, txn, document, &|binding| {
                if binding.revoked_at.is_some() {
                    return false;
                }
                binding.revoked_at = Some(now);
                true
            })
        })
    }

    /// Sets the expiry of every unrevoked QR capability `document`'s seals
    /// printed to `expires_at` (no read at or past it), or clears it with
    /// `None`. A revoked capability stays revoked. Answers how many it set.
    ///
    /// # Errors
    /// Not the live owner, or the store's.
    pub fn set_esign_qr_capability_expiry(
        &self,
        owner: &AuthenticatedOwner,
        document: EntityId,
        expires_at: Option<u64>,
    ) -> Result<usize> {
        self.with_write_txn_grouped(|txn| {
            verify_owner(self, txn, owner)?;
            update_document_capabilities_in_txn(self, txn, document, &|binding| {
                if binding.revoked_at.is_some() {
                    return false;
                }
                binding.expires_at = expires_at;
                true
            })
        })
    }
}
