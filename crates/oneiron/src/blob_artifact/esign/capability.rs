//! Session-less, high-entropy capabilities. Only SHA-256 digests persist here.
//!
//! A recipient may hold several live links: the one the owner hands out from
//! a draft, and a fresh one per delivery (FIX 5238 option 3). A delivery mint
//! adds a link and never revokes one the recipient holds; only an explicit
//! draft rotation revokes every indexed link, and `revoke` revokes one.
use super::{ledger::state_in, model::*, principals::verify_owner};
use crate::consent::AuthenticatedOwner;
use crate::side_table::classified::SideGet;
use crate::side_table::{self, CodecError, LegacyJson, Raw, RawValue, SideTable};
use crate::{EntityId, Result, Vault};
use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Signing capability row. Key: bytes32 (digest).
const TOKENS: SideTable<[u8; 32], CapabilityBinding, LegacyJson> =
    SideTable::new(&side_table::ESIGN_CAPABILITY_TOKEN);
/// Recipient capability index: every digest minted for the recipient, in
/// mint order. Key: id16 (document) + string (recipient id).
const RECIPIENT: SideTable<(EntityId, String), RecipientDigests, Raw> =
    SideTable::new(&side_table::ESIGN_RECIPIENT_CAPABILITY_INDEX);

/// The digests one recipient's links go by, stored as concatenated 32-byte
/// digests.
struct RecipientDigests(Vec<[u8; 32]>);

impl RawValue for RecipientDigests {
    fn to_raw(&self) -> std::result::Result<Vec<u8>, CodecError> {
        Ok(self.0.concat())
    }

    fn from_raw(bytes: &[u8]) -> std::result::Result<Self, CodecError> {
        if bytes.is_empty() || !bytes.len().is_multiple_of(32) {
            return Err(crate::Error::CorruptedIndex("esign recipient capability index").into());
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

/// Intentionally not serializable and always redacted in Debug. Its raw value
/// leaves the vault once: in the owner's issue response, or in the delivery
/// envelope its export writes.
pub struct EsignCapability(String);
impl std::fmt::Debug for EsignCapability {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("EsignCapability([redacted])")
    }
}
impl EsignCapability {
    pub fn parse(raw: &str) -> Result<Self> {
        if raw.len() != 64
            || !raw
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            return Err(invalid("invalid capability"));
        }
        Ok(Self(raw.into()))
    }
    pub fn expose_for_delivery(&self) -> &str {
        &self.0
    }
    fn digest(&self) -> [u8; 32] {
        Sha256::digest(self.0.as_bytes()).into()
    }
    /// 256 fresh random bits as 64 lower-hex characters.
    fn mint() -> Result<Self> {
        let mut entropy = [0u8; 32];
        OsRng
            .try_fill_bytes(&mut entropy)
            .map_err(|_| invalid("capability entropy unavailable"))?;
        Ok(Self(crate::entity_id::bytes_to_hex_lower(&entropy)))
    }
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct CapabilityBinding {
    pub(super) document: String,
    pub(super) recipient: String,
    pub(super) hard_expires_at: u64,
    pub(super) revoked_at: Option<u64>,
    /// The delivery lease a link was minted for, absent for an owner-issued
    /// one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) delivery: Option<DeliveryExport>,
    /// The link's own emailed-token cap end ([`LinkLifetime`]), fixed at its
    /// mint: no window extension moves it. Absent on a link minted before
    /// the cap was per link, whose cap is its document's token deadline.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) cap_expires_at: Option<u64>,
}
/// Non-secret export metadata of a delivery-minted link: the delivery lease
/// it went out under, and the digest of the content delivered with it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct DeliveryExport {
    /// The delivery attempt's id, 32 lower hex.
    pub(super) attempt_id: String,
    /// Its lease generation.
    pub(super) attempt_count: u32,
    /// The exporter's digest of the delivered content, 64 lower hex.
    pub(super) delivered_sha256: String,
}
pub(super) fn binding(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    token: &EsignCapability,
) -> Result<CapabilityBinding> {
    let cap = TOKENS
        .get(&vault.store, txn, &token.digest())?
        .ok_or_else(|| invalid("invalid capability"))?;
    // Event history and sealed artifacts survive erasure, but bearer authority does not.
    let document = EntityId::from_hex(&cap.document)?;
    if vault.get_blob_artifact_in_txn(txn, &document)?.is_none() {
        return Err(invalid("invalid capability"));
    }
    Ok(cap)
}
impl CapabilityBinding {
    /// Whether the link still signs at `now` and reaches as far as its own
    /// cap lets it under `document`'s current deadline.
    fn usable_until(&self, document: &EsignDocument, now: u64) -> bool {
        self.revoked_at.is_none()
            && now < self.hard_expires_at
            && self.reach(document) <= self.hard_expires_at
    }
    /// The latest instant the link may live to under `document`'s current
    /// deadline: its own cap end, else the document's token deadline, never
    /// past the document's deadline. A window extension re-dates a live link
    /// to this, never past it.
    pub(super) fn reach(&self, document: &EsignDocument) -> u64 {
        self.cap_expires_at
            .or(document.token_expires_at)
            .map_or(document.expires_at, |cap| cap.min(document.expires_at))
    }
}
/// How long one link minted now lives (ARCH-0064 section 2, emailed-token
/// cap): until the earlier of the document's deadline and its cap end. The
/// recipient's own signing window is judged at use besides.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct LinkLifetime {
    /// When the link stops signing.
    pub(super) hard_expires_at: u64,
    /// The earlier of the mint plus the draft's lifecycle token cap and the
    /// draft's absolute token deadline; `None` when neither is set.
    pub(super) cap_expires_at: Option<u64>,
}
/// The lifetime of a link `document` mints at `now`. Each delivery mints its
/// own, so a resend after a link's cap mints a live one, and a cap past the
/// document's deadline changes nothing. Recipient signing windows are
/// untouched.
pub(super) fn link_lifetime(document: &EsignDocument, now: u64) -> LinkLifetime {
    let per_link = document
        .lifecycle
        .as_ref()
        .and_then(|rules| rules.token_cap_seconds)
        .map(|cap| now.saturating_add(cap));
    let cap_expires_at = match (per_link, document.token_expires_at) {
        (Some(link), Some(absolute)) => Some(link.min(absolute)),
        (link, absolute) => link.or(absolute),
    };
    LinkLifetime {
        hard_expires_at: cap_expires_at
            .map_or(document.expires_at, |cap| cap.min(document.expires_at)),
        cap_expires_at,
    }
}
/// Every link indexed for `recipient` of `document`, in mint order.
fn recipient_bindings(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    document: EntityId,
    recipient: &str,
) -> Result<Vec<([u8; 32], CapabilityBinding)>> {
    recipient_bindings_read_in(vault, txn, document, recipient)?
}
/// [`recipient_bindings`], the store's own failure (the outer error) apart
/// from this recipient's links that do not read (the inner one): an index or
/// a binding that does not decode, an indexed link with no binding, or a
/// binding that names another document or recipient. A delivery that reads
/// them waits alone (FIX 6482).
pub(super) fn recipient_bindings_read_in(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    document: EntityId,
    recipient: &str,
) -> Result<Result<Vec<([u8; 32], CapabilityBinding)>>> {
    let digests =
        match RECIPIENT.get_classified(&vault.store, txn, &(document, recipient.to_owned())) {
            SideGet::Missing => return Ok(Ok(Vec::new())),
            SideGet::Decoded(RecipientDigests(digests)) => digests,
            SideGet::DecodeError(unreadable) => return Ok(Err(unreadable)),
            SideGet::StoreError(error) => return Err(error),
        };
    let mut bindings = Vec::with_capacity(digests.len());
    for digest in digests {
        let cap = match TOKENS.get_classified(&vault.store, txn, &digest) {
            SideGet::Decoded(cap) => cap,
            SideGet::Missing => return Ok(Err(invalid("missing recipient capability"))),
            SideGet::DecodeError(unreadable) => return Ok(Err(unreadable)),
            SideGet::StoreError(error) => return Err(error),
        };
        if cap.document != document.to_hex() || cap.recipient != recipient {
            return Ok(Err(invalid("recipient capability binding")));
        }
        bindings.push((digest, cap));
    }
    Ok(Ok(bindings))
}
/// Records `token`'s binding and adds its digest to its recipient's index.
fn put_capability(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    token: &EsignCapability,
    row: &CapabilityBinding,
    document: EntityId,
) -> Result<()> {
    let digest = token.digest();
    if TOKENS.contains(&vault.store, txn, &digest)? {
        return Err(invalid("capability collision"));
    }
    TOKENS.put(&vault.store, txn, &digest, row)?;
    let key = (document, row.recipient.clone());
    let mut digests = RECIPIENT
        .get(&vault.store, txn, &key)?
        .map_or_else(Vec::new, |RecipientDigests(digests)| digests);
    digests.push(digest);
    RECIPIENT.put(&vault.store, txn, &key, &RecipientDigests(digests))?;
    Ok(())
}
/// Whether `recipient` of `document` holds a capability no one revoked. One
/// that holds none reads no PDF and signs nothing, whatever its ceremony.
pub(crate) fn recipient_capability_unrevoked_in(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    document: EntityId,
    recipient: &str,
) -> Result<bool> {
    Ok(recipient_bindings(vault, txn, document, recipient)?
        .iter()
        .any(|(_, cap)| cap.revoked_at.is_none()))
}
/// Mints a fresh link for one delivery lease (FIX 5238 option 3): it lives
/// for `lifetime`, minted now ([`link_lifetime`]), and `deliver` is the
/// exporter's digest of the content delivered with it, kept beside the
/// lease as the only trace of the link's delivery. An earlier link minted
/// for the same lease, one an export never finished, keeps working but no
/// longer names the lease. No link is revoked. The mint's own read
/// ([`super::delivery_capability::delivery_read_in`]) waited a delivery whose
/// recipient's links do not read, under this same writer, so only the
/// store fails this read.
pub(super) fn mint_delivery_capability_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    document: EntityId,
    recipient: &str,
    lifetime: LinkLifetime,
    lease: (&str, u32),
    deliver: &dyn Fn(&EsignCapability, u64) -> [u8; 32],
) -> Result<EsignCapability> {
    let (attempt_id, attempt_count) = lease;
    for (digest, mut prior) in recipient_bindings(vault, txn, document, recipient)? {
        if prior.delivery.as_ref().is_some_and(|export| {
            export.attempt_id == attempt_id && export.attempt_count == attempt_count
        }) {
            prior.delivery = None;
            TOKENS.put(&vault.store, txn, &digest, &prior)?;
        }
    }
    let token = EsignCapability::mint()?;
    let delivered = deliver(&token, lifetime.hard_expires_at);
    let row = CapabilityBinding {
        document: document.to_hex(),
        recipient: recipient.to_owned(),
        hard_expires_at: lifetime.hard_expires_at,
        revoked_at: None,
        delivery: Some(DeliveryExport {
            attempt_id: attempt_id.to_owned(),
            attempt_count,
            delivered_sha256: crate::entity_id::bytes_to_hex_lower(&delivered),
        }),
        cap_expires_at: lifetime.cap_expires_at,
    };
    put_capability(vault, txn, &token, &row, document)?;
    Ok(token)
}
/// The delivered-content digest of the link minted for one delivery lease,
/// or `None` when no link names that lease: the store's own failure (the
/// outer error) apart from the recipient's links that do not read (the inner
/// one, [`recipient_bindings_read_in`]).
pub(super) fn delivered_digest_in(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    document: EntityId,
    recipient: &str,
    lease: (&str, u32),
) -> Result<Result<Option<String>>> {
    let (attempt_id, attempt_count) = lease;
    Ok(
        recipient_bindings_read_in(vault, txn, document, recipient)?.map(|bindings| {
            bindings
                .into_iter()
                .filter_map(|(_, cap)| cap.delivery)
                .find(|export| {
                    export.attempt_id == attempt_id && export.attempt_count == attempt_count
                })
                .map(|export| export.delivered_sha256)
        }),
    )
}

/// The draft's signing links minted under `txn`, its minter's authority
/// already proved there ([`Vault::issue_esign_capabilities`], or a narrowed
/// owner credential's own proof, FIX 6403): each recipient holding no link
/// that covers the current deadline, or every one on a `rotate`, gets a
/// fresh link, its earlier ones revoked first.
pub(super) fn mint_draft_capabilities_in(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    document: EntityId,
    rotate: bool,
) -> Result<Vec<(String, EsignCapability)>> {
    let state = state_in(vault, txn, document)?;
    if state.status != DocumentStatus::Draft {
        return Err(invalid("tokens are minted before send"));
    }
    let now = vault.now_recorded_at();
    let lifetime = link_lifetime(&state.document, now);
    let mut issued = Vec::new();
    for recipient in &state.document.recipients {
        let held = recipient_bindings(vault, txn, document, &recipient.id)?;
        if !rotate
            && held
                .iter()
                .any(|(_, cap)| cap.usable_until(&state.document, now))
        {
            continue;
        }
        // A rotation, or a recipient whose every link lapsed: each
        // indexed link is revoked before the fresh one.
        for (digest, mut prior) in held {
            if prior.revoked_at.is_none() {
                prior.revoked_at = Some(now);
                TOKENS.put(&vault.store, txn, &digest, &prior)?;
            }
        }
        let token = EsignCapability::mint()?;
        let row = CapabilityBinding {
            document: document.to_hex(),
            recipient: recipient.id.clone(),
            hard_expires_at: lifetime.hard_expires_at,
            revoked_at: None,
            delivery: None,
            cap_expires_at: lifetime.cap_expires_at,
        };
        put_capability(vault, txn, &token, &row, document)?;
        issued.push((recipient.id.clone(), token));
    }
    Ok(issued)
}

/// Re-dates the live links of `document` after its window moved to
/// `state`'s deadline (RULING ESIGN-WINDOW-EXTEND-AUTHORITY = A): each link
/// no one revoked and still signing at `now` lives to its own reach
/// ([`CapabilityBinding::reach`]). A link's cap never moves, no link lives
/// past it or is shortened, and a revoked or lapsed link stays as it is: a
/// resend mints the recipient a fresh one.
pub(super) fn extend_links_in(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    document: EntityId,
    state: &EsignState,
    now: u64,
) -> Result<()> {
    for recipient in &state.document.recipients {
        for (digest, mut link) in recipient_bindings(vault, txn, document, &recipient.id)? {
            let reach = link.reach(&state.document);
            if link.revoked_at.is_none()
                && now < link.hard_expires_at
                && link.hard_expires_at < reach
            {
                link.hard_expires_at = reach;
                TOKENS.put(&vault.store, txn, &digest, &link)?;
            }
        }
    }
    Ok(())
}

impl Vault {
    /// The token-expiry job (ARCH-0064 SGN-09: "a separate token-expiry job
    /// enforces the configured emailed-token cap"): removes the verifier of
    /// every link of `documents` past its hard expiry, and its digest from
    /// its recipient's index. Refusal stays check-at-use, so a lapsed link
    /// the job has not reached yet is refused all the same. The job never
    /// touches a signing window, and the window sweep
    /// ([`Self::sweep_esign_expiry`]) never touches a link. Counts the
    /// links removed.
    /// # Errors
    /// A document whose trail or links do not read, or the store's failure.
    pub fn sweep_esign_tokens(&self, documents: &[EntityId], now: u64) -> Result<usize> {
        self.with_write_txn_grouped(|txn| {
            let mut removed = 0;
            for &document in documents {
                let state = super::ledger::restrictive_state_in(self, txn, document)?;
                for recipient in &state.document.recipients {
                    let key = (document, recipient.id.clone());
                    let Some(RecipientDigests(digests)) = RECIPIENT.get(&self.store, txn, &key)?
                    else {
                        continue;
                    };
                    let held = digests.len();
                    let mut kept = Vec::with_capacity(held);
                    for digest in digests {
                        match TOKENS.get(&self.store, txn, &digest)? {
                            Some(link) if now >= link.hard_expires_at => {
                                TOKENS.delete(&self.store, txn, &digest)?;
                                removed += 1;
                            }
                            Some(_) => kept.push(digest),
                            // An index digest with no verifier opens nothing:
                            // it leaves the index.
                            None => {}
                        }
                    }
                    if kept.is_empty() {
                        RECIPIENT.delete(&self.store, txn, &key)?;
                    } else if kept.len() != held {
                        RECIPIENT.put(&self.store, txn, &key, &RecipientDigests(kept))?;
                    }
                }
            }
            Ok(removed)
        })
    }
    /// Mint missing or unusable recipient capabilities in DRAFT, for the
    /// owner to hand out. A recipient already holding a link that covers the
    /// current deadline gets none, and no link is returned again. Delivery
    /// mints its own fresh link per envelope, whatever the draft held.
    pub fn issue_esign_capabilities(
        &self,
        owner: &AuthenticatedOwner,
        document: EntityId,
    ) -> Result<Vec<(String, EsignCapability)>> {
        self.mint_esign_capabilities(owner, document, false)
    }
    /// [`Self::issue_esign_capabilities`] that first revokes every live
    /// token of the draft, so each recipient gets a fresh one: the door for
    /// tokens their holder lost before the send.
    pub fn reissue_esign_capabilities(
        &self,
        owner: &AuthenticatedOwner,
        document: EntityId,
    ) -> Result<Vec<(String, EsignCapability)>> {
        self.mint_esign_capabilities(owner, document, true)
    }
    fn mint_esign_capabilities(
        &self,
        owner: &AuthenticatedOwner,
        document: EntityId,
        rotate: bool,
    ) -> Result<Vec<(String, EsignCapability)>> {
        self.with_write_txn_grouped(|txn| {
            verify_owner(self, txn, owner)?;
            mint_draft_capabilities_in(self, txn, document, rotate)
        })
    }
    pub fn revoke_esign_capability(
        &self,
        owner: &AuthenticatedOwner,
        token: &EsignCapability,
    ) -> Result<()> {
        self.with_write_txn_grouped(|txn| {
            verify_owner(self, txn, owner)?;
            let mut row = binding(self, txn, token)?;
            row.revoked_at = Some(self.now_recorded_at());
            TOKENS.put(&self.store, txn, &token.digest(), &row)?;
            Ok(())
        })
    }
}
