//! A retained carrier's own erasable key (KS-6, FIX-LIST 5687 part 1): one
//! per custody transition instance and one per request's whole protected
//! input, on the shared typed custody (`crate::store`
//! `mint_carrier_leaf_in_txn`).
//!
//! SHIPPED OFF ([`CUSTODY_CARRIER_LEAF_WIRE`] is false): a carrier sealed
//! under its own key opens only where that key is released live, to the
//! exact current request's executor or one of its recipient permits, and no
//! channel that keeps nothing exists between machines yet: windows, custody
//! heads and the authority log all retain what they carry, and a key, or a
//! wrap of it under a permanent key, never rides a retained carrier. Until
//! that delivery seam lands (FIX-LIST), transitions and inputs travel
//! exactly as on main, byte for byte, their wire versions unchanged. What
//! is here is the part every later wire takes: the key's identity and
//! binding, the mint-before-carrier order and the release rule.

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use rand::RngCore;
use zeroize::Zeroizing;

use crate::authority::{AuthorityEntryHash, AuthorityFold, OwnerWorkBody, OwnerWorkOutcome};
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::store::{CredentialLeaf, CustodyKind};

/// Whether transitions and inputs are sealed under their own custody keys
/// on the wire (CALLS `KS-6 carrier wire`): false until live leaf delivery
/// lands, so no carrier needs a key its recipient cannot get.
#[allow(dead_code, reason = "KS-6 carrier wire ships off (FIX-LIST)")]
pub(crate) const CUSTODY_CARRIER_LEAF_WIRE: bool = false;

/// The transition wire a leaf-sealed carrier takes (CALLS `KS-6 carrier
/// wire`): the payload domains are v2 today.
#[allow(dead_code, reason = "KS-6 carrier wire ships off (FIX-LIST)")]
pub(crate) const CUSTODY_TRANSITION_WIRE_VERSION: u8 = 3;

/// The input wire a leaf-sealed input takes, its numbered envelopes and
/// attached frames with it: the input domains are v1 today.
#[allow(dead_code, reason = "KS-6 carrier wire ships off (FIX-LIST)")]
pub(crate) const CUSTODY_INPUT_WIRE_VERSION: u8 = 2;

/// A carrier's key identity (CALLS `KS-6 leaf ids`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CustodyCarrierIdForm {
    /// The credential's id (16), then a random instance id (16) minted
    /// before any byte the carrier seals; slot 0. Never a value or
    /// ciphertext hash: a key never derives from what it seals.
    CredentialId16ThenRandomInstance16Slot0,
}

const CUSTODY_CARRIER_ID_FORM: CustodyCarrierIdForm =
    CustodyCarrierIdForm::CredentialId16ThenRandomInstance16Slot0;

/// How much of an input one key covers (CALLS `KS-6 leaf ids`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CustodyInputLeafUnit {
    /// The whole input, sealed once before it is split or sealed to its
    /// holder; every numbered part names the same key and its own position.
    WholeMultipartInput,
}

const CUSTODY_INPUT_LEAF_UNIT: CustodyInputLeafUnit = CustodyInputLeafUnit::WholeMultipartInput;

/// What a carrier's key and bytes are bound to (CALLS `KS-6 leaf deposit`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CustodyLeafDeposit {
    /// The key is published and its Mint journaled in the writer that names
    /// the carrier, before its ciphertext or the request's digest exists; a
    /// carrier aborted after that leaves a key its credential's prefix still
    /// finds and erases. A client's deposit rides the capability its call
    /// already holds: no extra proof.
    AuthorizedPreimageBoundJournaledPublishBeforeCarrier,
}

const CUSTODY_LEAF_DEPOSIT: CustodyLeafDeposit =
    CustodyLeafDeposit::AuthorizedPreimageBoundJournaledPublishBeforeCarrier;

/// Who a carrier's key is released to, live (CALLS `KS-6 live leaf
/// release`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CustodyLiveLeafRelease {
    /// The exact current request's executor, for its input; one of its
    /// recipient permits, for its transition. Never a root, an image or a
    /// key's possession alone.
    ExactCurrentRequestExecutorOrRecipientPermit,
}

const CUSTODY_LIVE_LEAF_RELEASE: CustodyLiveLeafRelease =
    CustodyLiveLeafRelease::ExactCurrentRequestExecutorOrRecipientPermit;

const CARRIER_AAD_DOMAIN: &[u8] = b"oneiron/custody-carrier/v1\0";
const NONCE_BYTES: usize = 12;

/// One carrier's key reference: the credential, the instance, the
/// generation it carries and its role, never an absolute custody path
/// (CALLS `KS-6 leaf ids`, CUSTODY_REF_BINDING).
#[allow(dead_code, reason = "KS-6 carrier wire ships off (FIX-LIST)")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct CarrierRef {
    pub(crate) kind: CustodyKind,
    pub(crate) credential: EntityId,
    pub(crate) instance: [u8; 16],
    pub(crate) generation: u32,
    pub(crate) role: u8,
}

#[allow(dead_code, reason = "KS-6 carrier wire ships off (FIX-LIST)")]
impl CarrierRef {
    /// The bytes a carrier's seal binds: the reference, then the part's
    /// position (`u32::MAX` for a whole carrier).
    fn aad(&self, part: Option<u32>) -> Vec<u8> {
        match (CUSTODY_CARRIER_ID_FORM, CUSTODY_INPUT_LEAF_UNIT) {
            (
                CustodyCarrierIdForm::CredentialId16ThenRandomInstance16Slot0,
                CustodyInputLeafUnit::WholeMultipartInput,
            ) => {}
        }
        let mut aad = Vec::with_capacity(CARRIER_AAD_DOMAIN.len() + 1 + 32 + 4 + 1 + 4);
        aad.extend_from_slice(CARRIER_AAD_DOMAIN);
        aad.push(self.kind.tag());
        aad.extend_from_slice(self.credential.as_bytes());
        aad.extend_from_slice(&self.instance);
        aad.extend_from_slice(&self.generation.to_be_bytes());
        aad.push(self.role);
        aad.extend_from_slice(&part.unwrap_or(u32::MAX).to_be_bytes());
        aad
    }

    /// Seals `plain` under `leaf` for this reference at `part`.
    pub(crate) fn seal(
        &self,
        leaf: &CredentialLeaf,
        part: Option<u32>,
        plain: &[u8],
    ) -> Result<Vec<u8>> {
        let mut nonce = [0; NONCE_BYTES];
        rand::rngs::OsRng.fill_bytes(&mut nonce);
        let cipher = Aes256Gcm::new_from_slice(&leaf[..]).map_err(|_| self.kind.corrupt())?;
        let sealed = cipher
            .encrypt(
                &Nonce::from(nonce),
                Payload {
                    msg: plain,
                    aad: &self.aad(part),
                },
            )
            .map_err(|_| self.kind.corrupt())?;
        let mut out = nonce.to_vec();
        out.extend_from_slice(&sealed);
        Ok(out)
    }

    /// Opens `sealed` under `leaf` for this reference at `part`.
    pub(crate) fn open(
        &self,
        leaf: &CredentialLeaf,
        part: Option<u32>,
        sealed: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>> {
        let (nonce, ciphertext) = sealed
            .split_first_chunk::<NONCE_BYTES>()
            .ok_or_else(|| self.kind.corrupt())?;
        let cipher = Aes256Gcm::new_from_slice(&leaf[..]).map_err(|_| self.kind.corrupt())?;
        cipher
            .decrypt(
                &Nonce::from(*nonce),
                Payload {
                    msg: ciphertext,
                    aad: &self.aad(part),
                },
            )
            .map(Zeroizing::new)
            .map_err(|_| self.kind.corrupt())
    }
}

/// Whether `fold` lets carrier `carrier`'s key go, live, to `requester` for
/// the request signed as entry `request` (CALLS `KS-6 live leaf release`):
/// the request counts here and targets the carrier's credential; an input's
/// key goes to the request's executor while it is unanswered, a
/// transition's to one of its recipient permits once it was enacted, never
/// refused. Any other asker gets nothing.
#[allow(dead_code, reason = "KS-6 carrier wire ships off (FIX-LIST)")]
pub(crate) fn carrier_release_admits(
    fold: &AuthorityFold,
    carrier: &CarrierRef,
    request: &AuthorityEntryHash,
    requester: EntityId,
) -> bool {
    match (CUSTODY_LIVE_LEAF_RELEASE, CUSTODY_LEAF_DEPOSIT) {
        (
            CustodyLiveLeafRelease::ExactCurrentRequestExecutorOrRecipientPermit,
            CustodyLeafDeposit::AuthorizedPreimageBoundJournaledPublishBeforeCarrier,
        ) => {}
    }
    let Some(counted) = fold.counted_owner_work_request(request) else {
        return false;
    };
    let OwnerWorkBody::Custody { recipients, .. } = &counted.work else {
        return false;
    };
    if counted.act.target != carrier.credential {
        return false;
    }
    let answer = fold.owner_work_result(request);
    match carrier.kind {
        CustodyKind::CustodyRequestInput => answer.is_none() && counted.executor == requester,
        CustodyKind::CustodyTransition => {
            answer.is_some_and(|answer| !matches!(answer.outcome, OwnerWorkOutcome::Refused { .. }))
                && recipients.iter().any(|permit| permit.machine == requester)
        }
        _ => false,
    }
}
