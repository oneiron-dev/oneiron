//! Propose-only authority widening. Only the existing authenticated-owner door
//! can turn a frozen canonical delta into a standing grant.
use super::codec::{decode_bound_value, encode_bound_value};
use super::contact_clearance::{CONTACT_DISCLOSURE_WIDEN_KIND, ContactDisclosureProposal};
use super::support::{invalid_row, normalized_ref};
use super::{
    AuthenticatedOwner, ConsentDomain, ConsentReceipt, GrantBound, bound_catastrophe_class,
};
use crate::authority::VerifiedSlip;
use crate::error::GateError;
use crate::side_table::{self, LegacyJson, SideTable};
use crate::store::{GATE_DECISION_LEDGER_VERSION, GateDecisionId, GateDecisionRecord};
use crate::{EdgeActorClass, Error, Result, Vault, WriteActor};
use rmpv::Value;
use serde::{Deserialize, Serialize};
use std::io::Cursor;

/// Parked authority-widening request, keyed by its own hex64 reference.
const WIDEN_PROPOSALS: SideTable<String, StoredProposal, LegacyJson> =
    SideTable::new(&side_table::CONSENT_WIDEN_PROPOSAL);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WidenKind {
    Action,
    Disclosure,
    AutoConfirm,
}
impl WidenKind {
    fn label(self) -> &'static str {
        match self {
            Self::Action => "propose_action_widen",
            Self::Disclosure => "propose_disclosure_widen",
            Self::AutoConfirm => "propose_auto_confirm_widen",
        }
    }
    fn parse(text: &str) -> Option<Self> {
        match text {
            "propose_action_widen" => Some(Self::Action),
            "propose_disclosure_widen" => Some(Self::Disclosure),
            "propose_auto_confirm_widen" => Some(Self::AutoConfirm),
            _ => None,
        }
    }
}

/// A proposal receipt confers no authority. It is not a ConsentGrant.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WidenProposal {
    pub proposal_ref: String,
    pub canonical_delta: Vec<u8>,
    pub proposer: String,
    pub owner_ref: String,
    pub created_at: u64,
    pub expires_at: u64,
    pub decision_id: [u8; 16],
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct StoredProposal {
    version: u8,
    proposal: WidenProposal,
    resolved: bool,
    /// The terminal answer that resolved this proposal.
    #[serde(default)]
    settlement: Option<StoredSettlement>,
    /// The credential slips the proposal was filed under. None of them, and
    /// no slip they parent, may settle it.
    #[serde(default)]
    opener_lineage: Vec<[u8; 32]>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct StoredSettlement {
    verdict: String,
    decision_id: [u8; 16],
}

/// A decoded widen delta: a canonical bound, or a typed contact-disclosure
/// offer (OF-365) that only the contact clearance door settles.
enum WidenDelta {
    Bound(GrantBound),
    ContactDisclosure(ContactDisclosureProposal),
}

pub fn canonical_widen_delta(kind: WidenKind, bound: &GrantBound) -> Result<Vec<u8>> {
    if (kind == WidenKind::Disclosure) != (bound.domain() == ConsentDomain::Disclosure) {
        return Err(Error::Gate(GateError::InvalidConsentBound(
            "widen kind crosses bound domain",
        )));
    }
    let value = Value::Array(vec![
        Value::from(1),
        Value::from(kind.label()),
        encode_bound_value(bound)?,
    ]);
    let mut bytes = Vec::new();
    rmpv::encode::write_value(&mut bytes, &value).map_err(|_| invalid_row())?;
    Ok(bytes)
}
/// The canonical delta of one frozen contact-disclosure offer.
pub(super) fn contact_disclosure_widen_delta(
    proposal: &ContactDisclosureProposal,
) -> Result<Vec<u8>> {
    let value = Value::Array(vec![
        Value::from(1),
        Value::from(CONTACT_DISCLOSURE_WIDEN_KIND),
        proposal.to_value()?,
    ]);
    let mut bytes = Vec::new();
    rmpv::encode::write_value(&mut bytes, &value).map_err(|_| invalid_row())?;
    Ok(bytes)
}
fn decode_delta(bytes: &[u8]) -> Result<WidenDelta> {
    let mut cursor = Cursor::new(bytes);
    let value = rmpv::decode::read_value(&mut cursor).map_err(|_| invalid_row())?;
    if cursor.position() != bytes.len() as u64 {
        return Err(invalid_row());
    }
    let Value::Array(parts) = value else {
        return Err(invalid_row());
    };
    let [version, kind, bound] = parts.as_slice() else {
        return Err(invalid_row());
    };
    if version.as_u64() != Some(1) {
        return Err(invalid_row());
    }
    if kind.as_str() == Some(CONTACT_DISCLOSURE_WIDEN_KIND) {
        let proposal = ContactDisclosureProposal::from_value(bound)?;
        if contact_disclosure_widen_delta(&proposal)? != bytes {
            return Err(invalid_row());
        }
        return Ok(WidenDelta::ContactDisclosure(proposal));
    }
    let kind = kind
        .as_str()
        .and_then(WidenKind::parse)
        .ok_or_else(invalid_row)?;
    let bound = decode_bound_value(bound)?;
    if canonical_widen_delta(kind, &bound)? != bytes {
        return Err(invalid_row());
    }
    Ok(WidenDelta::Bound(bound))
}
fn proposal_ref(delta: &[u8], proposer: &str, owner: &str, created: u64, expires: u64) -> String {
    let mut hasher = blake3::Hasher::new();
    hasher.update(WIDEN_PROPOSALS.decl().prefix);
    for field in [
        delta,
        proposer.as_bytes(),
        owner.as_bytes(),
        &created.to_be_bytes(),
        &expires.to_be_bytes(),
    ] {
        hasher.update(&(field.len() as u64).to_be_bytes());
        hasher.update(field);
    }
    hasher.finalize().to_hex().to_string()
}
/// The hex64 reference shape every widen row has always been keyed by. Kept
/// as a gate ahead of storage rather than folded into the key type, so a
/// caller-supplied `reference` that fails the shape check is refused the
/// SAME [`GateError::InvalidConsentBound`]-flavored `invalid_row()` it always
/// was, before the key ever reaches the table.
fn validate_reference_shape(reference: &str) -> Result<()> {
    if reference.len() != 64
        || !reference
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err(invalid_row());
    }
    Ok(())
}
fn validate_row(row: StoredProposal, reference: &str) -> Result<StoredProposal> {
    let p = &row.proposal;
    decode_delta(&p.canonical_delta)?;
    if row.version != 1
        || p.proposal_ref != reference
        || p.expires_at <= p.created_at
        || p.expires_at - p.created_at > 3600
        || crate::EntityId::from_hex(&p.proposer).is_err()
        || normalized_ref("widen owner", p.owner_ref.clone())? != p.owner_ref
        || proposal_ref(
            &p.canonical_delta,
            &p.proposer,
            &p.owner_ref,
            p.created_at,
            p.expires_at,
        ) != reference
    {
        return Err(invalid_row());
    }
    Ok(row)
}
impl Vault {
    /// A verified agent may propose an action widening, but cannot grant it.
    pub fn propose_action_widen(
        &self,
        credential: &VerifiedSlip,
        bound: GrantBound,
        owner_ref: &str,
        expires_at: u64,
    ) -> Result<WidenProposal> {
        self.propose_credential_widen(credential, WidenKind::Action, bound, owner_ref, expires_at)
    }

    /// A verified agent may propose a disclosure widening, but cannot grant it.
    pub fn propose_disclosure_widen(
        &self,
        credential: &VerifiedSlip,
        bound: GrantBound,
        owner_ref: &str,
        expires_at: u64,
    ) -> Result<WidenProposal> {
        self.propose_credential_widen(
            credential,
            WidenKind::Disclosure,
            bound,
            owner_ref,
            expires_at,
        )
    }

    /// A verified agent may propose an auto-confirm widening, but cannot grant it.
    pub fn propose_auto_confirm_widen(
        &self,
        credential: &VerifiedSlip,
        bound: GrantBound,
        owner_ref: &str,
        expires_at: u64,
    ) -> Result<WidenProposal> {
        self.propose_credential_widen(
            credential,
            WidenKind::AutoConfirm,
            bound,
            owner_ref,
            expires_at,
        )
    }

    fn propose_credential_widen(
        &self,
        credential: &VerifiedSlip,
        kind: WidenKind,
        bound: GrantBound,
        owner_ref: &str,
        expires_at: u64,
    ) -> Result<WidenProposal> {
        let claims = credential.claims();
        // A read-only VerifiedSlip is reusable. This door has no atomic
        // SlipConsume, so refuse one-shots (including offline caveats) rather
        // than spending them outside the proposal transaction.
        if claims.single_use {
            return Err(Error::Gate(GateError::InvalidConsentBound(
                "single-use credential cannot file a widen proposal",
            )));
        }
        if claims.actor_class.as_deref() != Some("agent") || !credential.allows_verb(kind.label()) {
            return Err(Error::Gate(GateError::InvalidConsentBound(
                "agent credential lacks widen proposal authority",
            )));
        }
        let agent = crate::EntityId::from_hex(&claims.holder_ref).map_err(|_| {
            Error::Gate(GateError::InvalidConsentBound(
                "agent credential lacks entity binding",
            ))
        })?;
        self.propose_widen_with_credential(
            WriteActor::new(agent, EdgeActorClass::Agent),
            credential,
            kind,
            bound,
            owner_ref,
            expires_at,
        )
    }

    fn propose_widen_with_credential(
        &self,
        actor: WriteActor,
        credential: &VerifiedSlip,
        kind: WidenKind,
        bound: GrantBound,
        owner_ref: &str,
        expires_at: u64,
    ) -> Result<WidenProposal> {
        if actor.actor_class() != EdgeActorClass::Agent {
            return Err(Error::Gate(GateError::InvalidConsentBound(
                "widen proposer must be an agent",
            )));
        }
        if bound_catastrophe_class(&bound).is_some() {
            return Err(Error::Gate(GateError::ConsentCatastropheNotRememberable(
                "catastrophe widen is forbidden",
            )));
        }
        let canonical_delta = canonical_widen_delta(kind, &bound)?;
        self.with_write_txn_grouped(|txn| {
            // Recheck in the committing transaction: a verified handle can be
            // revoked or expire between proof verification and this write.
            if !self.capability_slip_is_live_in_txn(&*txn, credential)? {
                return Err(Error::Gate(GateError::InvalidConsentBound(
                    "agent credential is no longer live",
                )));
            }
            let raw = crate::ports::EntityStoreRead::port_entity_raw(
                &self.store,
                &*txn,
                &actor.entity_ref(),
            )?
            .ok_or(Error::EntityNotFound)?;
            let header = crate::batch::EntityMetadataHeader::parse(&raw)
                .ok_or(Error::CorruptedIndex("entity header"))?;
            crate::provenance::validate_actor_class(header.entity_type, actor.actor_class())?;
            self.file_widen_row_in_txn(
                txn,
                canonical_delta,
                &actor.entity_ref(),
                owner_ref,
                expires_at,
                vec![credential.claims().slip_id],
            )
        })
    }

    /// Files one contact-disclosure offer, frozen by the clearance door, on
    /// the same table and pending Gate decision as every widen proposal.
    pub(super) fn file_contact_disclosure_offer_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        proposer: &crate::EntityId,
        proposal: &ContactDisclosureProposal,
        owner_ref: &str,
        expires_at: u64,
        opener_lineage: Vec<[u8; 32]>,
    ) -> Result<WidenProposal> {
        let canonical_delta = contact_disclosure_widen_delta(proposal)?;
        self.file_widen_row_in_txn(
            txn,
            canonical_delta,
            proposer,
            owner_ref,
            expires_at,
            opener_lineage,
        )
    }

    /// The row write every widen proposal shares: an identical refiling
    /// returns the row already filed; a new one appends its pending Gate
    /// decision and the row in the caller's transaction.
    fn file_widen_row_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        canonical_delta: Vec<u8>,
        proposer: &crate::EntityId,
        owner_ref: &str,
        expires_at: u64,
        opener_lineage: Vec<[u8; 32]>,
    ) -> Result<WidenProposal> {
        let now = self.store.clock.now_recorded_at();
        if expires_at <= now || expires_at - now > 3600 {
            return Err(Error::Gate(GateError::InvalidConsentBound(
                "widen proposal expiry must be within one hour",
            )));
        }
        let owner_ref = normalized_ref("widen owner", owner_ref.to_owned())?;
        let proposer = proposer.to_hex();
        let reference = proposal_ref(&canonical_delta, &proposer, &owner_ref, now, expires_at);
        validate_reference_shape(&reference)?;
        {
            if let Some(row) = WIDEN_PROPOSALS.get(&self.store, &*txn, &reference)? {
                return Ok(validate_row(row, &reference)?.proposal);
            }
            let proposal = WidenProposal {
                proposal_ref: reference,
                canonical_delta,
                proposer,
                owner_ref,
                created_at: now,
                expires_at,
                decision_id: GateDecisionId::now().as_bytes(),
            };
            let record = GateDecisionRecord {
                version: GATE_DECISION_LEDGER_VERSION,
                decision_id: GateDecisionId::from_bytes(proposal.decision_id),
                created_at: now,
                outcome: "pending".into(),
                reason_codes: vec!["gate.consent.widen_proposed".into()],
                receipt_reasons: Vec::new(),
                system_notices: Vec::new(),
                actor_class: "agent".into(),
                actor_ref: Some(proposal.proposer.clone()),
                content_kind: "consent_widen".into(),
                policy_manifest_version: crate::gate::POLICY_SCHEMA_VERSION.into(),
                claim_id: None,
                grant_ref: None,
                diff_handle: blake3::hash(&proposal.canonical_delta).as_bytes().to_vec(),
                read_frontier_hash: [0; 32],
                redacted_at: None,
            };
            self.store.append_gate_decision_in_txn(txn, &record)?;
            let row = StoredProposal {
                version: 1,
                proposal: proposal.clone(),
                resolved: false,
                settlement: None,
                opener_lineage,
            };
            WIDEN_PROPOSALS.put(&self.store, txn, &row.proposal.proposal_ref, &row)?;
            Ok(proposal)
        }
    }
    /// Resolve one frozen proposal. An approve-once receipt cannot be supplied
    /// here: the existing authenticated owner handle is the separate authority axis.
    pub fn accept_widen(
        &self,
        owner: &AuthenticatedOwner,
        reference: &str,
        expected_delta: &[u8],
    ) -> Result<ConsentReceipt> {
        self.accept_widen_checked(owner, None, reference, expected_delta)
    }

    /// The HTTP holder route passes its logged capability, rechecked in the
    /// SAME transaction as grant minting. A revoked slip cannot win a race
    /// between transport authentication and the actual approval.
    pub fn accept_credential_widen(
        &self,
        owner: &AuthenticatedOwner,
        credential: &VerifiedSlip,
        reference: &str,
        expected_delta: &[u8],
    ) -> Result<ConsentReceipt> {
        let claims = credential.claims();
        if claims.single_use
            || claims.holder_ref != owner.revalidate(self)?.to_hex()
            || claims.actor_class.as_deref() != Some("human")
            || !credential.allows_verb("core:auth")
        {
            return Err(Error::Gate(GateError::ConsentOwnerNotAuthenticated(
                "holder credential does not authorize a widen",
            )));
        }
        self.accept_widen_checked(owner, Some(credential), reference, expected_delta)
    }

    fn accept_widen_checked(
        &self,
        owner: &AuthenticatedOwner,
        credential: Option<&VerifiedSlip>,
        reference: &str,
        expected_delta: &[u8],
    ) -> Result<ConsentReceipt> {
        validate_reference_shape(reference)?;
        let key = reference.to_owned();
        self.with_write_txn_grouped(|txn| {
            let principal_ref = owner.principal_ref_in_txn(self, &*txn)?;
            if let Some(credential) = credential
                && !self.capability_slip_is_live_in_txn(&*txn, credential)?
            {
                return Err(Error::Gate(GateError::ConsentOwnerNotAuthenticated(
                    "holder credential is no longer live",
                )));
            }
            let row = WIDEN_PROPOSALS
                .get(&self.store, &*txn, &key)?
                .ok_or_else(invalid_row)?;
            let mut row = validate_row(row, reference)?;
            let proposal = &row.proposal;
            if proposal.owner_ref != principal_ref {
                return Err(Error::Gate(GateError::ConsentOwnerNotAuthenticated(
                    "widen proposal belongs to another holder",
                )));
            }
            if row.resolved
                || proposal.expires_at <= self.store.clock.now_recorded_at()
                || proposal.canonical_delta != expected_delta
            {
                return Err(Error::Gate(GateError::InvalidConsentBound(
                    "widen proposal is stale, changed, or resolved",
                )));
            }
            let WidenDelta::Bound(bound) = decode_delta(&proposal.canonical_delta)? else {
                return Err(Error::Gate(GateError::InvalidConsentBound(
                    "a contact-disclosure offer settles through confirm_contact_disclosure",
                )));
            };
            let receipt = self.create_standing_grant_in_txn(txn, owner, bound)?;
            row.resolved = true;
            row.settlement = Some(StoredSettlement {
                verdict: "accepted".to_owned(),
                decision_id: receipt.decision_id().as_bytes(),
            });
            WIDEN_PROPOSALS.put(&self.store, txn, &key, &row)?;
            Ok(receipt)
        })
    }

    /// The open contact-disclosure offer `reference` names, checked in the
    /// settling transaction: this owner's, unexpired, unsettled,
    /// byte-identical to what the owner saw, and not answered from the
    /// lineage that opened it.
    pub(super) fn open_contact_disclosure_offer_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        owner: &AuthenticatedOwner,
        reference: &str,
        expected_delta: &[u8],
        now: u64,
    ) -> Result<ContactDisclosureProposal> {
        validate_reference_shape(reference)?;
        let principal_ref = owner.principal_ref_in_txn(self, txn)?.to_owned();
        let actor = owner.revalidate_in_txn(self, txn)?;
        let row = WIDEN_PROPOSALS
            .get(&self.store, txn, &reference.to_owned())?
            .ok_or_else(invalid_row)?;
        let row = validate_row(row, reference)?;
        let proposal = &row.proposal;
        if proposal.owner_ref != principal_ref {
            return Err(Error::Gate(GateError::ConsentOwnerNotAuthenticated(
                "widen proposal belongs to another holder",
            )));
        }
        if proposal.proposer == actor.to_hex()
            || owner
                .credential_lineage()
                .iter()
                .any(|slip| row.opener_lineage.contains(slip))
        {
            return Err(Error::Gate(GateError::ConsentOwnerNotAuthenticated(
                "the lineage that opened an offer cannot settle it",
            )));
        }
        if row.resolved || proposal.expires_at <= now || proposal.canonical_delta != expected_delta
        {
            return Err(Error::Gate(GateError::InvalidConsentBound(
                "widen proposal is stale, changed, or resolved",
            )));
        }
        match decode_delta(&proposal.canonical_delta)? {
            WidenDelta::ContactDisclosure(offer) => Ok(offer),
            WidenDelta::Bound(_) => Err(Error::Gate(GateError::InvalidConsentBound(
                "widen proposal is not a contact-disclosure offer",
            ))),
        }
    }

    /// Settles one proposal with its terminal answer, in the answering txn.
    pub(super) fn settle_widen_offer_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        reference: &str,
        verdict: &str,
        decision_id: GateDecisionId,
    ) -> Result<()> {
        let key = reference.to_owned();
        let row = WIDEN_PROPOSALS
            .get(&self.store, &*txn, &key)?
            .ok_or_else(invalid_row)?;
        let mut row = validate_row(row, reference)?;
        row.resolved = true;
        row.settlement = Some(StoredSettlement {
            verdict: verdict.to_owned(),
            decision_id: decision_id.as_bytes(),
        });
        WIDEN_PROPOSALS.put(&self.store, txn, &key, &row)
    }

    /// Every contact-disclosure offer settled with `verdict`, read in the
    /// caller's `txn`, beside its proposal reference and in reference order.
    /// There is no index by verdict, so this scans the table. A row that
    /// fails validation is skipped: it settles nothing.
    pub(super) fn settled_contact_disclosure_offers_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        verdict: &str,
    ) -> Result<Vec<(String, ContactDisclosureProposal)>> {
        let mut offers = Vec::new();
        for (reference, row) in WIDEN_PROPOSALS.scan(&self.store, txn)? {
            if !row.resolved
                || !row
                    .settlement
                    .as_ref()
                    .is_some_and(|settlement| settlement.verdict == verdict)
            {
                continue;
            }
            let Ok(row) = validate_row(row, &reference) else {
                continue;
            };
            if let Ok(WidenDelta::ContactDisclosure(offer)) =
                decode_delta(&row.proposal.canonical_delta)
            {
                offers.push((reference, offer));
            }
        }
        Ok(offers)
    }

    /// The frozen contact-disclosure offer `reference` names, for the private
    /// owner surface that asks it. `None` when no such offer is filed.
    pub fn contact_disclosure_offer(
        &self,
        reference: &str,
    ) -> Result<Option<ContactDisclosureProposal>> {
        validate_reference_shape(reference)?;
        let txn = self.store.env.read_txn()?;
        let Some(row) = WIDEN_PROPOSALS.get(&self.store, &txn, &reference.to_owned())? else {
            return Ok(None);
        };
        match decode_delta(&validate_row(row, reference)?.proposal.canonical_delta)? {
            WidenDelta::ContactDisclosure(offer) => Ok(Some(offer)),
            WidenDelta::Bound(_) => Ok(None),
        }
    }
    pub fn widen_proposal(&self, reference: &str) -> Result<Option<WidenProposal>> {
        validate_reference_shape(reference)?;
        let txn = self.store.env.read_txn()?;
        WIDEN_PROPOSALS
            .get(&self.store, &txn, &reference.to_owned())?
            .map(|row| validate_row(row, reference).map(|row| row.proposal))
            .transpose()
    }
}
