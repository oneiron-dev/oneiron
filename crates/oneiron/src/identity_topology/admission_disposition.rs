//! Signed append-only admission facts, independent of a decision's erasable author.

use std::collections::BTreeSet;
use std::sync::Arc;

use ed25519_dalek::{Signature, Signer, VerifyingKey};
use rmpv::Value;

use crate::authority::{
    AuthorityEntryHash, AuthorityFold, CausalPoints, ExternalAct, ExternalActStanding,
};
use crate::entity_id::EntityId;
use crate::error::{Error, Result, SyncError};
use crate::side_table::{self, HexId, Raw, SideTable};
use crate::store::Store;
use crate::vault::Vault;

use super::act_admission::{ResolvedSeal, SealAuthority, SealStanding};
use super::stored_event::{StoredIdentityOpAction, StoredIdentityOpEvent};

/// The seal transcript's domain: v3 signs a decision's causal point, the
/// authority-log heads its carrier held (FIX 4649), beside the carrier, the
/// deciding authority, the core digest, verdict and reason (mesh
/// PR2-topology).
const DOMAIN: &[u8] = b"oneiron.identity-topology.admission.v3\0";
/// The domain of a decision seal's act token: what a carrier's removal lists
/// as seen to keep the decision standing (FIX 4649, CALLS "FIX 4649 seal
/// causal envelope").
const SEAL_ACT_TOKEN_DOMAIN: &[u8] = b"oneiron.identity-topology.seal-act.v1\0";
/// Integrity: the fact's act, verdict or shape is malformed (an owner act of
/// another kind or target, a verdict with a reason it never carries, a
/// missing or doubled authority).
const MALFORMED: &str = "identity topology admission disposition is malformed";
/// Integrity: a fact names itself as the decision it seals.
const SELF_TARGET: &str = "identity topology admission disposition targets itself";
/// Integrity and key possession: the signature does not verify under the
/// fact's signer key.
const BAD_SIGNATURE: &str = "identity topology admission disposition signature does not verify";

/// The seals this vault wrote itself, by fact row: signer key and signature.
/// Local truth that never replicates, so no peer can vouch for its own seal,
/// and a copy restored beside the vault keeps its history in force. An
/// engine seal stands here on it; for a decision seal it records provenance
/// only (mesh PR2-topology).
const SEALED_HERE: SideTable<HexId, [u8; 96], Raw> =
    SideTable::new(&side_table::IDENTITY_TOPOLOGY_SEALED_HERE);
/// The seal standing an authority write last reconciled the shell edges
/// under, as one digest: the mine signers, and the decision seals' carriers,
/// owners and named Grants. Local, like the marker.
const MINE_SIGNERS: SideTable<(), [u8; 32], Raw> =
    SideTable::new(&side_table::IDENTITY_TOPOLOGY_MINE_SIGNERS);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AdmissionVerdict {
    Validated,
    RefusedActorClass,
    RefusedNonStructural,
    RefusedFacetMerge,
    /// Local projection only: incompatible signed refusals, never a wire verdict.
    RefusedConflict,
}

impl AdmissionVerdict {
    fn as_str(self) -> &'static str {
        match self {
            Self::Validated => "validated",
            Self::RefusedActorClass => "refused_actor_class",
            Self::RefusedNonStructural => "refused_nonstructural",
            Self::RefusedFacetMerge => "refused_facet_merge",
            Self::RefusedConflict => "refused_conflict",
        }
    }
    fn parse(s: &str) -> Option<Self> {
        match s {
            "validated" => Some(Self::Validated),
            "refused_actor_class" => Some(Self::RefusedActorClass),
            "refused_nonstructural" => Some(Self::RefusedNonStructural),
            "refused_facet_merge" => Some(Self::RefusedFacetMerge),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdmissionDisposition {
    pub target: EntityId,
    pub core_digest: [u8; 32],
    pub verdict: AdmissionVerdict,
    pub reason: Option<EntityId>,
    /// The MACHINE whose install key signed: the seal's carrier.
    pub carrier: EntityId,
    /// Who decided, under the same signature: the owner's or an agent's
    /// [`oneiron_authority::authority::OwnerAct`], or the engine's cause.
    pub authority: SealAuthority,
    /// A decision's causal point, under the same signature: the main-log
    /// heads and the carrier's standing rows its carrier held as it decided
    /// (FIX 4649), one to [`crate::authority::MAX_PARENTS`]. An engine seal
    /// names none.
    pub authority_heads: BTreeSet<AuthorityEntryHash>,
    pub signer_pk: [u8; 32],
    pub signature: [u8; 64],
}

impl AdmissionDisposition {
    /// The one signed transcript: the target, the core digest, the verdict,
    /// the optional reason, the carrier, the deciding authority and its
    /// causal heads.
    fn transcript(
        target: &EntityId,
        digest: &[u8; 32],
        verdict: AdmissionVerdict,
        reason: Option<EntityId>,
        carrier: &EntityId,
        (authority, heads): (&SealAuthority, &BTreeSet<AuthorityEntryHash>),
    ) -> Result<Vec<u8>> {
        let mut bytes = Vec::with_capacity(DOMAIN.len() + 16 + 32 + 32 + 17 + 16 + 256);
        bytes.extend_from_slice(DOMAIN);
        bytes.extend_from_slice(target.as_bytes());
        bytes.extend_from_slice(digest);
        bytes.extend_from_slice(verdict.as_str().as_bytes());
        bytes.push(0);
        match reason {
            Some(id) => {
                bytes.push(1);
                bytes.extend_from_slice(id.as_bytes());
            }
            None => bytes.push(0),
        }
        bytes.extend_from_slice(carrier.as_bytes());
        bytes.extend_from_slice(&authority.transcript_bytes()?);
        bytes.extend_from_slice(&(heads.len() as u64).to_be_bytes());
        for head in heads {
            bytes.extend_from_slice(head);
        }
        Ok(bytes)
    }

    fn own_transcript(&self) -> Result<Vec<u8>> {
        Self::transcript(
            &self.target,
            &self.core_digest,
            self.verdict,
            self.reason,
            &self.carrier,
            (&self.authority, &self.authority_heads),
        )
    }

    /// The token of this seal's act (FIX 4649): BLAKE3 over its own domain,
    /// the signed transcript and the signer key. Derived from the seal's
    /// signed bytes, never its time; a carrier's removal that lists it keeps
    /// the decision standing.
    pub(super) fn act_token(&self) -> Result<AuthorityEntryHash> {
        let mut hasher = blake3::Hasher::new();
        hasher.update(SEAL_ACT_TOKEN_DOMAIN);
        hasher.update(&self.own_transcript()?);
        hasher.update(&self.signer_pk);
        Ok(*hasher.finalize().as_bytes())
    }

    /// The verified signed payload, a seal's immutable decision bytes: the
    /// transcript, the signer key and its signature.
    pub(super) fn signed_payload(&self) -> Result<Vec<u8>> {
        let mut bytes = self.own_transcript()?;
        bytes.extend_from_slice(&self.signer_pk);
        bytes.extend_from_slice(&self.signature);
        Ok(bytes)
    }

    /// A seal of `target`'s decision `core`, signed by `signer`'s carrier
    /// with `authority`, in the one transcript. A decision signs the causal
    /// point `signer` captured; an engine seal signs none.
    pub(super) fn signed(
        signer: &ResolvedSeal,
        target: EntityId,
        core: &StoredIdentityOpEvent,
        verdict: AdmissionVerdict,
        reason: Option<EntityId>,
        authority: SealAuthority,
    ) -> Result<Self> {
        let core_digest = core_digest(core)?;
        let carrier = signer.carrier();
        let authority_heads = match authority {
            SealAuthority::Decision(_) => signer.heads().clone(),
            SealAuthority::Engine(_) => BTreeSet::new(),
        };
        let transcript = Self::transcript(
            &target,
            &core_digest,
            verdict,
            reason,
            &carrier,
            (&authority, &authority_heads),
        )?;
        Ok(Self {
            target,
            core_digest,
            verdict,
            reason,
            carrier,
            authority,
            authority_heads,
            signer_pk: signer.key().verifying_key().to_bytes(),
            signature: signer.key().sign(&transcript).to_bytes(),
        })
    }

    /// Records this seal as this vault's own under `fact`, the row that will
    /// carry it.
    pub(super) fn record_sealed_here(
        &self,
        vault: &Vault,
        wtxn: &mut heed::RwTxn<'_>,
        fact: EntityId,
    ) -> Result<()> {
        SEALED_HERE.put(&vault.store, wtxn, &HexId(fact), &self.seal_bytes())
    }

    /// Seals as this install's machine, whose key is the one pairing enrols,
    /// an engine seal of a door signature that names no deciding authority,
    /// and records the seal as this vault's own under `fact`, the row that
    /// will carry it.
    #[cfg(test)]
    pub(super) fn seal(
        vault: &Vault,
        wtxn: &mut heed::RwTxn<'_>,
        fact: EntityId,
        target: EntityId,
        core: &StoredIdentityOpEvent,
        verdict: AdmissionVerdict,
        reason: Option<EntityId>,
    ) -> Result<Self> {
        let cause = super::act_admission::EngineCause::Unattributed;
        let signer = ResolvedSeal::engine_in_txn(vault, wtxn, cause)?;
        let sealed = Self::signed(
            &signer,
            target,
            core,
            verdict,
            reason,
            SealAuthority::Engine(cause),
        )?;
        sealed.record_sealed_here(vault, wtxn, fact)?;
        Ok(sealed)
    }

    fn seal_bytes(&self) -> [u8; 96] {
        let mut bytes = [0; 96];
        bytes[..32].copy_from_slice(&self.signer_pk);
        bytes[32..].copy_from_slice(&self.signature);
        bytes
    }

    pub(super) fn verify(&self) -> Result<()> {
        let malformed = || Error::Sync(SyncError::InvalidIdentityTopologyEventBody(MALFORMED));
        if self.verdict == AdmissionVerdict::RefusedConflict
            || (matches!(
                self.verdict,
                AdmissionVerdict::Validated | AdmissionVerdict::RefusedActorClass
            ) && self.reason.is_some())
            || (matches!(
                self.verdict,
                AdmissionVerdict::RefusedNonStructural | AdmissionVerdict::RefusedFacetMerge
            ) && self.reason.is_none())
        {
            return Err(malformed());
        }
        // A decision's act is a topology seal of exactly the sealed event,
        // and it signs its causal point; an engine seal signs none.
        let heads_ok = match &self.authority {
            SealAuthority::Decision(act) => {
                act.validate_carried(crate::authority::OwnerActKind::TopologySeal, self.target)
                    .map_err(|_| malformed())?;
                !self.authority_heads.is_empty()
                    && self.authority_heads.len() <= crate::authority::MAX_PARENTS
            }
            SealAuthority::Engine(_) => self.authority_heads.is_empty(),
        };
        if !heads_ok {
            return Err(malformed());
        }
        let bad_signature =
            || Error::Sync(SyncError::InvalidIdentityTopologyEventBody(BAD_SIGNATURE));
        let key = VerifyingKey::from_bytes(&self.signer_pk).map_err(|_| bad_signature())?;
        key.verify_strict(
            &self.own_transcript()?,
            &Signature::from_bytes(&self.signature),
        )
        .map_err(|_| bad_signature())
    }

    pub(super) fn encode_entries(&self, entries: &mut Vec<(Value, Value)>) {
        use super::wire_keys::*;
        entries.push((
            BODY_KEY_TARGET.into(),
            Value::Binary(self.target.as_bytes().to_vec()),
        ));
        entries.push((
            BODY_KEY_CORE_DIGEST.into(),
            Value::Binary(self.core_digest.to_vec()),
        ));
        entries.push((BODY_KEY_VERDICT.into(), self.verdict.as_str().into()));
        if let Some(reason) = self.reason {
            entries.push((
                BODY_KEY_REASON.into(),
                Value::Binary(reason.as_bytes().to_vec()),
            ));
        }
        entries.push((
            BODY_KEY_CARRIER.into(),
            Value::Binary(self.carrier.as_bytes().to_vec()),
        ));
        self.authority.encode_entry(entries);
        if !self.authority_heads.is_empty() {
            entries.push((
                BODY_KEY_AUTHORITY_HEADS.into(),
                Value::Array(
                    self.authority_heads
                        .iter()
                        .map(|head| Value::Binary(head.to_vec()))
                        .collect(),
                ),
            ));
        }
        entries.push((
            BODY_KEY_SIGNER.into(),
            Value::Binary(self.signer_pk.to_vec()),
        ));
        entries.push((
            BODY_KEY_SIGNATURE.into(),
            Value::Binary(self.signature.to_vec()),
        ));
    }

    pub(super) fn decode(map: &[(Value, Value)]) -> Result<Self> {
        use super::event_body_codec::{decode_id_value, map_field};
        use super::wire_keys::*;
        let malformed = || Error::Sync(SyncError::InvalidIdentityTopologyEventBody(MALFORMED));
        let field = |key| {
            map_field(map, key)
                .and_then(Value::as_slice)
                .ok_or_else(malformed)
        };
        let target = decode_id_value(
            map_field(map, BODY_KEY_TARGET).ok_or_else(malformed)?,
            MALFORMED,
        )?;
        let core_digest: [u8; 32] = field(BODY_KEY_CORE_DIGEST)?
            .try_into()
            .map_err(|_| malformed())?;
        let verdict = map_field(map, BODY_KEY_VERDICT)
            .and_then(Value::as_str)
            .and_then(AdmissionVerdict::parse)
            .ok_or_else(malformed)?;
        let reason = map_field(map, BODY_KEY_REASON)
            .map(|v| decode_id_value(v, MALFORMED))
            .transpose()?;
        let carrier = decode_id_value(
            map_field(map, BODY_KEY_CARRIER).ok_or_else(malformed)?,
            MALFORMED,
        )?;
        let authority = SealAuthority::decode_entry(map, target, MALFORMED)?;
        // Canonical: re-encode equality refuses an unsorted or empty list.
        let mut authority_heads = BTreeSet::new();
        if let Some(value) = map_field(map, BODY_KEY_AUTHORITY_HEADS) {
            for head in value.as_array().ok_or_else(malformed)? {
                let head: AuthorityEntryHash = head
                    .as_slice()
                    .and_then(|bytes| bytes.try_into().ok())
                    .ok_or_else(malformed)?;
                if !authority_heads.insert(head) {
                    return Err(malformed());
                }
            }
        }
        let signer_pk: [u8; 32] = field(BODY_KEY_SIGNER)?
            .try_into()
            .map_err(|_| malformed())?;
        let signature: [u8; 64] = field(BODY_KEY_SIGNATURE)?
            .try_into()
            .map_err(|_| malformed())?;
        let disposition = Self {
            target,
            core_digest,
            verdict,
            reason,
            carrier,
            authority,
            authority_heads,
            signer_pk,
            signature,
        };
        disposition.verify()?;
        Ok(disposition)
    }
}

/// Canonical immutable decision core: actor and mutable historical flags are
/// explicitly excluded. Its other fields, including seq and consent, are bound.
pub(crate) fn core_digest(record: &StoredIdentityOpEvent) -> Result<[u8; 32]> {
    if matches!(
        record.action,
        StoredIdentityOpAction::AdmissionDisposition(_)
    ) {
        return Err(Error::Sync(SyncError::InvalidIdentityTopologyEventBody(
            MALFORMED,
        )));
    }
    let mut canonical = record.clone();
    canonical.actor = None;
    canonical.validated_at_write = false;
    canonical.invalidated = false;
    Ok(*blake3::hash(&super::encode_identity_topology_event_body(&canonical)?).as_bytes())
}

/// Who may seal. An engine seal (H161): this vault, for the facts it sealed
/// itself, and a live machine the owner marked mine; a fact anyone else
/// sealed is stored but inert, verdict and refusal alike, until its signer is
/// enrolled as mine. A decision seal (mesh PR2-topology): the same rule on
/// every replica, this one included, `act_admission`'s carrier and owner at
/// its signed heads (FIX 4649) and Grant standing. The roster is read once
/// per pass, and only for a fact the marker does not settle; every decision
/// seal's causal standing is judged once per pass too.
#[derive(Default)]
pub(crate) struct SealTrust {
    roster: Option<AuthorityFold>,
    causal: Option<Arc<CausalPoints>>,
}

impl SealTrust {
    fn fold(&mut self, store: &Store, rtxn: &heed::RoTxn<'_>) -> Result<&AuthorityFold> {
        if self.roster.is_none() {
            self.roster = Some(crate::authority::authority_fold_readonly_for_store_in_txn(
                store,
                store.privacy_posture,
                rtxn,
            )?);
        }
        self.roster.as_ref().ok_or(Error::InvariantViolation(
            "identity topology seal trust fold",
        ))
    }

    /// How a decision seal's carrier and owner stand at its signed heads,
    /// and whether every later removal of the carrier saw it: one fold
    /// judges every decision seal this vault holds, and a seal outside that
    /// set (not stored yet) joins it.
    fn causal_standing(
        &mut self,
        store: &Store,
        rtxn: &heed::RoTxn<'_>,
        act: &ExternalAct,
    ) -> Result<ExternalActStanding> {
        if let Some(standing) = self.causal.as_ref().and_then(|points| points.standing(act)) {
            return Ok(standing);
        }
        let mut acts = super::seal_standing::decision_seal_acts_in_txn(store, rtxn)?;
        acts.insert(act.clone());
        let points = crate::authority::causal_points_in_txn(store, rtxn, &acts)?;
        let standing = points.standing(act).ok_or(Error::InvariantViolation(
            "identity topology seal causal standing",
        ))?;
        self.causal = Some(points);
        Ok(standing)
    }

    /// How fact row `id`, sealing `core`, stands here.
    pub(super) fn standing(
        &mut self,
        store: &Store,
        rtxn: &heed::RoTxn<'_>,
        id: &EntityId,
        fact: &AdmissionDisposition,
        core: &StoredIdentityOpEvent,
    ) -> Result<SealStanding> {
        match &fact.authority {
            // Today's admission exactly: this vault's own seal, else a
            // trusted machine's.
            SealAuthority::Engine(_) => {
                if SEALED_HERE.get(store, rtxn, &HexId(*id))? == Some(fact.seal_bytes())
                    || signer_is_mine(self.fold(store, rtxn)?, &fact.signer_pk)
                {
                    Ok(SealStanding::Admitted)
                } else {
                    Ok(SealStanding::Refused)
                }
            }
            // `SEALED_HERE` is provenance only: the carrier, owner and Grant
            // rule every replica runs.
            SealAuthority::Decision(act) => {
                let act_at = super::seal_standing::external_act(fact, act)?;
                let causal = self.causal_standing(store, rtxn, &act_at)?;
                super::act_admission::decision_standing_in_txn(store, rtxn, causal, act, core.at)
            }
        }
    }

    pub(super) fn attributed(
        &mut self,
        store: &Store,
        rtxn: &heed::RoTxn<'_>,
        id: &EntityId,
        fact: &AdmissionDisposition,
        core: &StoredIdentityOpEvent,
    ) -> Result<bool> {
        Ok(self.standing(store, rtxn, id, fact, core)? == SealStanding::Admitted)
    }
}

/// The one reader of machine standing for seals: a machine mine under this
/// install's pin whose trusted identity signs with `signer` (world privacy
/// P6b: a chain this install does not trust never lends a machine its key).
fn signer_is_mine(roster: &AuthorityFold, signer: &[u8; 32]) -> bool {
    roster.mine_machine_by_key(signer).is_some()
}

/// Whether the seal standing differs from the one the last authority write
/// or Grant delete reconciled against, recording the new digest: the mine
/// signers, and the decision seals' carriers, owners, causal evidence and
/// named Grants (`act_admission::decision_standing_digest_in_txn`). A roster
/// change, a carrier's removal or new revision, a seal's causal point
/// arriving, or an owner's or Grant's revocation decides again which seals
/// count, so the stored shell edges must follow it; an authority write that
/// changes no standing (a header-only replay, a slip mint) does not pay for a
/// reconcile.
pub(super) fn mine_signers_changed_in_txn(
    store: &Store,
    wtxn: &mut heed::RwTxn<'_>,
) -> Result<bool> {
    let roster = crate::authority::authority_fold_readonly_for_store_in_txn(
        store,
        store.privacy_posture,
        wtxn,
    )?;
    let mut signers: Vec<[u8; 32]> = roster
        .machines
        .keys()
        .filter_map(|machine| roster.trusted_machine(*machine))
        .map(|trusted| trusted.profile.machine_key)
        .collect();
    signers.sort_unstable();
    signers.dedup();
    let mut digest = blake3::Hasher::new();
    for signer in &signers {
        digest.update(signer);
    }
    digest.update(&super::act_admission::decision_standing_digest_in_txn(
        store, wtxn, &roster,
    )?);
    let digest = *digest.finalize().as_bytes();
    if MINE_SIGNERS.get(store, wtxn, &())? == Some(digest) {
        return Ok(false);
    }
    MINE_SIGNERS.put(store, wtxn, &(), &digest)?;
    Ok(true)
}

/// A missing target is a pending fact, never an authority shortcut. Conflicts
/// between incompatible refusals or different core digests fail closed. Only
/// facts `trust` attributes count.
pub(super) fn joined_verdict_for_store_in_txn(
    store: &Store,
    rtxn: &heed::RoTxn<'_>,
    target: &EntityId,
    core: &StoredIdentityOpEvent,
    trust: &mut SealTrust,
) -> Result<Option<AdmissionVerdict>> {
    let digest = core_digest(core)?;
    let mut validated = false;
    let mut refused = None;
    for id in crate::ports::EntityStoreRead::port_entity_ids_by_type(
        store,
        rtxn,
        crate::registry::ENTITY_TYPE_IDENTITY_TOPOLOGY_EVENT,
        None,
    )? {
        let id = id?;
        let row = super::store_entity_helpers::identity_topology_event_for_store_in_txn(
            store, rtxn, &id,
        )?
        .ok_or(Error::CorruptedIndex("identity topology event index"))?;
        let StoredIdentityOpAction::AdmissionDisposition(fact) = row.action else {
            continue;
        };
        // A wrong-core fact cannot poison the whole vault. It remains inert:
        // admission rejects it when the core is already available; if it
        // arrived earlier, target arrival cannot retroactively quarantine
        // the already committed row, but its digest never binds this core.
        if fact.target != *target || fact.core_digest != digest {
            continue;
        }
        fact.verify()
            .map_err(|_| Error::CorruptedIndex("identity topology admission signature"))?;
        if !trust.attributed(store, rtxn, &id, &fact, core)? {
            continue;
        }
        if fact.verdict == AdmissionVerdict::Validated {
            validated = true;
        } else if refused.is_some_and(|v| v != (fact.verdict, fact.reason)) {
            refused = Some((AdmissionVerdict::RefusedConflict, None));
        } else {
            refused = Some((fact.verdict, fact.reason));
        }
    }
    Ok(refused
        .map(|(verdict, _)| verdict)
        .or(validated.then_some(AdmissionVerdict::Validated)))
}

/// Whether seal standing lets `core` count as a completed act (H161): an
/// `Auto` or `Approved` decision needs a Validated seal `trust` attributes and
/// no refusal it attributes, as in the effective fold. Other rows need no
/// seal. The projections that read the raw family read standing here.
pub(crate) fn decision_in_force_by_seal_in_txn(
    store: &Store,
    rtxn: &heed::RoTxn<'_>,
    event: &EntityId,
    core: &StoredIdentityOpEvent,
    trust: &mut SealTrust,
) -> Result<bool> {
    if !matches!(
        core.approval,
        crate::claim::ClaimApprovalStatus::Auto | crate::claim::ClaimApprovalStatus::Approved
    ) {
        return Ok(true);
    }
    Ok(
        joined_verdict_for_store_in_txn(store, rtxn, event, core, trust)?
            == Some(AdmissionVerdict::Validated),
    )
}

/// Peer admission check for both arrival orders. A pending target is not
/// accepted as proof; the signed fact stays inert until core binding succeeds.
pub(crate) fn validate_incoming_disposition_in_txn(
    store: &Store,
    rtxn: &heed::RoTxn<'_>,
    incoming_id: &EntityId,
    incoming: &StoredIdentityOpEvent,
) -> Result<()> {
    let StoredIdentityOpAction::AdmissionDisposition(fact) = &incoming.action else {
        return Ok(());
    };
    fact.verify()?;
    if fact.target == *incoming_id {
        return Err(Error::Sync(SyncError::InvalidIdentityTopologyEventBody(
            SELF_TARGET,
        )));
    }
    if let Some(row) = super::store_entity_helpers::identity_topology_event_for_store_in_txn(
        store,
        rtxn,
        &fact.target,
    )? && fact.core_digest != core_digest(&row)?
    {
        return Err(Error::Sync(SyncError::InvalidIdentityTopologyEventBody(
            "identity topology admission core conflict",
        )));
    }
    Ok(())
}

/// A fact sealed by `key`, as an install this vault may not know seals it:
/// the trust-root fixtures deliver it like any peer row.
#[cfg(all(test, feature = "sync"))]
pub(crate) fn sealed_by_key_for_test(
    key: &ed25519_dalek::SigningKey,
    target: EntityId,
    core: &StoredIdentityOpEvent,
    verdict: AdmissionVerdict,
) -> Result<AdmissionDisposition> {
    let core_digest = core_digest(core)?;
    let signature = key
        .sign(&AdmissionDisposition::transcript(
            &target,
            &core_digest,
            verdict,
            None,
        ))
        .to_bytes();
    Ok(AdmissionDisposition {
        target,
        core_digest,
        verdict,
        reason: None,
        signer_pk: key.verifying_key().to_bytes(),
        signature,
    })
}

/// A genuine signed producer fact for cross-module sync/batch fixtures. The
/// test still delivers the core and fact as SEPARATE records in either order.
/// It is `vault`'s own seal, the one kind that vault counts with no roster
/// entry (H161), so delivered to `vault` it stands in for a trusted producer.
/// Whose seals a receiver counts is checked across two vaults in
/// `sync/bridge/companion_identity_tests.rs`.
#[cfg(all(test, feature = "sync"))]
pub(crate) fn signed_validated_row_for_test(
    vault: &Vault,
    target: EntityId,
    core: &StoredIdentityOpEvent,
) -> Result<(EntityId, StoredIdentityOpEvent)> {
    vault.with_write_txn_grouped(|wtxn| {
        let id = vault.store.clock.entity_id()?;
        let fact = AdmissionDisposition::seal(
            vault,
            wtxn,
            id,
            target,
            core,
            AdmissionVerdict::Validated,
            None,
        )?;
        let row = StoredIdentityOpEvent {
            seq: core
                .seq
                .checked_add(1)
                .ok_or(Error::ArithmeticOverflow("identity fixture seq"))?,
            validated_at_write: false,
            invalidated: false,
            at: core.at,
            actor: None,
            source: core.source,
            approval: crate::claim::ClaimApprovalStatus::Auto,
            confidence: 1.0,
            evidence: None,
            action: StoredIdentityOpAction::AdmissionDisposition(fact),
        };
        Ok((id, row))
    })
}
