//! The e-sign rule pack (ARCH-0064 section 2 "Reminders, expiry and compliance are pack data",
//! section 8; SGN-08, SGN-09): the lifecycle default row and the compliance rows, seeded from
//! `rules_seed_v1.json` and amended on the OF-404 path the campaign compliance pack runs
//! (`campaign/compliance/amend.rs`). Any verified writer proposes a whole pack; a provable
//! tightening inside the caller's live ceiling activates with a durable notice, and every other
//! change is staged until the owner stamps its exact hash. An agent or system caller also needs
//! a live Grant listing the verb. The UETA section 10 row, and every other non-waivable row, is
//! never waived, rewritten or removed: no amend, stamp or seed passes with it changed.

use std::collections::BTreeSet;

use oneiron_contracts::fingerprint::ContentHash;

use crate::EdgeActorClass;
use crate::consent::AuthenticatedOwner;
use crate::error::{Error, Result};
use crate::gate::{
    PolicyApprovalCeiling, agent_definition_ceiling_for_actor, resolve_policy_manifest,
};
use crate::memory::{
    MEMORY_CODE_FORBIDDEN, MEMORY_CODE_INVALID_STATE, Memory, MemoryError, MemoryResult,
};
use crate::side_table::{self, Named, Raw, SideTable};
use crate::store::Store;

use super::EsignLifecycleRules;

#[doc(hidden)]
pub use oneiron_verb_wire::blob_artifact::esign::rules::{
    ESIGN_RULES_PACK_ID, ESIGN_UETA_REVIEW_ROW, EsignComplianceRow, EsignComplianceRowKind,
    EsignComplianceSource, EsignRulePack, EsignRulesAmendRequest, EsignRulesDecisionRequest,
    EsignRulesDisposition, EsignRulesGetRequest, EsignRulesPending, EsignRulesReceipt,
    EsignRulesView,
};

/// The active pack. Key: `()`. Absent until the first activation: the seed answers.
const ACTIVE: SideTable<(), EsignRulePack, Named> = SideTable::new(&side_table::ESIGN_RULES_ACTIVE);
/// The one proposal awaiting an owner stamp. Key: `()`.
const PENDING: SideTable<(), EsignRulePack, Named> =
    SideTable::new(&side_table::ESIGN_RULES_PENDING);
/// The durable activation notices, one per activated version. Key: `pack_version` (u32
/// big-endian).
const NOTICE: SideTable<[u8; 4], String, Raw> = SideTable::new(&side_table::ESIGN_RULES_NOTICE);

const SEED_JSON: &str = include_str!("rules_seed_v1.json");
const GET_VERB: &str = "vault.esign.rules.get";
const AMEND_VERB: &str = "vault.esign.rules.amend";

/// How a proposal orders against the active pack.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AmendClass {
    /// Strictly narrower: activates within the caller's ceiling.
    Tightening,
    /// Citations, check dates or row versions only: activates within the caller's ceiling.
    MetadataRefresh,
    /// Anything wider or not provably narrower: waits for the owner's stamp.
    LooseningOrAmbiguous,
}

fn invalid_pack(message: &str) -> Error {
    Error::InvalidConfig(format!("e-sign rule pack: {message}"))
}

/// The embedded seed, parsed and validated.
fn seed_pack() -> Result<EsignRulePack> {
    let pack: EsignRulePack = serde_json::from_str(SEED_JSON)
        .map_err(|_| Error::InvariantViolation("e-sign rule seed pack is not valid JSON"))?;
    validate_pack(&pack)?;
    Ok(pack)
}

/// Rejects a pack that cannot apply. Runs on the seed, on every proposal before it is staged and
/// on every pack before it activates.
fn validate_pack(pack: &EsignRulePack) -> Result<()> {
    if pack.pack_id != ESIGN_RULES_PACK_ID {
        return Err(invalid_pack("the pack id is esign.rules"));
    }
    if pack.pack_version == 0 {
        return Err(invalid_pack("the pack version starts at 1"));
    }
    pack.lifecycle
        .validate()
        .map_err(|_| invalid_pack("the lifecycle default row is not a valid lifecycle"))?;
    let mut ids = BTreeSet::new();
    for row in &pack.rows {
        let blank = row.id.trim().is_empty()
            || row.regime.trim().is_empty()
            || row.rule.trim().is_empty()
            || row.source.citation.trim().is_empty()
            || row.source.url.trim().is_empty();
        if blank {
            return Err(invalid_pack("a compliance row has a blank required field"));
        }
        if row.verified_at == 0 || row.version == 0 {
            return Err(invalid_pack(
                "a compliance row needs a verified_at and a version",
            ));
        }
        if !ids.insert(row.id.as_str()) {
            return Err(invalid_pack("two compliance rows share one id"));
        }
    }
    match pack.rows.iter().find(|row| row.id == ESIGN_UETA_REVIEW_ROW) {
        Some(row) if !row.waivable && row.kind == EsignComplianceRowKind::Requirement => Ok(()),
        Some(_) => Err(invalid_pack(
            "the UETA section 10 review-before-complete row is a non-waivable requirement",
        )),
        None => Err(invalid_pack(
            "the non-waivable UETA section 10 review-before-complete row may not be removed",
        )),
    }
}

/// `Some(true)` when `proposed` is looser than `current`, `Some(false)` when it is tighter,
/// `None` when they are equal. `looser_when_greater` names the direction that widens.
fn order(current: u64, proposed: u64, looser_when_greater: bool) -> Option<bool> {
    (proposed != current).then_some((proposed > current) == looser_when_greater)
}

/// Orders `proposed` against `current`, refusing a proposal that does not advance the version or
/// that waives, rewrites or removes a non-waivable row.
fn classify(current: &EsignRulePack, proposed: &EsignRulePack) -> Result<AmendClass> {
    validate_pack(proposed)?;
    if proposed.pack_version <= current.pack_version {
        return Err(invalid_pack("an amend must advance the pack version"));
    }
    for kept in current.rows.iter().filter(|row| !row.waivable) {
        let unchanged = proposed.rows.iter().any(|row| {
            row.id == kept.id
                && !row.waivable
                && row.kind == kept.kind
                && row.regime == kept.regime
                && row.rule == kept.rule
        });
        if !unchanged {
            return Err(invalid_pack(&format!(
                "the non-waivable row {} may not be waived, rewritten or removed",
                kept.id
            )));
        }
    }
    let (current_rules, proposed_rules) = (&current.lifecycle, &proposed.lifecycle);
    // A longer window or reminder cap, and an earlier or more frequent reminder, widen what the
    // pack sends and how long a link may sign.
    let mut orders = vec![
        order(
            current_rules.expiry_after_seconds,
            proposed_rules.expiry_after_seconds,
            true,
        ),
        order(
            current_rules.reminder_cap_seconds,
            proposed_rules.reminder_cap_seconds,
            true,
        ),
        order(
            current_rules.first_reminder_after_seconds,
            proposed_rules.first_reminder_after_seconds,
            false,
        ),
        order(
            current_rules.repeat_reminder_every_seconds,
            proposed_rules.repeat_reminder_every_seconds,
            false,
        ),
        // An unset token cap lets a link live to the document's deadline: the widest cap.
        order(
            current_rules.token_cap_seconds.unwrap_or(u64::MAX),
            proposed_rules.token_cap_seconds.unwrap_or(u64::MAX),
            true,
        ),
    ];
    // A notice switch changes what a signer is told: never provably narrower.
    if current_rules.notices != proposed_rules.notices {
        orders.push(Some(true));
    }
    for row in &proposed.rows {
        match current.rows.iter().find(|held| held.id == row.id) {
            // A new row waits for the owner, as a new jurisdiction's rows do (OF-404).
            None => orders.push(Some(true)),
            Some(held) => {
                if held.kind != row.kind || held.regime != row.regime || held.rule != row.rule {
                    orders.push(Some(true));
                }
                if held.waivable && !row.waivable {
                    orders.push(Some(false));
                }
            }
        }
    }
    if current
        .rows
        .iter()
        .any(|held| !proposed.rows.iter().any(|row| row.id == held.id))
    {
        orders.push(Some(true));
    }
    let loosened = orders.contains(&Some(true));
    let tightened = orders.contains(&Some(false));
    Ok(match (loosened, tightened) {
        (true, _) => AmendClass::LooseningOrAmbiguous,
        (false, true) => AmendClass::Tightening,
        (false, false) => AmendClass::MetadataRefresh,
    })
}

/// The canonical hash a stamp binds: the content hash (the fingerprint door's plain BLAKE3)
/// of the pack encoded with its rows in id order.
fn proposal_hash(pack: &EsignRulePack) -> Result<[u8; 32]> {
    let mut canonical = pack.clone();
    canonical.rows.sort_by(|left, right| left.id.cmp(&right.id));
    let bytes = rmp_serde::to_vec_named(&canonical)
        .map_err(|_| Error::InvariantViolation("e-sign rule pack encode failed"))?;
    Ok(ContentHash::of(&bytes).into_bytes())
}

fn hash_hex(hash: &[u8; 32]) -> String {
    hash.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// The active pack, or the seed while none was activated.
fn active_in_txn(store: &Store, txn: &heed::RoTxn<'_>) -> Result<EsignRulePack> {
    match ACTIVE.get(store, txn, &())? {
        Some(pack) => Ok(pack),
        None => seed_pack(),
    }
}

/// The active lifecycle default row, which a draft created without `lifecycle` carries.
/// # Errors
/// A store failure, or an active row that does not decode.
pub(crate) fn lifecycle_default_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
) -> Result<EsignLifecycleRules> {
    Ok(active_in_txn(store, txn)?.lifecycle)
}

/// The only writer of the active pack: validates it, stores it and writes its notice.
fn activate(
    store: &Store,
    wtxn: &mut heed::RwTxn<'_>,
    pack: &EsignRulePack,
    class: AmendClass,
    actor: &str,
) -> Result<String> {
    validate_pack(pack)?;
    ACTIVE.put(store, wtxn, &(), pack)?;
    let how = match class {
        AmendClass::Tightening => "tightening",
        AmendClass::MetadataRefresh => "metadata refresh",
        AmendClass::LooseningOrAmbiguous => "owner stamped",
    };
    let notice = format!(
        "e-sign rule pack {} activated at version {} ({how}) by {actor}; {} compliance rows",
        pack.pack_id,
        pack.pack_version,
        pack.rows.len(),
    );
    NOTICE.put(store, wtxn, &pack.pack_version.to_be_bytes(), &notice)?;
    Ok(notice)
}

fn prior_pack(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    prior_version: u32,
) -> MemoryResult<EsignRulePack> {
    let current = active_in_txn(store, txn)?;
    if current.pack_version != prior_version {
        return Err(MemoryError::new(
            MEMORY_CODE_INVALID_STATE,
            "prior_version does not match the active e-sign rule pack",
            &["Read vault.esign.rules.get and propose against its active version."],
        ));
    }
    Ok(current)
}

/// The staged proposal, if `proposal_hash` binds it exactly.
fn matching_pending(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    proposal_hash_hex: &str,
) -> MemoryResult<(EsignRulePack, [u8; 32])> {
    let pending = PENDING.get(store, txn, &())?.ok_or_else(|| {
        MemoryError::new(
            MEMORY_CODE_INVALID_STATE,
            "no e-sign rule proposal is awaiting an owner stamp",
            &[],
        )
    })?;
    let hash = proposal_hash(&pending)?;
    if hash_hex(&hash) != proposal_hash_hex {
        return Err(MemoryError::new(
            MEMORY_CODE_INVALID_STATE,
            "the proposal_hash does not bind the staged e-sign rule proposal",
            &["Read vault.esign.rules.get and stamp the pending proposal_hash it shows."],
        ));
    }
    Ok((pending, hash))
}

fn receipt(
    disposition: EsignRulesDisposition,
    active_version: u32,
    hash: &[u8; 32],
    notice: Option<String>,
) -> EsignRulesReceipt {
    EsignRulesReceipt {
        disposition,
        active_version,
        proposal_hash: hash_hex(hash),
        notice,
    }
}

/// An agent or system caller acts on the pack only under a live Grant from a live owner that
/// names it and lists `verb` (substrate behind grants); a human caller is judged by the gate.
fn require_listed_grant(
    memory: &Memory<'_>,
    txn: &heed::RoTxn<'_>,
    verb: &str,
) -> MemoryResult<()> {
    if memory.actor_class() == EdgeActorClass::Human {
        return Ok(());
    }
    let standing = crate::authority::principal_standing_in_txn(
        memory.vault(),
        txn,
        memory.actor(),
        memory.actor_class(),
        verb,
    )?;
    if standing.is_none() {
        return Err(MemoryError::new(
            MEMORY_CODE_FORBIDDEN,
            format!(
                "{verb} takes a live Grant from a live owner that names this caller and lists the verb"
            ),
            &["Ask the owner for a Grant that lists this verb."],
        ));
    }
    Ok(())
}

fn require_owner(
    memory: &Memory<'_>,
    owner: &AuthenticatedOwner,
    txn: &heed::RoTxn<'_>,
) -> MemoryResult<()> {
    if owner.revalidate_in_txn(memory.vault(), txn)? != memory.actor()
        || memory.actor_class() != EdgeActorClass::Human
    {
        return Err(MemoryError::new(
            MEMORY_CODE_FORBIDDEN,
            "e-sign rule decisions act as the authenticated owner",
            &[],
        ));
    }
    Ok(())
}

impl Memory<'_> {
    /// `vault.esign.rules.get`: the active pack, the staged proposal with the hash a stamp must
    /// bind, and every activation notice, from one snapshot.
    /// # Errors
    /// FORBIDDEN for an agent with no live Grant listing the verb; a store failure.
    pub fn esign_rules_get(&self, _input: &EsignRulesGetRequest) -> MemoryResult<EsignRulesView> {
        let vault = self.vault();
        let store = &vault.store;
        let txn = store.env.read_txn().map_err(Error::from)?;
        crate::memory::verify_actor_binding_in_txn(vault, &txn, self.actor(), self.actor_class())?;
        require_listed_grant(self, &txn, GET_VERB)?;
        let pending = PENDING
            .get(store, &txn, &())?
            .map(|pack| {
                let proposal_hash = hash_hex(&proposal_hash(&pack)?);
                Ok::<_, Error>(EsignRulesPending {
                    pack,
                    proposal_hash,
                })
            })
            .transpose()?;
        Ok(EsignRulesView {
            active: active_in_txn(store, &txn)?,
            pending,
            notices: NOTICE
                .scan(store, &txn)?
                .into_iter()
                .map(|(_, notice)| notice)
                .collect(),
        })
    }

    /// `vault.esign.rules.amend`: proposes a whole pack against the active version. A provable
    /// tightening or a metadata refresh activates with a durable notice when the caller's live
    /// ceiling is Auto; anything else is staged for the owner's stamp, replacing an earlier
    /// staged proposal.
    /// # Errors
    /// FORBIDDEN for a fail-closed gate or an agent with no live Grant listing the verb;
    /// INVALID_STATE for a stale `prior_version`; the pack's refusal for a malformed pack, a
    /// version that does not advance, or a non-waivable row waived, rewritten or removed.
    pub fn esign_rules_amend(
        &self,
        input: &EsignRulesAmendRequest,
    ) -> MemoryResult<EsignRulesReceipt> {
        self.with_verified_actor_write_txn(|txn| {
            require_listed_grant(self, txn, AMEND_VERB)?;
            let vault = self.vault();
            let store = &vault.store;
            let policy = resolve_policy_manifest(store, txn)?;
            if policy.is_fail_closed() {
                return Err(MemoryError::new(
                    MEMORY_CODE_FORBIDDEN,
                    "the caller's Gate refused this e-sign rule amend",
                    &[],
                ));
            }
            let can_activate = policy.actor_ceiling(
                self.actor_class().gate_actor_class(),
                Some(&self.actor().to_hex()),
            ) == PolicyApprovalCeiling::Auto
                && agent_definition_ceiling_for_actor(store, txn, self.write_actor())
                    != Some(PolicyApprovalCeiling::Proposed);
            let current = prior_pack(store, txn, input.prior_version)?;
            let class = classify(&current, &input.pack)?;
            let hash = proposal_hash(&input.pack)?;
            if !can_activate || class == AmendClass::LooseningOrAmbiguous {
                PENDING.put(store, txn, &(), &input.pack)?;
                return Ok(receipt(
                    EsignRulesDisposition::PendingOwnerStamp,
                    current.pack_version,
                    &hash,
                    None,
                ));
            }
            let notice = activate(store, txn, &input.pack, class, &self.actor().to_hex())?;
            Ok(receipt(
                EsignRulesDisposition::Applied,
                input.pack.pack_version,
                &hash,
                Some(notice),
            ))
        })
    }

    /// `vault.esign.rules.approve`: the owner activates the staged proposal whose exact hash the
    /// stamp names, judged again against the active pack.
    /// # Errors
    /// FORBIDDEN for anyone but the authenticated owner; INVALID_STATE for a stale
    /// `prior_version`, no staged proposal or a hash that does not bind it; the pack's refusal
    /// when the staged proposal no longer orders against the active pack.
    pub fn esign_rules_approve_as(
        &self,
        owner: &AuthenticatedOwner,
        input: &EsignRulesDecisionRequest,
    ) -> MemoryResult<EsignRulesReceipt> {
        self.with_verified_actor_write_txn(|txn| {
            require_owner(self, owner, txn)?;
            let store = &self.vault().store;
            let current = prior_pack(store, txn, input.prior_version)?;
            let (pending, hash) = matching_pending(store, txn, &input.proposal_hash)?;
            classify(&current, &pending)?;
            let notice = activate(
                store,
                txn,
                &pending,
                AmendClass::LooseningOrAmbiguous,
                &self.actor().to_hex(),
            )?;
            PENDING.delete(store, txn, &())?;
            Ok(receipt(
                EsignRulesDisposition::Applied,
                pending.pack_version,
                &hash,
                Some(notice),
            ))
        })
    }

    /// `vault.esign.rules.reject`: the owner drops the staged proposal whose exact hash the
    /// decision names; the active pack is unchanged.
    /// # Errors
    /// As [`Self::esign_rules_approve_as`], less the ordering refusal.
    pub fn esign_rules_reject_as(
        &self,
        owner: &AuthenticatedOwner,
        input: &EsignRulesDecisionRequest,
    ) -> MemoryResult<EsignRulesReceipt> {
        self.with_verified_actor_write_txn(|txn| {
            require_owner(self, owner, txn)?;
            let store = &self.vault().store;
            let current = prior_pack(store, txn, input.prior_version)?;
            let (_, hash) = matching_pending(store, txn, &input.proposal_hash)?;
            PENDING.delete(store, txn, &())?;
            Ok(receipt(
                EsignRulesDisposition::Rejected,
                current.pack_version,
                &hash,
                None,
            ))
        })
    }
}
