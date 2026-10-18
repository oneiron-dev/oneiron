//! The binding: minted beside the held effect's pending row, in its writer;
//! sealed with the parked checkpoint (1b, `replay.rs`); read by the answer
//! and by the effect's own gate.

use crate::Vault;
use crate::code_run::storage::derived_executor_id;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::side_table::{self, Named, SideTable};
use crate::task_verb::sdk::AgentVerb;

use super::types::{
    CODE_CONSENT_SCHEMA_VERSION, CodeConsentAdmission, CodeConsentBinding, CodeConsentCallSite,
    CodeConsentCheckpoint, CodeConsentPendingEffect, CodeConsentPrincipal, CodeConsentQuestion,
    CodeConsentRememberOffer, CodeConsentWaitRow,
};

/// Every code consent wait, by its wait id. Only this module writes it.
const WAITS: SideTable<EntityId, CodeConsentWaitRow, Named> =
    SideTable::new(&side_table::CODE_RUN_CONSENT_WAIT);

/// The derivation domain of a wait id: its write receipt and call identity.
const CODE_CONSENT_WAIT_DOMAIN: &[u8] = b"oneiron:code-consent-wait:v1";

/// The hash domain of a binding digest.
const CODE_CONSENT_BINDING_DOMAIN: &[u8] = b"oneiron:code-consent-binding:v1";

/// Whether a code-mode call of `verb` binds a code consent wait when its
/// effect is held for consent alone (CALLS: first adapter). 1a binds
/// `connector.call`; every other verb keeps its own wait.
pub(crate) fn code_consent_binds(verb: AgentVerb) -> bool {
    verb == AgentVerb::ConnectorCall
}

/// The wait id one write site's held call takes: derived from its write
/// receipt and its call identity, so a replayed step meets the same wait and
/// never mints a second one.
pub(crate) fn code_consent_wait_id(
    write_receipt_id: EntityId,
    request_digest: &[u8; 32],
) -> Result<EntityId> {
    derived_executor_id(
        CODE_CONSENT_WAIT_DOMAIN,
        &[write_receipt_id.as_bytes(), request_digest],
    )
}

/// One wait's row, read in `txn`.
pub(crate) fn read_code_consent_wait_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    wait_id: EntityId,
) -> Result<Option<CodeConsentWaitRow>> {
    WAITS.get(&vault.store, txn, &wait_id)
}

/// Writes one wait's row at its next revision.
pub(super) fn put_code_consent_wait_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    row: &mut CodeConsentWaitRow,
) -> Result<()> {
    row.revision = row
        .revision
        .checked_add(1)
        .ok_or(Error::ArithmeticOverflow("code consent wait revision"))?;
    WAITS.put(&vault.store, txn, &row.binding.wait_id, row)
}

/// What a held effect's owner hands the mint: its call site, its original
/// caller, the pending effect and the frozen bytes' digest.
pub(crate) struct CodeConsentDraft {
    pub(crate) site: CodeConsentCallSite,
    pub(crate) verb: AgentVerb,
    pub(crate) principal: CodeConsentPrincipal,
    pub(crate) pending: CodeConsentPendingEffect,
    pub(crate) frozen_input_digest: [u8; 32],
    pub(crate) hold_reasons: Vec<String>,
    pub(crate) remember_offer: Option<CodeConsentRememberOffer>,
}

/// Mints the provisional binding of a consent-only hold in the caller's
/// writer, beside the held row, and returns its wait id. `approval_digest`
/// is the effect gate's own code-bound composer over the binding digest.
/// `None` mints nothing, and the hold stays the effect's own wait: the
/// caller's credential no longer verifies, the vault has no owner to ask,
/// the gate cannot compose the effect, or the wait id already names another
/// call. A replay of the same mint returns the same wait.
pub(crate) fn mint_code_consent_wait_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    draft: CodeConsentDraft,
    approval_digest: impl FnOnce(&[u8; 32]) -> Option<[u8; 32]>,
) -> Result<Option<EntityId>> {
    let wait_id = draft.site.wait_id;
    if let Some(known) = read_code_consent_wait_in_txn(vault, txn, wait_id)? {
        return Ok((known.binding.pending == draft.pending).then_some(wait_id));
    }
    let mut principal = draft.principal;
    if let Some(credential) = &principal.credential {
        let Ok(verified) = vault.invocation_slip_in_txn(txn, &credential.witness) else {
            return Ok(None);
        };
        let slip = verified.claims().slip_id;
        if credential
            .instrument
            .as_ref()
            .is_some_and(|instrument| instrument.slip != slip)
        {
            return Ok(None);
        }
        principal.opener_slip = Some(slip);
    }
    let Some(owner) = crate::policy_model::owners_in_txn(vault, txn)?
        .into_iter()
        .min()
    else {
        return Ok(None);
    };
    let question = CodeConsentQuestion {
        owner,
        conversation: vault.store.clock.entity_id()?,
        turn: vault.store.clock.entity_id()?,
        message: vault.store.clock.entity_id()?,
        at: vault.store.clock.now_recorded_at(),
    };
    let policy_frontier =
        crate::gate::resolve_policy_manifest(&vault.store, txn)?.read_frontier_hash()?;
    let mut binding = CodeConsentBinding {
        schema_version: CODE_CONSENT_SCHEMA_VERSION,
        wait_id,
        run_id: draft.site.run_id,
        run_ref: draft.site.run_ref,
        step_start: draft.site.step_start,
        bridge_seq: draft.site.bridge_seq,
        write_ordinal: draft.site.write_ordinal,
        write_receipt_id: draft.site.write_receipt_id,
        verb_row: draft.verb.as_str().to_owned(),
        request_digest: draft.site.request_digest,
        frozen_input_digest: draft.frozen_input_digest,
        binding_digest: [0; 32],
        effect_digest: [0; 32],
        original: principal,
        pending: draft.pending,
        hold_reasons: draft.hold_reasons,
        remember_offer: draft.remember_offer,
        question,
        policy_frontier,
        created_at_ms: super::settle::now_ms(),
    };
    binding.binding_digest = binding_digest(&binding);
    let Some(effect_digest) = approval_digest(&binding.binding_digest) else {
        return Ok(None);
    };
    binding.effect_digest = effect_digest;
    let mut row = CodeConsentWaitRow {
        binding,
        ask: None,
        checkpoint: None,
        answer: None,
        admission: None,
        settlement: None,
        consumption: None,
        revision: 0,
    };
    put_code_consent_wait_in_txn(vault, txn, &mut row)?;
    Ok(Some(wait_id))
}

/// The binding digest: BLAKE3 over the stable call site, the request and
/// frozen digests, the original caller's instrument and the pending effect.
/// It names no effect digest, ask, time, checkpoint or receipt, so nothing
/// computed from it later feeds back into it.
pub(super) fn binding_digest(binding: &CodeConsentBinding) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    let mut field = |bytes: &[u8]| {
        hasher.update(&(bytes.len() as u64).to_le_bytes());
        hasher.update(bytes);
    };
    field(CODE_CONSENT_BINDING_DOMAIN);
    field(&binding.schema_version.to_le_bytes());
    field(binding.wait_id.as_bytes());
    field(binding.run_id.as_bytes());
    field(binding.run_ref.as_bytes());
    field(&binding.step_start.to_le_bytes());
    field(&binding.bridge_seq.to_le_bytes());
    field(&binding.write_ordinal.to_le_bytes());
    field(binding.write_receipt_id.as_bytes());
    field(binding.verb_row.as_bytes());
    field(&binding.request_digest);
    field(&binding.frozen_input_digest);
    let original = &binding.original;
    field(original.actor_ref.as_bytes());
    field(
        original
            .opener_slip
            .as_ref()
            .map_or(&[][..], |slip| &slip[..]),
    );
    match original
        .credential
        .as_ref()
        .and_then(|credential| credential.instrument.as_ref())
    {
        Some(instrument) => {
            field(&instrument.vault);
            field(&instrument.slip);
            field(&instrument.fingerprint);
            field(&instrument.ceiling);
        }
        None => field(&[]),
    }
    let call = binding.pending.connector_call();
    field(call.call_ref.as_bytes());
    field(&call.attempt_id);
    field(&call.call_seq.to_le_bytes());
    field(call.grant_ref.as_bytes());
    field(call.key_ref.as_bytes());
    field(call.name.as_bytes());
    field(call.server.as_bytes());
    field(call.tool.as_bytes());
    field(call.endpoint.as_bytes());
    field(&call.manifest_hash);
    field(call.protocol_revision.as_bytes());
    field(
        call.credential_record
            .as_ref()
            .map_or(&[][..], |record| &record.as_bytes()[..]),
    );
    *hasher.finalize().as_bytes()
}

/// Whether wait `wait_id` is bound to the held call `call_ref` and still
/// open: the dispatcher parks a run on the wait only then.
pub(crate) fn code_consent_binds_held_call(
    vault: &Vault,
    wait_id: EntityId,
    call_ref: EntityId,
) -> Result<bool> {
    let txn = vault.store.env.read_txn()?;
    Ok(
        read_code_consent_wait_in_txn(vault, &txn, wait_id)?.is_some_and(|row| {
            row.settlement.is_none() && row.binding.pending.connector_call().call_ref == call_ref
        }),
    )
}

/// Binds the admitted ask `group` to wait `wait_id`, once, in the ask's own
/// admission commit.
pub(crate) fn attach_code_consent_ask_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    wait_id: EntityId,
    group: EntityId,
) -> Result<()> {
    let Some(mut row) = read_code_consent_wait_in_txn(vault, txn, wait_id)? else {
        return Ok(());
    };
    if row.ask.is_some() {
        return Ok(());
    }
    row.ask = Some(group);
    put_code_consent_wait_in_txn(vault, txn, &mut row)
}

/// Records the effect gate's admission of wait `wait_id`'s effect, in the
/// admission writer that spends its approval, records the gate's decision
/// and inserts the ledger's Pending row: the admission commits with them or
/// not at all.
pub(crate) fn record_code_consent_admission_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    wait_id: EntityId,
    intent_id: [u8; 32],
    gate_decision: crate::store::GateDecisionId,
) -> Result<()> {
    let Some(mut row) = read_code_consent_wait_in_txn(vault, txn, wait_id)? else {
        return Err(Error::EntityNotFound);
    };
    if row.admission.is_some() {
        return Ok(());
    }
    row.admission = Some(CodeConsentAdmission {
        intent_id,
        gate_decision,
        admitted_at_ms: super::settle::now_ms(),
    });
    put_code_consent_wait_in_txn(vault, txn, &mut row)
}

/// Seals a provisional wait with its parked step, in the executor's replay
/// commit, so an answer can reach it. The same seal again is a no-op; any
/// other seal is refused.
pub(super) fn seal_code_consent_wait_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    wait_id: EntityId,
    checkpoint: CodeConsentCheckpoint,
) -> Result<()> {
    let Some(mut row) = read_code_consent_wait_in_txn(vault, txn, wait_id)? else {
        return Err(Error::EntityNotFound);
    };
    match &row.checkpoint {
        Some(sealed) if *sealed == checkpoint => return Ok(()),
        Some(_) => {
            return Err(Error::InvariantViolation(
                "a code consent wait was sealed with another step",
            ));
        }
        None => {}
    }
    row.checkpoint = Some(checkpoint);
    put_code_consent_wait_in_txn(vault, txn, &mut row)
}
