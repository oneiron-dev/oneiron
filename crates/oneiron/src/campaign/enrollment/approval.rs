//! FIX 6424 part 2a (Engine 10-20 21:0x rulings 6 and 7): the owner's
//! approve-once ask on one campaign enrollment's outbound leg.
//!
//! The leg's press pins the consequence, never the event row that carried
//! it (CALLS `FIX 6424 campaign event row versus logical event`): the logical
//! event (query, campaign, recipient entity, epoch), the program step, the
//! consequence id and its durable call sequence (the nonce), and the digest
//! of the frozen outbound body. Duplicate event rows for one consequence name
//! one digest; another step, epoch, call sequence or body is another send and
//! a new ask.
//!
//! The first approvable hold of a consequence's call is kept by
//! (consequence, call sequence), with the event row it was asked under as
//! evidence, and read on its retry (CALLS `FIX 6424 pre-ask prepared snapshot
//! retention`): a retry whose prepared target names the same digest is the
//! same ask and keeps that first event row; a changed target or body is a new
//! ask and replaces it. The kept ask is evidence only: the digest is always
//! composed from the rows themselves, so a kept row that does not read, or
//! does not write, changes no decision.

use super::detection::CampaignEnrollmentEvent;
use super::program::{CampaignProgramOutbound, CampaignProgramStep};
use crate::Vault;
use crate::attempt_queue::AttemptId;
use crate::entity_id::EntityId;
use crate::gate::{ApprovalTarget, CampaignLegFacts};
use crate::side_table::{self, Raw, SideTable};

// The leg that reads and keeps the first ask is ONE-1778 staging, used by
// nothing outside this module's tests yet (see `mod.rs`): its helpers below
// carry the same dead-code carve-out.

/// The kept ask's row layout version.
#[cfg_attr(not(test), allow(dead_code))]
const ASK_VERSION: u8 = 1;
/// Version, the 64 lower-hex digest, then the event row id.
const ASK_LEN: usize = 1 + 64 + 16;

/// (consequence id, call sequence) → the first approvable hold's ask.
#[cfg_attr(not(test), allow(dead_code))]
const FIRST_ASK: SideTable<([u8; 16], u64), [u8; ASK_LEN], Raw> =
    SideTable::new(&side_table::CAMPAIGN_ENROLLMENT_ASK);

/// The target the leg's press pins, from the persisted rows only.
pub(super) fn leg_approval_target(
    event: &CampaignEnrollmentEvent,
    step: &CampaignProgramStep,
    outbound: &CampaignProgramOutbound,
    consequence_id: AttemptId,
) -> ApprovalTarget {
    ApprovalTarget::Campaign(CampaignLegFacts {
        query_ref: event.query_ref,
        campaign_ref: event.campaign_ref,
        entity_ref: event.entity_ref,
        epoch: event.epoch,
        program_ref: step.program_ref,
        step_ref: step.step_ref,
        consequence_id: *consequence_id.as_bytes(),
        call_seq: outbound.call_seq,
        payload_digest: crate::outbound_intent_ledger::hash_frozen_payload(&outbound.payload),
    })
}

/// The ask one consequence's call was first held under.
#[cfg_attr(not(test), allow(dead_code))]
#[derive(Debug, Clone, PartialEq, Eq)]
struct FirstAsk {
    approval_digest: String,
    event_ref: EntityId,
}

#[cfg_attr(not(test), allow(dead_code))]
fn first_ask(vault: &Vault, key: &([u8; 16], u64)) -> Option<FirstAsk> {
    let txn = vault.store.env.read_txn().ok()?;
    let value = FIRST_ASK.get(&vault.store, &txn, key).ok().flatten()?;
    if value[0] != ASK_VERSION {
        return None;
    }
    let approval_digest = std::str::from_utf8(&value[1..65]).ok()?.to_owned();
    let event_ref = EntityId::from_bytes(value[65..].try_into().ok()?).ok()?;
    Some(FirstAsk {
        approval_digest,
        event_ref,
    })
}

#[cfg_attr(not(test), allow(dead_code))]
fn keep_first_ask(vault: &Vault, key: &([u8; 16], u64), ask: &FirstAsk) {
    if ask.approval_digest.len() != 64 {
        return;
    }
    let mut value = [0_u8; ASK_LEN];
    value[0] = ASK_VERSION;
    value[1..65].copy_from_slice(ask.approval_digest.as_bytes());
    value[65..].copy_from_slice(ask.event_ref.as_bytes());
    let kept = vault.with_write_txn_grouped(|wtxn| FIRST_ASK.put(&vault.store, wtxn, key, &value));
    if kept.is_err() {
        tracing::warn!(
            reason = "campaign_enrollment_ask_not_kept",
            "the first ask of a campaign enrollment's outbound call was not kept"
        );
    }
}

/// Reads the ask this consequence's call was first held under and settles
/// it against this run: `live_digest` is the digest the leg's prepared
/// target names, `held_digest` the one the Gate's hold names now (`None`
/// when it did not hold the call for a press). Returns the event row the
/// ask for `live_digest` was first made under, keeping this run's ask when
/// it is a new one.
#[cfg_attr(not(test), allow(dead_code))]
pub(super) fn settle_first_ask(
    vault: &Vault,
    consequence_id: AttemptId,
    call_seq: u64,
    live_digest: Option<&str>,
    held_digest: Option<&str>,
    event_ref: EntityId,
) -> Option<EntityId> {
    let key = (*consequence_id.as_bytes(), call_seq);
    let kept =
        first_ask(vault, &key).filter(|ask| live_digest == Some(ask.approval_digest.as_str()));
    if let Some(ask) = kept {
        return Some(ask.event_ref);
    }
    let held = held_digest?;
    keep_first_ask(
        vault,
        &key,
        &FirstAsk {
            approval_digest: held.to_owned(),
            event_ref,
        },
    );
    Some(event_ref)
}
