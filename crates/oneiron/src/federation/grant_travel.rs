//! The owner's grant travel door (OF-491, FIX 2998): which born-with text one
//! federation grant's windows carry to another vault, set once for every
//! machine of the owner's that serves the grant.
//!
//! Each choice is a signed authority action, folded across the owner's
//! machines (`authority::grant_travel`): concurrent choices meet, a later one
//! supersedes what it saw. The owner's say-so counts from any surface where
//! he is authenticated as the owner, his devices and the hosted console
//! alike (OWNER RULING 10-19 00:5x); a host's operator root alone acts as
//! nobody and never reaches this door (FIX 2222). Setting and clearing both
//! need a live grant, and each owner act writes a fresh Gate decision in the
//! same transaction. A choice that arrives by sync writes none: it is no new
//! gesture.

use crate::Vault;
use crate::authority::ActSurface;
use crate::batch::EntityMetadataHeader;
use crate::consent::AuthenticatedOwner;
use crate::entity_id::{EntityId, bytes_to_hex_lower};
use crate::error::{Error, Result, SyncProtocolValidation, SyncSelectorValidation};
use crate::registry::ENTITY_TYPE_FEDERATION_GRANT;
use crate::share_travel::{GrantTravel, TravelChoice, travelled_value};
use crate::store::{
    GATE_DECISION_LEDGER_VERSION, GateDecisionId, GateDecisionRecord, GateSystemNoticeRecord,
};

/// The Gate decision reason of an owner act that sets a choice.
pub(crate) const GRANT_TRAVEL_SET_REASON: &str = "gate.federation.grant_travel.set";
/// The Gate decision reason of an owner act that clears one.
pub(crate) const GRANT_TRAVEL_CLEAR_REASON: &str = "gate.federation.grant_travel.clear";
/// The content kind, and the receipt-detail channel, of that decision.
const GRANT_TRAVEL_CONTENT_KIND: &str = "grant_travel";
/// The context of a choice's digest on the decision.
const GRANT_TRAVEL_CHOICE_DIGEST_CONTEXT: &str = "oneiron/federation/grant-travel/choice/v1";

fn grant_err(reason: SyncSelectorValidation) -> Error {
    Error::sync_protocol(SyncProtocolValidation::Selector { reason })
}

/// The stored FederationGrant row `id` names, read with its liveness in
/// `txn`. A deleted grant is no grant, even while an unapplied delete leaves
/// its body stored.
pub(crate) fn live_federation_grant_in(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    id: &EntityId,
) -> Result<Vec<u8>> {
    let raw = vault
        .get_raw_in(txn, id)?
        .ok_or_else(|| grant_err(SyncSelectorValidation::GrantNotFound))?;
    let header = EntityMetadataHeader::parse(&raw)
        .ok_or_else(|| grant_err(SyncSelectorValidation::GrantHeader))?;
    if header.entity_type != ENTITY_TYPE_FEDERATION_GRANT {
        return Err(grant_err(SyncSelectorValidation::GrantWrongType));
    }
    if !crate::vault::live_entity_row_in_txn(&vault.store, txn, id)?.is_live() {
        return Err(grant_err(SyncSelectorValidation::GrantNotFound));
    }
    Ok(raw)
}

/// One choice's digest: the domain-separated field names, comma-joined.
fn choice_digest(choice: Option<&GrantTravel>) -> [u8; 32] {
    let fields = choice.map_or_else(String::new, |choice| {
        travelled_value(choice.travel.born_with.iter().copied())
    });
    let mut hasher = blake3::Hasher::new_derive_key(GRANT_TRAVEL_CHOICE_DIGEST_CONTEXT);
    hasher.update(fields.as_bytes());
    *hasher.finalize().as_bytes()
}

/// One owner act, as its Gate decision binds it.
struct GrantTravelAct<'a> {
    actor: EntityId,
    grant: EntityId,
    clear: bool,
    machine: EntityId,
    entry_hash: [u8; 32],
    before: Option<&'a GrantTravel>,
    after: Option<&'a GrantTravel>,
    /// The main-log heads the act observed.
    frontier: [u8; 32],
    /// The grant's revision the signed act names as seen (mesh PR1b), and
    /// where the owner said so (audit only).
    seen: [u8; 32],
    surface: ActSurface,
}

impl GrantTravelAct<'_> {
    /// A fresh decision in the act's transaction: its failure aborts the act.
    fn record_in_txn(&self, vault: &Vault, txn: &mut heed::RwTxn<'_>) -> Result<()> {
        let before = choice_digest(self.before);
        let after = choice_digest(self.after);
        let details = vec![
            format!("grant:{}", self.grant.to_hex()),
            format!("machine:{}", self.machine.to_hex()),
            format!("entry:{}", bytes_to_hex_lower(&self.entry_hash)),
            format!("before:{}", bytes_to_hex_lower(&before)),
            format!("after:{}", bytes_to_hex_lower(&after)),
            format!("seen:{}", bytes_to_hex_lower(&self.seen)),
            format!("surface:{}", surface_name(self.surface)),
        ];
        let reason = if self.clear {
            GRANT_TRAVEL_CLEAR_REASON
        } else {
            GRANT_TRAVEL_SET_REASON
        };
        let mut record = GateDecisionRecord {
            version: GATE_DECISION_LEDGER_VERSION,
            decision_id: GateDecisionId::from_bytes(vault.store.clock.ulid()?),
            created_at: crate::ports::recorded_at_in_txn(&vault.store, txn)?,
            outcome: "approved".to_owned(),
            reason_codes: vec![reason.to_owned()],
            receipt_reasons: Vec::new(),
            system_notices: GateSystemNoticeRecord::receipt_details(
                GRANT_TRAVEL_CONTENT_KIND,
                details,
            ),
            actor_class: "human".to_owned(),
            actor_ref: Some(self.actor.to_hex()),
            content_kind: GRANT_TRAVEL_CONTENT_KIND.to_owned(),
            policy_manifest_version: crate::gate::POLICY_SCHEMA_VERSION.to_owned(),
            claim_id: None,
            grant_ref: Some(self.grant.to_hex()),
            diff_handle: after.to_vec(),
            read_frontier_hash: self.frontier,
            redacted_at: None,
        };
        vault
            .store
            .append_fresh_gate_decision_in_txn(txn, &mut record)
    }
}

/// The act surface's name in a decision's details: audit only.
fn surface_name(surface: ActSurface) -> &'static str {
    match surface {
        ActSurface::ThisInstall => "this_install",
        ActSurface::LinkedDevice { .. } => "linked_device",
        ActSurface::HostedConsole => "hosted_console",
    }
}

impl Vault {
    /// The born-with text `grant`'s windows carry to another vault, read in
    /// the caller's snapshot: the fold's effective choice; `None` sends none,
    /// as does a conflicted vault root, whose fold knows no choice.
    pub(crate) fn federation_grant_travel_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        grant: &EntityId,
    ) -> Result<Option<GrantTravel>> {
        let fold = self.authority_view_readonly_in_txn(txn)?;
        if fold.vault_root_is_conflicted() {
            return Ok(None);
        }
        Ok(fold
            .signed_grant_travel(*grant)
            .and_then(|folded| folded.choice()))
    }

    /// The owner's act on `grant`'s choice in the caller's transaction: sets
    /// `travel`, or with `None` or a choice of no field clears it, and
    /// answers the effective choice after. The owner is revalidated and the
    /// grant must be live, for a clear too; this install signs the action
    /// under his act and the Gate decision lands beside it. `surface` is
    /// where he said so (audit only); `seen` is the grant's revision the
    /// deciding surface showed him (`Vault::grant_travel_revision`), and a
    /// stale one is a conflict; `None` takes the current one.
    pub(crate) fn set_federation_grant_travel_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        owner: &AuthenticatedOwner,
        surface: ActSurface,
        grant: &EntityId,
        travel: Option<TravelChoice>,
        seen: Option<[u8; 32]>,
        now: u64,
    ) -> Result<Option<GrantTravel>> {
        let actor = owner.revalidate_in_txn(self, txn)?;
        live_federation_grant_in(self, txn, grant)?;
        let choice = travel.filter(|choice| !choice.born_with.is_empty());
        let clear = choice.is_none();
        let before = self.federation_grant_travel_in_txn(txn, grant)?;
        let frontier = self
            .authority_view_readonly_in_txn(txn)?
            .append_heads_digest();
        let signed =
            self.append_grant_travel_set_in_txn(txn, actor, surface, *grant, choice, seen, now)?;
        let after = self.federation_grant_travel_in_txn(txn, grant)?;
        GrantTravelAct {
            actor,
            grant: *grant,
            clear,
            machine: signed.machine,
            entry_hash: signed.entry_hash,
            before: before.as_ref(),
            after: after.as_ref(),
            frontier,
            seen: signed.seen,
            surface,
        }
        .record_in_txn(self, txn)?;
        Ok(after)
    }
}
