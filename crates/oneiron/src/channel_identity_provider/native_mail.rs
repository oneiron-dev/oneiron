//! Native mail fulfillment adapter. MTA, JMAP, DNS and DKIM stay in the host.
mod canonical;
mod host_pass;
mod mailbox;
pub mod pack;
mod skipped;
pub(crate) use canonical::{CanonicalMailSend, approval_digest_from_frozen_payload};
pub use host_pass::NativeMailInboxPass;
pub use mailbox::PREDICATE_NATIVE_MAIL_MAILBOX;
pub use pack::{NativeMailPack, PreparedNativeMailSend};
pub use skipped::{
    NATIVE_MAIL_SET_ASIDE_AFTER_STOPS, NativeMailSkippedMessage, native_mail_skipped_messages,
};
pub(crate) use skipped::{
    clear_native_mail_stopping_message, drop_native_mail_skipped_messages_in_txn,
    native_mail_message_stops, native_mail_stopping_message, record_native_mail_skipped_message,
    record_native_mail_stopping_message,
};

use super::shared_validate::{
    normalize_domain, normalize_email_address, split_email_address,
    validate_email_inbound_metadata, validate_provision_intent,
};
use super::{
    ChannelIdentityProviderAdapter, ChannelIdentityProviderInbound,
    ChannelIdentityProviderProvision, EmailProviderInbound,
};
use crate::batch::{ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader};
use crate::channel_identity::{
    ChannelIdentity, ChannelIdentityBinding, ChannelIdentityFacts, ChannelIdentityFulfillment,
    SelfHeldShape, decode_channel_identity_body,
};
use crate::channel_identity_lifecycle::{ChannelIdentityLifecycleVerb, ProvisionIntent};
use crate::consent::{AuthenticatedOwner, ConsentReceipt};
use crate::consent_graduation::{RampScope, RampState};
use crate::gate::{
    ExternalEffectGateInput, ExternalEffectPolicyRisk, GateActor, GateProvenanceHandles,
};
use crate::outbound::{
    OutboundDispatchError, OutboundDispatchRequest, OutboundDispatchResult, OutboundExecutionSink,
};
use crate::ports::EntityStoreRead;
use crate::registry::ENTITY_TYPE_CHANNEL_IDENTITY;
use crate::store::Store;
use crate::surface_event::{
    InboundSurfaceEventInput, SurfaceCounterpartyStamp, SurfaceEventAdmission,
};
use crate::{EntityId, Error, Result, Vault};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NativeMailRunMode {
    SelfRun,
    CloudRun,
}
/// The host implementation uses its embedded Stalwart >=0.16 JMAP driver.
/// It must enforce domain isolation and Track-B key custody there; the engine
/// does not replace those controls with an SMTP client or a SaaS inbox.
pub trait NativeMailHost {
    fn provision(&self, intent: &ProvisionIntent, mode: NativeMailRunMode) -> Result<String>;
    /// Verify the signature over the ORIGINAL bytes before parsing, deduping
    /// or routing. Verification failure must not return an inbound envelope.
    fn verify_webhook(
        &self,
        body: &[u8],
        headers: &BTreeMap<String, String>,
    ) -> Result<EmailProviderInbound>;
}
/// A live cold-send offer as the owner's card shows it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ColdSendOffer {
    pub scope: RampScope,
    /// What every actor can send now, and with the standing grant accepting
    /// the offer mints (ARCH-0070 `shape:reach-line`). It informs the tap
    /// and never blocks it.
    pub reach_line: String,
}
pub struct NativeMailAdapter<H> {
    domain: String,
    mode: NativeMailRunMode,
    host: H,
}
impl<H: NativeMailHost> NativeMailAdapter<H> {
    pub fn new(domain: &str, mode: NativeMailRunMode, host: H) -> Result<Self> {
        Ok(Self {
            domain: normalize_domain(domain)?,
            mode,
            host,
        })
    }
    /// The derived `mail-<id>` mailbox: the address an identity takes when
    /// no name is chosen for it.
    pub fn address_for_identity(&self, id: EntityId) -> String {
        format!("mail-{}@{}", id.to_hex(), self.domain)
    }
    pub fn requested_identity(&self, id: EntityId, agent: EntityId, now: u64) -> ChannelIdentity {
        ChannelIdentity::requested(
            "email",
            self.address_for_identity(id),
            SelfHeldShape::DedicatedAddress,
            ChannelIdentityBinding::agent(agent),
            now,
        )
    }
    /// A requested identity at a chosen local part on the managed domain:
    /// the agent's own named work address (`eiri@`, ARCH-0063 R6). The MTA
    /// account takes the same local part at provisioning.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidConfig`] for a local part outside the engine's email
    /// grammar, or one of the derived `mail-<id>` form naming another
    /// identity.
    pub fn requested_named_identity(
        &self,
        id: EntityId,
        local_part: &str,
        agent: EntityId,
        now: u64,
    ) -> Result<ChannelIdentity> {
        let address = format!("{}@{}", local_part.trim(), self.domain);
        let local_part = mailbox_local_part(&self.domain, id, &address)?;
        Ok(ChannelIdentity::requested(
            "email",
            format!("{local_part}@{}", self.domain),
            SelfHeldShape::DedicatedAddress,
            ChannelIdentityBinding::agent(agent),
            now,
        ))
    }
    /// Whether `address` is `identity_ref`'s mailbox on the managed domain,
    /// derived or named.
    fn holds_mailbox(&self, identity_ref: EntityId, address: &str) -> bool {
        mailbox_local_part(&self.domain, identity_ref, address).is_ok()
    }
    /// Native-mail send door. The host supplies the sink; the engine owns the
    /// sender/recipient check, gate, intent ledger and receipt. No SMTP or
    /// cloud-send implementation lives here. Other email dispatch callers
    /// reach the same mail-recipient floor at the common external-effect gate.
    pub fn dispatch_send<S: OutboundExecutionSink>(
        &self,
        vault: &Vault,
        request: OutboundDispatchRequest,
        sink: &mut S,
    ) -> std::result::Result<OutboundDispatchResult, OutboundDispatchError> {
        let invalid = || Error::InvalidConfig("invalid native-mail send envelope".into());
        let identity_ref = request.channel_identity_ref.ok_or_else(invalid)?;
        let identity = native_mail_identity(vault, identity_ref)?.ok_or_else(invalid)?;
        if request.intent.channel != "email"
            || request.intent.verb != "send"
            || !self.holds_mailbox(identity_ref, &identity.facts.address_or_handle)
            || identity.facts.binding.actor_ref() != request.actor.actor_entity_ref
        {
            return Err(invalid().into());
        }
        // The common dispatch door canonicalizes and binds the recipient
        // before freezing the intent. This adapter cannot authorize a second
        // delivery path or normalize only the Gate's counterparty copy.
        vault.dispatch_outbound_intent_recorded(request, sink)
    }

    /// Owner approval for exactly one cold send. This mints no standing
    /// authority; dispatch still rechecks recipient, sender and Gate policy.
    /// A changed recipient or logical send reference gets a different digest.
    pub fn approve_send_once(
        &self,
        vault: &Vault,
        owner: &AuthenticatedOwner,
        request: &OutboundDispatchRequest,
    ) -> Result<ConsentReceipt> {
        let invalid = || Error::InvalidConfig("invalid native-mail send envelope".into());
        let identity_ref = request.channel_identity_ref.ok_or_else(invalid)?;
        let identity = native_mail_identity(vault, identity_ref)?.ok_or_else(invalid)?;
        let Some(actor) = request.actor.actor_entity_ref else {
            return Err(invalid());
        };
        if request.intent.channel != "email"
            || request.intent.verb != "send"
            || request.intent_ref.trim().is_empty()
            || !self.holds_mailbox(identity_ref, &identity.facts.address_or_handle)
            || !identity.custody.may_send()
            || identity.facts.binding.actor_ref() != Some(actor)
            || request.actor.actor_ref.as_deref() != Some(actor.to_hex().as_str())
        {
            return Err(invalid());
        }
        approve_canonical_mail_send_once(vault, owner, request, identity_ref, actor)
    }

    /// CID-5 health is a prerequisite for OFFERING cold-recipient autonomy,
    /// not a new prohibition on an owner's already granted send authority.
    /// The OF-399 ramp supplies the approval streak; the owner alone accepts
    /// the offer and mints the standing action grant.
    pub fn cold_send_graduation_offer(
        &self,
        vault: &Vault,
        identity_ref: EntityId,
    ) -> Result<Option<RampScope>> {
        let txn = vault.store.env.read_txn()?;
        let Some(identity) = native_mail_identity_in_txn(&vault.store, &txn, identity_ref)? else {
            return Ok(None);
        };
        if !self.holds_mailbox(identity_ref, &identity.facts.address_or_handle)
            || !identity.custody.may_send()
        {
            return Ok(None);
        }
        let Some(actor) = identity.facts.binding.actor_ref() else {
            return Ok(None);
        };
        if !native_mail_reputation_earned(vault, &txn, identity_ref)? {
            return Ok(None);
        }
        let scope = RampScope::new(
            "send",
            format!("recipient:cold_external:{}", identity_ref.to_hex()),
            actor.to_hex(),
        )?;
        drop(txn);
        if vault.ramp_scope_state(&scope)? == RampState::Offered {
            Ok(Some(scope))
        } else {
            Ok(None)
        }
    }

    /// [`Self::cold_send_graduation_offer`] with the reach line its
    /// acceptance carries.
    pub fn cold_send_offer_card(
        &self,
        vault: &Vault,
        identity_ref: EntityId,
    ) -> Result<Option<ColdSendOffer>> {
        let Some(scope) = self.cold_send_graduation_offer(vault, identity_ref)? else {
            return Ok(None);
        };
        let reach_line = vault.ramp_offer_reach(&scope)?.line;
        Ok(Some(ColdSendOffer { scope, reach_line }))
    }

    /// Production ingress: verified bytes -> untrusted semantic envelope ->
    /// identity quarantine gate -> durable, idempotent surface-event handoff.
    /// Mail with threading headers joins its thread and is handed to
    /// propose/confirm (INB-05, CC-the-agent).
    pub fn accept_webhook(
        &self,
        vault: &Vault,
        body: &[u8],
        headers: &BTreeMap<String, String>,
        now: u64,
    ) -> Result<SurfaceEventAdmission> {
        if body.len() > 16 * 1024 * 1024 {
            return Err(Error::InvalidConfig("mail webhook too large".into()));
        }
        let mut verified = self.host.verify_webhook(body, headers)?;
        archive_native_mail_inbound(vault, &mut verified, now)?;
        let thread = verified.thread_headers.clone();
        let input = self.parse_inbound(ChannelIdentityProviderInbound::Email(verified))?;
        vault.enqueue_inbound_email(input, thread.as_ref(), now)
    }
}
/// Keeps one native mail inbound in the vault as its provider event
/// ([`Vault::archive_provider_event`]): the inbound as it arrived, its
/// threading headers, subject, text body and quarantine reference included.
/// Its `payload_ref` becomes the archive's, so a reply to the message reads
/// the headers it threads on back through the answered event.
pub(crate) fn archive_native_mail_inbound(
    vault: &Vault,
    inbound: &mut EmailProviderInbound,
    now: u64,
) -> Result<()> {
    let body = serde_json::to_vec(&*inbound)
        .map_err(|_| Error::InvalidConfig("native mail inbound did not encode".into()))?;
    inbound.payload_ref = Some(vault.archive_provider_event(
        super::EMAIL_CHANNEL,
        &inbound.provider_event_id,
        &body,
        now,
    )?);
    Ok(())
}
impl<H: NativeMailHost> ChannelIdentityProviderAdapter for NativeMailAdapter<H> {
    fn provider_key(&self) -> &'static str {
        "native_mail"
    }
    fn fulfillment_mode(
        &self,
        verb: ChannelIdentityLifecycleVerb,
    ) -> Option<ChannelIdentityFulfillment> {
        match verb {
            ChannelIdentityLifecycleVerb::Provision => Some(ChannelIdentityFulfillment::Api),
            _ => None,
        }
    }
    fn provision(
        &self,
        intent: &ProvisionIntent,
        fulfilled_at: u64,
    ) -> Result<ChannelIdentityProviderProvision> {
        // The identity's own address, derived or named, is the mailbox.
        let address = intent.identity.address_or_handle().to_owned();
        mailbox_local_part(&self.domain, intent.identity_id, &address)?;
        validate_provision_intent(intent, "email", &address, ChannelIdentityFulfillment::Api)?;
        let provider_identity_ref = self.host.provision(intent, self.mode)?;
        if provider_identity_ref.is_empty() || provider_identity_ref.len() > 512 {
            return Err(Error::InvalidConfig(
                "invalid native mailbox receipt".into(),
            ));
        }
        Ok(ChannelIdentityProviderProvision {
            provider_key: self.provider_key().into(),
            identity_id: intent.identity_id,
            channel: "email".into(),
            address_or_handle: address,
            fulfillment_mode: ChannelIdentityFulfillment::Api,
            provider_identity_ref,
            fulfilled_at,
        })
    }
    /// Semantic adapter entry point for an already-authenticated host event.
    /// HTTP callers must use accept_webhook, not construct trusted envelopes.
    fn parse_inbound(
        &self,
        input: ChannelIdentityProviderInbound,
    ) -> Result<InboundSurfaceEventInput> {
        let ChannelIdentityProviderInbound::Email(mail) = input else {
            return Err(Error::InvalidConfig(
                "native mail requires an email envelope".into(),
            ));
        };
        validate_email_inbound_metadata(&mail)?;
        // Any mailbox on the managed domain reaches routing: a derived or
        // named address, or an alias (ARCH-0063 R6). Routing finds the
        // identity that holds it and rejects one nobody holds.
        let (local, domain) = split_email_address(&mail.envelope_to)?;
        if domain != self.domain {
            return Err(Error::InvalidConfig(
                "mail recipient outside managed domain".into(),
            ));
        }
        let sender = split_email_address(&mail.envelope_from)
            .and_then(|(_, domain)| normalize_email_address(&mail.envelope_from, &domain));
        let counterparty = match sender {
            Ok(sender) => SurfaceCounterpartyStamp::unknown(format!("email:{sender}")),
            Err(_) => SurfaceCounterpartyStamp::unparsed(
                "email",
                Sha256::digest(mail.envelope_from.as_bytes()).into(),
            ),
        };
        let mut event = InboundSurfaceEventInput::new(
            mail.provider_event_id,
            "email",
            format!("{local}@{domain}"),
            counterparty,
            mail.received_at,
            true,
        );
        event.payload_ref = mail.payload_ref;
        Ok(event)
    }
}

/// Owner approval for exactly one canonical mail send: the shared tail of the
/// native-mail and member-mailbox (OF-374) approve doors. Each door checks its
/// own sender shape first; this composes the one digest the Gate's mail lane
/// looks up, so the owner approves the exact operation dispatch re-evaluates.
/// A changed recipient, content or logical send ref is a different digest.
pub(crate) fn approve_canonical_mail_send_once(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    request: &OutboundDispatchRequest,
    identity_ref: EntityId,
    actor: EntityId,
) -> Result<ConsentReceipt> {
    let digest = canonical_mail_send_digest(request, identity_ref, actor)?;
    vault.approve_once(owner, digest)
}

/// The canonical mail operation's approve-once digest for one checked send
/// envelope: the key both owner doors mint and the Gate's mail lane reads.
pub(crate) fn canonical_mail_send_digest(
    request: &OutboundDispatchRequest,
    identity_ref: EntityId,
    actor: EntityId,
) -> Result<crate::consent::EffectDigest> {
    let invalid = || Error::InvalidConfig("invalid mail send envelope".into());
    let canonical = CanonicalMailSend::from_request(request)?;
    let effect = ExternalEffectGateInput {
        actor: GateActor {
            actor_class: request.actor.actor_class.clone(),
            actor_ref: request.actor.actor_ref.clone(),
            delegation_grant_ref: None,
        },
        provenance: GateProvenanceHandles {
            actor_entity_ref: Some(actor),
            mail_content_ref: request.intent.content_ref.clone(),
            ..GateProvenanceHandles::default()
        },
        verb: "send".into(),
        channel: "email".into(),
        channel_identity_ref: Some(identity_ref),
        counterparty: Some(canonical.recipient),
        brief_ref: canonical.brief_ref,
        send_ref: Some(request.intent_ref.clone()),
        standing_grant_ref: None,
        scoped_mcp_call: None,
        counterparty_first_touch: None,
        counterparty_opted_out: false,
        counterparty_opt_out_receipt_reason: None,
        has_opted_in: request.gate.has_opted_in,
        has_permission: request.gate.has_permission,
        policy_risk: ExternalEffectPolicyRisk::HoldToProposal,
        send_autonomy: None,
    };
    crate::gate::native_mail_cold_approval_digest(&effect).ok_or_else(invalid)
}

/// Canonical recipient used by both the Gate and the frozen transport intent.
/// Kept in the pack so every path uses the same strict address parser.
pub(crate) fn canonical_recipient(address: &str) -> Result<String> {
    let (_, domain) = split_email_address(address)?;
    normalize_email_address(address, &domain)
}

/// The local part of a native mailbox address on `domain`, which names its
/// MTA account. A local part of the derived `mail-<id>` form must name
/// `identity_ref` itself, so no identity takes another's derived mailbox.
pub(super) fn mailbox_local_part(
    domain: &str,
    identity_ref: EntityId,
    address: &str,
) -> Result<String> {
    let (local, address_domain) = split_email_address(address)?;
    if address_domain != domain {
        return Err(Error::InvalidConfig(
            "native mailbox outside managed domain".into(),
        ));
    }
    if let Some(hex) = local.strip_prefix("mail-")
        && hex.len() == 32
        && hex.bytes().all(|byte| byte.is_ascii_hexdigit())
        && hex != identity_ref.to_hex()
    {
        return Err(Error::InvalidConfig(
            "native mailbox names another identity".into(),
        ));
    }
    Ok(local)
}

/// The recipient posture is only for active native-mail identities. Plain
/// `email` connectors keep their pre-existing gate semantics; an explicit
/// native-mail dispatch cannot evade this test because its send door requires
/// the same active, identity-shaped sender.
pub(crate) fn is_native_mail_sender_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    identity_ref: EntityId,
) -> Result<bool> {
    Ok(native_mail_identity_in_txn(store, txn, identity_ref)?
        .is_some_and(|identity| identity.custody.may_send()))
}

/// The Gate requires a live identity belonging to its authenticated actor,
/// not just an active mailbox named in a caller's explicit sender slot.
pub(crate) fn native_mail_actor_may_send_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    identity_ref: EntityId,
    actor: Option<EntityId>,
) -> Result<bool> {
    Ok(
        native_mail_identity_in_txn(store, txn, identity_ref)?.is_some_and(|identity| {
            identity.custody.may_send() && identity.facts.binding.actor_ref() == actor
        }),
    )
}

/// Structural sender binding survives Released/Quarantine for terminal replay,
/// but never permits another effect without a fresh may_send check.
pub(crate) fn is_native_mail_identity_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    identity_ref: EntityId,
) -> Result<bool> {
    Ok(native_mail_identity_in_txn(store, txn, identity_ref)?.is_some())
}

/// A native-mail identity: its facts (channel, address, binding) from its
/// `channel_identity.*` heads, its custody (`may_send`) from the local row.
struct NativeMailIdentity {
    facts: ChannelIdentityFacts,
    custody: ChannelIdentity,
}

/// [`native_mail_identity_in_txn`] on a fresh snapshot, for the send doors.
fn native_mail_identity(
    vault: &Vault,
    identity_ref: EntityId,
) -> Result<Option<NativeMailIdentity>> {
    let txn = vault.store.env.read_txn()?;
    native_mail_identity_in_txn(&vault.store, &txn, identity_ref)
}

fn native_mail_identity_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    identity_ref: EntityId,
) -> Result<Option<NativeMailIdentity>> {
    // Recognition reads the identity's channel and address heads (OF-272);
    // the row is read for its custody only.
    let Some(facts) =
        crate::channel_identity::channel_identity_facts_in_txn(store, txn, &identity_ref)?
    else {
        return Ok(None);
    };
    // A derived `mail-<id>` address names its own identity; a named one is a
    // native mailbox once the pack recorded the MTA holding it.
    if facts.channel != "email" {
        return Ok(None);
    }
    let derived = facts
        .address_or_handle
        .starts_with(&format!("mail-{}@", identity_ref.to_hex()));
    if !derived
        && !mailbox::native_mailbox_recorded_in_txn(
            store,
            txn,
            identity_ref,
            &facts.address_or_handle,
        )?
    {
        return Ok(None);
    }
    let Some(raw) = store
        .port_entity_record(txn, &identity_ref)?
        .map(|row| row.encode())
    else {
        return Ok(None);
    };
    let header = EntityMetadataHeader::parse(&raw)
        .ok_or(Error::CorruptedIndex("native-mail identity entity header"))?;
    if header.entity_type != ENTITY_TYPE_CHANNEL_IDENTITY {
        return Ok(None);
    }
    let custody = decode_channel_identity_body(&raw[ENTITY_METADATA_HEADER_LEN..])?;
    Ok(Some(NativeMailIdentity { facts, custody }))
}

/// Called only by the external-effect Gate on its own transaction. The
/// graduation grant is both DEC-0006 consent and outbound authority, but
/// only for the exact actor × native-mail identity × cold-recipient class.
/// Missing or malformed identity/grant rows cannot authorize an effect.
pub(crate) fn native_mail_cold_send_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    effect: &ExternalEffectGateInput,
    policy: &crate::gate::PolicyManifestResolution,
) -> Result<bool> {
    if effect.channel != "email"
        || effect.verb != "send"
        || effect.counterparty.as_deref().is_none_or(str::is_empty)
    {
        return Ok(false);
    }
    let Some(identity_ref) = effect.channel_identity_ref else {
        return Ok(false);
    };
    let Some(actor) = effect.provenance.actor_entity_ref else {
        return Ok(false);
    };
    if effect.actor.actor_ref.as_deref() != Some(actor.to_hex().as_str()) {
        return Ok(false);
    }
    let Some(identity) = native_mail_identity_in_txn(store, txn, identity_ref)? else {
        return Ok(false);
    };
    if identity.facts.binding.actor_ref() != Some(actor) || !identity.custody.may_send() {
        return Ok(false);
    }
    Ok(policy
        .native_mail_policy_for(Some(actor), Some(identity_ref))
        .is_some_and(|row| !row.is_known(effect.counterparty_first_touch)))
}

/// A cold send may borrow the graduated owner grant only after the current
/// counterparty and sender were classified on this Gate transaction.
pub(crate) fn mail_graduated_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    effect: &ExternalEffectGateInput,
    policy: &crate::gate::PolicyManifestResolution,
) -> Result<bool> {
    if !native_mail_cold_send_in_txn(store, txn, effect, policy)? {
        return Ok(false);
    }
    let (Some(identity_ref), Some(actor)) = (
        effect.channel_identity_ref,
        effect.provenance.actor_entity_ref,
    ) else {
        return Ok(false);
    };
    let scope = RampScope::new(
        "send",
        format!("recipient:cold_external:{}", identity_ref.to_hex()),
        actor.to_hex(),
    )?;
    crate::consent::standing_grant_is_active_in_txn(store, txn, &scope.grant_ref()?)
}

/// Only current, observed CID-5 evidence earns a ramp offer. Missing or
/// conflicting heads do not prove a healthy established sender. A weak sender
/// may still receive explicit owner authority through the ordinary gate.
pub(crate) fn native_mail_reputation_earned(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    identity_ref: EntityId,
) -> Result<bool> {
    use crate::claim::{ClaimApprovalStatus, ClaimLifecycleStatus, ClaimSource};
    use crate::identity_reputation::{
        PREDICATE_IDENTITY_REPUTATION_ATTESTATION_TIER, PREDICATE_IDENTITY_REPUTATION_BOUNCE_RATE,
        PREDICATE_IDENTITY_REPUTATION_COMPLAINT_RATE,
        PREDICATE_IDENTITY_REPUTATION_SPAM_LABEL_OBSERVATIONS,
        PREDICATE_IDENTITY_REPUTATION_WARMUP_STAGE,
    };
    use crate::ports::TombstoneStore;
    let Some(identity) = native_mail_identity_in_txn(&vault.store, txn, identity_ref)? else {
        return Ok(false);
    };
    let policy = crate::gate::resolve_policy_manifest(&vault.store, txn)?;
    let Some(row) =
        policy.native_mail_policy_for(identity.facts.binding.actor_ref(), Some(identity_ref))
    else {
        return Ok(false);
    };
    let mut seen = [false; 5];
    for id in vault.claims_for_subject_in_txn(txn, &identity_ref)? {
        let Some(claim) = vault.get_claim_in_txn(txn, &id)? else {
            continue;
        };
        if claim.lifecycle != ClaimLifecycleStatus::Active
            || claim.stale
            || crate::ports::stale_in_txn(&vault.store, txn, &id)?
            || vault.port_tombstone_is_deleted(txn, &id)?
            || !matches!(
                claim.approval,
                ClaimApprovalStatus::Auto | ClaimApprovalStatus::Approved
            )
            || claim.source != Some(ClaimSource::Observed)
        {
            continue;
        }
        let index = match claim.predicate.as_str() {
            PREDICATE_IDENTITY_REPUTATION_WARMUP_STAGE => 0,
            PREDICATE_IDENTITY_REPUTATION_COMPLAINT_RATE => 1,
            PREDICATE_IDENTITY_REPUTATION_BOUNCE_RATE => 2,
            PREDICATE_IDENTITY_REPUTATION_SPAM_LABEL_OBSERVATIONS => 3,
            PREDICATE_IDENTITY_REPUTATION_ATTESTATION_TIER => 4,
            _ => continue,
        };
        crate::identity_reputation::validate_identity_reputation_claim_structure(&claim)?;
        let safe = match index {
            0 => claim
                .value
                .as_str()
                .is_some_and(|stage| row.warmup_earns(stage)),
            1 => claim
                .value
                .as_f64()
                .is_some_and(|n| n < row.max_complaint_rate),
            2 => claim
                .value
                .as_f64()
                .is_some_and(|n| n < row.max_bounce_rate),
            3 => claim
                .value
                .as_u64()
                .is_some_and(|n| n <= row.max_spam_labels),
            4 => claim
                .value
                .as_str()
                .is_some_and(|tier| row.attestation_earns(tier)),
            _ => unreachable!(),
        };
        if !safe {
            return Ok(false);
        }
        // An unsafe value vetoes held or not; held evidence never earns.
        if crate::gate::claim_critical_confirm_settled_in_txn(&vault.store, txn, &id)? {
            seen[index] = true;
        }
    }
    Ok(seen.into_iter().all(|present| present))
}

#[cfg(test)]
#[path = "native_mail/tests.rs"]
mod tests;
