//! Gmail/Workspace read-side adapter for `delegated_grant` rows (INB-00).
//!
//! This adapter binds a member's own mailbox — one the product never minted and
//! never owns — to a ChannelIdentity of the fourth shape. Everything downstream
//! is the machinery that already exists: [`parse_inbound`] hands the engine an
//! ordinary [`InboundSurfaceEventInput`] on the `email` channel, so routing,
//! receipts, health claims, and manifests never learn that this row is
//! delegated.
//!
//! Three things are structural here rather than configured:
//!
//! * **Scoped-read only.** [`GmailReadWire`] has no send, reply, delete, or
//!   modify method, and [`delegated_scope_for_google_oauth_scope`] maps only the
//!   two read scopes. A caller cannot widen this by passing a different string;
//!   there is no variant for a write scope to land in.
//! * **No credential in a signature.** The wire is handed a `secret_ref`
//!   (a custody record NAME) and resolves the value at its own egress door,
//!   exactly as [`crate::calendar::google_internal::GoogleInternalWire`] does.
//!   In-crate, [`GmailDelegatedAdapter::with_delegated_token_at_door`] is the
//!   only path to the bytes, and it is SECRET-02's T0 door under the
//!   `connector:gmail` effector binding.
//! * **No new dependency.** The protocol lives behind the wire trait, so the
//!   dependency graph and lockfile are untouched (the calendar precedent).
//!
//! Rotation is absent by construction: the member's provider owns revoking and
//! re-issuing this grant, and the lifecycle layer denies `rotate` on the shape.

use serde::{Deserialize, Serialize};

use super::{
    ChannelIdentityProviderAdapter, ChannelIdentityProviderInbound,
    ChannelIdentityProviderProvision, EMAIL_CHANNEL, EmailProviderInbound, normalize_email_address,
    split_email_address, validate_email_inbound_metadata, validate_max_bytes, validate_non_blank,
};
use crate::Vault;
use crate::attempt_queue::{AttemptQueue, EnqueueAttempt, EnqueueOutcome};
use crate::channel_identity::{
    ChannelIdentity, ChannelIdentityBinding, ChannelIdentityFulfillment, ChannelIdentityShape,
    DelegatedGrant, DelegatedGrantScope,
};
use crate::channel_identity_lifecycle::{ChannelIdentityLifecycleVerb, ProvisionIntent};
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::secret_custody::{SECRET_SCOPE_READ, SecretCustodyStatus};
use crate::secret_lease::DoorInjectionReceipt;
use crate::surface_event::{InboundSurfaceEventInput, SurfaceCounterpartyStamp};

/// Stable key for the Gmail/Workspace delegated-grant adapter.
pub const GMAIL_DELEGATED_PROVIDER_KEY: &str = "gmail_delegated";

/// Effector name the delegated grant's custody binding must cover.
pub const GMAIL_CONNECTOR_EFFECTOR: &str = "connector:gmail";

/// Durable attempt kind minted by the scheduled Gmail inbox poller.
pub const GMAIL_INBOX_POLL_ATTEMPT_KIND: &str = "gmail_inbox_poll";

/// Google OAuth scope granting read of message bodies.
pub const GMAIL_READONLY_OAUTH_SCOPE: &str = "https://www.googleapis.com/auth/gmail.readonly";

/// Google OAuth scope granting read of message headers/metadata only.
pub const GMAIL_METADATA_OAUTH_SCOPE: &str = "https://www.googleapis.com/auth/gmail.metadata";

const GMAIL_INBOX_POLL_DEDUPE_PREFIX: &str = "gmail:inbox_poll:v1:";
const GMAIL_EVENT_ID_PREFIX: &str = "gmail:";
const GMAIL_THREAD_PAYLOAD_PREFIX: &str = "gmail:thread:";
const MAX_GMAIL_ID_BYTES: usize = 128;
const MAX_GMAIL_CURSOR_BYTES: usize = 256;
const MAX_GMAIL_MESSAGES_PER_PAGE: usize = 500;

/// Maps a Google OAuth scope URL onto the read scope class it grants.
///
/// Returns `None` for every write scope Google offers (`gmail.send`,
/// `gmail.modify`, `gmail.compose`, `mail.google.com`, ...). This is the only
/// entry point from provider scope strings, so an over-broad consent screen
/// fails closed here instead of quietly minting a row that claims send.
#[must_use]
pub fn delegated_scope_for_google_oauth_scope(scope_url: &str) -> Option<DelegatedGrantScope> {
    match scope_url.trim() {
        GMAIL_READONLY_OAUTH_SCOPE => Some(DelegatedGrantScope::MailRead),
        GMAIL_METADATA_OAUTH_SCOPE => Some(DelegatedGrantScope::MailMetadata),
        _ => None,
    }
}

/// One Gmail message projected down to what routing needs.
///
/// Deliberately header-shaped: the adapter never carries body text into the
/// engine, only the identifiers and envelope needed to route and to point back
/// at the provider-held message.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GmailMessageMetadata {
    pub message_id: String,
    pub thread_id: String,
    pub to: String,
    pub from: String,
    pub internal_date_secs: u64,
}

impl GmailMessageMetadata {
    /// Builds a Gmail message projection.
    #[must_use]
    pub fn new(
        message_id: impl Into<String>,
        thread_id: impl Into<String>,
        to: impl Into<String>,
        from: impl Into<String>,
        internal_date_secs: u64,
    ) -> Self {
        Self {
            message_id: message_id.into(),
            thread_id: thread_id.into(),
            to: to.into(),
            from: from.into(),
            internal_date_secs,
        }
    }

    /// Normalizes Gmail-native fields into the shared email inbound payload.
    ///
    /// Gmail's message id becomes the provider event id and its thread id the
    /// payload ref, so the delegated path reaches routing in exactly the same
    /// envelope a dedicated ESP webhook does.
    pub fn into_provider_inbound(self) -> Result<EmailProviderInbound> {
        validate_gmail_id(&self.message_id, "gmail message id")?;
        validate_gmail_id(&self.thread_id, "gmail thread id")?;
        let message_id = self.message_id;
        let thread_id = self.thread_id;
        Ok(EmailProviderInbound::new(
            format!("{GMAIL_EVENT_ID_PREFIX}{message_id}"),
            self.to,
            self.from,
            self.internal_date_secs,
        )
        .with_payload_ref(format!("{GMAIL_THREAD_PAYLOAD_PREFIX}{thread_id}")))
    }
}

/// One page of read-side Gmail results.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GmailInboxPage {
    pub messages: Vec<GmailMessageMetadata>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub next_cursor: Option<String>,
}

impl GmailInboxPage {
    /// Builds a page of Gmail read results.
    #[must_use]
    pub const fn new(messages: Vec<GmailMessageMetadata>, next_cursor: Option<String>) -> Self {
        Self {
            messages,
            next_cursor,
        }
    }

    fn validate(&self) -> Result<()> {
        if self.messages.len() > MAX_GMAIL_MESSAGES_PER_PAGE {
            return Err(Error::InvalidConfig(format!(
                "gmail inbox page exceeds {MAX_GMAIL_MESSAGES_PER_PAGE} messages"
            )));
        }
        if let Some(cursor) = &self.next_cursor {
            validate_non_blank(cursor, "gmail page cursor must be non-empty")?;
            validate_max_bytes(
                cursor,
                MAX_GMAIL_CURSOR_BYTES,
                "gmail page cursor exceeds maximum length",
            )?;
        }
        Ok(())
    }
}

/// The Gmail read protocol seam.
///
/// Implementations own the REST calls, pagination, and the OAuth refresh, and
/// resolve `secret_ref` at their own egress door. No credential crosses these
/// signatures, and there is exactly one method: reading. A send or delete verb
/// would have to be added here to exist, which is the point.
pub trait GmailReadWire {
    /// Reads one page of the granted mailbox after `cursor`.
    ///
    /// # Errors
    ///
    /// Provider and custody failures surface as [`Error`]; the adapter adds no
    /// interpretation beyond page-shape validation.
    fn fetch_inbox_page(
        &self,
        secret_ref: &str,
        mailbox_address: &str,
        cursor: Option<&str>,
    ) -> Result<GmailInboxPage>;
}

/// Binding config for one member-held Gmail/Workspace mailbox.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GmailDelegatedAdapterConfig {
    mailbox_address: String,
    mailbox_domain: String,
    custody_record_ref: String,
    scopes: Vec<DelegatedGrantScope>,
}

impl GmailDelegatedAdapterConfig {
    /// Binds a mailbox address to an already-granted custody record name.
    ///
    /// `custody_record_ref` is a name, never a token. Defaults to read of
    /// message bodies; narrow it with [`Self::with_google_oauth_scopes`].
    pub fn new(
        mailbox_address: impl Into<String>,
        custody_record_ref: impl Into<String>,
    ) -> Result<Self> {
        let custody_record_ref = custody_record_ref.into();
        validate_non_blank(
            &custody_record_ref,
            "gmail delegated grant custody record ref must be non-empty",
        )?;
        let (local_part, mailbox_domain) = split_email_address(&mailbox_address.into())?;
        Ok(Self {
            mailbox_address: format!("{local_part}@{mailbox_domain}"),
            mailbox_domain,
            custody_record_ref,
            scopes: vec![DelegatedGrantScope::MailRead],
        })
    }

    /// Replaces the grant scopes from the Google OAuth scope URLs consented to.
    ///
    /// Any scope outside the two read scopes fails the call: an over-broad
    /// grant is refused rather than silently narrowed, so the row never claims
    /// less than the token can actually do.
    pub fn with_google_oauth_scopes(mut self, scope_urls: &[&str]) -> Result<Self> {
        let mut scopes = Vec::with_capacity(scope_urls.len());
        for scope_url in scope_urls {
            let scope = delegated_scope_for_google_oauth_scope(scope_url).ok_or_else(|| {
                Error::InvalidConfig(format!(
                    "gmail delegated grant admits read scopes only, not {scope_url}"
                ))
            })?;
            if !scopes.contains(&scope) {
                scopes.push(scope);
            }
        }
        if scopes.is_empty() {
            return Err(Error::InvalidConfig(
                "gmail delegated grant requires at least one read scope".to_owned(),
            ));
        }
        self.scopes = scopes;
        Ok(self)
    }

    /// The normalized mailbox address this adapter reads.
    #[must_use]
    pub fn mailbox_address(&self) -> &str {
        &self.mailbox_address
    }

    /// The custody record name holding the OAuth grant.
    #[must_use]
    pub fn custody_record_ref(&self) -> &str {
        &self.custody_record_ref
    }

    /// The read scopes the grant covers.
    #[must_use]
    pub fn scopes(&self) -> &[DelegatedGrantScope] {
        &self.scopes
    }
}

/// Read-side Gmail/Workspace adapter over a member-held mailbox.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GmailDelegatedAdapter {
    config: GmailDelegatedAdapterConfig,
}

impl GmailDelegatedAdapter {
    /// Binds the adapter to one mailbox and its custody record.
    #[must_use]
    pub const fn new(config: GmailDelegatedAdapterConfig) -> Self {
        Self { config }
    }

    /// The binding config.
    #[must_use]
    pub const fn config(&self) -> &GmailDelegatedAdapterConfig {
        &self.config
    }

    /// The delegated grant handle this adapter stamps onto its identity rows.
    #[must_use]
    pub fn delegated_grant(&self) -> DelegatedGrant {
        DelegatedGrant::new(
            self.config.custody_record_ref.clone(),
            self.config.scopes.clone(),
        )
    }

    /// Proves the OAuth grant is already in custody with a covering binding.
    ///
    /// Provisioning a delegated row asserts we can read the member's mailbox.
    /// Checking the custody record here means that assertion is backed before
    /// the row exists, rather than discovered at the first poll. The value is
    /// never read: this is a metadata projection with no value field.
    pub fn assert_custody_grant(&self, vault: &Vault) -> Result<()> {
        let secret_ref = self.config.custody_record_ref.as_str();
        let id = vault
            .resolve_secret_ref(secret_ref)?
            .ok_or_else(|| Error::SecretRefNotFound {
                name: secret_ref.to_owned(),
            })?;
        let metadata = vault
            .get_secret_metadata(&id)?
            .ok_or_else(|| Error::SecretRefNotFound {
                name: secret_ref.to_owned(),
            })?;
        if metadata.status != SecretCustodyStatus::Active {
            return Err(Error::SecretCustodyNotActive {
                name: metadata.name,
            });
        }
        let covered = metadata.bindings.iter().any(|binding| {
            binding.effector == GMAIL_CONNECTOR_EFFECTOR
                && binding
                    .scopes
                    .iter()
                    .any(|scope| scope == SECRET_SCOPE_READ)
        });
        if covered {
            Ok(())
        } else {
            Err(Error::SecretBindingDenied {
                effector: GMAIL_CONNECTOR_EFFECTOR.to_owned(),
                secret_ref: secret_ref.to_owned(),
            })
        }
    }

    /// Builds the requested delegated row for this mailbox.
    ///
    /// Fails closed when the grant is not already in custody under a
    /// `connector:gmail` read binding.
    pub fn requested_identity(
        &self,
        vault: &Vault,
        agent_ref: EntityId,
        requested_at: u64,
    ) -> Result<ChannelIdentity> {
        self.assert_custody_grant(vault)?;
        let identity = ChannelIdentity::requested_delegated(
            EMAIL_CHANNEL,
            self.config.mailbox_address.clone(),
            ChannelIdentityBinding::agent(agent_ref),
            self.delegated_grant(),
            requested_at,
        );
        identity.validate()?;
        Ok(identity)
    }

    /// Runs `apply` with the grant's token injected at the SECRET-02 T0 door.
    ///
    /// The only in-crate path to the bytes. `apply` cannot return them, the
    /// receipt carries none, and the effector is pinned to
    /// [`GMAIL_CONNECTOR_EFFECTOR`] so an unbound record denies.
    pub fn with_delegated_token_at_door(
        &self,
        vault: &Vault,
        apply: &mut dyn FnMut(&[u8]) -> Result<()>,
    ) -> Result<DoorInjectionReceipt> {
        vault.inject_secret_at_door(
            &self.config.custody_record_ref,
            GMAIL_CONNECTOR_EFFECTOR,
            apply,
        )
    }

    /// Reads one page of the granted mailbox through the host wire.
    ///
    /// The wire receives the custody NAME, not the value.
    pub fn fetch_inbox_page<W: GmailReadWire + ?Sized>(
        &self,
        wire: &W,
        cursor: Option<&str>,
    ) -> Result<GmailInboxPage> {
        let page = wire.fetch_inbox_page(
            &self.config.custody_record_ref,
            &self.config.mailbox_address,
            cursor,
        )?;
        page.validate()?;
        Ok(page)
    }

    /// Enqueues one scheduled inbox poll for this delegated mailbox.
    ///
    /// The payload carries the custody NAME and the identity ref only; the
    /// dedupe key is per identity, so re-arming a live poll is a no-op.
    pub fn enqueue_inbox_poll(
        &self,
        vault: &Vault,
        identity_id: EntityId,
        now: u64,
    ) -> Result<EnqueueOutcome> {
        let config = GmailInboxPollConfig {
            mailbox_address: self.config.mailbox_address.clone(),
            custody_record_ref: self.config.custody_record_ref.clone(),
            identity_ref: identity_id.to_hex(),
        };
        let payload = serde_json::to_vec(&config).map_err(|err| {
            Error::InvalidConfig(format!("gmail inbox poll config did not encode: {err}"))
        })?;
        AttemptQueue::new(vault).enqueue(EnqueueAttempt {
            kind: GMAIL_INBOX_POLL_ATTEMPT_KIND.to_owned(),
            payload,
            dedupe_key: Some(gmail_inbox_poll_dedupe_key(identity_id)),
            run_id: None,
            now,
        })
    }
}

/// Durable payload of a `gmail_inbox_poll` attempt.
///
/// Names only: the mailbox, the custody record, and the identity row. No token
/// bytes reach the queue.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GmailInboxPollConfig {
    pub mailbox_address: String,
    pub custody_record_ref: String,
    pub identity_ref: String,
}

/// Stable dedupe key for one delegated mailbox's scheduled poll.
#[must_use]
pub fn gmail_inbox_poll_dedupe_key(identity_id: EntityId) -> String {
    format!("{GMAIL_INBOX_POLL_DEDUPE_PREFIX}{}", identity_id.to_hex())
}

impl ChannelIdentityProviderAdapter for GmailDelegatedAdapter {
    fn provider_key(&self) -> &'static str {
        GMAIL_DELEGATED_PROVIDER_KEY
    }

    fn fulfillment_mode(
        &self,
        verb: ChannelIdentityLifecycleVerb,
    ) -> Option<ChannelIdentityFulfillment> {
        match verb {
            // The grant already exists when the row is provisioned, so
            // fulfillment is a programmatic confirmation. Rotate is absent
            // here as well as at the lifecycle gate: this adapter has no
            // re-minting surface to offer.
            ChannelIdentityLifecycleVerb::Provision => Some(ChannelIdentityFulfillment::Api),
            ChannelIdentityLifecycleVerb::Bind
            | ChannelIdentityLifecycleVerb::Rotate
            | ChannelIdentityLifecycleVerb::Release
            | ChannelIdentityLifecycleVerb::RouteInbound => None,
        }
    }

    fn provision(
        &self,
        intent: &ProvisionIntent,
        fulfilled_at: u64,
    ) -> Result<ChannelIdentityProviderProvision> {
        self.validate_provision_intent(intent)?;
        Ok(ChannelIdentityProviderProvision {
            provider_key: self.provider_key().to_owned(),
            identity_id: intent.identity_id,
            channel: EMAIL_CHANNEL.to_owned(),
            address_or_handle: self.config.mailbox_address.clone(),
            fulfillment_mode: ChannelIdentityFulfillment::Api,
            provider_identity_ref: format!("gmail:{}", intent.identity_id.to_hex()),
            fulfilled_at,
        })
    }

    fn parse_inbound(
        &self,
        inbound: ChannelIdentityProviderInbound,
    ) -> Result<InboundSurfaceEventInput> {
        let ChannelIdentityProviderInbound::Email(email) = inbound else {
            return Err(Error::InvalidConfig(
                "gmail delegated adapter rejects non-email inbound".to_owned(),
            ));
        };
        validate_email_inbound_metadata(&email)?;
        let normalized_to = normalize_email_address(
            &email.envelope_to,
            &self.config.mailbox_domain,
        )
        .map_err(|_| {
            Error::InvalidConfig("gmail inbound envelope-to is not the granted mailbox".to_owned())
        })?;
        if normalized_to != self.config.mailbox_address {
            return Err(Error::InvalidConfig(
                "gmail inbound envelope-to is not the granted mailbox".to_owned(),
            ));
        }
        let (_, sender_domain) = split_email_address(&email.envelope_from)?;
        let normalized_from = normalize_email_address(&email.envelope_from, &sender_domain)?;

        let mut input = InboundSurfaceEventInput::new(
            email.provider_event_id,
            EMAIL_CHANNEL,
            normalized_to,
            SurfaceCounterpartyStamp::unknown(format!("email:{normalized_from}")),
            email.received_at,
            true,
        );
        input.payload_ref = email.payload_ref;
        Ok(input)
    }
}

impl GmailDelegatedAdapter {
    fn validate_provision_intent(&self, intent: &ProvisionIntent) -> Result<()> {
        if intent.fulfillment_mode != ChannelIdentityFulfillment::Api {
            return Err(Error::InvalidConfig(
                "gmail delegated adapter requires api fulfillment".to_owned(),
            ));
        }
        if intent.identity.channel != EMAIL_CHANNEL {
            return Err(Error::InvalidConfig(
                "gmail delegated adapter channel does not match ProvisionIntent".to_owned(),
            ));
        }
        if intent.identity.shape != ChannelIdentityShape::DelegatedGrant {
            return Err(Error::InvalidConfig(
                "gmail delegated adapter requires delegated_grant identities".to_owned(),
            ));
        }
        if intent.identity.address_or_handle != self.config.mailbox_address {
            return Err(Error::InvalidConfig(
                "gmail delegated adapter address does not match the granted mailbox".to_owned(),
            ));
        }
        if !matches!(
            intent.identity.binding,
            ChannelIdentityBinding::Agent { .. }
        ) {
            return Err(Error::InvalidConfig(
                "gmail delegated adapter requires agent-scoped identities".to_owned(),
            ));
        }
        if intent.identity.delegated_grant.as_ref() != Some(&self.delegated_grant()) {
            return Err(Error::InvalidConfig(
                "gmail delegated adapter grant ref does not match ProvisionIntent".to_owned(),
            ));
        }
        intent.identity.validate()
    }
}

fn validate_gmail_id(value: &str, label: &'static str) -> Result<()> {
    validate_non_blank(value, label)?;
    validate_max_bytes(value, MAX_GMAIL_ID_BYTES, label)?;
    if value.contains(':') {
        return Err(Error::InvalidConfig(format!(
            "{label} must not contain a namespace separator"
        )));
    }
    Ok(())
}
