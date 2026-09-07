//! Gmail/Workspace read-side adapter for `delegated_grant` rows.
//!
//! This adapter binds a member's own mailbox — one the product never minted and
//! never owns — to a ChannelIdentity of the fourth shape. Everything downstream
//! is the machinery that already exists: [`GmailDelegatedAdapter::parse_inbound`]
//! hands the engine an ordinary [`InboundSurfaceEventInput`] on the `email`
//! channel, so routing, receipts, health claims and manifests never learn that
//! this row is delegated.
//!
//! Four things are structural here rather than configured:
//!
//! * **Custody is verified, never asserted — and so is the ROW.** The
//!   provisioning write re-reads the custody record and refuses unless it is
//!   live and `connector:gmail` read-bound at that instant, inside the
//!   transaction that writes the row. But custody alone is not the claim: the
//!   member's OAuth grant is not ours to revoke, so it stays Active in the vault
//!   after the delegated ROW is released or tombstoned. Both read doors —
//!   [`GmailDelegatedAdapter::enqueue_inbox_poll`] and
//!   [`GmailDelegatedAdapter::with_delegated_token_at_door`] — therefore require
//!   an ACTIVE delegated row that matches this adapter, not just a live secret.
//! * **Scoped-read only.** [`GmailReadWire`] has no send, reply, delete, or
//!   modify method, and [`delegated_scope_for_google_oauth_scope`] maps only the
//!   two read scopes. A caller cannot widen this by passing a different string;
//!   there is no variant for a write scope to land in.
//! * **No credential in a signature.** The wire is handed a `secret_ref` (a
//!   custody record NAME) and resolves the value at its own egress door.
//!   In-crate, [`GmailDelegatedAdapter::with_delegated_token_at_door`] is the
//!   only path to the bytes, and it is the SECRET-02 T0 door under the
//!   `connector:gmail` effector binding.
//! * **No new dependency.** The protocol lives behind the wire trait, so the
//!   dependency graph and lockfile are untouched.
//!
//! Rotation is absent by construction: the member's provider owns revoking and
//! re-issuing this grant, and the delegated edge table has no `Rotating` state
//! to step into.

use serde::{Deserialize, Serialize};

use super::{
    ChannelIdentityProviderAdapter, ChannelIdentityProviderInbound,
    ChannelIdentityProviderProvision, EMAIL_CHANNEL, EmailProviderInbound,
    MAX_EMAIL_PAYLOAD_REF_BYTES, MAX_EMAIL_PROVIDER_EVENT_ID_BYTES, split_email_address,
    validate_email_inbound_metadata, validate_max_bytes, validate_non_blank,
};
use crate::Vault;
use crate::attempt_queue::{AttemptQueue, EnqueueAttempt, EnqueueOutcome};
use crate::channel_identity::{
    AssignmentAddress, ChannelIdentity, ChannelIdentityBinding, ChannelIdentityFulfillment,
    ChannelIdentityState, DelegatedGrant, DelegatedGrantScope, DelegatedProvisionRequest,
};
use crate::channel_identity_lifecycle::{ChannelIdentityLifecycleVerb, ProvisionIntent};
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
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
const MAX_GMAIL_CURSOR_BYTES: usize = 256;
const MAX_GMAIL_MESSAGES_PER_PAGE: usize = 500;

/// Provider-native ceiling on a Gmail id, independent of where it lands.
const MAX_GMAIL_ID_BYTES: usize = 128;

/// Ceiling on a raw Gmail message id.
///
/// The provider-native cap AND the room the destination field actually leaves,
/// whichever is tighter. A Gmail id is namespaced with
/// [`GMAIL_EVENT_ID_PREFIX`] before it becomes the shared `provider_event_id`,
/// so checking the raw id against a flat cap would validate the wrong string.
const MAX_GMAIL_MESSAGE_ID_BYTES: usize = min_bytes(
    MAX_GMAIL_ID_BYTES,
    MAX_EMAIL_PROVIDER_EVENT_ID_BYTES - GMAIL_EVENT_ID_PREFIX.len(),
);

/// Ceiling on a raw Gmail thread id, derived the same way against the
/// payload-ref field its prefixed form lands in.
const MAX_GMAIL_THREAD_ID_BYTES: usize = min_bytes(
    MAX_GMAIL_ID_BYTES,
    MAX_EMAIL_PAYLOAD_REF_BYTES - GMAIL_THREAD_PAYLOAD_PREFIX.len(),
);

const fn min_bytes(a: usize, b: usize) -> usize {
    if a < b { a } else { b }
}

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
    ///
    /// # Errors
    ///
    /// [`Error::InvalidConfig`] when either id is blank, over the ceiling its
    /// namespaced form leaves, or itself namespaced.
    pub fn into_provider_inbound(self) -> Result<EmailProviderInbound> {
        validate_gmail_id(
            &self.message_id,
            MAX_GMAIL_MESSAGE_ID_BYTES,
            "gmail message id",
        )?;
        validate_gmail_id(
            &self.thread_id,
            MAX_GMAIL_THREAD_ID_BYTES,
            "gmail thread id",
        )?;
        let message_id = self.message_id;
        let thread_id = self.thread_id;
        let inbound = EmailProviderInbound::new(
            format!("{GMAIL_EVENT_ID_PREFIX}{message_id}"),
            self.to,
            self.from,
            self.internal_date_secs,
        )
        .with_payload_ref(format!("{GMAIL_THREAD_PAYLOAD_PREFIX}{thread_id}"));
        validate_email_inbound_metadata(&inbound)?;
        Ok(inbound)
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
            validate_gmail_cursor(cursor)?;
        }
        Ok(())
    }
}

/// The one cursor rule, applied on BOTH sides of the wire.
///
/// A cursor is opaque host state that gets handed straight back to the
/// provider, so the caller-supplied one deserves the same bound as the one the
/// provider returned — checking only `next_cursor` validates the value we
/// already trust and skips the value we do not.
fn validate_gmail_cursor(cursor: &str) -> Result<()> {
    validate_non_blank(cursor, "gmail page cursor must be non-empty")?;
    validate_max_bytes(
        cursor,
        MAX_GMAIL_CURSOR_BYTES,
        "gmail page cursor exceeds maximum length",
    )
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
    custody_record_ref: String,
    scopes: Vec<DelegatedGrantScope>,
}

impl GmailDelegatedAdapterConfig {
    /// Binds a mailbox address to an already-granted custody record name.
    ///
    /// `custody_record_ref` is a name, never a token. Defaults to read of
    /// message bodies; narrow it with [`Self::with_google_oauth_scopes`].
    ///
    /// The ref is admitted by the GRANT SCHEMA ITSELF — the config is built out
    /// of a [`DelegatedGrant`] that [`DelegatedGrant::validate`] has already
    /// accepted, so a ref this constructor returns is by construction a ref an
    /// identity body can carry. Both roads out of this config hand the ref
    /// somewhere the body's cap does not reach (the provider wire, and a durable
    /// attempt payload), so binding the schema's own door here rather than
    /// restating its rule is what keeps the two from drifting apart.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidChannelIdentityBody`] when the custody record name is
    /// blank or exceeds the grant schema's ref cap; [`Error::InvalidConfig`]
    /// when the mailbox is not a single ordinary address.
    pub fn new(
        mailbox_address: impl Into<String>,
        custody_record_ref: impl Into<String>,
    ) -> Result<Self> {
        let grant = DelegatedGrant::new(custody_record_ref, vec![DelegatedGrantScope::MailRead]);
        grant.validate()?;
        let (local_part, mailbox_domain) = split_email_address(&mailbox_address.into())?;
        Ok(Self {
            mailbox_address: format!("{local_part}@{mailbox_domain}"),
            custody_record_ref: grant.custody_record_ref,
            scopes: grant.scopes,
        })
    }

    /// Replaces the grant scopes from the Google OAuth scope URLs consented to.
    ///
    /// Any scope outside the two read scopes fails the call: an over-broad
    /// grant is refused rather than silently narrowed, so the row never claims
    /// less than the token can actually do.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidConfig`] for a write scope or an empty scope list.
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

/// What [`GmailDelegatedAdapter::provision_delegated_identity`] hands back.
///
/// One call, two answers: the stored `Requested` row, and the provider-side
/// provision record the CID-3 provider surface reports.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GmailDelegatedProvision {
    /// The delegated row, already durable at the requested id.
    pub identity: ChannelIdentity,
    /// The provider-side record of this provisioning.
    pub provision: ChannelIdentityProviderProvision,
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

    /// Proves the OAuth grant is in custody RIGHT NOW for THIS mailbox.
    ///
    /// The value is never read: the engine check projects to the value-less
    /// custody admission. It also does not hand a proof back — a proof borrows
    /// the transaction that read the record, and a proof that outlives its
    /// transaction is exactly the stale evidence the type exists to prevent.
    ///
    /// # Errors
    ///
    /// [`Error::SecretRefNotFound`], [`Error::SecretCustodyNotActive`] or
    /// [`Error::SecretBindingDenied`].
    pub fn verify_custody_grant(&self, vault: &Vault) -> Result<()> {
        vault.verify_delegated_custody(
            EMAIL_CHANNEL,
            &self.config.mailbox_address,
            &self.delegated_grant(),
        )
    }

    /// Stands up this mailbox's delegated identity row through the ONE engine
    /// door, and returns it alongside the provider provision record.
    ///
    /// [`Vault::provision_delegated_identity`] mints the custody proof inside
    /// the transaction that writes the row, so there is no check-then-write
    /// interval for a host to police and no second check to forget. Going live
    /// from there is the gated lifecycle road, whose bind and fulfillment steps
    /// each re-prove custody in their own transaction.
    ///
    /// The row is built from THIS adapter's own `(channel, mailbox, grant)`
    /// plus the caller's agent, so "a self-held row provisioned through the
    /// delegated adapter" and "a row whose grant ref disagrees with the config"
    /// are not refusals; they are unspellable.
    ///
    /// # Errors
    ///
    /// As [`Self::verify_custody_grant`], plus
    /// [`Error::ChannelIdentityAlreadyExists`] when `identity_id` is taken or
    /// the mailbox already has an occupant, plus body validation.
    pub fn provision_delegated_identity(
        &self,
        vault: &Vault,
        identity_id: EntityId,
        agent_ref: EntityId,
        provisioned_at: u64,
    ) -> Result<GmailDelegatedProvision> {
        let identity = vault.provision_delegated_identity(
            &identity_id,
            DelegatedProvisionRequest {
                channel: EMAIL_CHANNEL.to_owned(),
                address_or_handle: self.config.mailbox_address.clone(),
                binding: ChannelIdentityBinding::agent(agent_ref),
                grant: self.delegated_grant(),
            },
            provisioned_at,
        )?;
        let provision = self.provision_record(identity_id, provisioned_at);
        Ok(GmailDelegatedProvision {
            identity,
            provision,
        })
    }

    /// Runs `apply` with the grant's token injected at the SECRET-02 T0 door,
    /// for a LIVE delegated row this adapter speaks for.
    ///
    /// The only in-crate path to the bytes. `apply` cannot return them, the
    /// receipt carries none, and the effector is pinned to
    /// [`GMAIL_CONNECTOR_EFFECTOR`] so an unbound record denies.
    ///
    /// `identity_id` is not decoration, and it is not a second copy of the
    /// enqueue-time check. A door that could not SEE a row would have to
    /// validate the custody record alone — but custody OUTLIVES the row that
    /// points at it: releasing or tombstoning a delegated identity retires the
    /// ROW and leaves the member's OAuth grant Active in the vault, because
    /// nothing in the release path revokes a secret the product never minted.
    /// So work already sitting in the attempt queue when a member disconnected
    /// their mailbox would still open the token door and read mail the row no
    /// longer claims any right to. The enqueue-side check cannot close that: the
    /// queue is durable and the row moves afterwards.
    ///
    /// The refusal therefore lives HERE, at the last gate before the bytes, and
    /// it is the same predicate [`Self::enqueue_inbox_poll`] uses — a row that
    /// is delegated, ACTIVE, and this adapter's `(mailbox, custody record,
    /// scopes)`. It runs BEFORE the injection, so a refusal never reaches the
    /// value. `Requested` is refused for the same reason: a row whose grant has
    /// not been fulfilled has not yet been admitted to read anything.
    ///
    /// # Errors
    ///
    /// As [`Self::require_active_row_matches_adapter`], plus the SECRET-02
    /// door's own custody arms.
    pub fn with_delegated_token_at_door(
        &self,
        vault: &Vault,
        identity_id: EntityId,
        apply: &mut dyn FnMut(&[u8]) -> Result<()>,
    ) -> Result<DoorInjectionReceipt> {
        self.require_active_row_matches_adapter(vault, &identity_id)?;
        vault.inject_secret_at_door(
            &self.config.custody_record_ref,
            GMAIL_CONNECTOR_EFFECTOR,
            apply,
        )
    }

    /// Reads one page of the granted mailbox through the host wire.
    ///
    /// The wire receives the custody NAME, not the value.
    ///
    /// The caller's cursor is validated BEFORE the wire is invoked. A blank or
    /// oversized cursor is a caller bug, and validating it only on the way back
    /// out means the egress call — token resolution, network round trip, and
    /// whatever the provider does with a malformed page token — has already
    /// happened by the time it is caught.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidConfig`] for a bad cursor or an over-large page, plus
    /// whatever the wire returns.
    pub fn fetch_inbox_page<W: GmailReadWire + ?Sized>(
        &self,
        wire: &W,
        cursor: Option<&str>,
    ) -> Result<GmailInboxPage> {
        if let Some(cursor) = cursor {
            validate_gmail_cursor(cursor)?;
        }
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
    ///
    /// `identity_id` is proved to name THIS ADAPTER'S ROW, and a LIVE one,
    /// before anything is written. Matching the adapter's fields is not the same
    /// question as "may we still read this mailbox": a `Requested` row has not
    /// been admitted yet, and a `Released`/`Tombstone` row has been withdrawn,
    /// while its custody record stays Active in the vault either way. Arming a
    /// scheduled poll against either one schedules mailbox reads the row does
    /// not authorize.
    ///
    /// # Errors
    ///
    /// As [`Self::require_active_row_matches_adapter`], plus attempt-queue and
    /// storage errors.
    pub fn enqueue_inbox_poll(
        &self,
        vault: &Vault,
        identity_id: EntityId,
        now: u64,
    ) -> Result<EnqueueOutcome> {
        self.require_active_row_matches_adapter(vault, &identity_id)?;
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

    /// Proves the STORED row at `identity_id` is an ACTIVE row this adapter
    /// speaks for — the one predicate behind both delegated doors.
    ///
    /// The payload of a poll carries THIS adapter's mailbox and custody name
    /// while the dedupe key names the CALLER'S identity id. Those two halves can
    /// describe two different mailboxes, and the durable attempt is what a
    /// poller acts on later:
    ///
    /// * the poll reads mailbox B under grant B and files the results under row
    ///   A's `identity_ref`, so inbound routing — which trusts the identity ref
    ///   to say whose mailbox this was — delivers one member's mail to the agent
    ///   bound to ANOTHER member's row. Nothing downstream can catch it: the
    ///   payload is internally consistent, and the row it points at is real;
    /// * a self-held or absent id passed the same way arms a delegated poll over
    ///   a row that never carried a grant at all;
    /// * because the dedupe key is per IDENTITY, the mismatched attempt then
    ///   OCCUPIES row A's key, so row A's own lawful poll dedupes into it and
    ///   silently never runs.
    ///
    /// So the four facts the payload asserts are checked against the row that id
    /// actually names: the delegated shape, the channel and assignment mailbox,
    /// the custody record name, and the granted scopes.
    ///
    /// The mailbox is compared through the engine's own normalizer rather than
    /// by string equality: the stored value is
    /// [`AssignmentAddress::normalize`]d, while this config keeps the local-part
    /// as the host spelled it, so a `Member@…` mailbox would otherwise refuse
    /// the very row this adapter provisioned. Scopes compare as a SET — a grant
    /// is what it permits, not the order the consent screen listed it in.
    ///
    /// The fifth fact is the one the other four cannot stand in for: the row's
    /// LIFECYCLE STATE. The four field checks answer "whose mailbox is this",
    /// not "may we still read it". A delegated row is born `Requested` and
    /// retires through `Released`/`Tombstone`, and neither end of that lifecycle
    /// revokes the custody record — the member's OAuth grant is not ours to
    /// revoke, so it stays Active in the vault while the row that pointed at it
    /// is gone. Without this arm a not-yet-live row and a withdrawn one are
    /// admitted identically to a live one on every road that asks only about
    /// custody.
    ///
    /// The state arm is LAST, so every field mismatch keeps its own refusal: a
    /// foreign mailbox is still refused for being a foreign mailbox rather than
    /// for whatever state it happens to sit in.
    ///
    /// This is a read BEFORE the queue write, not inside it: [`AttemptQueue`]
    /// owns its own transactions and exposes no in-transaction enqueue, so the
    /// check cannot yet be sealed to the write. What that leaves open is narrow
    /// and one-directional — a row released or re-bound in the interval arms a
    /// poll that [`Self::with_delegated_token_at_door`] then refuses at egress,
    /// where the SAME predicate runs against the row as it stands at that
    /// instant, rather than a mismatched pair reaching the queue.
    ///
    /// # Errors
    ///
    /// [`Error::EntityNotFound`] when no row exists at `identity_id`,
    /// [`Error::InvalidEntityType`] when the id names another kind, and
    /// [`Error::InvalidConfig`] when the row is not this adapter's delegated
    /// mailbox, custody record, and scope set, or is not `Active`.
    fn require_active_row_matches_adapter(
        &self,
        vault: &Vault,
        identity_id: &EntityId,
    ) -> Result<()> {
        let identity = vault
            .get_channel_identity(identity_id)?
            .ok_or(Error::EntityNotFound)?;
        let Some(grant) = identity.grant.as_ref() else {
            return Err(Error::InvalidConfig(
                "gmail inbox poll requires a delegated_grant identity row".to_owned(),
            ));
        };
        let mailbox = AssignmentAddress::normalize(EMAIL_CHANNEL, &self.config.mailbox_address);
        if identity.channel != EMAIL_CHANNEL || identity.address_or_handle != mailbox.as_str() {
            return Err(Error::InvalidConfig(
                "gmail inbox poll identity row is assigned to another channel or mailbox"
                    .to_owned(),
            ));
        }
        if grant.custody_record_ref != self.config.custody_record_ref {
            return Err(Error::InvalidConfig(
                "gmail inbox poll identity row names another custody record".to_owned(),
            ));
        }
        let mut granted = grant.scopes.clone();
        let mut configured = self.config.scopes.clone();
        granted.sort_unstable();
        configured.sort_unstable();
        if granted != configured {
            return Err(Error::InvalidConfig(
                "gmail inbox poll identity row grants another scope set".to_owned(),
            ));
        }
        if identity.state != ChannelIdentityState::Active {
            return Err(Error::InvalidConfig(format!(
                "gmail delegated reads require an active identity row, not {}",
                identity.state.as_str()
            )));
        }
        Ok(())
    }

    fn provision_record(
        &self,
        identity_id: EntityId,
        fulfilled_at: u64,
    ) -> ChannelIdentityProviderProvision {
        ChannelIdentityProviderProvision {
            provider_key: GMAIL_DELEGATED_PROVIDER_KEY.to_owned(),
            identity_id,
            channel: EMAIL_CHANNEL.to_owned(),
            address_or_handle: self.config.mailbox_address.clone(),
            fulfillment_mode: ChannelIdentityFulfillment::Api,
            provider_identity_ref: format!("gmail:{}", identity_id.to_hex()),
            fulfilled_at,
        }
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
            // here as well as on the delegated edge table: this adapter has no
            // re-minting surface to offer.
            ChannelIdentityLifecycleVerb::Provision => Some(ChannelIdentityFulfillment::Api),
            ChannelIdentityLifecycleVerb::Bind
            | ChannelIdentityLifecycleVerb::Rotate
            | ChannelIdentityLifecycleVerb::Release
            | ChannelIdentityLifecycleVerb::RouteInbound => None,
        }
    }

    /// Structurally unavailable: this adapter cannot assert a delegated grant
    /// without re-reading custody, and the vault-free trait signature has
    /// nothing to read it from.
    ///
    /// A provision that skipped the recheck would stand up a row on a grant the
    /// member may already have revoked, so this door refuses rather than
    /// fulfilling on stale evidence. It also takes a caller-built
    /// `ProvisionIntent`, and
    /// [`GmailDelegatedAdapter::provision_delegated_identity`] builds the row
    /// from this adapter's own mailbox and grant — so there is no
    /// caller-supplied row left to agree or disagree with the config.
    fn provision(
        &self,
        _intent: &ProvisionIntent,
        _fulfilled_at: u64,
    ) -> Result<ChannelIdentityProviderProvision> {
        Err(Error::InvalidConfig(
            "gmail delegated provisioning must revalidate custody: \
             use GmailDelegatedAdapter::provision_delegated_identity"
                .to_owned(),
        ))
    }

    /// Normalizes one polled Gmail message into engine SurfaceEvent input.
    ///
    /// The RECEIVING address is the adapter's configured granted mailbox, not
    /// the `To` header. That is the honest reading of where the message came
    /// from: this adapter polls exactly one mailbox under exactly one grant, so
    /// a message it read IS a message that landed there. The `To` header is not
    /// evidence of that — real mail arrives via an alias, with the mailbox on
    /// `Cc`, addressed to a list, or (on a `Bcc`) with the mailbox appearing in
    /// no recipient header at all. Requiring `To` to equal the mailbox address
    /// would drop all four on the floor while admitting nothing extra, since the
    /// adapter cannot read another mailbox.
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
        let (_, sender_domain) = split_email_address(&email.envelope_from)?;
        let normalized_from = super::normalize_email_address(&email.envelope_from, &sender_domain)?;

        let mut input = InboundSurfaceEventInput::new(
            email.provider_event_id,
            EMAIL_CHANNEL,
            self.config.mailbox_address.clone(),
            SurfaceCounterpartyStamp::unknown(format!("email:{normalized_from}")),
            email.received_at,
            true,
        );
        input.payload_ref = email.payload_ref;
        Ok(input)
    }
}

fn validate_gmail_id(value: &str, max: usize, label: &'static str) -> Result<()> {
    validate_non_blank(value, label)?;
    validate_max_bytes(value, max, label)?;
    if value.contains(':') {
        return Err(Error::InvalidConfig(format!(
            "{label} must not contain a namespace separator"
        )));
    }
    Ok(())
}
