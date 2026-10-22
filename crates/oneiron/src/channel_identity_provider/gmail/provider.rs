//! The Gmail delegated adapter's provider trait: provisioning, the read pass
//! and the inbound surface events a fetched message becomes.
//! Entry: `ChannelIdentityProviderAdapter for GmailDelegatedAdapter`. Defines its own items.

use super::*;

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
        let counterparty = match email.header_mailbox {
            Some(HeaderMailbox::Parsed(mailbox)) => {
                SurfaceCounterpartyStamp::unknown(format!("email:{mailbox}"))
            }
            Some(HeaderMailbox::Unparsed { raw_hash }) => {
                SurfaceCounterpartyStamp::unparsed(EMAIL_CHANNEL, raw_hash)
            }
            None => counterparty_from_raw_sender(&email.envelope_from),
        };

        let correlation_id =
            run::delivery_correlation_id(&self.config.mailbox_address, &email.provider_event_id);
        let mut input = InboundSurfaceEventInput::new(
            email.provider_event_id,
            EMAIL_CHANNEL,
            self.config.mailbox_address.clone(),
            counterparty,
            email.received_at,
            true,
        )
        .with_correlation_id(correlation_id);
        input.payload_ref = email.payload_ref;
        Ok(input)
    }
}

/// Converts a raw sender field into routing identity without making parsing a
/// delivery gate. Invalid or unsupported From syntax degrades to a digest-only
/// counterparty stamp; the receiving mailbox remains the configured identity.
fn counterparty_from_raw_sender(raw_sender: &str) -> SurfaceCounterpartyStamp {
    let parsed = split_email_address(raw_sender)
        .and_then(|(_, domain)| super::super::normalize_email_address(raw_sender, &domain));
    match parsed {
        Ok(address) => SurfaceCounterpartyStamp::unknown(format!("email:{address}")),
        Err(_) => SurfaceCounterpartyStamp::unparsed(
            EMAIL_CHANNEL,
            Sha256::digest(raw_sender.as_bytes()).into(),
        ),
    }
}
