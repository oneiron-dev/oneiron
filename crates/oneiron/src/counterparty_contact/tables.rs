//! The side tables `counterparty_contact` keeps (core split slice 1): each row declares one, and the crate's
//! build script places it in `side_table`'s catalogue.

crate::side_table::side_tables! {
    /// Contacts by live `identity_ref` head, to its head claim. Key: id16(identity) + id16(contact).
    COUNTERPARTY_CONTACT_IDENTITY_INDEX: VaultMeta b"counterparty.contact.identity.v1:" Raw
        [restore: not_imaged] [family: not_imaged] [tier: derived];
    /// Completeness flag of the identity index above (u64 version). Key: ().
    COUNTERPARTY_CONTACT_IDENTITY_INDEX_STATE: VaultMeta b"counterparty.contact.identity_state.v1" Raw
        [restore: not_imaged] [family: not_imaged] [tier: derived];
    /// Deduplicated set of contact refs reachable for a (party, channel class) pair. Key:
    /// hash32(sha256).
    COUNTERPARTY_CONTACT_PARTY_CHANNEL_INDEX: VaultMeta b"counterparty.contact.party_channel.v1:" Raw
        [restore: not_imaged] [family: not_imaged] [tier: derived];
    /// Lookup index from (identity ref, normalized counterparty) to the contact entity id. Key: id16
    /// + hash32(sha256).
    COUNTERPARTY_CONTACT_INDEX: VaultMeta b"counterparty_contact.index.v1:" Raw
        [restore: not_imaged] [family: not_imaged] [tier: derived];
    /// One open, answered or superseded "may I reach your trusted contact?" ask, raised by a
    /// `RouteToHelp` the person's dial or the row's tier says to ask about first. Key: id16(ask).
    TRUSTED_CONTACT_ASK: VaultMeta b"trusted_contact.ask.v1:" Named
        // Restore class: Consent and the owner's tiers stand on their own: a restore never brings
        // back a relation either side has since revoked, or an ask already answered.
        [restore: live] [family: unclassified] [tier: canonical];
    /// One trusted-contact notice the engine staged, by its fire ref: the witness that claim and
    /// dispatch require, so a notice queued any other way is never sent. Key: id16(fire).
    TRUSTED_CONTACT_FIRE: VaultMeta b"trusted_contact.fire.v1:" Named
        [restore: live] [family: unclassified] [tier: canonical];
    /// A person's trusted contact: the PERSON named, how to reach them, the fixed notice, the
    /// dial, and both sides' consent or revocation. Key: id16(person) + id16(contact).
    TRUSTED_CONTACT_RELATION: VaultMeta b"trusted_contact.relation.v1:" Named
        [restore: live] [family: unclassified] [tier: canonical];
    /// The trusted-contact tier the owner gave one `RouteToHelp` policy row. Key: string (row ref).
    TRUSTED_CONTACT_TIER: VaultMeta b"trusted_contact.tier.v1:" Named
        [restore: live] [family: unclassified] [tier: canonical];
}
