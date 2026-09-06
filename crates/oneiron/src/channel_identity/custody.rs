//! Delegated-grant custody: the grant handle, the txn-bound proof, and the one
//! verification door.
//!
//! A `delegated_grant` row is a claim that this device may read a mailbox the
//! product never minted and does not own. What makes that claim true is a live
//! SECRET_CUSTODY record with a `connector:<provider>` read binding that NAMES
//! THIS MAILBOX as its subject. So the custody record names its subject through
//! a `subject:<channel>:<address>` scope, the proof carries the address, and
//! `covers` is a three-way match: a caller holding a proof for one member's
//! record cannot stand up a row over another member's mailbox.

use std::marker::PhantomData;

use crate::error::{Error, Result};
use crate::secret_custody::{
    SECRET_SCOPE_READ, SecretBinding, SecretCustodyStatus, read_secret_custody_admission_in_txn,
    resolve_secret_ref_in_txn,
};
use crate::store::Store;

use super::address::{AssignmentAddress, ChannelKey};

const MAX_DELEGATED_GRANT_REF_BYTES: usize = 256;
const MAX_DELEGATED_GRANT_SCOPES: usize = 8;

/// Read-only OAuth scope classes a `delegated_grant` row may carry.
///
/// There is deliberately no send, reply, delete, or modify variant. Scoped-read
/// is not a policy setting that a caller could widen: the absence of the variant
/// is what makes a delegated row structurally incapable of naming a write scope,
/// including through a decoded body.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[non_exhaustive]
pub enum DelegatedGrantScope {
    /// Read message bodies in the granted mailbox.
    MailRead,
    /// Read message headers/metadata only.
    MailMetadata,
}

impl DelegatedGrantScope {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::MailRead => "mail.read",
            Self::MailMetadata => "mail.metadata",
        }
    }

    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "mail.read" => Some(Self::MailRead),
            "mail.metadata" => Some(Self::MailMetadata),
            _ => None,
        }
    }
}

/// The custody handle a `delegated_grant` row carries.
///
/// This is a custody record NAME plus the read scopes the grant covers. The
/// OAuth access/refresh token bytes live in the custody record and are reachable
/// only through the SECRET-02 door under an effector binding; they never land on
/// this struct, on the encoded body, or on any claim derived from it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DelegatedGrant {
    /// Custody record name (`Vault::resolve_secret_ref` key), never a token.
    pub custody_record_ref: String,
    /// Read scopes the grant covers; non-empty, deduplicated.
    pub scopes: Vec<DelegatedGrantScope>,
}

impl DelegatedGrant {
    /// Builds a delegated grant handle from a custody record name and scopes.
    #[must_use]
    pub fn new(custody_record_ref: impl Into<String>, scopes: Vec<DelegatedGrantScope>) -> Self {
        Self {
            custody_record_ref: custody_record_ref.into(),
            scopes,
        }
    }

    /// Validates the grant handle's own bounds.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidChannelIdentityBody`] for a blank or over-long custody
    /// record name, an empty or over-long scope set, or a repeated scope.
    pub fn validate(&self) -> Result<()> {
        let trimmed = self.custody_record_ref.trim();
        if trimmed.is_empty() || self.custody_record_ref.len() > MAX_DELEGATED_GRANT_REF_BYTES {
            return Err(Error::InvalidChannelIdentityBody(
                "delegated_grant_ref must be a non-empty custody record name of at most 256 bytes",
            ));
        }
        if self.scopes.is_empty() || self.scopes.len() > MAX_DELEGATED_GRANT_SCOPES {
            return Err(Error::InvalidChannelIdentityBody(
                "delegated grant must declare 1..=8 read scopes",
            ));
        }
        for (index, scope) in self.scopes.iter().enumerate() {
            if self.scopes[..index].contains(scope) {
                return Err(Error::InvalidChannelIdentityBody(
                    "delegated grant scopes must not repeat",
                ));
            }
        }
        Ok(())
    }
}

/// The effector whose read binding is what "custody" MEANS for a delegated
/// row on a given channel.
///
/// One entry today: a delegated `email` row is a member-held Gmail/Workspace
/// mailbox, and the only thing that makes the row true is a live
/// `connector:gmail` read binding on the named custody record. A channel with
/// no entry admits no delegated row at all, so an unknown channel fails closed
/// rather than defaulting to "any binding will do".
const DELEGATED_CUSTODY_EFFECTORS: [(&str, &str); 1] = [("email", "connector:gmail")];

/// The effector binding a delegated `channel` row's custody record must carry.
///
/// `None` means the channel admits no delegated rows. The lookup takes the
/// channel through [`ChannelKey::normalize`] for the same reason
/// [`delegated_custody_subject_scope`] does: a table keyed on lowercase nouns
/// answers a raw spelling honestly or not at all.
#[must_use]
pub fn delegated_custody_effector(channel: &str) -> Option<&'static str> {
    let channel = ChannelKey::normalize(channel);
    DELEGATED_CUSTODY_EFFECTORS
        .iter()
        .find_map(|(candidate, effector)| (*candidate == channel.as_str()).then_some(*effector))
}

/// The scope string a custody record must declare to name `(channel, address)`
/// as its SUBJECT.
///
/// Scope-string form, not a codec change: `SecretBinding.scopes` is already a
/// free-form `Vec<String>` whose documented job is naming what a binding is
/// FOR, so the subject rides there with no on-disk migration.
///
/// The host registers it at OAuth completion — it has the account email from
/// the token exchange, which the engine does not and must not.
///
/// BOTH halves of the subject are normalized here, and the channel half is what
/// ONE-1825 closes. Every writer that consumes this scope —
/// [`verify_delegated_custody_in_txn`], reached through
/// [`Vault::provision_delegated_identity`](crate::Vault::provision_delegated_identity)
/// and [`Vault::verify_delegated_custody`](crate::Vault::verify_delegated_custody) —
/// runs the request channel through [`ChannelKey::normalize`] FIRST and then
/// looks for `subject:email:…`. A helper that interpolated the caller's raw
/// spelling would put the registration side and the admission side of the same
/// tie out of step on any channel spelling that normalizes:
/// [`delegated_custody_scopes`]`("Email", addr)` would emit `subject:Email:…`,
/// the engine would look for `subject:email:…`, and a binding a host registered
/// in good faith would be refused forever for a mailbox the engine otherwise
/// accepts. Normalizing once, here, is what keeps the two halves from drifting;
/// already-normalized inputs are byte-for-byte unaffected.
#[must_use]
pub fn delegated_custody_subject_scope(channel: &str, address: &str) -> String {
    let channel = ChannelKey::normalize(channel);
    format!(
        "subject:{}:{}",
        channel.as_str(),
        AssignmentAddress::normalize(channel.as_str(), address).as_str()
    )
}

/// The read + subject scope pair a delegated custody binding must declare.
///
/// The registration-side twin of [`verify_delegated_custody_in_txn`], so a host
/// registering a grant and the engine admitting it cannot drift. `"Email"`,
/// `"EMAIL"` and `" email "` all register the one scope the engine looks for.
#[must_use]
pub fn delegated_custody_scopes(channel: &str, address: &str) -> Vec<String> {
    vec![
        SECRET_SCOPE_READ.to_owned(),
        delegated_custody_subject_scope(channel, address),
    ]
}

/// Typed proof that a delegated grant's custody record was read out of the
/// vault and found active, with the channel's required read binding present AND
/// that binding naming this exact mailbox as its subject.
///
/// There is no public constructor and no public field: the ONLY way to hold one
/// is [`verify_delegated_custody_in_txn`], which reads the custody record. That
/// is the difference between a caller ASSERTING custody and custody having been
/// VERIFIED.
///
/// The `'txn` lifetime is load-bearing, not decoration. The proof borrows the
/// transaction that read the record, so it cannot outlive it: "a point-in-time
/// proof reused after the grant was revoked" stops being a discipline the
/// callers have to remember and becomes a BORROW ERROR.
///
/// The proof carries names, never bytes: it is minted from the value-less
/// admission projection, so no OAuth token material reaches it or anything
/// derived from it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DelegatedCustodyProof<'txn> {
    channel: String,
    address: String,
    custody_record_ref: String,
    effector: &'static str,
    _txn: PhantomData<&'txn ()>,
}

impl DelegatedCustodyProof<'_> {
    /// The channel this proof was verified for.
    #[must_use]
    pub fn channel(&self) -> &str {
        &self.channel
    }

    /// The mailbox (assignment address) this proof was verified for.
    #[must_use]
    pub fn address(&self) -> &str {
        &self.address
    }

    /// The custody record NAME whose bindings were verified.
    #[must_use]
    pub fn custody_record_ref(&self) -> &str {
        &self.custody_record_ref
    }

    /// The effector whose read binding covered the record.
    #[must_use]
    pub const fn effector(&self) -> &'static str {
        self.effector
    }

    /// Whether this proof covers exactly `(channel, address, grant)`.
    ///
    /// The ADDRESS arm is the one that matters: a two-way `(channel, record)`
    /// match is what would let a proof for one member's record stand up a row
    /// over another member's mailbox.
    #[must_use]
    pub fn covers(&self, channel: &str, address: &str, grant: &DelegatedGrant) -> bool {
        self.channel == channel
            && self.address == address
            && self.custody_record_ref == grant.custody_record_ref
    }
}

/// Verifies the custody record behind a delegated grant inside an existing txn.
///
/// Fails closed when the channel admits no delegated rows, when the named
/// record is missing, when it is not `Active`, when the binding the token door
/// would select for the channel's effector does not declare the read scope, or
/// when that binding does not name `address` as its subject.
///
/// The record's value bytes are never MATERIALIZED, not merely never printed:
/// the read is [`read_secret_custody_admission_in_txn`], whose projection has
/// no value field at all. Decoding the full `SecretCustodyRecord` here would
/// heap-copy the member's OAuth token into a verification path that has no
/// business holding it; the one sanctioned value read stays the SECRET-02 door.
///
/// # Errors
///
/// [`Error::InvalidChannelIdentityBody`], [`Error::SecretRefNotFound`],
/// [`Error::SecretCustodyNotActive`], or [`Error::SecretBindingDenied`].
pub(crate) fn verify_delegated_custody_in_txn<'txn>(
    store: &Store,
    txn: &'txn heed::RoTxn<'_>,
    channel: &str,
    address: &str,
    grant: &DelegatedGrant,
) -> Result<DelegatedCustodyProof<'txn>> {
    grant.validate()?;
    let effector = delegated_custody_effector(channel).ok_or(Error::InvalidChannelIdentityBody(
        "channel admits no delegated_grant custody effector",
    ))?;
    let missing = || Error::SecretRefNotFound {
        name: grant.custody_record_ref.clone(),
    };
    let id =
        resolve_secret_ref_in_txn(store, txn, &grant.custody_record_ref)?.ok_or_else(missing)?;
    let admission = read_secret_custody_admission_in_txn(store, txn, &id)?.ok_or_else(missing)?;
    if admission.status != SecretCustodyStatus::Active {
        return Err(Error::SecretCustodyNotActive {
            name: admission.name,
        });
    }
    // The SELECTION rule has to be the token door's, not a looser one. The
    // door resolves `binding_for` — the FIRST binding naming the effector —
    // and then asks that one binding for `read`. An `any()` scan answers a
    // different question: it would mint a proof for a record whose first
    // `connector:gmail` binding grants nothing and whose second grants read,
    // and the door this proof exists to stand for would then refuse to service
    // the row at poll time. A proof that outruns its door is not a proof.
    //
    // The subject rides on that same one binding, for the same reason: the
    // door services a MAILBOX, and a binding that grants read of some other
    // member's mail is not custody of this one.
    let subject = delegated_custody_subject_scope(channel, address);
    let denied = || Error::SecretBindingDenied {
        effector: effector.to_owned(),
        secret_ref: admission.name.clone(),
    };
    let binding = admission.binding_for(effector).ok_or_else(denied)?;
    if !binding.grants_read() || !binding_names_subject(binding, &subject) {
        return Err(denied());
    }
    Ok(DelegatedCustodyProof {
        channel: channel.to_owned(),
        address: address.to_owned(),
        custody_record_ref: grant.custody_record_ref.clone(),
        effector,
        _txn: PhantomData,
    })
}

/// Whether the binding declares this exact subject scope.
///
/// An empty scope list is not a wildcard, and neither is a missing subject:
/// both mean the record never named a mailbox, which is precisely the
/// mailbox-unbound custody this check exists to refuse. Fail closed.
fn binding_names_subject(binding: &SecretBinding, subject: &str) -> bool {
    binding.scopes.iter().any(|scope| scope == subject)
}
