//! Authenticated identity carried by a scoped read.
use crate::EntityId;

/// Actor key bound to a scoped read lane over the `core:read` surface.
///
/// The fields are private and construction rejects blank actor refs, so a
/// [`ScopedRead`](crate::claim::ScopedRead) cannot be built as an unkeyed bulk read handle.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScopedReadActorKey {
    actor_ref: String,
    actor_class: Option<String>,
    pub(super) principal_ref: Option<EntityId>,
    pub(super) enforce_access_grants: bool,
    pub(super) proof: Option<crate::authority::VerifiedSlip>,
    /// Set only on the vault owner's own key; see [`Self::vault_owner`].
    owner: Option<EntityId>,
}

impl ScopedReadActorKey {
    #[must_use]
    pub fn new(actor_ref: impl Into<String>) -> Option<Self> {
        Self::from_parts(actor_ref.into(), None)
    }

    #[must_use]
    pub fn with_actor_class(
        actor_ref: impl Into<String>,
        actor_class: impl Into<String>,
    ) -> Option<Self> {
        Self::from_parts(actor_ref.into(), Some(actor_class.into()))
    }

    fn from_parts(actor_ref: String, actor_class: Option<String>) -> Option<Self> {
        if actor_ref.trim().is_empty() {
            return None;
        }
        let actor_class = actor_class
            .and_then(|class| (!class.trim().is_empty()).then(|| class.trim().to_owned()));
        Some(Self {
            actor_ref: actor_ref.trim().to_owned(),
            actor_class,
            principal_ref: None,
            enforce_access_grants: false,
            proof: None,
            owner: None,
        })
    }

    /// The vault owner's own key: the owner's un-narrowed Grant.
    ///
    /// DEC-0005: an own device's ceiling defaults to all of the owner's vault,
    /// and ARCH-0057: a manifest never overrules the person on their own
    /// vault. So this key resolves to the full (legacy) floor, matches no
    /// manifest grant row, and needs no positive record stamp. The off-record
    /// band never reaches base, so it is absent by construction.
    ///
    /// Crate-private on purpose: only the Memory facade mints it, after the
    /// owner verification passes, and every read transaction re-checks that
    /// binding before it resolves a plan (`ScopedRead` refuses a key whose
    /// owner binding no longer holds).
    #[must_use]
    pub(crate) fn vault_owner(owner: EntityId) -> Self {
        Self {
            actor_ref: owner.to_hex(),
            actor_class: Some(
                crate::edge::EdgeActorClass::Human
                    .gate_actor_class()
                    .to_owned(),
            ),
            principal_ref: None,
            enforce_access_grants: false,
            proof: None,
            owner: Some(owner),
        }
    }

    /// The owner this key was minted for, when it is the vault owner's key.
    pub(crate) fn vault_owner_ref(&self) -> Option<EntityId> {
        self.owner
    }

    /// Attach the authenticated principal. An unbound delegated caller has no grants.
    #[must_use]
    pub fn require_access_grants(mut self, principal_ref: Option<EntityId>) -> Self {
        self.principal_ref = principal_ref;
        self.enforce_access_grants = true;
        self
    }

    /// Constructs a read capability only from a log/MAC/holder-verified slip.
    #[must_use]
    pub fn from_verified_slip(proof: &crate::authority::VerifiedSlip) -> Option<Self> {
        // `core:read` is the host's spelling of the same verb (the server's pairing and OAuth
        // slips carry it; its relay already reads either as a read grant).
        if !(proof.allows_verb("read") || proof.allows_verb("core:read")) {
            return None;
        }
        let mut key = Self::from_parts(
            proof.claims().holder_ref.clone(),
            proof.claims().actor_class.clone(),
        )?;
        key.proof = Some(proof.clone());
        Some(key)
    }

    pub(crate) fn authority_scope(&self) -> Option<&crate::federation::Scope> {
        self.proof
            .as_ref()
            .map(crate::authority::VerifiedSlip::scope)
    }

    #[must_use]
    pub fn actor_ref(&self) -> &str {
        &self.actor_ref
    }

    #[must_use]
    pub fn actor_class(&self) -> Option<&str> {
        self.actor_class.as_deref()
    }
}
