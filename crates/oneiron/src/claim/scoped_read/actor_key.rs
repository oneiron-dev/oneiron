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
        })
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
        if !proof.allows_verb("read") {
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
