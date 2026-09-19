//! Authenticated identity carried by a scoped read.
use crate::EntityId;

/// Actor key bound to a scoped read lane over the `core:read` surface.
///
/// The fields are private and construction rejects blank actor refs, so a
/// [`ScopedRead`] cannot be built as an unkeyed bulk read handle.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScopedReadActorKey {
    actor_ref: String,
    actor_class: Option<String>,
    pub(super) principal_ref: Option<EntityId>,
    pub(super) enforce_access_grants: bool,
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
        })
    }

    /// Attach the authenticated principal. An unbound delegated caller has no grants.
    #[must_use]
    pub fn require_access_grants(mut self, principal_ref: Option<EntityId>) -> Self {
        self.principal_ref = principal_ref;
        self.enforce_access_grants = true;
        self
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
