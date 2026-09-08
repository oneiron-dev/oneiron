//! Backing refs, selection requests, and engine-issued read handles.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::lens::validate::validate_lens_token;
use crate::lens::wire_ids::{
    LensAtomId, LensBackingRefId, LensHandleName, LensHandleRole, LensRenderId, LensResultSetRowId,
};

use super::{GeneratedUiValidatedAction, LensPrincipalBinding};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LensBackingTargetKind {
    Entity,
    Claim,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LensBackingTarget {
    kind: LensBackingTargetKind,
    pub(crate) entity_id: EntityId,
    short_id: String,
    content_hash: u8,
}

impl LensBackingTarget {
    pub fn entity(
        entity_id: EntityId,
        short_id: impl Into<String>,
        content_hash: u8,
    ) -> Result<Self> {
        Self::new(
            LensBackingTargetKind::Entity,
            entity_id,
            short_id,
            content_hash,
        )
    }

    pub fn claim(
        entity_id: EntityId,
        short_id: impl Into<String>,
        content_hash: u8,
    ) -> Result<Self> {
        Self::new(
            LensBackingTargetKind::Claim,
            entity_id,
            short_id,
            content_hash,
        )
    }

    fn new(
        kind: LensBackingTargetKind,
        entity_id: EntityId,
        short_id: impl Into<String>,
        content_hash: u8,
    ) -> Result<Self> {
        let short_id = short_id.into();
        validate_lens_token("lens backing short id", &short_id)?;
        Ok(Self {
            kind,
            entity_id,
            short_id,
            content_hash,
        })
    }

    #[must_use]
    pub fn kind(&self) -> LensBackingTargetKind {
        self.kind
    }

    #[must_use]
    pub fn entity_id(&self) -> &EntityId {
        &self.entity_id
    }

    #[must_use]
    pub fn short_id(&self) -> &str {
        &self.short_id
    }

    #[must_use]
    pub fn content_hash(&self) -> u8 {
        self.content_hash
    }

    #[must_use]
    pub fn short_ref(&self) -> String {
        format!("{}:{:02x}", self.short_id, self.content_hash)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct LensBackingRefToken {
    pub(crate) render_id: LensRenderId,
    pub(crate) ref_id: LensBackingRefId,
}

impl LensBackingRefToken {
    #[must_use]
    pub fn render_id(&self) -> &LensRenderId {
        &self.render_id
    }

    #[must_use]
    pub fn ref_id(&self) -> &LensBackingRefId {
        &self.ref_id
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LensHostBackingRef {
    pub(super) token: LensBackingRefToken,
    pub(super) handle: LensHandleName,
    pub(super) role: LensHandleRole,
    pub(super) target: LensBackingTarget,
}

impl LensHostBackingRef {
    #[must_use]
    pub fn token(&self) -> &LensBackingRefToken {
        &self.token
    }

    #[must_use]
    pub fn handle(&self) -> &LensHandleName {
        &self.handle
    }

    #[must_use]
    pub fn role(&self) -> LensHandleRole {
        self.role
    }

    #[must_use]
    pub fn target(&self) -> &LensBackingTarget {
        &self.target
    }
}

/// Client-authored atom selection. It names *what was pointed at* and nothing else:
/// no entity id, body text, screenshot, write token, authority, or query string is
/// expressible here. The engine looks the node up in the exact render it emitted and
/// takes the target from its own backing table.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct LensAtomSelectionRequest {
    pub card_id: LensRenderId,
    pub atom_id: LensAtomId,
    pub handle: LensHandleName,
}

/// The read reach a selection may carry: [`LensHandleRole`] minus
/// [`LensHandleRole::ActionTarget`]. An action-target binding is reach for the action
/// backchannel, so it can never be laundered into a selection handle.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LensReadReach {
    ClaimSet,
    EntitySet,
    Timeline,
    QueryResult,
}

impl TryFrom<LensHandleRole> for LensReadReach {
    type Error = Error;

    fn try_from(role: LensHandleRole) -> Result<Self> {
        match role {
            LensHandleRole::ClaimSet => Ok(Self::ClaimSet),
            LensHandleRole::EntitySet => Ok(Self::EntitySet),
            LensHandleRole::Timeline => Ok(Self::Timeline),
            LensHandleRole::QueryResult => Ok(Self::QueryResult),
            LensHandleRole::ActionTarget => Err(Error::InvalidConfig(
                "lens action-target bindings are not selectable read reach".to_string(),
            )),
        }
    }
}

/// Engine-issued read reach over one selected atom. Serialize-only, with no public
/// constructor: the only way to hold one is to have passed
/// [`LensRenderFrame::select_atom`]. It carries an opaque backing token plus locator
/// metadata — never body text, screenshot bytes, a raw URL, authority, or a write
/// chokepoint — and has no conversion into [`LensApprovedAction`],
/// [`LensHostMediatedWrite`], or [`LensGateWriteChokepoint`]. Selection is not approval.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LensReadHandle {
    pub(super) render_id: LensRenderId,
    pub(super) atom_id: LensAtomId,
    pub(super) reach: LensReadReach,
    pub(super) target_kind: LensBackingTargetKind,
    /// A locator the acting principal already resolves under `ScopedRead`, so
    /// disclosing it widens nothing. The stored body it locates is never disclosed.
    pub(super) short_ref: String,
    pub(super) backing_token: LensBackingRefToken,
}

impl LensReadHandle {
    #[must_use]
    pub fn render_id(&self) -> &LensRenderId {
        &self.render_id
    }

    #[must_use]
    pub fn atom_id(&self) -> &LensAtomId {
        &self.atom_id
    }

    #[must_use]
    pub fn reach(&self) -> LensReadReach {
        self.reach
    }

    #[must_use]
    pub fn target_kind(&self) -> LensBackingTargetKind {
        self.target_kind
    }

    #[must_use]
    pub fn short_ref(&self) -> &str {
        &self.short_ref
    }
}

/// What a proved result-set selection actually reaches. Engine-owned output: it holds
/// only engine-issued [`LensReadHandle`]s and the deduplicated row-id echo set, so it
/// has no `Serialize`/`Deserialize` and no client can submit or forge one.
#[derive(Debug, Clone, PartialEq)]
pub enum GeneratedUiResultSetScope {
    Explicit {
        row_ids: BTreeSet<LensResultSetRowId>,
        selected: Vec<LensReadHandle>,
    },
    Predicate {
        predicate: LensReadHandle,
    },
}

/// A pre-gate validated plan. Ticking rows produces one of these and nothing else: it
/// has private fields, no public constructor, no `Deserialize`, and no `approve` or
/// `execute`. Selection is not approval — the receipt is the
/// [`LensHostMediatedWrite`] that [`LensRenderFrame::dispatch_result_set_action`]
/// returns after re-proving every handle.
#[derive(Debug, Clone, PartialEq)]
pub struct GeneratedUiResultSetWritePlan {
    pub(super) emitter: LensPrincipalBinding,
    pub(super) action: GeneratedUiValidatedAction,
    pub(super) scope: GeneratedUiResultSetScope,
}

impl GeneratedUiResultSetWritePlan {
    #[must_use]
    pub fn emitter(&self) -> &LensPrincipalBinding {
        &self.emitter
    }

    #[must_use]
    pub fn action(&self) -> &GeneratedUiValidatedAction {
        &self.action
    }

    #[must_use]
    pub fn scope(&self) -> &GeneratedUiResultSetScope {
        &self.scope
    }
}
