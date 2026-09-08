//! Read phase of the render frame: backing refs and read handles.

use crate::claim::ScopedRead;
use crate::error::{Error, Result};
use crate::lens::generated_ui::GeneratedUiRender;
use crate::lens::validate::validate_lens_collection_len;
use crate::lens::wire_ids::{
    LensAtomId, LensBackingRefId, LensHandleName, LensHandleRole, LensRenderId,
};
use crate::registry::ENTITY_TYPE_CLAIM;

use super::{
    GeneratedUiAgentCallback, LensAtomSelectionRequest, LensBackingRefToken, LensBackingTarget,
    LensBackingTargetKind, LensHostBackingRef, LensPrincipalBinding, LensReadHandle, LensReadReach,
};

#[derive(Debug, Clone)]
pub struct LensRenderFrame {
    pub(super) render_id: LensRenderId,
    pub(super) principal: LensPrincipalBinding,
    pub(super) backing_refs: Vec<LensHostBackingRef>,
}

impl LensRenderFrame {
    #[must_use]
    pub fn new(render_id: LensRenderId, principal: LensPrincipalBinding) -> Self {
        Self {
            render_id,
            principal,
            backing_refs: Vec::new(),
        }
    }

    #[must_use]
    pub fn render_id(&self) -> &LensRenderId {
        &self.render_id
    }

    #[must_use]
    pub fn principal(&self) -> &LensPrincipalBinding {
        &self.principal
    }

    #[must_use]
    pub fn backing_refs(&self) -> &[LensHostBackingRef] {
        &self.backing_refs
    }

    pub fn mint_backing_ref(
        &mut self,
        scoped_read: &ScopedRead<'_>,
        handle: LensHandleName,
        role: LensHandleRole,
        target: LensBackingTarget,
    ) -> Result<LensBackingRefToken> {
        self.ensure_scoped_read_actor(scoped_read)?;
        if self
            .backing_refs
            .iter()
            .any(|backing_ref| backing_ref.handle == handle)
        {
            return Err(Error::InvalidConfig(
                "lens backing handle must be host-bound at most once per render".to_string(),
            ));
        }
        Self::ensure_target_readable(scoped_read, &target)?;

        let ref_id = LensBackingRefId::new(format!("ref-{}", self.backing_refs.len()))?;
        let token = LensBackingRefToken {
            render_id: self.render_id.clone(),
            ref_id,
        };
        self.backing_refs.push(LensHostBackingRef {
            token: token.clone(),
            handle,
            role,
            target,
        });
        Ok(token)
    }

    pub fn resolve_backing_ref_token(
        &self,
        scoped_read: &ScopedRead<'_>,
        token: &LensBackingRefToken,
    ) -> Result<LensHostBackingRef> {
        self.ensure_scoped_read_actor(scoped_read)?;
        if token.render_id != self.render_id {
            return Err(Error::InvalidConfig(
                "lens backing ref token belongs to a different render".to_string(),
            ));
        }
        let backing_ref = self
            .backing_refs
            .iter()
            .find(|backing_ref| backing_ref.token.ref_id == token.ref_id)
            .ok_or_else(|| {
                Error::InvalidConfig("lens backing ref token was not host-minted".to_string())
            })?;
        Self::ensure_target_readable(scoped_read, &backing_ref.target)?;
        Ok(backing_ref.clone())
    }

    /// Turn a client atom selection into engine-issued read reach.
    ///
    /// The request names no target. The node is looked up in the exact render this
    /// frame emitted, the named handle must be one that node itself advertised, and the
    /// returned token is copied off this frame's host backing row — never synthesized
    /// from client data. The target is re-hydrated under the acting principal's
    /// selected read key before any handle is issued.
    pub fn select_atom(
        &self,
        scoped_read: &ScopedRead<'_>,
        render: &GeneratedUiRender,
        request: &LensAtomSelectionRequest,
    ) -> Result<LensReadHandle> {
        self.ensure_scoped_read_actor(scoped_read)?;
        self.ensure_render_is_ours(render)?;
        if request.card_id != render.card_id {
            return Err(Error::InvalidConfig(
                "lens atom selection must name the card it was rendered from".to_string(),
            ));
        }

        let row = self
            .backing_refs
            .iter()
            .find(|backing_ref| backing_ref.handle == request.handle)
            .ok_or_else(|| {
                Error::InvalidConfig(
                    "lens selection handle was not host-bound for this render".to_string(),
                )
            })?;
        let resolved = self.resolve_backing_ref_token(scoped_read, &row.token)?;
        self.issue_read_handle(render, &request.atom_id, &resolved)
    }

    /// The handle that selecting `atom_id` onto `resolved` proves *right now*.
    ///
    /// Issuance and re-resolution share this one derivation, so every field a handle
    /// carries is engine-derived at both ends and none of them can drift apart. Reach
    /// is derived through [`LensReadReach`], which has no action-target variant: an
    /// action-target row yields no handle at all rather than a read handle over it.
    fn issue_read_handle(
        &self,
        render: &GeneratedUiRender,
        atom_id: &LensAtomId,
        resolved: &LensHostBackingRef,
    ) -> Result<LensReadHandle> {
        // The host row names the handle; the client's copy never gets a vote.
        let role = Self::declared_binding_role(render, atom_id, &resolved.handle)?;
        if role != resolved.role {
            return Err(Error::InvalidConfig(
                "lens selection handle role must match its host backing row".to_string(),
            ));
        }
        Ok(LensReadHandle {
            render_id: self.render_id.clone(),
            atom_id: atom_id.clone(),
            reach: LensReadReach::try_from(role)?,
            target_kind: resolved.target.kind(),
            short_ref: resolved.target.short_ref(),
            backing_token: resolved.token.clone(),
        })
    }

    /// Re-resolve an issued read handle at use time.
    ///
    /// An issued handle is honored only when re-deriving it against the *current*
    /// render, backing table, and scope reproduces it exactly: the presented handle is
    /// compared whole against a freshly issued one, so its recorded short ref, target
    /// kind, and reach are re-proved rather than trusted. A switched principal, a
    /// target that stopped hydrating, a render revision that no longer advertises the
    /// binding at the same role, and a same-named row that a later frame minted over a
    /// *different* target all fail here rather than letting an old handle widen — or
    /// silently relocate — what it reaches.
    pub fn resolve_read_handle(
        &self,
        scoped_read: &ScopedRead<'_>,
        render: &GeneratedUiRender,
        handle: &LensReadHandle,
    ) -> Result<LensHostBackingRef> {
        self.ensure_scoped_read_actor(scoped_read)?;
        self.ensure_render_is_ours(render)?;
        let resolved = self.resolve_backing_ref_token(scoped_read, &handle.backing_token)?;
        if self.issue_read_handle(render, &handle.atom_id, &resolved)? != *handle {
            return Err(Error::InvalidConfig(
                "lens read handle no longer matches the reach this render issues".to_string(),
            ));
        }
        Ok(resolved)
    }

    /// Carry proven selections into a model-round-trip callback as *context*.
    ///
    /// Every handle is re-resolved through this frame before it is attached, so a
    /// callback can never carry reach that selection no longer proves. Context is not
    /// approval: the callback still names no gated verb, and a later mutation resolves
    /// its own action target through the action backchannel.
    pub fn with_selected_context(
        &self,
        scoped_read: &ScopedRead<'_>,
        render: &GeneratedUiRender,
        callback: GeneratedUiAgentCallback,
        selected: Vec<LensReadHandle>,
    ) -> Result<GeneratedUiAgentCallback> {
        validate_lens_collection_len("lens selected read context", selected.len())?;
        if callback.source_card_id != self.render_id {
            return Err(Error::InvalidConfig(
                "lens selected context must ride a callback from this render frame".to_string(),
            ));
        }
        for handle in &selected {
            self.resolve_read_handle(scoped_read, render, handle)?;
        }
        Ok(GeneratedUiAgentCallback {
            selected_context: selected,
            ..callback
        })
    }

    /// The role a render node itself advertised for one handle name. A node must
    /// declare the handle exactly once: a duplicated binding is ambiguous about which
    /// reach was offered, so it resolves to nothing.
    fn declared_binding_role(
        render: &GeneratedUiRender,
        atom_id: &LensAtomId,
        handle: &LensHandleName,
    ) -> Result<LensHandleRole> {
        let node = render
            .nodes
            .iter()
            .find(|node| &node.id == atom_id)
            .ok_or_else(|| {
                Error::InvalidConfig(
                    "lens atom selection must name an element of this render".to_string(),
                )
            })?;
        let mut declared = node
            .bindings
            .iter()
            .filter(|binding| &binding.name == handle);
        let binding = declared.next().ok_or_else(|| {
            Error::InvalidConfig(
                "lens atom selection must name a handle the element advertised".to_string(),
            )
        })?;
        if declared.next().is_some() {
            return Err(Error::InvalidConfig(
                "lens atom bindings must declare each handle at most once".to_string(),
            ));
        }
        Ok(binding.role)
    }

    pub(super) fn ensure_render_is_ours(&self, render: &GeneratedUiRender) -> Result<()> {
        if render.card_id == self.render_id {
            return Ok(());
        }
        Err(Error::InvalidConfig(
            "generated-ui render must belong to this render frame".to_string(),
        ))
    }

    pub(super) fn ensure_scoped_read_actor(&self, scoped_read: &ScopedRead<'_>) -> Result<()> {
        if scoped_read.actor_key() == self.principal.selected_read_key() {
            return Ok(());
        }
        Err(Error::InvalidConfig(
            "lens render must use the acting principal's selected read key".to_string(),
        ))
    }

    pub(super) fn ensure_target_readable(
        scoped_read: &ScopedRead<'_>,
        target: &LensBackingTarget,
    ) -> Result<()> {
        let Some(hydrated) =
            scoped_read.hydrate_short_id(target.short_id(), target.content_hash())?
        else {
            return Err(Error::InvalidConfig(
                "lens backing short ref is not readable by the acting principal".to_string(),
            ));
        };
        if hydrated.id != *target.entity_id() || hydrated.body.is_none() {
            return Err(Error::InvalidConfig(
                "lens backing short ref does not resolve to the target entity".to_string(),
            ));
        }
        match (target.kind(), hydrated.entity_type) {
            (LensBackingTargetKind::Claim, ENTITY_TYPE_CLAIM) => {}
            (LensBackingTargetKind::Claim, _) => {
                return Err(Error::InvalidConfig(
                    "lens claim backing ref target must resolve to a claim entity".to_string(),
                ));
            }
            (LensBackingTargetKind::Entity, ENTITY_TYPE_CLAIM) => {
                return Err(Error::InvalidConfig(
                    "lens entity backing ref target must not resolve to a claim entity".to_string(),
                ));
            }
            (LensBackingTargetKind::Entity, _) => {}
        }
        Ok(())
    }
}
