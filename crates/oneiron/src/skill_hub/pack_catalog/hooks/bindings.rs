//! Pack hook bindings: the stored row, its read doors and the owner's bind
//! and enable switches.
//! Entry: `PackHookBinding`. Defines its own items; the binding scan stays in `hooks`, its writes in `install`.

use super::*;

/// A hook's binding: the claim payload under the subscription predicate.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PackHookBinding {
    /// [`HOOK_BINDING_VERSION`].
    pub version: u8,
    /// The CODE entity the binding names; the claim's subject.
    #[serde(with = "crate::serialize::entity_ref")]
    #[schemars(with = "String")]
    pub code: EntityId,
    #[serde(with = "crate::serialize::entity_ref")]
    #[schemars(with = "String")]
    pub owner: EntityId,
    /// The exact pack source the body came from.
    #[serde(with = "crate::serialize::entity_ref")]
    #[schemars(with = "String")]
    pub source: EntityId,
    pub pack: String,
    pub hook: String,
    pub hook_version: String,
    /// BLAKE3 of `body.js`, lowercase hex.
    pub body_hash: String,
    pub selector: HookSelector,
    /// Row state, like `AgentDefinition.enabled`; a rebind never flips it.
    pub enabled: bool,
    /// Whose authority the hook's outcomes run under; `owner` stays the one
    /// who consented to the binding.
    pub author: HookAuthor,
}

impl PackHookBinding {
    /// The binding `hook` of `source` gets, with its id: the CODE entity,
    /// the owner who consents and the author its outcomes run as.
    pub(crate) fn for_hook(
        pack: &str,
        source: EntityId,
        owner: EntityId,
        author: HookAuthor,
        hook: &PackHook,
        enabled: bool,
    ) -> Result<(EntityId, Self)> {
        let material: [&[u8]; 3] = [pack.as_bytes(), hook.name.as_bytes(), &hook.body_hash];
        let code =
            crate::codebase::entity_id_from_hash_material(b"oneiron.pack-hook.v1", &material)?;
        let id = crate::codebase::entity_id_from_hash_material(
            b"oneiron.pack-hook-binding.v1",
            &material,
        )?;
        Ok((
            id,
            Self {
                version: HOOK_BINDING_VERSION,
                code,
                owner,
                source,
                pack: pack.to_owned(),
                hook: hook.name.clone(),
                hook_version: hook.version.clone(),
                body_hash: blake3::Hash::from_bytes(hook.body_hash)
                    .to_hex()
                    .to_string(),
                selector: hook.selector.clone(),
                enabled,
                author,
            },
        ))
    }

    /// The actor the hook's outcomes run as.
    #[must_use]
    pub fn author_id(&self) -> EntityId {
        match &self.author {
            HookAuthor::Owner => self.owner,
            HookAuthor::Agent { agent } => *agent,
            HookAuthor::ForeignActor { actor, .. } => *actor,
        }
    }

    /// That actor's class: the owner is a person; a resident agent acts as
    /// itself, and a publisher as an agent, at its own Grant.
    #[must_use]
    pub const fn author_class(&self) -> HookActorClass {
        match self.author {
            HookAuthor::Owner => HookActorClass::Human,
            HookAuthor::Agent { .. } | HookAuthor::ForeignActor { .. } => HookActorClass::Agent,
        }
    }
}

/// Whether a subscription-predicate claim carries a hook binding rather than
/// a connector-event subscription.
pub(crate) fn is_hook_binding(body: &crate::ClaimBody) -> bool {
    #[derive(Deserialize)]
    struct Version {
        version: u8,
    }
    body.value
        .as_str()
        .and_then(|text| serde_json::from_str::<Version>(text).ok())
        .is_some_and(|row| row.version == HOOK_BINDING_VERSION)
}

impl Vault {
    /// Every live hook binding, enabled or not. The hook runner reads these.
    /// A hub hook whose publisher's Grant was revoked is not live.
    pub fn pack_hook_bindings(&self) -> Result<Vec<(EntityId, PackHookBinding)>> {
        let txn = self.store.env.read_txn()?;
        self.pack_hook_bindings_in_txn(&txn)
    }

    /// Live bindings in the caller's snapshot, including publisher Grant checks.
    pub(crate) fn pack_hook_bindings_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
    ) -> Result<Vec<(EntityId, PackHookBinding)>> {
        let mut live = Vec::new();
        for (id, row) in bindings_in_txn(&self.store, txn)? {
            if let HookAuthor::ForeignActor { grant, .. } = &row.author
                && !crate::consent::standing_grant_is_active_in_txn(&self.store, txn, grant)?
            {
                continue;
            }
            live.push((id, row));
        }
        Ok(live)
    }

    /// The body a binding names, read from its exact pack source and checked
    /// against the binding's hash.
    pub fn pack_hook_body(&self, binding: &PackHookBinding) -> Result<Vec<u8>> {
        let source = self
            .get_pack_source(&binding.source)?
            .ok_or_else(|| invalid("pack source missing"))?;
        let path = format!("{HOOK_DIR}{}/{HOOK_BODY}", binding.hook);
        let body = source
            .files()
            .iter()
            .find(|file| file.path == path)
            .ok_or_else(|| invalid("hook body missing"))?;
        if blake3::hash(&body.content).to_hex().as_str() != binding.body_hash {
            return Err(invalid("hook body does not match its binding"));
        }
        Ok(body.content.clone())
    }

    /// Owner consent binds an installed pack's hooks. A hub install lands
    /// the bytes; content never installs a hook by itself (ARCH-0080 §8).
    pub fn bind_pack_hooks(&self, owner: &AuthenticatedOwner, pack: &str) -> Result<Vec<EntityId>> {
        let bound = self.with_write_txn_grouped(|txn| {
            let receipt = self
                .installed_pack_in_txn(txn, pack)?
                .ok_or_else(|| invalid("pack is not installed"))?;
            let source_id = EntityId::from_hex(&receipt.source_id)?;
            let source = self
                .pack_source_in_txn(txn, &source_id)?
                .ok_or_else(|| invalid("pack source missing"))?;
            self.bind_pack_hooks_in_txn(txn, owner, source_id, &source)
        })?;
        self.verb_hook_bindings_changed();
        Ok(bound)
    }

    /// The owner's dial on one binding. The CODE entity stays.
    pub fn set_pack_hook_enabled(
        &self,
        owner: &AuthenticatedOwner,
        binding: EntityId,
        enabled: bool,
    ) -> Result<()> {
        self.with_write_txn_grouped(|txn| {
            let owner_id = owner.revalidate_in_txn(self, txn)?;
            let (id, mut row) = bindings_in_txn(&self.store, txn)?
                .into_iter()
                .find(|(id, _)| *id == binding)
                .ok_or(Error::EntityNotFound)?;
            let previous = row.clone();
            row.enabled = enabled;
            let envelope = owner_envelope(owner, owner_id, &row.pack, &row.source)?;
            let at = crate::unix_seconds_now();
            self.batch_in()
                .claim_candidate(
                    &id,
                    binding_candidate(&row)?,
                    &envelope,
                    TimeRange { start: at, end: at },
                    at,
                )
                .apply(txn)?;
            crate::runtime_hooks::sync_binding_cursor_in_txn(
                self,
                txn,
                binding,
                Some(&previous),
                &row,
            )?;
            Ok(())
        })?;
        self.verb_hook_bindings_changed();
        Ok(())
    }
}
