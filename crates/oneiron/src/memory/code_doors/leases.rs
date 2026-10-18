use super::*;
use crate::code_symbol::code_symbol_entity_id;
use crate::registry::ENTITY_TYPE_TASK;
use crate::task_verb::{SymbolLease, SymbolLeaseOutcome};

impl Memory<'_> {
    /// `vault.code.symbols.declare`: the caller declares the current symbols
    /// of one repository that a task will touch, through the unchanged
    /// trusted scheduler declaration. An overlap is retained as a waiting
    /// declaration behind the tasks it names; nothing is refused, approved
    /// or landed.
    pub fn code_symbols_declare_as(
        &self,
        owner: &AuthenticatedOwner,
        input: CodeSymbolsDeclareRequest,
    ) -> MemoryResult<CodeSymbolsDeclared> {
        let holder = self.code_owner(owner)?;
        self.code_readable(input.repo, Some(ENTITY_TYPE_CODE_ARTIFACT))?;
        self.code_readable(input.task, Some(ENTITY_TYPE_TASK))?;
        let symbols = self.code_symbol_keys(input.repo, &input.symbols)?;
        let outcome = self.vault.declare_symbols(
            input.task,
            holder,
            symbols,
            input.ttl_seconds,
            self.code_lease_clock(),
        )?;
        let (declaration, blockers) = match outcome {
            SymbolLeaseOutcome::Granted(declaration) => (declaration, Vec::new()),
            SymbolLeaseOutcome::Waiting {
                declaration,
                blockers,
            } => (declaration, blockers),
        };
        self.code_listed(blockers.iter().copied())?;
        Ok(CodeSymbolsDeclared {
            declaration: self.code_lease_view(&declaration)?,
            blockers,
        })
    }

    /// `vault.code.symbols.renew`: extends the caller's own live declaration
    /// of `task` by its declared lifetime. A waiting, expired or other
    /// holder's declaration refuses.
    pub fn code_symbols_renew_as(
        &self,
        owner: &AuthenticatedOwner,
        input: CodeSymbolsTaskRequest,
    ) -> MemoryResult<CodeSymbolLeaseView> {
        let holder = self.code_owner(owner)?;
        self.code_readable(input.task, Some(ENTITY_TYPE_TASK))?;
        let lease = self
            .vault
            .renew_symbols(input.task, holder, self.code_lease_clock())?;
        self.code_lease_view(&lease)
    }

    /// `vault.code.symbols.release`: removes the caller's own declaration of
    /// `task`. It is keyed by task and holder only, with no generation
    /// fence, and it starts no proposal or scheduling.
    pub fn code_symbols_release_as(
        &self,
        owner: &AuthenticatedOwner,
        input: CodeSymbolsTaskRequest,
    ) -> MemoryResult<CodeSymbolsReleased> {
        let holder = self.code_owner(owner)?;
        self.code_readable(input.task, Some(ENTITY_TYPE_TASK))?;
        let released = self.vault.release_symbols(input.task, holder)?;
        Ok(CodeSymbolsReleased {
            task: input.task,
            released,
        })
    }

    /// The CALL behind symbol keys: each named symbol is a current CODE_SYMBOL
    /// id derived from the stored symbol manifest of `repo`, held under its
    /// exact 32-hex spelling. A bare name, a path or a symbol of another
    /// repository or revision refuses; no stable span id is made up.
    fn code_symbol_keys(
        &self,
        repo: EntityId,
        symbols: &[EntityId],
    ) -> MemoryResult<BTreeSet<String>> {
        let manifest = self.vault.get_code_symbol_manifest(&repo)?.ok_or_else(|| {
            MemoryError::not_found("the repository has no stored symbol manifest")
        })?;
        let current = manifest
            .symbols
            .iter()
            .map(|symbol| code_symbol_entity_id(&manifest.repo_ref, symbol))
            .collect::<crate::error::Result<BTreeSet<EntityId>>>()?;
        if let Some(stray) = symbols.iter().find(|symbol| !current.contains(*symbol)) {
            return Err(MemoryError::bad_request(format!(
                "symbol {} is not in the current symbol manifest of the repository",
                stray.to_hex()
            )));
        }
        self.code_listed(symbols.iter().copied())?;
        Ok(symbols.iter().map(EntityId::to_hex).collect())
    }

    /// The CALL behind lease time: the vault host clock, in Unix seconds,
    /// never a request field. Expiry is that time plus the declared lifetime.
    fn code_lease_clock(&self) -> u64 {
        self.vault.now_recorded_at()
    }

    /// The CALL behind the lease reply: the stored declaration as the engine
    /// holds it, with no lease ref, epoch or receipt the engine does not keep.
    fn code_lease_view(&self, lease: &SymbolLease) -> MemoryResult<CodeSymbolLeaseView> {
        let symbols = lease
            .symbols
            .iter()
            .map(|symbol| EntityId::from_hex(symbol))
            .collect::<crate::error::Result<Vec<EntityId>>>()?;
        self.code_listed(symbols.iter().copied())?;
        Ok(CodeSymbolLeaseView {
            task: EntityId::from_hex(&lease.task_ref)?,
            holder: EntityId::from_hex(&lease.holder_ref)?,
            symbols,
            expires_at: lease.expires_at,
            held: lease.held,
        })
    }
}
