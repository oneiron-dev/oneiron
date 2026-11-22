//! One create's drive (FIX 6871): the admitted request to its receipt,
//! the exact base, the fetch, the seed and the head send, each send proved
//! from the door's own receive records.

use super::*;

impl Vault {
    /// `vault.code.imports.create`'s engine half: admits `host`'s caller,
    /// freezes the source, resolves the exact base, fetches, seeds, sends
    /// the head and proves each send, answering the import's receipt. A
    /// hold, a refused fetch or an unproved send is a receipt whose status
    /// names it; a refusal before the source claim is an error.
    ///
    /// # Errors
    /// An admission refusal, a malformed request, a source that differs
    /// from its frozen claim, a redirect off the source host (naming its
    /// target), or a store or object store failure.
    pub(crate) fn import_external_change(
        &self,
        host: &dyn ExternalGitSourceHost,
        request: &ExternalImportRequest,
    ) -> Result<ExternalImportReceipt> {
        let normalized = request.source.normalized().map_err(malformed)?;
        let dir = self.admit_external_import(host.caller(), &request.repo, &request.door)?;
        host.revalidate()?;
        let wire = GitWire::new(self)?;
        let store = self.external_import_store(&wire, request.code_repo, &dir)?;
        let importer = host.caller().principal();
        let name =
            imported_ref(request.imported_ref.as_deref(), &normalized.source).map_err(malformed)?;
        let record = SourceRecord::new(
            importer,
            request.code_repo,
            &request.repo,
            &store,
            &normalized.source,
            request.base_revision,
            name.as_str(),
        );
        let now = self.now_recorded_at();
        let import = self
            .with_write_txn_grouped(|txn| {
                // An imported ref is never rebound from an unrelated source.
                let bound =
                    self.external_import_ref_binding_in_txn(txn, request.code_repo, name.as_str())?;
                if bound.as_ref().is_some_and(|bound| !bound.binds(&record)) {
                    return Ok(Err("external_import_ref_bound_to_another_source"));
                }
                let import = self.put_external_import_source_in_txn(txn, &record, now)?;
                if import.is_ok() && bound.is_none() {
                    self.put_external_import_ref_binding_in_txn(txn, &record, now)?;
                }
                Ok(import)
            })?
            .map_err(refused)?;
        let call = ImportCall {
            host,
            wire,
            lookup: ExternalImportLookup {
                repo: request.repo.clone(),
                code_repo: request.code_repo,
                import,
                door: request.door.clone(),
            },
            import,
            attempt: self.new_entity_id()?,
            importer,
            store,
        };
        self.drive_external_import(&call, request, &normalized, &name, &dir)?;
        self.external_import_status(&call.store, &request.repo, request.code_repo, import)?
            .map(|projection| projection.receipt)
            .ok_or(Error::EntityNotFound)
    }

    /// Steps 3 to 6 of one create: the exact base, the reconciliation of
    /// saved sends, the imported ref's plan, the fetch, the seed and the
    /// head. Each hold writes its fact and stops; none is an error.
    fn drive_external_import(
        &self,
        call: &ImportCall<'_>,
        request: &ExternalImportRequest,
        normalized: &NormalizedSource,
        name: &GitRefName,
        dir: &Path,
    ) -> Result<()> {
        let (base, head) = (&normalized.base, &normalized.head);
        let served = match call.wire.open_repo(
            RepoRef::LocalFolder {
                path: dir.to_string_lossy().into_owned(),
                commit: base.as_str().to_owned(),
            },
            dir,
        ) {
            Ok(served) => served,
            Err(_) => {
                return self.observe(
                    call,
                    ImportStep::Base,
                    ImportOutcome::Held,
                    "base_commit_not_in_store",
                );
            }
        };
        if let Err(reason) =
            self.external_import_base(&call.wire, &served, request.base_revision, base)?
        {
            return self.observe(call, ImportStep::Base, ImportOutcome::Held, &reason);
        }
        let seed = ImportSend {
            step: ImportStep::Seed,
            update: ImportRefUpdate {
                name: name.clone(),
                old: None,
                new: base.clone(),
            },
        };
        let send_head = ImportSend {
            step: ImportStep::Head,
            update: ImportRefUpdate {
                name: name.clone(),
                old: Some(base.clone()),
                new: head.clone(),
            },
        };
        let (seed_sent, head_sent) = {
            let txn = self.store.env.read_txn()?;
            (
                self.external_import_dispatch_in_txn(&txn, call.import, ImportStep::Seed)?
                    .is_some(),
                self.external_import_dispatch_in_txn(&txn, call.import, ImportStep::Head)?
                    .is_some(),
            )
        };
        // Once a send was dispatched, create only reconciles: it never
        // sends an unproved effect again.
        if head_sent
            || (seed_sent
                && self
                    .received_import_update(&call.store, &seed.update, Some(call.importer))?
                    .is_none())
        {
            return Ok(());
        }
        let current = call.wire.read_ref(&served, name)?;
        let plan = match prepare_external_import_ref(current.as_ref(), base, head) {
            ExternalImportRefPlan::SeedBase if seed_sent => ExternalImportRefPlan::Held,
            ExternalImportRefPlan::AtHead
                if self
                    .received_import_update(&call.store, &send_head.update, Some(call.importer))?
                    .is_some() =>
            {
                return Ok(());
            }
            ExternalImportRefPlan::AtHead => ExternalImportRefPlan::Held,
            plan => plan,
        };
        if plan == ExternalImportRefPlan::Held {
            return self.observe(
                call,
                ImportStep::Base,
                ImportOutcome::Held,
                "imported_ref_holds_another_commit",
            );
        }
        let Some(fetched) = self.fetch_external_import(call, request, normalized)? else {
            return Ok(());
        };
        // Its LFS objects first, so the door admits the pointers it sends.
        self.install_external_import_lfs(call, request, normalized, &fetched)?;
        if plan == ExternalImportRefPlan::SeedBase
            && (!self.send_external_import(call, &fetched, &seed)?
                || self
                    .proved_import_update(&call.wire, &served, &seed.update, call.importer)?
                    .is_none())
        {
            return Ok(());
        }
        if self.send_external_import(call, &fetched, &send_head)? {
            // The proof is read now so the receipt names it; an unproved
            // head stays unknown until a receive record resolves it.
            self.proved_import_update(&call.wire, &served, &send_head.update, call.importer)?;
        }
        Ok(())
    }

    /// The exact fetch: the binding judged first, then the host's fetch.
    /// `None` after a refused, moved or failed fetch, whose fact is
    /// written; a redirect off the source host is a typed refusal naming
    /// its target.
    fn fetch_external_import(
        &self,
        call: &ImportCall<'_>,
        request: &ExternalImportRequest,
        normalized: &NormalizedSource,
    ) -> Result<Option<FetchedExternalGit>> {
        if let Some(binding) = request.source_binding.as_deref()
            && let Err((code, message)) = self.external_import_binding_admits(
                binding,
                &normalized.source.host,
                call.importer,
            )?
        {
            self.observe(call, ImportStep::Fetch, ImportOutcome::Refused, code)?;
            return Err(Error::Refused(format!("{code}: {message}")));
        }
        let fetched = call.host.fetch_exact(
            &call.wire,
            &normalized.source,
            request.source_binding.as_deref(),
        );
        match fetched {
            Ok(GitImportFetchOutcome::Fetched(fetched)) => {
                self.observe(call, ImportStep::Fetch, ImportOutcome::Fetched, "fetched")?;
                Ok(Some(fetched))
            }
            Ok(GitImportFetchOutcome::Moved) => {
                self.observe(
                    call,
                    ImportStep::Fetch,
                    ImportOutcome::Moved,
                    "source_moved",
                )?;
                Ok(None)
            }
            Ok(GitImportFetchOutcome::Refused(reason)) => {
                self.observe(call, ImportStep::Fetch, ImportOutcome::Refused, &reason)?;
                match reason.strip_prefix(REDIRECT_REFUSED) {
                    Some(target) => Err(Error::Refused(format!(
                        "external_import_redirect_refused: the source redirects to {target}, \
                         off its own https host; import from that repository instead"
                    ))),
                    None => Ok(None),
                }
            }
            Err(error) => {
                self.observe(
                    call,
                    ImportStep::Fetch,
                    ImportOutcome::Refused,
                    "fetch_failed",
                )?;
                Err(error)
            }
        }
    }

    /// Sends `send` once: its dispatch fact first, then the host's push,
    /// then the observed transport outcome. Answers whether the door took
    /// it; a send another call already dispatched is never sent again.
    fn send_external_import(
        &self,
        call: &ImportCall<'_>,
        fetched: &FetchedExternalGit,
        send: &ImportSend,
    ) -> Result<bool> {
        let dispatch = DispatchRecord::new(
            call.import,
            send.step,
            send.update.name.as_str(),
            send.update.old.as_ref().map(GitOid::as_str),
            send.update.new.as_str(),
        );
        let now = self.now_recorded_at();
        if !self.with_write_txn_grouped(|txn| {
            self.put_external_import_dispatch_in_txn(txn, call.import, &dispatch, now)
        })? {
            return Ok(false);
        }
        let outcome = call.host.push_exact(
            &call.wire,
            fetched,
            &call.lookup,
            &send.update.name,
            send.update.old.as_ref(),
            &send.update.new,
        );
        let (outcome, reason, applied) = match outcome {
            Ok(GitImportPushOutcome::Applied) => {
                (ImportOutcome::Applied, "applied".to_owned(), true)
            }
            Ok(GitImportPushOutcome::Rejected(reason)) => (ImportOutcome::Rejected, reason, false),
            Ok(GitImportPushOutcome::Unknown(reason)) => (ImportOutcome::Unknown, reason, false),
            Err(_) => (ImportOutcome::Unknown, "send_failed".to_owned(), false),
        };
        self.observe(call, send.step, outcome, &reason)?;
        Ok(applied)
    }
}
