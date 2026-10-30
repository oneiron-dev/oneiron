//! Exact outside import (FIX 6871, G7 PR1): one outside commit, fetched
//! exactly and sent through the vault's own authenticated Git door, so the
//! accepted push becomes ONE aggregate candidate through the queue's one
//! existing drain.
//!
//! The order is the contract: admit the caller first (the owner, or the
//! SAME receive admission any push meets: a `git_push` Grant on this repo,
//! or a checkout whose run's Grant covers it); freeze the immutable source
//! claim before any network effect; resolve the exact base with the
//! candidate matcher's own resolver; fetch exactly the named ref into a
//! private scratch store; seed the imported ref with the verified base when
//! it is absent; send the head; prove each send from the door's own
//! receive records. Every send writes its one dispatch fact first, so an
//! unproved send is never sent again by this path: it stays unknown until
//! a receive record resolves it. The door's receive-pack quarantine is the
//! only way the bytes enter the served store; nothing here approves,
//! enqueues, checks, merges or exports, and no owner door changes.

mod host;
mod receive;
mod source;
mod status;
mod types;

pub use host::ExternalGitSourceHost;
pub use types::{
    ExternalImportDoor, ExternalImportLookup, ExternalImportPhase, ExternalImportReceipt,
    ExternalImportRequest, ExternalImportSource, ExternalImportStatus,
};

pub(crate) use source::EXTERNAL_IMPORT_SOURCE_PREDICATE;

use std::path::{Path, PathBuf};

use receive::ImportRefUpdate;
use source::{DispatchRecord, ImportOutcome, ImportStep, ObservationRecord, SourceRecord};
use types::{Malformed, NormalizedSource};

use crate::codebase::RepoRef;
use crate::error::{Error, Result};
use crate::federation::GitPushCaller;
use crate::federation::git_push::ServedPushRepo;
use crate::git_wire::{
    FetchedExternalGit, GitImportFetchOutcome, GitImportPushOutcome, GitOid, GitRefName, GitWire,
};
use crate::{EntityId, Vault};

/// CALL T: the one custody effector an import's source binding is
/// injected through. A binding must also name the source's https origin
/// (`origin:<https origin>`) and the importer (`actor:<id hex>`) among its
/// scopes: a credential reaches only its own host, for the actor it names,
/// and a refused binding never falls back to an anonymous or ambient fetch.
pub const EXTERNAL_IMPORT_FETCH_EFFECTOR: &str = "origin:import-fetch";

/// Where an import's status is answered.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExternalStatusRoute {
    /// The local `vault.code.imports.get` read alone: no outside status or
    /// check write, no sink.
    Local,
}

/// CALL U: an import's status is local only.
pub const EXTERNAL_IMPORT_STATUS_ROUTE: ExternalStatusRoute = ExternalStatusRoute::Local;

/// What the imported ref's current value asks of an import (CALL S).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExternalImportRefPlan {
    /// The ref is absent: seed it with the exact base, then send the head.
    SeedBase,
    /// The ref holds the base: send the head.
    SendHead,
    /// The ref holds the frozen head: done only if a receive proves it.
    AtHead,
    /// The ref holds anything else: this import is held, nothing moves.
    Held,
}

/// CALL S `prepare_external_import_ref`: the plan the imported ref's value
/// `current` asks for, given the import's exact `base` and `head`. No
/// reset, rebase, merge, retry or timeout follows from any answer.
#[must_use]
pub fn prepare_external_import_ref(
    current: Option<&GitOid>,
    base: &GitOid,
    head: &GitOid,
) -> ExternalImportRefPlan {
    match current {
        None => ExternalImportRefPlan::SeedBase,
        Some(value) if value == base => ExternalImportRefPlan::SendHead,
        Some(value) if value == head => ExternalImportRefPlan::AtHead,
        Some(_) => ExternalImportRefPlan::Held,
    }
}

/// The imported ref a request names, or the one the engine derives (CALL
/// S): `refs/imported/<host>/<owner>/<repo>/<ref-or-pr-N>`.
fn imported_ref(
    named: Option<&str>,
    source: &ExternalImportSource,
) -> std::result::Result<GitRefName, Malformed> {
    if let Some(named) = named {
        let named = named.trim();
        if !named.starts_with("refs/imported/") {
            return Err((
                "imported_ref_outside_namespace",
                "imported_ref must be a full refs/imported/... name".to_owned(),
            ));
        }
        return GitRefName::parse_full(named).map_err(|_| {
            (
                "imported_ref_invalid",
                "imported_ref is not a valid full ref name".to_owned(),
            )
        });
    }
    let host = source
        .host
        .strip_prefix("https://")
        .unwrap_or(&source.host)
        .replace(':', "_");
    let path = source
        .repository
        .strip_prefix(&source.host)
        .unwrap_or_default()
        .trim_matches('/');
    let path = path.strip_suffix(".git").unwrap_or(path);
    let leaf = match source.pull_request {
        Some(number) => format!("pr-{number}"),
        None => source
            .source_ref
            .strip_prefix("refs/")
            .unwrap_or(&source.source_ref)
            .to_owned(),
    };
    GitRefName::parse_full(format!("refs/imported/{host}/{path}/{leaf}")).map_err(|_| {
        (
            "imported_ref_underivable",
            "no valid refs/imported/ name derives from this source: name imported_ref".to_owned(),
        )
    })
}

fn malformed((code, detail): Malformed) -> Error {
    Error::Refused(format!("{code}: {detail}"))
}

fn refused(code: &str) -> Error {
    Error::Refused(format!("{code}: this outside import is refused"))
}

/// The verb an agent's Grant must list to import under its granter's
/// source binding (the delegated path).
pub(crate) const EXTERNAL_IMPORT_CREATE_VERB: &str = "vault.code.imports.create";

/// Whether an importer acts under a standing Grant from a binding's actor.
enum DelegatedBinding {
    /// A Grant from the bound actor lists the verb and stands now.
    Stands,
    /// Such a Grant stood but its pact membership lapsed.
    Lapsed,
    /// No such Grant.
    Absent,
}

/// One send an import makes: its step and exact ref update.
struct ImportSend {
    step: ImportStep,
    update: ImportRefUpdate,
}

/// What one create invocation carries past admission.
struct ImportCall<'c> {
    host: &'c dyn ExternalGitSourceHost,
    wire: GitWire<'c>,
    lookup: ExternalImportLookup,
    import: EntityId,
    attempt: EntityId,
    importer: EntityId,
    store: String,
}

impl Vault {
    /// The served repository `repo`'s directory, once `caller` is admitted
    /// to push into it over `door` by the one receive decision any push
    /// meets, read in a fresh snapshot.
    ///
    /// # Errors
    /// [`crate::error::CodeError::GitPushCapabilityRequired`] naming the
    /// missing capability; a malformed door; a store failure.
    pub(crate) fn admit_external_import(
        &self,
        caller: &GitPushCaller,
        repo: &str,
        door: &ExternalImportDoor,
    ) -> Result<PathBuf> {
        let ticket = door.ticket().map_err(malformed)?;
        let dir = crate::origin::smart_http::origin_repo_dir(self, repo)?;
        let served = ServedPushRepo::resolve(self, repo, &dir);
        let txn = self.store.env.read_txn()?;
        self.admit_git_receive_pack_in_txn(&txn, caller, &served, ticket.as_deref())?;
        Ok(dir)
    }

    /// [`Self::admit_external_import`] that also answers the Grant a
    /// checkout's admission stood on (FIX 7591): a member's status read is
    /// judged under that one Grant again; `None` for any other arm.
    ///
    /// # Errors
    /// As [`Self::admit_external_import`].
    pub(crate) fn admit_external_import_bound(
        &self,
        caller: &GitPushCaller,
        repo: &str,
        door: &ExternalImportDoor,
    ) -> Result<Option<EntityId>> {
        let ticket = door.ticket().map_err(malformed)?;
        let dir = crate::origin::smart_http::origin_repo_dir(self, repo)?;
        let served = ServedPushRepo::resolve(self, repo, &dir);
        let txn = self.store.env.read_txn()?;
        let stamp = self
            .admit_git_receive_pack_in_txn(&txn, caller, &served, ticket.as_deref())?
            .into_stamp();
        Ok(stamp.is_checkout().then(|| stamp.grant()).flatten())
    }

    /// The object store `code_repo`'s stored local folder proves, refused
    /// unless it is the served directory `dir`'s own.
    ///
    /// # Errors
    /// A refusal naming the mismatch, or a store failure.
    pub(crate) fn external_import_store(
        &self,
        wire: &GitWire<'_>,
        code_repo: EntityId,
        dir: &Path,
    ) -> Result<String> {
        let mismatch = || {
            Error::Refused(
                "external_import_code_repo_mismatch: code_repo is not the CODE anchor of this \
                 served repository"
                    .to_owned(),
            )
        };
        let store = wire.repository_identity(dir)?.as_hex();
        let artifact = self.get_code_artifact(&code_repo)?.ok_or_else(mismatch)?;
        let Ok(RepoRef::LocalFolder { path, .. }) = RepoRef::parse(&artifact.repo_ref) else {
            return Err(mismatch());
        };
        match wire.repository_identity(Path::new(&path)) {
            Ok(anchored) if anchored.as_hex() == store => Ok(store),
            _ => Err(mismatch()),
        }
    }

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

    /// Writes one fact of this attempt; answers `Ok(())` so a hold reads as
    /// the step's end.
    fn observe(
        &self,
        call: &ImportCall<'_>,
        step: ImportStep,
        outcome: ImportOutcome,
        reason: &str,
    ) -> Result<()> {
        let record = ObservationRecord::new(
            call.import,
            call.attempt,
            step,
            outcome,
            self.now_recorded_at(),
        )
        .because(reason);
        self.put_external_import_observation(call.import, &record)
    }

    /// Whether the custody secret `binding` may carry this import's fetch
    /// (CALL T, the actor-bound source credential): a binding for
    /// [`EXTERNAL_IMPORT_FETCH_EFFECTOR`] whose scopes name the source's
    /// https `origin` and ONE actor's principal id (`actor:<id hex>`), that
    /// the door would release now. The custody register and bind doors fill
    /// the binder's actor on a binding that names none (FIX 7592), so a
    /// binding that still names no actor serves no one: `binding_actor_missing`
    /// (source-credential isolation; its owner binds it again, as themselves).
    /// The importer is admitted when it is the bound actor, or an agent
    /// acting under a Grant FROM the bound actor that lists
    /// [`EXTERNAL_IMPORT_CREATE_VERB`] and stands now (the delegated path,
    /// CALLS "G7 PR1 delegated binding"). `Err` names the code and the fix;
    /// nothing falls back to an anonymous or ambient fetch.
    ///
    /// # Errors
    /// A store, fold or clock failure.
    fn external_import_binding_admits(
        &self,
        binding: &str,
        origin: &str,
        importer: EntityId,
    ) -> Result<std::result::Result<(), (&'static str, String)>> {
        let fix = format!(
            "bind a credential for {EXTERNAL_IMPORT_FETCH_EFFECTOR} whose scopes name \
             origin:{origin} and actor:{}",
            importer.to_hex()
        );
        {
            let txn = self.store.env.read_txn()?;
            let custody =
                match crate::secret_custody::resolve_secret_ref_in_txn(&self.store, &txn, binding)?
                {
                    Some(id) => crate::secret_custody::read_secret_custody_admission_in_txn(
                        &self.store,
                        &txn,
                        &id,
                    )?,
                    None => None,
                };
            let Some(custody) = custody else {
                return Ok(Err(("binding_not_found", fix)));
            };
            let Some(scopes) = custody
                .binding_for(EXTERNAL_IMPORT_FETCH_EFFECTOR)
                .map(|bound| bound.scopes.clone())
            else {
                return Ok(Err(("binding_not_for_import_fetch", fix)));
            };
            if !scopes.contains(&format!("origin:{origin}")) {
                return Ok(Err(("binding_not_for_this_host", fix)));
            }
            let actors: Vec<&str> = scopes
                .iter()
                .filter_map(|scope| scope.strip_prefix("actor:"))
                .collect();
            let bound = match actors.as_slice() {
                [] => {
                    return Ok(Err((
                        "binding_actor_missing",
                        format!("a source credential names the actor it serves: {fix}"),
                    )));
                }
                [one] => match EntityId::from_hex(one) {
                    Ok(actor) => actor,
                    Err(_) => return Ok(Err(("binding_actor_malformed", fix))),
                },
                _ => {
                    return Ok(Err((
                        "binding_names_more_than_one_actor",
                        format!("a source credential names one actor: {fix}"),
                    )));
                }
            };
            let owners = crate::policy_model::owners_in_txn(self, &txn)?;
            if bound != importer {
                match self.delegated_import_binding_in_txn(&txn, &owners, bound, importer)? {
                    DelegatedBinding::Stands => {}
                    DelegatedBinding::Lapsed => {
                        let lapse = crate::authority::PACT_STANDING_LAPSED;
                        return Ok(Err((
                            "pact_standing_lapsed",
                            lapse
                                .strip_prefix("pact_standing_lapsed: ")
                                .unwrap_or(lapse)
                                .to_owned(),
                        )));
                    }
                    DelegatedBinding::Absent => {
                        let kind = self.bound_actor_kind_in_txn(&txn, &owners, bound)?;
                        return Ok(Err((
                            "binding_bound_to_another_actor",
                            format!(
                                "this source credential is bound to another actor (a {kind}); \
                                 {fix}, or act under a standing Grant from that actor that \
                                 lists {EXTERNAL_IMPORT_CREATE_VERB}"
                            ),
                        )));
                    }
                }
            }
        }
        if self
            .check_secret_at_door(binding, EXTERNAL_IMPORT_FETCH_EFFECTOR)
            .is_err()
        {
            return Ok(Err(("binding_refused_at_door", fix)));
        }
        Ok(Ok(()))
    }

    /// The delegated path: an agent `importer` acting under a Grant FROM
    /// the binding's actor `bound` that lists
    /// [`EXTERNAL_IMPORT_CREATE_VERB`], stands by the Grant rule now, and
    /// on a shared vault keeps its pact membership. A Grant that fails on
    /// its pact membership alone is the lapse.
    fn delegated_import_binding_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        owners: &[EntityId],
        bound: EntityId,
        importer: EntityId,
    ) -> Result<DelegatedBinding> {
        let now = self.instant_in_txn(txn)?.secs();
        let mut lapsed = false;
        for standing in self.agent_grants_in_txn(txn)? {
            if standing.delegated_by != bound
                || !standing.stands_for(importer, EXTERNAL_IMPORT_CREATE_VERB, now, owners)
            {
                continue;
            }
            if standing.stands_in_txn(
                self,
                txn,
                importer,
                EXTERNAL_IMPORT_CREATE_VERB,
                now,
                owners,
            ) {
                return Ok(DelegatedBinding::Stands);
            }
            lapsed = true;
        }
        Ok(if lapsed {
            DelegatedBinding::Lapsed
        } else {
            DelegatedBinding::Absent
        })
    }

    /// What kind of principal a binding's actor is: an owner, a person, an
    /// agent, or no live principal.
    fn bound_actor_kind_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        owners: &[EntityId],
        actor: EntityId,
    ) -> Result<&'static str> {
        if owners.contains(&actor) {
            return Ok("vault owner");
        }
        if crate::consent::person_is_live_in_txn(self, txn, &actor)? {
            return Ok("person");
        }
        Ok(
            match crate::vault::live_entity_row_in_txn(&self.store, txn, &actor)? {
                crate::vault::LiveEntityRow::Live {
                    entity_type: crate::registry::ENTITY_TYPE_AGENT_DEF,
                    ..
                } => "agent",
                _ => "principal that is not live",
            },
        )
    }
}

/// The reason prefix a host's fetch refusal names a redirect target with.
pub const REDIRECT_REFUSED: &str = "redirect_refused:";
