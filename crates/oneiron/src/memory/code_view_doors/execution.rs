//! Native owner build/verify execution; result admission stays in the engine.
use super::*;
use crate::build_cache::{ActionResult, ArtifactVersionRef, BuildCacheResult};
use crate::blob_artifact::{BlobArtifactBody, BlobVersionProvenance};
use crate::checkout::CheckoutTaskClass;
use crate::temporal::TimeRange;
use crate::WriteActor;

impl Memory<'_> {
    pub fn code_view_build_as(&self, owner: &AuthenticatedOwner, input: CodeViewBuildRequest)
        -> MemoryResult<CodeCacheOutcome> {
        self.view_build(owner, input, false)
    }

    pub fn code_cache_reuse_as(&self, owner: &AuthenticatedOwner, input: CodeViewBuildRequest)
        -> MemoryResult<CodeCacheOutcome> {
        self.view_build(owner, input, true)
    }

    fn view_build(&self, owner: &AuthenticatedOwner, input: CodeViewBuildRequest, reuse_only: bool)
        -> MemoryResult<CodeCacheOutcome> {
        let (set, receipt, snapshot) = self.admitted_view(owner, &input.view)?;
        let action = build_action(&snapshot, &input.spec)?;
        for output in action.declared_outputs() {
            if receipt.files.contains_key(output.as_str()) {
                return Err(MemoryError::bad_request("build output overlaps an input"));
            }
        }
        let frozen = set.build_action(input.view.view, &action).map_err(cache_error)?;
        let actual = digest(frozen.reapi_digest().map_err(cache_error)?);
        if actual != input.action_digest {
            return Err(MemoryError::bad_request("action_digest does not match the current view inputs"));
        }
        let key = frozen.action_key().map_err(cache_error)?;
        let cache = BuildCache::for_owner(self.vault, owner, &input.view.account.to_hex())
            .map_err(cache_error)?;
        match cache.get(&key) {
            Ok(None) if reuse_only => return Ok(outcome(CodeCacheState::Miss, None)),
            Ok(_) => (),
            Err(BuildCacheError::TaintedResult { .. } | BuildCacheError::ArtifactUnavailable { .. }) =>
                return Ok(outcome(CodeCacheState::Denied, None)),
            Err(error) => return Err(cache_error(error)),
        }
        let class = match input.spec.class {
            CodeBuildClass::Build => CheckoutTaskClass::Build,
            CodeBuildClass::Verify => CheckoutTaskClass::Verify,
        };
        let leg = set.build_pinned(input.view.view, &cache, class, &action, &key, |path, _| {
            if reuse_only {
                return Err(BuildCacheError::InvalidAction("cached entry is no longer reusable"));
            }
            // A native build is the owner's own host action, never a foreign
            // code sandbox. Nothing from the daemon environment is inherited.
            {
                let txn = self.vault.store.env.read_txn().map_err(Error::from)?;
                cache.admit_account_in_txn(&txn)?;
                if !input.spec.secret_taint_refs.is_empty()
                    && crate::secret_rotation::taint_state_for_refs_in_txn(
                        &self.vault.store, &txn, &input.spec.engine_taint_refs(),
                    )? != crate::secret_rotation::ArtifactTaintState::TaintedLive
                {
                    return Err(BuildCacheError::InvalidAction("declared secret generation is stale"));
                }
            }
            let output = oneiron_spawn::command(&input.spec.argv[0])
                .args(&input.spec.argv[1..]).current_dir(path).env_clear()
                .envs(&input.spec.env_allowlist).output()?;
            let mut outputs = BTreeMap::new();
            for declared in frozen.declared_outputs() {
                outputs.insert(declared.clone(), crate::code_view::read_view_file(path, declared.as_str())?);
            }
            self.store_build_exhaust(owner, &input, &key.to_hex(), output, outputs)
        }).map_err(cache_error)?;
        Ok(outcome(if leg.receipt.cache_hit { CodeCacheState::Hit } else { CodeCacheState::Miss },
            Some(self.build_entry(&leg.cached, input.view.account, leg.reusable)?)))
    }

    fn store_build_exhaust(&self, owner: &AuthenticatedOwner, input: &CodeViewBuildRequest,
        action: &str, output: std::process::Output,
        outputs: BTreeMap<DeclaredOutputPath, Vec<u8>>) -> BuildCacheResult<ActionResult> {
        let build_id = EntityId::now();
        let stored = self.with_actor_content_write_txn(|content| {
            owner.revalidate_in_txn(self.vault, content.read())?;
            let writer = WriteActor::new(self.actor, self.actor_class);
            let at = self.vault.store.clock.now_recorded_at();
            let occurred = TimeRange { start: at, end: at };
            let provenance = BlobVersionProvenance::AgentRun { run_ref: build_id.to_hex() };
            let mut store = |name: &str, bytes: &[u8]| -> MemoryResult<ArtifactVersionRef> {
                let id = EntityId::now();
                let body = BlobArtifactBody::new(name, "application/octet-stream")
                    .with_secret_taint_refs(input.spec.engine_taint_refs());
                let body = crate::blob_artifact::encode_blob_artifact_body(&body)?;
                content.apply_batch(self.vault.batch_in().put(
                    &id, crate::registry::ENTITY_TYPE_BLOB_ARTIFACT, occurred, at, &body,
                ))?;
                let version = content.update_artifact(id, |txn| {
                    self.vault.append_blob_artifact_version_in_txn(txn, &id, bytes,
                        &provenance, writer, occurred, at)
                })?;
                ArtifactVersionRef::new(id, version.version).map_err(cache_error)
            };
            let mut references = BTreeMap::new();
            for (path, bytes) in outputs {
                let reference = store(path.as_str(), &bytes)?;
                references.insert(path, reference);
            }
            let stdout_ref = if output.stdout.is_empty() { None } else { Some(store("stdout", &output.stdout)?) };
            let stderr_ref = if output.stderr.is_empty() { None } else { Some(store("stderr", &output.stderr)?) };
            let exit_code = output.status.code().unwrap_or(-1);
            let manifest = serde_json::to_vec(&serde_json::json!({
                "build": build_id.to_hex(), "view": input.view.view, "repo": input.view.repo,
                "tested": input.view.tested, "account": input.view.account,
                "action_digest": action, "spec": input.spec, "exit_code": exit_code,
                "outputs": references.iter().map(|(path, reference)|
                    (path.as_str(), reference.to_result_ref())).collect::<BTreeMap<_, _>>(),
                "stdout_ref": stdout_ref.as_ref().map(|r| r.to_result_ref()),
                "stderr_ref": stderr_ref.as_ref().map(|r| r.to_result_ref()),
            })).map_err(|_| MemoryError::bad_request("build receipt could not encode"))?;
            let producer_ref = store("build-receipt", &manifest)?.to_result_ref();
            Ok(ActionResult { exit_code, outputs: references, stdout_ref, stderr_ref,
                produced_at: at, producer_ref })
        });
        stored.map_err(|_| BuildCacheError::InvalidAction("build exhaust write admission refused"))
    }
}
