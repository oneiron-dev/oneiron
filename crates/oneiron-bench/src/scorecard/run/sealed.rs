//! The sealed once-run: which sealed run the flags ask for, its spent claim,
//! and the load-and-replay under it.

use super::*;

/// Run the sealed slice once, spending its claim before the slice is opened.
pub(super) fn run_sealed(
    flags: &BTreeMap<String, String>,
    kind: ArmKind,
) -> Result<serde_json::Value, ScorecardFailure> {
    let ledger = required_flag(flags, "sealed-ledger")?;
    let campaign_path = required_flag(flags, "campaign")?;
    let mode = sealed_mode(flags)?;
    let engine_commit = required_flag(flags, "engine-commit")?;
    check_commit(engine_commit)?;
    let owned = match kind {
        ArmKind::Pipeline => {
            OwnedArm::Pipeline(params::resolve(flags.get("params").map(String::as_str))?)
        }
        ArmKind::Keyword => OwnedArm::Keyword {
            profile: profile::resolve_profile(flags.get("rank-profile").map(String::as_str))?,
            dict_dir: flags.get("dict-dir").map(|dir| PathBuf::from(dir.as_str())),
        },
        ArmKind::WorldScoped => return Err(world_scoped::sealed_refusal()),
    };
    // Before the claim: a dictionary dir that loads fewer than the ja, zh and
    // ko dictionaries would spend the sealed run under the bm25f+dicts id.
    if let OwnedArm::Keyword {
        dict_dir: Some(dicts),
        ..
    } = &owned
    {
        keyword::check_dict_dir(dicts)?;
    }
    let campaign = campaign::load_campaign(campaign_path)?;
    let identity = ExperimentIdentity {
        engine_commit: engine_commit.to_owned(),
        params_digest: owned.digest().to_owned(),
        pack_digest: campaign.splits.sealed.revision.clone(),
    };
    let (pack_dir, out, budget_rows, repeats) = replay_flags(flags)?;
    let mut proposal_model_id: Option<String> = None;
    if let SealedMode::Proposal { id, dir } = mode {
        let store = ProposalStore::open(Path::new(dir))
            .map_err(|error| ScorecardFailure::Input(error.to_string()))?;
        let listing = store
            .get(id)
            .map_err(|error| ScorecardFailure::Input(error.to_string()))?;
        if listing.sealed.is_some() {
            return Err(ScorecardFailure::Input(
                "proposal already has its sealed outcome".to_owned(),
            ));
        }
        if listing.held_out.campaign_id != campaign.campaign_id {
            return Err(ScorecardFailure::Input(
                "proposal is for another campaign".to_owned(),
            ));
        }
        if listing.held_out.candidate.engine_commit != engine_commit
            || listing.held_out.candidate.params_digest != owned.digest()
        {
            return Err(ScorecardFailure::Input(
                "this run is not the proposal's candidate".to_owned(),
            ));
        }
        if listing.held_out.budget_rows != budget_rows {
            let wanted = listing.held_out.budget_rows;
            return Err(ScorecardFailure::Input(format!(
                "this run's budget_rows is {budget_rows}, the proposal's is {wanted}"
            )));
        }
        let wanted = listing.held_out.model_id.as_str();
        let same_retriever = match &owned {
            OwnedArm::Keyword { dict_dir, .. } => {
                keyword::retriever_id(dict_dir.as_deref()) == wanted
            }
            OwnedArm::Pipeline(_) => {
                ![keyword::RETRIEVER, keyword::RETRIEVER_DICTS].contains(&wanted)
            }
        };
        if !same_retriever {
            return Err(ScorecardFailure::Input(format!(
                "this run's arm is not the proposal's retriever {wanted}"
            )));
        }
        proposal_model_id = Some(wanted.to_owned());
    }
    let claim = match mode {
        SealedMode::Incumbent => {
            claim_incumbent_once(Path::new(ledger), &campaign.campaign_id, &identity)
        }
        SealedMode::Proposal { .. } => claim_sealed_once(Path::new(ledger), &identity),
    }
    .map_err(map_sealed_error)?;
    let loaded = load_slice(Path::new(pack_dir), Slice::Sealed).map_err(|error| {
        ScorecardFailure::Run(format!(
            "sealed slice load failed: {error}; the sealed run was spent"
        ))
    })?;
    if loaded.pack_digest != campaign.splits.sealed.revision
        || loaded.slice.pack_id != campaign.splits.sealed.dataset_id
    {
        return Err(ScorecardFailure::Run(
            "sealed pack does not match the campaign: the sealed run was spent".to_owned(),
        ));
    }
    if kind == ArmKind::Pipeline && loaded.vectors.is_none() {
        return Err(ScorecardFailure::Run(
            "sealed pack has no vectors: the sealed run was spent".to_owned(),
        ));
    }
    if kind == ArmKind::Pipeline
        && let Some(wanted) = &proposal_model_id
        && loaded.slice.embedding.as_ref().map(|pin| &pin.model_id) != Some(wanted)
    {
        return Err(ScorecardFailure::Run(format!(
            "sealed pack is not embedded by the proposal's model {wanted}: the sealed run was spent"
        )));
    }
    let mut summary = replay(
        &loaded,
        engine_commit,
        owned.arm(),
        budget_rows,
        repeats,
        out,
    )?;
    if let serde_json::Value::Object(map) = &mut summary {
        map.insert(
            "sealed_claim".to_owned(),
            serde_json::Value::from(claim.path.to_string_lossy().into_owned()),
        );
    }
    Ok(summary)
}

/// Which sealed run the flags ask for: exactly one of `--incumbent` or `--proposal` with `--proposals`.
fn sealed_mode(flags: &BTreeMap<String, String>) -> Result<SealedMode<'_>, ScorecardFailure> {
    let incumbent = flags.get("incumbent").map(String::as_str);
    let proposal = flags.get("proposal").map(String::as_str);
    let proposals = flags.get("proposals").map(String::as_str);
    match (incumbent, proposal, proposals) {
        (Some(value), None, None) => {
            if value != "true" {
                return Err(ScorecardFailure::Input(format!(
                    "--incumbent takes only true, got {value:?}"
                )));
            }
            Ok(SealedMode::Incumbent)
        }
        (None, Some(id), Some(dir)) => Ok(SealedMode::Proposal { id, dir }),
        (None, Some(_), None) => Err(ScorecardFailure::Input(
            "--proposal needs --proposals".to_owned(),
        )),
        (None, None, Some(_)) => Err(ScorecardFailure::Input(
            "--proposals needs --proposal".to_owned(),
        )),
        (None, None, None) => Err(ScorecardFailure::Input(
            "sealed run needs --incumbent true or --proposal ID with --proposals D".to_owned(),
        )),
        _ => Err(ScorecardFailure::Input(
            "sealed run takes exactly one of --incumbent true or --proposal ID with --proposals D"
                .to_owned(),
        )),
    }
}

/// Map a claim failure: a spent run is bad input, IO is a run failure.
fn map_sealed_error(error: SealedError) -> ScorecardFailure {
    let message = error.to_string();
    if matches!(
        error,
        SealedError::AlreadySpent { .. } | SealedError::IncumbentAlreadyMeasured { .. }
    ) {
        ScorecardFailure::Input(message)
    } else {
        ScorecardFailure::Run(message)
    }
}
