//! Decision host doors: the ladder, dials and the hooks built on them.
//! Entry: DecisionHost::ladder.
//! Definitions: types stay in the parent; this module owns the listed impls.

use super::{
    ATTRIBUTION_BUDGET, ATTRIBUTION_DIAL, ATTRIBUTION_WORDING, AnswerContract, Arc,
    AttributionDecisions, AttributionNotes, AttributionRules, BookingDecisions, BoundedAutoChecker,
    CAMPAIGN_TASTE_BUDGET, CAMPAIGN_TASTE_DIAL, CAMPAIGN_TASTE_SCORE_WORDING,
    CAMPAIGN_TASTE_USEFUL_WORDING, CampaignTasteDecisions, CampaignTasteWording,
    ClaimReplayDecisions, ConsolidationDecisions, DecisionAsks, DecisionBand, DecisionBandPolicy,
    DecisionDial, DecisionHost, DecisionLadder, DecisionProvider, DecisionRung, EntityId,
    FanoutDecisions, HeldLadder, HostingPrivacyPosture, ImagePick, LadderNotes,
    MembershipDecisions, PLACEMENT_BUDGET, PLACEMENT_WORDING, PLANNER_BUDGET, PLANNER_WORDING,
    PlacementDecisions, PolicyDecisions, REVIEW_DIAL, REVIEW_HARD_CHECK_WORDING,
    REVIEW_LENS_BUDGET, REVIEW_OUT_OF_SCOPE_WORDING, REVIEW_SEVERITY_WORDING,
    REVIEW_VERDICT_WORDING, RetrievalDeadline, ReviewDecisions, ReviewWording, SeatDecisions,
    SeatPickSettings, TASK_ASK_UP_WORDING, TASK_DECISION_BUDGET, TASK_DONE_MET_WORDING,
    TASK_SURFACE, TASK_TAKE_WORDING, TaskDecisions, UsefulUpstreamDecisions, Vault,
    WAVE_FANOUT_WORDING,
};

impl DecisionHost {
    /// The ladder every typed decision on this host goes through.
    #[must_use]
    pub fn ladder(&self) -> &HeldLadder {
        &self.ladder
    }

    /// Whether the owner opted in to sending unit text off the host, for
    /// [`oneiron::llm::decision::DecisionLadder::under_posture`].
    #[must_use]
    pub fn remote_opt_in(&self) -> bool {
        self.remote_opt_in
    }

    /// `ladder`, this host's ([`Self::ladder`]), under a question's
    /// `posture` (FIX 9525). Where the posture keeps unit text on the host,
    /// the Big rung is this host's big model sent only to the offers of its
    /// live route that keep the text there; then every slot whose calls
    /// would still send it off is emptied, as
    /// [`DecisionLadder::under_posture`] empties one. A ladder whose Big rung
    /// is not this host's keeps it.
    #[must_use]
    pub(crate) fn under_posture<'l>(
        &'l self,
        mut ladder: DecisionLadder<'l>,
        posture: HostingPrivacyPosture,
    ) -> DecisionLadder<'l> {
        // The rule `DecisionLadder::under_posture` keeps: text leaves only
        // under MANAGED posture or the owner's explicit opt-in.
        let leaves = oneiron::llm::decision::unit_text_may_leave_host(posture, self.remote_opt_in);
        let held = self.ladder.big.as_deref();
        let ours = |big: &dyn DecisionProvider| held.is_some_and(|own| std::ptr::addr_eq(own, big));
        if !leaves
            && ladder.big.is_some_and(ours)
            && let Some(on_host) = self.big_on_host.as_deref()
        {
            ladder.big = Some(on_host);
        }
        ladder.under_posture(posture, self.remote_opt_in)
    }

    /// The ladder's last rung: the vault owner's durable ask queue. A caller
    /// whose decision came back with a human ask finds it with
    /// [`DecisionAsks::latest`] and waits on [`DecisionAsks::answered`].
    #[must_use]
    pub fn asks(&self) -> &Arc<DecisionAsks> {
        &self.asks
    }

    /// The bands a caller starts from: the host's PersonThreshold row when
    /// the house read names a person question.
    #[must_use]
    pub fn bands(&self) -> DecisionBandPolicy {
        self.bands.clone()
    }

    /// Installs the newest accepted Coach revision of the person row (Q3)
    /// above the configured start row, else the start row, on every clone of
    /// the host's bands. A host whose recipe names no person question keeps
    /// none.
    pub(crate) fn refresh_person_threshold(&self, vault: &Vault) -> oneiron::Result<()> {
        let Some(start) = self.person_start else {
            return Ok(());
        };
        let _turn = self
            .person_refresh
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let row = vault
            .latest_accepted_person_threshold()?
            .map(|(_, row)| row)
            .filter(|row| row.version > start.version)
            .unwrap_or(start);
        if self.bands.person_threshold() != Some(row) {
            self.bands.replace_person_threshold(row)?;
            tracing::info!(
                threshold = row.threshold,
                version = row.version,
                "the person threshold row changed"
            );
        }
        Ok(())
    }

    /// A dial from the rule table up to `ceiling`, with the default band.
    #[must_use]
    pub fn dial(&self, ceiling: DecisionRung) -> DecisionDial {
        let first = [
            (DecisionRung::Rule, self.ladder.rule.is_some()),
            (DecisionRung::Local, self.ladder.local.is_some()),
            (DecisionRung::SystemOne, self.ladder.system_one.is_some()),
            (DecisionRung::Escalation, self.ladder.escalation.is_some()),
            (DecisionRung::Big, self.ladder.big.is_some()),
        ]
        .into_iter()
        .find_map(|(rung, filled)| filled.then_some(rung))
        .unwrap_or(DecisionRung::Human)
        .min(ceiling);
        DecisionDial {
            first,
            ceiling,
            band: DecisionBand::default(),
        }
    }

    /// The write gate's auto check through this ladder, when
    /// `[models.decisions].auto_check` words it.
    #[must_use]
    pub fn auto_checker(&self) -> Option<&BoundedAutoChecker> {
        self.auto_checker.as_ref()
    }

    /// The task highway's three surface questions through this ladder, up
    /// to the Big rung: a question no model answers asks up on the TASK.
    pub(crate) fn task_decisions(&self) -> oneiron::Result<TaskDecisions<'_>> {
        let question = |which: &[u8], wording: &str| {
            TASK_SURFACE.question(&[which], wording.to_owned(), AnswerContract::Noul)
        };
        Ok(TaskDecisions {
            ladder: self.ladder.ladder(),
            dial: self.dial(DecisionRung::Big),
            bands: self.bands.clone(),
            take: question(b"take".as_slice(), TASK_TAKE_WORDING)?,
            done: question(b"done_met".as_slice(), TASK_DONE_MET_WORDING)?,
            ask_up: question(b"ask_up".as_slice(), TASK_ASK_UP_WORDING)?,
            budget: TASK_DECISION_BUDGET,
        })
    }

    /// The placement question through this ladder for `principal`, up to the
    /// Big rung (a placement never asks a person), within `deadline`.
    pub(crate) fn placement_decisions<'a>(
        &'a self,
        principal: EntityId,
        deadline: &'a RetrievalDeadline,
    ) -> PlacementDecisions<'a> {
        PlacementDecisions {
            ladder: self.ladder.ladder(),
            principal,
            dial: self.dial(DecisionRung::Big),
            bands: self.bands.clone(),
            wording: PLACEMENT_WORDING.to_owned(),
            deadline,
        }
    }

    /// A leased agent run's planner ladder (OF-541, OF-389): the shape pick
    /// and the type placement for `principal`, up to the Big rung, each call
    /// on its own fresh clock.
    pub(crate) fn host_planner_decisions(
        &self,
        principal: EntityId,
    ) -> oneiron::code_run::HostPlannerDecisions<'_> {
        oneiron::code_run::HostPlannerDecisions {
            ladder: &self.ladder,
            principal,
            bands: self.bands.clone(),
            planner_wording: PLANNER_WORDING.to_owned(),
            planner_budget: PLANNER_BUDGET,
            placement_dial: self.dial(DecisionRung::Big),
            placement_wording: PLACEMENT_WORDING.to_owned(),
            placement_budget: PLACEMENT_BUDGET,
        }
    }

    /// The Dreamer's consolidation questions through this ladder, in the
    /// shipped wording: the verdict role's generated read sits at the Local
    /// slot, and an answer still in the band steps up the host's stronger
    /// rungs under the host's bands. A consolidation verdict never asks a
    /// person: the executor caps its dial at Big (`VERDICT_CEILING`, OF-023),
    /// and a verdict still in band parks its pair as a `conflict.open` with
    /// both claims standing.
    pub(crate) fn consolidation_decisions(&self) -> oneiron::Result<ConsolidationDecisions> {
        Ok(ConsolidationDecisions {
            ladder: self.ladder.clone(),
            dial: DecisionDial {
                first: DecisionRung::Local,
                ceiling: DecisionRung::Human,
                band: DecisionBand::default(),
            },
            bands: self.bands.clone(),
            ..ConsolidationDecisions::shipped()?
        })
    }

    /// The fast per-image pick (OF-329) for `principal`'s `task`, when
    /// `[models.decisions.image_pick]` words it. It asks the quick rungs
    /// only, up to System One, under the host's bands; a pick no rung
    /// answers in band serves the image in full.
    #[must_use]
    pub fn image_pick(&self, principal: EntityId, task: String) -> Option<ImagePick<'_>> {
        let settings = self.image_pick.as_ref()?;
        Some(ImagePick {
            ladder: self.ladder.ladder(),
            principal,
            dial: self.dial(DecisionRung::SystemOne),
            bands: self.bands.clone(),
            wording: settings.wording.clone(),
            task,
            budget: settings.budget,
        })
    }

    /// The saved-query membership judge through this ladder, in the shipped
    /// wording and budget: the judge's generated read sits at the Local slot,
    /// and an answer still in the band steps up the host's stronger rungs to
    /// the Big rung, under the host's bands.
    pub fn membership_decisions(&self) -> oneiron::Result<MembershipDecisions> {
        Ok(MembershipDecisions {
            ladder: self.ladder.clone(),
            dial: DecisionDial {
                first: DecisionRung::Local,
                ceiling: DecisionRung::Big,
                band: DecisionBand::default(),
            },
            bands: self.bands.clone(),
            ..MembershipDecisions::shipped()?
        })
    }

    /// A booking's free-text parse through this ladder for `principal`, on
    /// the shipped budget: the parse tier's read sits at System One, and an
    /// answer still in the band steps up to the Big rung.
    #[must_use]
    pub fn booking_decisions(&self, principal: EntityId) -> BookingDecisions {
        BookingDecisions {
            ladder: self.ladder.clone(),
            dial: DecisionDial {
                first: DecisionRung::SystemOne,
                ceiling: DecisionRung::Big,
                band: DecisionBand::default(),
            },
            bands: self.bands.clone(),
            ..BookingDecisions::shipped(principal)
        }
    }

    /// The fan-out AUTO ruling through this ladder for `principal`, worded
    /// `wording`, up to the Big rung: the fan-out's own approval asks the
    /// person, so this dial never does.
    #[must_use]
    pub fn fanout_decisions<'a>(
        &'a self,
        principal: EntityId,
        wording: String,
        deadline: &'a RetrievalDeadline,
    ) -> FanoutDecisions<'a> {
        FanoutDecisions {
            ladder: self.ladder.ladder(),
            principal,
            dial: self.dial(DecisionRung::Big),
            bands: self.bands.clone(),
            wording,
            deadline,
        }
    }

    /// A served wave cut's fan-out AUTO ruling (FIX 939) for `principal`, the
    /// actor whose request queued the cut, in this host's wording, on
    /// `deadline` ([`WAVE_FANOUT_BUDGET`](super::WAVE_FANOUT_BUDGET) from the ask).
    #[must_use]
    pub(crate) fn wave_fanout_decisions<'a>(
        &'a self,
        principal: EntityId,
        deadline: &'a RetrievalDeadline,
    ) -> FanoutDecisions<'a> {
        self.fanout_decisions(principal, WAVE_FANOUT_WORDING.to_owned(), deadline)
    }

    /// The skill-attribution sweep's ladder (OF-420): this host's, with the
    /// rule tier ([`AttributionRules`]) on its Rule rung, so a settled cause
    /// is routed before any model is asked.
    #[must_use]
    pub(crate) fn attribution_ladder(&self) -> HeldLadder {
        HeldLadder {
            rule: Some(Arc::new(AttributionRules) as Arc<dyn DecisionProvider>),
            ..self.ladder.clone()
        }
    }

    /// The attempt sweep's attribution for `principal` on `ladder` (from
    /// [`Self::attribution_ladder`]), in this host's wording: the rules
    /// first, then this host's model rungs up to Big, never a person, since
    /// a doubtful outcome already holds in the unclear ledger. Each doubtful
    /// answer takes its note from `notes`.
    #[must_use]
    pub(crate) fn attribution_decisions<'a>(
        &self,
        ladder: &'a HeldLadder,
        principal: EntityId,
        notes: &'a dyn AttributionNotes,
    ) -> AttributionDecisions<'a> {
        AttributionDecisions {
            ladder: ladder.ladder(),
            principal,
            dial: DecisionDial {
                first: DecisionRung::Rule,
                ..ATTRIBUTION_DIAL
            },
            bands: self.bands.clone(),
            wording: ATTRIBUTION_WORDING.to_owned(),
            budget: ATTRIBUTION_BUDGET,
            notes: Some(notes),
        }
    }

    /// A critic review's questions through this ladder for `principal`, the
    /// caller, over `state`, the target as the caller reads it: the engine's
    /// review dial, this host's bands and wording, one clock per lens, and no
    /// notes.
    #[must_use]
    pub(crate) fn review_decisions<'a>(
        &'a self,
        principal: EntityId,
        state: &'a serde_json::Value,
    ) -> ReviewDecisions<'a> {
        ReviewDecisions {
            ladder: self.ladder.ladder(),
            principal,
            dial: REVIEW_DIAL,
            bands: self.bands.clone(),
            state,
            budget: REVIEW_LENS_BUDGET,
            wording: ReviewWording {
                verdict: REVIEW_VERDICT_WORDING.to_owned(),
                severity: REVIEW_SEVERITY_WORDING.to_owned(),
                hard_check: REVIEW_HARD_CHECK_WORDING.to_owned(),
                out_of_scope: REVIEW_OUT_OF_SCOPE_WORDING.to_owned(),
            },
            notes: None,
        }
    }

    /// A campaign split's taste pack through this ladder for `principal`, the
    /// owner who asked for the evaluation: the engine's taste dial, this
    /// host's bands and wording, and one clock for the pack.
    #[must_use]
    pub(crate) fn campaign_taste(&self, principal: EntityId) -> CampaignTasteDecisions<'_> {
        CampaignTasteDecisions {
            ladder: self.ladder.ladder(),
            principal,
            dial: CAMPAIGN_TASTE_DIAL,
            bands: self.bands.clone(),
            wording: CampaignTasteWording {
                score: CAMPAIGN_TASTE_SCORE_WORDING.to_owned(),
                useful: CAMPAIGN_TASTE_USEFUL_WORDING.to_owned(),
            },
            budget: CAMPAIGN_TASTE_BUDGET,
        }
    }

    /// The merge doors' useful-upstream question through this ladder, on
    /// `deadline`. The doors require a System One or escalation seat to
    /// answer first, so the dial starts at the first of those this host
    /// fills; with neither, the question cannot be asked here.
    pub fn useful_upstream<'a>(
        &'a self,
        deadline: &'a RetrievalDeadline,
    ) -> oneiron::Result<UsefulUpstreamDecisions<'a>> {
        let first = if self.ladder.system_one.is_some() {
            DecisionRung::SystemOne
        } else if self.ladder.escalation.is_some() {
            DecisionRung::Escalation
        } else {
            return Err(oneiron::Error::InvalidConfig(
                "useful-upstream needs a System One seat or the house read on this host".into(),
            ));
        };
        Ok(UsefulUpstreamDecisions {
            ladder: self.ladder.ladder(),
            dial: DecisionDial {
                first,
                ceiling: DecisionRung::Big,
                band: DecisionBand::default(),
            },
            bands: self.bands.clone(),
            deadline,
        })
    }

    /// A claim refinement's held-out replay score through this ladder,
    /// worded `wording`, on `deadline`, up to the Big rung.
    #[must_use]
    pub fn claim_replay<'a>(
        &'a self,
        wording: String,
        deadline: &'a RetrievalDeadline,
    ) -> ClaimReplayDecisions<'a> {
        ClaimReplayDecisions {
            ladder: self.ladder.ladder(),
            dial: self.dial(DecisionRung::Big),
            bands: self.bands.clone(),
            wording,
            deadline,
        }
    }

    /// The policy safeguard's typed read through this ladder for `principal`,
    /// worded `wording` at `revision`, up to the Big rung, each read on
    /// `budget`: one per enabled plane, held by the plane's policy config.
    pub fn policy_decisions(
        &self,
        principal: EntityId,
        revision: String,
        wording: String,
        budget: std::time::Duration,
    ) -> oneiron::Result<PolicyDecisions> {
        PolicyDecisions::new(
            Arc::new(self.ladder.clone()),
            principal,
            self.dial(DecisionRung::Big),
            self.bands.clone(),
            revision,
            wording,
            budget,
        )
    }

    /// The policy safeguard's configuration this host serves (FIX 1201,
    /// FIX 2436): the host's own `base`, with this ladder's paired question
    /// lent to the safeguard's generated read, so its receipts keep the
    /// paired reading. A ladder with no paired question leaves `base` as it
    /// is. The planes' row questions (`owner_decisions`, `hosted_decisions`)
    /// stay the host's: no recipe names their wording.
    #[must_use]
    pub fn policy_model_config(
        &self,
        base: &oneiron::policy_model::PolicyModelConfig,
    ) -> oneiron::policy_model::PolicyModelConfig {
        let mut config = base.clone();
        if config.safeguard_paired.is_none() {
            config.safeguard_paired = self.ladder.paired.clone();
        }
        config
    }

    /// The code-mode seat pick through this ladder, for `principal`.
    pub(crate) fn seat_decisions(
        &self,
        settings: &SeatPickSettings,
        principal: EntityId,
    ) -> SeatDecisions {
        SeatDecisions {
            ladder: self.ladder.clone(),
            principal,
            dial: self.dial(DecisionRung::Big),
            bands: self.bands.clone(),
            model_wording: settings.model_wording.clone(),
            effort_wording: settings.effort_wording.clone(),
            budget: settings.budget,
            notes: Arc::new(LadderNotes),
        }
    }
}
