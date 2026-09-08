//! Content-invariant validators plus the require_text and preset_error helpers.

use super::content::{
    CONSULTANCY_AUDIT_WINDOW_DAYS, CONSULTANCY_DESK_PERIOD, CONSULTANCY_SNOOZE_MAX_SECS,
    CONSULTANCY_SNOOZE_MIN_SECS, CONSULTANCY_STAGE_EVIDENCE, MOM_TEST_PARTICIPANT_ROLE,
    MOM_TEST_QUESTION_BLOCK_KEYS, MOM_TEST_TEMPLATE_KEY, ONE_PAGER_EVIDENCE_SECTION,
    ONE_PAGER_SECTION_KEYS, PROSPECT_PARTICIPANT_ROLE, RATIFIED_REPLY_CODES,
    REQUIRED_RHYTHM_ANCHORS, SOW_EVIDENCE_SECTION, SOW_SECTION_KEYS, STAGE_REPLIED,
};
use super::shape::{
    BriefTemplateData, BriefTemplateKind, BriefTemplateSet, CONSULTANCY_PRESET_ID,
    CONSULTANCY_PRESET_VERSION, CampaignPresetData, CampaignTemplateData, CommitmentRhythmData,
    LanePolicyData, RhythmAnchor, RhythmCheckpointData, SnoozePolicyData,
};

use crate::Result;
use crate::campaign::claims::{StageEvidenceClass, StageKey};
use crate::campaign::stage::{
    NO_SHOW_BUMP_AFTER_SECS, NoShowRecoveryRule, ReplyCode, ReplyDisposition,
    StageLadderDefinition, validate_ladder,
};
use crate::error::Error;

pub(super) fn validate_preset(preset: &CampaignPresetData) -> Result<()> {
    if preset.id != CONSULTANCY_PRESET_ID {
        return Err(preset_error(format!(
            "id must be {CONSULTANCY_PRESET_ID:?}, found {:?}",
            preset.id
        )));
    }
    if preset.version != CONSULTANCY_PRESET_VERSION {
        return Err(preset_error(format!(
            "version must be {CONSULTANCY_PRESET_VERSION}, found {}",
            preset.version
        )));
    }
    require_text("display_name", &preset.display_name)?;
    // CA-04 owns ladder self-consistency: unique stages, unambiguous
    // transitions, one row per reply code. Its rejections are re-raised in this
    // module's error family rather than re-implemented.
    validate_ladder(&preset.stage_ladder)
        .map_err(|err| preset_error(format!("stage ladder: {err}")))?;
    validate_pipeline(&preset.stage_ladder)?;
    validate_reply_routes(&preset.stage_ladder)?;
    validate_no_show_recovery(&preset.stage_ladder.no_show_recovery)?;
    validate_lane_policy(&preset.lane_policy)?;
    validate_snooze_policy(&preset.snooze_policy)?;
    if preset.audit_window_days != CONSULTANCY_AUDIT_WINDOW_DAYS {
        return Err(preset_error(format!(
            "audit window must be {CONSULTANCY_AUDIT_WINDOW_DAYS} days, found {}",
            preset.audit_window_days
        )));
    }
    validate_templates(&preset.templates)?;
    validate_desk_month(&preset.desk_month)?;
    validate_campaign_templates(&preset.campaign_templates)
}

/// The eight stages, in order, each earned from its immediate predecessor by its
/// one ratified evidence class.
///
/// Order equality on the stage LIST is what keeps `member` and `cold` out: they
/// are not pipeline heads, so a ladder that declares one is not this preset.
/// Equality on the TRANSITIONS is what stops the list from being cosmetic — a
/// ladder that also admits `replied → call_held` still names eight stages in the
/// ratified order while letting a party reach the proposal with no meeting ever
/// having happened. The declared chain is the ratified chain and nothing beside
/// it.
fn validate_pipeline(ladder: &StageLadderDefinition) -> Result<()> {
    let declared: Vec<&str> = ladder
        .stages
        .iter()
        .map(|stage| stage.key.0.as_str())
        .collect();
    let ratified = CONSULTANCY_STAGE_EVIDENCE.map(|(stage, _)| stage);
    if declared != ratified {
        return Err(preset_error(format!(
            "stage order must be {ratified:?}, found {declared:?}"
        )));
    }
    for (index, (stage, class)) in CONSULTANCY_STAGE_EVIDENCE.into_iter().enumerate() {
        let from = index
            .checked_sub(1)
            .map(|previous| CONSULTANCY_STAGE_EVIDENCE[previous].0);
        let earned = ladder.transitions.iter().any(|rule| {
            rule.to.0 == stage
                && rule.from.as_ref().map(|key| key.0.as_str()) == from
                && rule.evidence_class == class
        });
        if !earned {
            return Err(preset_error(format!(
                "stage {stage} must be earned from {} by {} evidence",
                from.unwrap_or("no prior stage"),
                class.as_str()
            )));
        }
    }
    // CA-04 already refuses a repeated `(from, to)` pair, so eight matched rules
    // at this count leaves no room for a ninth: no second route into a stage,
    // and none that skips one.
    if ladder.transitions.len() != CONSULTANCY_STAGE_EVIDENCE.len() {
        return Err(preset_error(format!(
            "the pipeline is exactly {} transitions, found {}",
            CONSULTANCY_STAGE_EVIDENCE.len(),
            ladder.transitions.len()
        )));
    }
    Ok(())
}

/// All six coded replies, each on its ratified disposition.
///
/// CA-04 already rejects a code routed twice, so presence plus agreement is the
/// whole check.
fn validate_reply_routes(ladder: &StageLadderDefinition) -> Result<()> {
    for code in RATIFIED_REPLY_CODES {
        let Some(route) = ladder.reply_routes.iter().find(|route| route.code == code) else {
            return Err(preset_error(format!("reply code {code:?} is not routed")));
        };
        let ratified = ratified_disposition(code);
        if route.disposition != ratified {
            return Err(preset_error(format!(
                "reply code {code:?} must route to {ratified:?}, found {:?}",
                route.disposition
            )));
        }
    }
    Ok(())
}

fn ratified_disposition(code: ReplyCode) -> ReplyDisposition {
    match code {
        ReplyCode::PositiveNow => ReplyDisposition::Promote {
            stage: StageKey(STAGE_REPLIED.to_owned()),
        },
        ReplyCode::PositiveLater => ReplyDisposition::Snooze,
        ReplyCode::Referral => ReplyDisposition::RouteReferral,
        ReplyCode::Objection => ReplyDisposition::RecordOnly,
        ReplyCode::NotInterested => ReplyDisposition::Exit,
        ReplyCode::Complaint => ReplyDisposition::Suppress,
    }
}

/// Same-day reschedule, then the D+3 bump, then snooze.
///
/// The delay is compared against CA-04's own [`NO_SHOW_BUMP_AFTER_SECS`] so the
/// ratified 259200 seconds is stated once, in the module that applies it.
fn validate_no_show_recovery(rule: &NoShowRecoveryRule) -> Result<()> {
    if !rule.same_day_reschedule {
        return Err(preset_error(
            "no-show recovery must offer a same-day reschedule",
        ));
    }
    if rule.bump_after_secs != NO_SHOW_BUMP_AFTER_SECS {
        return Err(preset_error(format!(
            "no-show bump must be {NO_SHOW_BUMP_AFTER_SECS} seconds, found {}",
            rule.bump_after_secs
        )));
    }
    if !rule.snooze_after_failed_bump {
        return Err(preset_error(
            "no-show recovery must snooze after a failed bump",
        ));
    }
    Ok(())
}

fn validate_lane_policy(policy: &LanePolicyData) -> Result<()> {
    if !policy.warm_requires_evidence {
        return Err(preset_error(
            "warm reconnect must require prior-thread or relationship evidence",
        ));
    }
    if policy.trigger_fresh_for_secs == 0 || policy.prior_touch_warm_for_secs == 0 {
        return Err(preset_error("lane clocks must be non-zero"));
    }
    Ok(())
}

fn validate_snooze_policy(policy: &SnoozePolicyData) -> Result<()> {
    if policy.min_secs != CONSULTANCY_SNOOZE_MIN_SECS
        || policy.max_secs != CONSULTANCY_SNOOZE_MAX_SECS
    {
        return Err(preset_error(format!(
            "positive-later snooze must span {CONSULTANCY_SNOOZE_MIN_SECS}..={CONSULTANCY_SNOOZE_MAX_SECS} seconds, found {}..={}",
            policy.min_secs, policy.max_secs
        )));
    }
    if !(policy.min_secs..=policy.max_secs).contains(&policy.default_secs) {
        return Err(preset_error(format!(
            "default snooze {} is outside the ratified range",
            policy.default_secs
        )));
    }
    if !policy.wake_on_new_trigger {
        return Err(preset_error(
            "positive-later snooze must wake on a new trigger",
        ));
    }
    if policy.restart_touch_index != 0 {
        return Err(preset_error("campaign re-entry restarts at touch 1"));
    }
    Ok(())
}

fn validate_templates(templates: &BriefTemplateSet) -> Result<()> {
    validate_brief(
        &templates.sow,
        BriefTemplateKind::Sow,
        &SOW_SECTION_KEYS,
        SOW_EVIDENCE_SECTION,
    )?;
    validate_brief(
        &templates.one_pager,
        BriefTemplateKind::OnePager,
        &ONE_PAGER_SECTION_KEYS,
        ONE_PAGER_EVIDENCE_SECTION,
    )
}

/// One ARCH-0032b brief shape.
///
/// Section ORDER is host presentation, so only presence, uniqueness, and the
/// evidence anchor are enforced. Body text is validated for existence and never
/// for content: what a brief says is the host's, and reading it here would make
/// the engine an editor.
fn validate_brief(
    template: &BriefTemplateData,
    kind: BriefTemplateKind,
    required_keys: &[&str],
    evidence_section: &str,
) -> Result<()> {
    if template.kind != kind {
        return Err(preset_error(format!(
            "brief template {:?} must be {kind:?}, found {:?}",
            template.key, template.kind
        )));
    }
    require_text("brief template key", &template.key)?;
    require_text("brief title template", &template.title_template)?;
    let mut seen: Vec<&str> = Vec::with_capacity(template.sections.len());
    let mut evidence_slots = 0;
    for section in &template.sections {
        require_text("brief section key", &section.key)?;
        if seen.contains(&section.key.as_str()) {
            return Err(preset_error(format!(
                "brief declares section {:?} twice",
                section.key
            )));
        }
        seen.push(section.key.as_str());
        require_text("brief section heading", &section.heading)?;
        require_text("brief section body template", &section.body_template)?;
        for slot in &section.required_evidence_slots {
            require_text("brief evidence slot", slot)?;
        }
        if section.key == evidence_section {
            evidence_slots = section.required_evidence_slots.len();
        }
    }
    for required in required_keys {
        if !seen.contains(required) {
            return Err(preset_error(format!(
                "brief {:?} is missing section {required}",
                template.key
            )));
        }
    }
    if evidence_slots == 0 {
        return Err(preset_error(format!(
            "section {evidence_section} must declare at least one evidence slot"
        )));
    }
    Ok(())
}

/// The desk month, checked as data.
///
/// Every rejection answers "can this rhythm be read deterministically?": one
/// checkpoint per anchor so a reader knows which row it is looking at, an
/// evidence hook on each so a checkpoint has something to collect, and offsets
/// that point the direction their anchor names.
fn validate_desk_month(rhythm: &CommitmentRhythmData) -> Result<()> {
    if rhythm.period != CONSULTANCY_DESK_PERIOD {
        return Err(preset_error(format!(
            "desk period must be {CONSULTANCY_DESK_PERIOD:?}, found {:?}",
            rhythm.period
        )));
    }
    let mut anchors: Vec<RhythmAnchor> = Vec::with_capacity(rhythm.checkpoints.len());
    let mut keys: Vec<&str> = Vec::with_capacity(rhythm.checkpoints.len());
    for checkpoint in &rhythm.checkpoints {
        require_text("desk checkpoint key", &checkpoint.key)?;
        if keys.contains(&checkpoint.key.as_str()) {
            return Err(preset_error(format!(
                "desk rhythm declares checkpoint {:?} twice",
                checkpoint.key
            )));
        }
        keys.push(checkpoint.key.as_str());
        if anchors.contains(&checkpoint.anchor) {
            return Err(preset_error(format!(
                "desk rhythm declares anchor {:?} twice",
                checkpoint.anchor
            )));
        }
        anchors.push(checkpoint.anchor);
        if checkpoint.evidence_slots.is_empty() {
            return Err(preset_error(format!(
                "desk checkpoint {:?} names no evidence hook",
                checkpoint.key
            )));
        }
        for slot in &checkpoint.evidence_slots {
            require_text("desk evidence hook", slot)?;
        }
        validate_checkpoint_offset(checkpoint)?;
    }
    for anchor in REQUIRED_RHYTHM_ANCHORS {
        if !anchors.contains(&anchor) {
            return Err(preset_error(format!(
                "desk rhythm declares no {anchor:?} checkpoint"
            )));
        }
    }
    if rhythm.renewal_evidence.is_empty() {
        return Err(preset_error("desk renewal declares no evidence hook"));
    }
    for class in &rhythm.renewal_evidence {
        if !is_external_hook(*class) {
            return Err(preset_error(format!(
                "renewal evidence {} is not an external hook; renewal truth stays with the counterparty ledger",
                class.as_str()
            )));
        }
    }
    Ok(())
}

fn validate_checkpoint_offset(checkpoint: &RhythmCheckpointData) -> Result<()> {
    let consistent = match checkpoint.anchor {
        RhythmAnchor::Weekly => checkpoint.offset_days > 0,
        RhythmAnchor::BeforePeriodEnd => checkpoint.offset_days < 0,
        RhythmAnchor::PeriodStart | RhythmAnchor::PeriodEnd => true,
    };
    if !consistent {
        return Err(preset_error(format!(
            "checkpoint {:?} offset {} contradicts its {:?} anchor",
            checkpoint.key, checkpoint.offset_days, checkpoint.anchor
        )));
    }
    Ok(())
}

/// Whether a class is evidence some OTHER owner records.
///
/// Deposit, audit, desk, and renewal rest on these and only these: a reply or a
/// calendar entry is not a payment, a deliverable, or a renewal.
pub(super) const fn is_external_hook(class: StageEvidenceClass) -> bool {
    matches!(
        class,
        StageEvidenceClass::CounterpartyLedger
            | StageEvidenceClass::TaskListProgress
            | StageEvidenceClass::RecurringCommitment
    )
}

fn validate_campaign_templates(templates: &[CampaignTemplateData]) -> Result<()> {
    let mut keys: Vec<&str> = Vec::with_capacity(templates.len());
    let mut mom_test = None;
    for template in templates {
        require_text("campaign template key", &template.key)?;
        if keys.contains(&template.key.as_str()) {
            return Err(preset_error(format!(
                "campaign template {:?} is declared twice",
                template.key
            )));
        }
        keys.push(template.key.as_str());
        require_text("campaign template purpose", &template.purpose)?;
        require_text(
            "campaign template participant role",
            &template.participant_role,
        )?;
        if template
            .cross_campaign_exclusions
            .contains(&template.participant_role)
        {
            return Err(preset_error(format!(
                "campaign template {:?} excludes its own participant role",
                template.key
            )));
        }
        if template.key == MOM_TEST_TEMPLATE_KEY {
            mom_test = Some(template);
        }
    }
    let Some(mom_test) = mom_test else {
        return Err(preset_error(format!(
            "preset declares no {MOM_TEST_TEMPLATE_KEY} template"
        )));
    };
    validate_mom_test(mom_test)
}

/// The Mom-Test template is research, not prospecting.
///
/// Two things carry that. The SHAPE has no pitch, offer, or call-to-action
/// field, so an interview cannot express one. The DATA has to declare the
/// cross-campaign exclusion, so one person cannot be interviewed about their
/// problem and sold to about it in the same breath — a conflict of interest that
/// corrupts the research and the relationship at once.
fn validate_mom_test(template: &CampaignTemplateData) -> Result<()> {
    if template.participant_role != MOM_TEST_PARTICIPANT_ROLE {
        return Err(preset_error(format!(
            "mom test participant role must be {MOM_TEST_PARTICIPANT_ROLE:?}, found {:?}",
            template.participant_role
        )));
    }
    if !template
        .cross_campaign_exclusions
        .iter()
        .any(|role| role == PROSPECT_PARTICIPANT_ROLE)
    {
        return Err(preset_error(format!(
            "mom test must exclude the {PROSPECT_PARTICIPANT_ROLE} role"
        )));
    }
    require_text("mom test opening template", &template.opening_template)?;
    let mut blocks: Vec<&str> = Vec::with_capacity(template.question_blocks.len());
    for block in &template.question_blocks {
        require_text("question block key", &block.key)?;
        if blocks.contains(&block.key.as_str()) {
            return Err(preset_error(format!(
                "mom test declares question block {:?} twice",
                block.key
            )));
        }
        blocks.push(block.key.as_str());
        require_text("question block intent", &block.intent)?;
        if block.questions.is_empty() {
            return Err(preset_error(format!(
                "question block {:?} asks nothing",
                block.key
            )));
        }
        for question in &block.questions {
            require_text("interview question", question)?;
        }
    }
    for required in MOM_TEST_QUESTION_BLOCK_KEYS {
        if !blocks.contains(&required) {
            return Err(preset_error(format!(
                "mom test is missing the {required} question block"
            )));
        }
    }
    Ok(())
}

fn require_text(field: &str, value: &str) -> Result<()> {
    if value.trim().is_empty() {
        return Err(preset_error(format!("{field} must not be empty")));
    }
    Ok(())
}

pub(super) fn preset_error(message: impl Into<String>) -> Error {
    let message = message.into();
    Error::InvalidConfig(format!("campaign preset: {message}"))
}
