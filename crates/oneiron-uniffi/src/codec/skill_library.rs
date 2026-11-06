//! Owned arbitrary JSON leaves in skill-library output records.

use oneiron::task_verb::sdk::{
    BootstrapSkillView, SkillLibraryPage, SkillLibraryRestoreReceipt, SkillLibraryView,
};

use super::{Lift, OneironError, WireJson, lift_record};

type SkillLeaves = (WireJson, Option<(WireJson, WireJson)>);

pub(crate) fn lift_skill_library_view(
    verb: &str,
    mut skill: SkillLibraryView,
) -> Result<crate::SkillLibraryView, OneironError> {
    let leaves = take_skills(std::iter::once(&mut skill))?;
    let mut output = lift_record(verb, &skill)?;
    put_skills(std::iter::once(&mut output), leaves);
    Ok(output)
}

pub(crate) fn lift_skill_library_page(
    verb: &str,
    mut page: SkillLibraryPage,
) -> Result<crate::SkillLibraryPage, OneironError> {
    let leaves = take_skills(page.skills.iter_mut())?;
    let mut output: crate::SkillLibraryPage = lift_record(verb, &page)?;
    put_skills(output.skills.iter_mut(), leaves);
    Ok(output)
}

pub(crate) fn lift_bootstrap_skills(
    verb: &str,
    mut skills: Vec<BootstrapSkillView>,
) -> Result<Vec<crate::BootstrapSkillView>, OneironError> {
    let leaves = take_skills(
        skills
            .iter_mut()
            .filter_map(|skill| skill.resident.as_mut()),
    )?;
    let mut output: Vec<crate::BootstrapSkillView> = lift_record(verb, &skills)?;
    put_skills(
        output
            .iter_mut()
            .filter_map(|skill| skill.resident.as_mut()),
        leaves,
    );
    Ok(output)
}

pub(crate) fn lift_skill_library_restore(
    verb: &str,
    mut receipt: SkillLibraryRestoreReceipt,
) -> Result<crate::SkillLibraryRestoreReceipt, OneironError> {
    let leaves = match &mut receipt {
        SkillLibraryRestoreReceipt::Restored { skill, .. } => {
            take_skills(std::iter::once(skill.as_mut()))?
        }
        _ => Vec::new(),
    };
    let mut output = lift_record(verb, &receipt)?;
    if let crate::SkillLibraryRestoreReceipt::Restored { skill, .. } = &mut output {
        put_skills(std::iter::once(skill), leaves);
    }
    Ok(output)
}

fn take_skills<'a>(
    skills: impl Iterator<Item = &'a mut SkillLibraryView>,
) -> Result<Vec<SkillLeaves>, OneironError> {
    let leaves: Vec<Result<SkillLeaves, OneironError>> = skills
        .map(|skill| {
            let provenance = WireJson::lift(std::mem::take(&mut skill.provenance));
            let call: Result<_, OneironError> = skill
                .call
                .as_mut()
                .map(|call| {
                    let arguments = WireJson::lift(std::mem::take(&mut call.arguments));
                    let returns = WireJson::lift(std::mem::take(&mut call.returns));
                    Ok((arguments?, returns?))
                })
                .transpose();
            Ok((provenance?, call?))
        })
        .collect();
    // Every native JSON leaf is consumed before returning the first error.
    leaves.into_iter().collect()
}

fn put_skills<'a>(
    skills: impl Iterator<Item = &'a mut crate::SkillLibraryView>,
    leaves: Vec<SkillLeaves>,
) {
    for (skill, (provenance, call)) in skills.zip(leaves) {
        skill.provenance = provenance;
        if let (Some(output), Some((arguments, returns))) = (&mut skill.call, call) {
            output.arguments = arguments;
            output.returns = returns;
        }
    }
}
