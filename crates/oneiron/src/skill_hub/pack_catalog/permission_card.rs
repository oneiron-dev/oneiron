//! A pack's permission card: the powers its source requests, and the
//! widening an update over an installed receipt adds.
use super::{BundledSkillPermissions, PackInstallReceipt, PackPermissions, PackSource, invalid};
use crate::error::Result;

pub(super) fn pack_permissions(
    source: &PackSource,
    prior: Option<&PackInstallReceipt>,
) -> Result<PackPermissions> {
    let mut section_verbs = std::collections::BTreeSet::new();
    let mut section_authorities = std::collections::BTreeSet::new();
    for section in source.sections() {
        section_verbs.extend(section.verbs.iter().map(|verb| verb.0.clone()));
        section_authorities.insert(section.authority_lane.0.clone());
    }
    let grants: Vec<_> = source.manifest.requested_grants.iter().cloned().collect();
    let wakes: Vec<_> = source.manifest.wake_subscriptions.iter().cloned().collect();
    let hooks: Vec<_> = source
        .hooks()
        .iter()
        .flat_map(super::PackHook::capability_tokens)
        .collect::<std::collections::BTreeSet<_>>()
        .into_iter()
        .collect();
    let organs: Vec<_> = source
        .organs()
        .iter()
        .flat_map(super::PackOrgan::capability_tokens)
        .collect::<std::collections::BTreeSet<_>>()
        .into_iter()
        .collect();
    let section_verbs: Vec<_> = section_verbs.into_iter().collect();
    let section_authorities: Vec<_> = section_authorities.into_iter().collect();
    let added = |requested: &[String], previous: &[String]| {
        requested
            .iter()
            .filter(|power| !previous.contains(power))
            .cloned()
            .collect()
    };
    let empty: &[String] = &[];
    let mut folders = std::collections::BTreeMap::<String, Vec<crate::skill_hub::HubFile>>::new();
    for file in source.files() {
        if let Some(relative) = file.path.strip_prefix("skills/") {
            let (folder, path) = relative
                .split_once('/')
                .ok_or_else(|| invalid("pack skill must have a folder"))?;
            folders
                .entry(folder.to_owned())
                .or_default()
                .push(crate::skill_hub::HubFile::new(path, file.content.clone()));
        }
    }
    let mut bundled_skills = Vec::<BundledSkillPermissions>::new();
    for files in folders.into_values() {
        let package = super::super::folder::package_from_files(files)?;
        let caps = &package.capabilities;
        let skill = BundledSkillPermissions {
            skill_id: package.record.skill_id,
            bins: caps.bins.iter().cloned().collect(),
            env: caps.env.iter().cloned().collect(),
            mcp: caps.mcp.iter().cloned().collect(),
            allowed_tools: caps.allowed_tools.iter().cloned().collect(),
        };
        if bundled_skills
            .iter()
            .any(|prior| prior.skill_id == skill.skill_id)
        {
            return Err(invalid("duplicate bundled skill identity"));
        }
        bundled_skills.push(skill);
    }
    bundled_skills.sort_by(|a, b| a.skill_id.cmp(&b.skill_id));
    let mut widening_bundled_skills = Vec::new();
    for skill in &bundled_skills {
        let previous = prior.and_then(|receipt| {
            receipt
                .permissions
                .bundled_skills
                .iter()
                .find(|previous| previous.skill_id == skill.skill_id)
        });
        let widening = BundledSkillPermissions {
            skill_id: skill.skill_id.clone(),
            bins: added(&skill.bins, previous.map_or(empty, |prior| &prior.bins)),
            env: added(&skill.env, previous.map_or(empty, |prior| &prior.env)),
            mcp: added(&skill.mcp, previous.map_or(empty, |prior| &prior.mcp)),
            allowed_tools: added(
                &skill.allowed_tools,
                previous.map_or(empty, |prior| &prior.allowed_tools),
            ),
        };
        if !widening.bins.is_empty()
            || !widening.env.is_empty()
            || !widening.mcp.is_empty()
            || !widening.allowed_tools.is_empty()
        {
            widening_bundled_skills.push(widening);
        }
    }
    Ok(PackPermissions {
        bundled_skills,
        widening_bundled_skills,
        widening_grants: added(&grants, prior.map_or(empty, |row| &row.permissions.grants)),
        widening_wakes: added(&wakes, prior.map_or(empty, |row| &row.permissions.wakes)),
        widening_hooks: uncovered(
            &hooks,
            prior.map_or(empty, |row| &row.permissions.hooks),
            hook_token_covers,
        ),
        widening_organs: uncovered(
            &organs,
            prior.map_or(empty, |row| &row.permissions.organs),
            organ_token_covers,
        ),
        widening_section_verbs: added(
            &section_verbs,
            prior.map_or(empty, |row| &row.permissions.section_verbs),
        ),
        widening_section_authorities: added(
            &section_authorities,
            prior.map_or(empty, |row| &row.permissions.section_authorities),
        ),
        grants,
        wakes,
        hooks,
        organs,
        section_verbs,
        section_authorities,
    })
}

/// The requested tokens no previous token covers: a token covers itself,
/// and `covers` decides the typed rest.
fn uncovered(
    requested: &[String],
    previous: &[String],
    covers: fn(&str, &str) -> bool,
) -> Vec<String> {
    requested
        .iter()
        .filter(|token| {
            !previous
                .iter()
                .any(|held| held == *token || covers(held, token))
        })
        .cloned()
        .collect()
}

/// Whether the previous hook token `held` grants at least what `token`
/// asks of the same hook: a `budget_ms` at least as high, or `scope:*` over
/// any scope. Hook names hold no `/`.
fn hook_token_covers(held: &str, token: &str) -> bool {
    let (Some((held_hook, held)), Some((hook, token))) =
        (held.split_once('/'), token.split_once('/'))
    else {
        return false;
    };
    held_hook == hook
        && (ceiling_covers(held, token, "budget_ms:")
            || (held == "scope:*" && token.starts_with("scope:")))
}

/// Whether the previous organ token `held` grants at least what `token`
/// asks of the same organ: a `threads` or `memory` ceiling at least as
/// high. Organ names hold no `:`.
fn organ_token_covers(held: &str, token: &str) -> bool {
    fn organ_field(token: &str) -> Option<(&str, &str)> {
        token.strip_prefix("organ:")?.split_once(':')
    }
    let (Some((held_organ, held)), Some((organ, token))) = (organ_field(held), organ_field(token))
    else {
        return false;
    };
    held_organ == organ
        && (ceiling_covers(held, token, "threads:") || ceiling_covers(held, token, "memory:"))
}

/// Whether both tokens name the numeric ceiling `field` and the asked one
/// is no higher than the held one.
fn ceiling_covers(held: &str, token: &str, field: &str) -> bool {
    let value = |token: &str| token.strip_prefix(field)?.parse::<u64>().ok();
    matches!((value(held), value(token)), (Some(held), Some(asked)) if asked <= held)
}
