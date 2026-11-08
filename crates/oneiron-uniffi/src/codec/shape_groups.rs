//! Owned shape manifests in standalone and unified inbox groups.

use oneiron::inbox::{InboxGroupResolution, UnifiedInboxGroup, UnifiedInboxGroupPage};
use oneiron::vault_shape::ShapeInboxGroup;

use super::shape_plans::{restore_rows, take_rows};
use super::{Lift, OneironError, lift_record};

pub(crate) fn lift_shape_groups(
    mut value: Vec<ShapeInboxGroup>,
) -> Result<Vec<crate::ShapeInboxGroup>, OneironError> {
    let row_json = take_rows(value.iter_mut().flat_map(group_rows))?;
    let mut output: Vec<crate::ShapeInboxGroup> = lift_record("vault.shape.groups", &value)?;
    restore_rows(output.iter_mut().flat_map(output_group_rows), row_json);
    Ok(output)
}

impl Lift<UnifiedInboxGroupPage> for crate::UnifiedInboxGroupPage {
    fn lift(mut value: UnifiedInboxGroupPage) -> Result<Self, OneironError> {
        let row_json = take_rows(
            value
                .groups
                .iter_mut()
                .filter_map(|group| match group {
                    UnifiedInboxGroup::Shape { group } => Some(group),
                    UnifiedInboxGroup::Dreamer { .. } => None,
                })
                .flat_map(group_rows),
        )?;
        let mut output: Self = lift_record("vault.inbox.groups", &value)?;
        restore_rows(
            output
                .groups
                .iter_mut()
                .filter_map(|group| match group {
                    crate::UnifiedInboxGroup::Shape { group } => Some(group),
                    crate::UnifiedInboxGroup::Dreamer { .. } => None,
                })
                .flat_map(output_group_rows),
            row_json,
        );
        Ok(output)
    }
}

impl Lift<InboxGroupResolution> for crate::InboxGroupResolution {
    fn lift(value: InboxGroupResolution) -> Result<Self, OneironError> {
        Ok(match value {
            InboxGroupResolution::Shape { receipt } => Self::Shape {
                receipt: Lift::lift(receipt)?,
            },
            InboxGroupResolution::Dreamer { resolution } => Self::Dreamer {
                resolution: lift_record("vault.inbox.groups.resolve", &resolution)?,
            },
        })
    }
}

fn group_rows(
    group: &mut ShapeInboxGroup,
) -> impl Iterator<Item = &mut oneiron::vault_shape::ShapeRow> {
    group.members.iter_mut().flat_map(|member| {
        member
            .item
            .before
            .iter_mut()
            .chain(member.item.after.iter_mut())
    })
}

fn output_group_rows(
    group: &mut crate::ShapeInboxGroup,
) -> impl Iterator<Item = &mut crate::ShapeRow> {
    group.members.iter_mut().flat_map(|member| {
        member
            .item
            .before
            .iter_mut()
            .chain(member.item.after.iter_mut())
    })
}
