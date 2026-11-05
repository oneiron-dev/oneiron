//! Owned notification actions and component properties in opened inbox cards.

use oneiron::agent_inbox_lens::InboxItemView;
use oneiron::inbox::{NotificationPage, NotificationRow};

use super::generated_lenses::LensParts;
use super::{Lift, OneironError, WireJson, lift_record};

impl Lift<NotificationRow> for crate::NotificationRow {
    fn lift(mut value: NotificationRow) -> Result<Self, OneironError> {
        let args = take_action_args(&mut value)
            .into_iter()
            .collect::<Result<Vec<_>, _>>()?;
        let mut output: Self = lift_record("self.inbox.mark", &value)?;
        for (action, args) in output.actions.iter_mut().flatten().zip(args) {
            action.args = args;
        }
        Ok(output)
    }
}

impl Lift<NotificationPage> for crate::NotificationPage {
    fn lift(mut value: NotificationPage) -> Result<Self, OneironError> {
        let args = value
            .rows
            .iter_mut()
            .flat_map(take_action_args)
            .collect::<Vec<_>>();
        let args = args.into_iter().collect::<Result<Vec<_>, _>>()?;
        let mut output: Self = lift_record("self.inbox.list", &value)?;
        let actions = output
            .rows
            .iter_mut()
            .flat_map(|row| row.actions.iter_mut().flatten());
        for (action, args) in actions.zip(args) {
            action.args = args;
        }
        Ok(output)
    }
}

fn take_action_args(row: &mut NotificationRow) -> Vec<Result<WireJson, OneironError>> {
    row.actions
        .iter_mut()
        .map(|action| WireJson::lift(std::mem::take(&mut action.args)))
        .collect()
}

impl Lift<InboxItemView> for crate::InboxItemView {
    fn lift(mut value: InboxItemView) -> Result<Self, OneironError> {
        let args = value
            .notification
            .as_mut()
            .map(take_action_args)
            .unwrap_or_default();
        let lens = value.lens.take().map(LensParts::take);

        // Both optional subtrees are consumed before any error can return.
        let args = args.into_iter().collect::<Result<Vec<_>, _>>()?;
        let mut output: Self = lift_record("self.inbox.get", &value)?;
        let actions = output
            .notification
            .iter_mut()
            .flat_map(|row| row.actions.iter_mut().flatten());
        for (action, args) in actions.zip(args) {
            action.args = args;
        }
        output.lens = lens
            .map(|lens| lens.lift("self.inbox.get.lens"))
            .transpose()?;
        Ok(output)
    }
}
