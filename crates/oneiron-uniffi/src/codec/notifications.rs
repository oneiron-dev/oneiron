//! Owned notification actions and component properties in opened inbox cards.

use oneiron::agent_inbox_lens::InboxItemView;
use oneiron::inbox::{NotificationPage, NotificationRow};
use oneiron::lens::{LensAtom, LensNode};
use serde_json::Value;

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
        let lens = value.lens.take().map(|lens| {
            let stamp = lens.version_stamp();
            let mut root = lens.into_root();
            let props = take_component_props(&mut root);
            (stamp, root, props)
        });

        // Both optional subtrees are consumed before any error can return.
        let args = args.into_iter().collect::<Result<Vec<_>, _>>()?;
        let lens = lens
            .map(|(stamp, root, props)| {
                props
                    .into_iter()
                    .collect::<Result<Vec<_>, _>>()
                    .map(|props| (stamp, root, props))
            })
            .transpose()?;
        let mut output: Self = lift_record("self.inbox.get", &value)?;
        let actions = output
            .notification
            .iter_mut()
            .flat_map(|row| row.actions.iter_mut().flatten());
        for (action, args) in actions.zip(args) {
            action.args = args;
        }
        output.lens = lens
            .map(
                |(stamp, root, props)| -> Result<crate::GeneratedLens, OneironError> {
                    let mut root = lift_record("self.inbox.get.lens", &root)?;
                    restore_component_props(&mut root, props);
                    Ok(crate::GeneratedLens {
                        kit_version: stamp.kit_version(),
                        apps_contract_version: stamp.apps_contract_version(),
                        root,
                    })
                },
            )
            .transpose()?;
        Ok(output)
    }
}

fn take_component_props(root: &mut LensNode) -> Vec<Result<Option<WireJson>, OneironError>> {
    let mut pending = vec![root];
    let mut props = Vec::new();
    while let Some(node) = pending.pop() {
        if let LensAtom::Component(component) = &mut node.atom {
            props.push(match std::mem::take(&mut component.props) {
                Value::Null => Ok(None),
                value => WireJson::lift(value).map(Some),
            });
        }
        pending.extend(node.children.iter_mut().rev());
    }
    props
}

fn restore_component_props(root: &mut crate::LensNode, props: Vec<Option<WireJson>>) {
    let mut pending = vec![root];
    let mut props = props.into_iter();
    while let Some(node) = pending.pop() {
        if let crate::LensAtomWire::Component(component) = &mut node.atom {
            component.props = props
                .next()
                .expect("each native component keeps its mirror");
        }
        pending.extend(node.children.iter_mut().flatten().rev());
    }
}
