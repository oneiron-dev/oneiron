//! Owned opaque component properties in generated lens trees and flat cards.

use oneiron::claim::{ScopedReadResult, WeaveDigestView};
use oneiron::lens::{
    GeneratedLens, GeneratedUiRender, LensAtom, LensFrameCard, LensListPage, LensNode,
    LensRenderId, LensVersionStamp,
};
use serde_json::Value;

use super::{Lift, OneironError, WireJson, lift_record, weave_reports};

pub(super) struct LensParts {
    stamp: LensVersionStamp,
    root: LensNode,
    props: Vec<Result<Option<WireJson>, OneironError>>,
}

impl LensParts {
    pub(super) fn take(lens: GeneratedLens) -> Self {
        let stamp = lens.version_stamp();
        let mut root = lens.into_root();
        let props = take_component_props(&mut root);
        Self { stamp, root, props }
    }

    pub(super) fn lift(self, context: &str) -> Result<crate::GeneratedLens, OneironError> {
        let props = self.props.into_iter().collect::<Result<Vec<_>, _>>()?;
        let mut root = lift_record(context, &self.root)?;
        restore_component_props(&mut root, props);
        Ok(crate::GeneratedLens {
            kit_version: self.stamp.kit_version(),
            apps_contract_version: self.stamp.apps_contract_version(),
            root,
        })
    }
}

struct FrameParts {
    card_id: LensRenderId,
    render: GeneratedUiRender,
    props: Vec<Result<Option<WireJson>, OneironError>>,
    lens: LensParts,
}

impl FrameParts {
    fn take(card: LensFrameCard) -> Self {
        let LensFrameCard {
            card_id,
            mut render,
            lens,
        } = card;
        let props = render
            .nodes
            .iter_mut()
            .filter_map(|node| take_atom_props(&mut node.atom))
            .collect();
        let lens = LensParts::take(lens);
        Self {
            card_id,
            render,
            props,
            lens,
        }
    }

    fn lift(self, context: &str) -> Result<crate::LensFrameCard, OneironError> {
        let props = self.props.into_iter().collect::<Result<Vec<_>, _>>()?;
        let mut render: crate::GeneratedUiRender = lift_record(context, &self.render)?;
        let mut props = props.into_iter();
        for node in &mut render.nodes {
            if let crate::LensAtomWire::Component(component) = &mut node.atom {
                component.props = props
                    .next()
                    .expect("each native component keeps its mirror");
            }
        }
        Ok(crate::LensFrameCard {
            card_id: lift_record(context, &self.card_id)?,
            render,
            lens: self.lens.lift(context)?,
        })
    }
}

impl Lift<LensFrameCard> for crate::LensFrameCard {
    fn lift(value: LensFrameCard) -> Result<Self, OneironError> {
        FrameParts::take(value).lift("vault.weave.lens")
    }
}

impl Lift<ScopedReadResult<LensFrameCard>> for crate::ScopedReadResultLensFrameCard {
    fn lift(value: ScopedReadResult<LensFrameCard>) -> Result<Self, OneironError> {
        let ScopedReadResult { value, receipt } = value;
        let value = FrameParts::take(value);
        Ok(Self {
            value: value.lift("vault.lenses.default.value")?,
            narrowing: lift_record("vault.lenses.default.narrowing", &receipt)?,
        })
    }
}

impl Lift<WeaveDigestView> for crate::WeaveDigestView {
    fn lift(mut value: WeaveDigestView) -> Result<Self, OneironError> {
        let json = weave_reports::take_claims(&mut value.sections);
        let lens = value.lens.take().map(FrameParts::take);

        // Every claim and both card representations are drained before any error returns.
        let json = json?;
        let mut output: Self = lift_record("vault.weave.digest", &value)?;
        weave_reports::restore_claims(&mut output.sections, json);
        output.lens = lens
            .map(|lens| lens.lift("vault.weave.digest.lens"))
            .transpose()?;
        Ok(output)
    }
}

impl Lift<LensListPage> for crate::LensListPage {
    fn lift(mut value: LensListPage) -> Result<Self, OneironError> {
        let lenses = value
            .rows
            .iter_mut()
            .map(|row| row.compiled.take().map(LensParts::take))
            .collect::<Vec<_>>();
        let mut output: Self = lift_record("vault.lenses.list", &value)?;
        for (row, lens) in output.rows.iter_mut().zip(lenses) {
            row.compiled = lens
                .map(|lens| lens.lift("vault.lenses.list.compiled"))
                .transpose()?;
        }
        Ok(output)
    }
}

fn take_atom_props(atom: &mut LensAtom) -> Option<Result<Option<WireJson>, OneironError>> {
    if let LensAtom::Component(component) = atom {
        Some(match std::mem::take(&mut component.props) {
            Value::Null => Ok(None),
            value => WireJson::lift(value).map(Some),
        })
    } else {
        None
    }
}

fn take_component_props(root: &mut LensNode) -> Vec<Result<Option<WireJson>, OneironError>> {
    let mut pending = vec![root];
    let mut props = Vec::new();
    while let Some(node) = pending.pop() {
        if let Some(prop) = take_atom_props(&mut node.atom) {
            props.push(prop);
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
