//! Owned claim JSON in live and saved Weave sections.

use oneiron::claim::{WeaveItemView, WeaveReportView, WeaveSectionView};

use super::{Lift, OneironError, WireJson, claims, lift_record};

impl Lift<WeaveReportView> for crate::WeaveReportView {
    fn lift(mut value: WeaveReportView) -> Result<Self, OneironError> {
        let json = take_claims(&mut value.sections)?;
        let mut output: Self = lift_record("vault.weave.report", &value)?;
        restore_claims(&mut output.sections, json);
        Ok(output)
    }
}

pub(super) fn take_claims(
    sections: &mut [WeaveSectionView],
) -> Result<Vec<(WireJson, Option<WireJson>)>, OneironError> {
    sections
        .iter_mut()
        .flat_map(|section| &mut section.items)
        .filter_map(|item| {
            if let WeaveItemView::Claim { claim } = item {
                Some(claims::lift_json(
                    std::mem::take(&mut claim.value),
                    claim.scope.take(),
                ))
            } else {
                None
            }
        })
        .collect::<Vec<_>>()
        .into_iter()
        .collect()
}

pub(super) fn restore_claims(
    sections: &mut [crate::WeaveSectionView],
    json: Vec<(WireJson, Option<WireJson>)>,
) {
    let mut json = json.into_iter();
    for item in sections.iter_mut().flat_map(|section| &mut section.items) {
        if let crate::WeaveItemView::Claim { claim } = item {
            let (value, scope) = json.next().expect("each native claim keeps its mirror");
            claim.value = value;
            claim.scope = scope;
        }
    }
}
