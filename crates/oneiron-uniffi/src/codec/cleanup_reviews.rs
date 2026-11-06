//! Owned entity bodies in cleanup review output records.

use oneiron::vault_cleanup::CleanupReviewView;

use super::{Lift, OneironError, WireJson, lift_record};

pub(crate) fn lift_cleanup_review(
    verb: &str,
    mut review: CleanupReviewView,
) -> Result<crate::CleanupReviewView, OneironError> {
    let bodies: Vec<_> = review
        .items
        .iter_mut()
        .map(|item| {
            item.content
                .as_mut()
                .and_then(|content| content.record.as_mut())
                .and_then(|read| read.value.as_mut())
                .and_then(|entity| entity.body.take())
                .filter(|body| !body.is_null())
                .map(WireJson::lift)
                .transpose()
        })
        .collect();
    // Consume every entity body before returning the first error.
    let bodies: Vec<_> = bodies.into_iter().collect::<Result<_, _>>()?;
    let mut output: crate::CleanupReviewView = lift_record(verb, &review)?;
    for (item, body) in output.items.iter_mut().zip(bodies) {
        if let Some(entity) = item
            .content
            .as_mut()
            .and_then(|content| content.record.as_mut())
            .and_then(|read| read.value.as_mut())
        {
            entity.body = body;
        }
    }
    Ok(output)
}
