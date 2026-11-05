//! Retained causal inputs of a native map operation, never its admission.

use loro::Frontiers;

use super::super::super::EntityDoc;
use super::{NativeMapMutationView, NativeMapWriteView};
use crate::entity_doc::document::decode_frontier;
use crate::error::{Error, Result};

/// Missing retained state is unknown, not an absent native value. In
/// particular, neither the live selection nor the shallow floor replaces it.
/// These documents are read data; they confer no native or recipient permission.
pub(in crate::entity_doc) struct NativeMapReplay {
    before: Option<EntityDoc>,
    source: Option<EntityDoc>,
}

impl NativeMapReplay {
    pub(in crate::entity_doc) fn before(&self) -> Option<&EntityDoc> {
        self.before.as_ref()
    }

    /// An Insert's advertised source, when retained. A Delete advertises none.
    pub(in crate::entity_doc) fn source(&self) -> Option<&EntityDoc> {
        self.source.as_ref()
    }
}

impl NativeMapMutationView<'_> {
    /// Read the operation's actual causal predecessor and, for an Insert,
    /// its historical source. The caller still has to bind this inventory
    /// to its actual document and establish every source and native gate.
    pub(in crate::entity_doc) fn retained_inputs(
        &self,
        document: &EntityDoc,
    ) -> Result<NativeMapReplay> {
        if self.id.peer != self.change.peer || self.id.counter < self.change.counter {
            return Err(invalid());
        }
        // Earlier atoms of this same change are part of this operation's
        // input, even when they are not separate change dependencies.
        let before = if self.id.counter == self.change.counter {
            self.dependencies.iter().copied().collect::<Frontiers>()
        } else {
            Frontiers::from_id(self.id.inc(-1))
        };
        let before_vv = document.doc.frontiers_to_vv(&before);
        let source = match &self.write {
            NativeMapWriteView::Insert(fact) => {
                let operation = fact.operation()?;
                if document.birth().entity
                    != crate::EntityId::from_bytes(*operation.entity)?.to_hex()
                    || document.birth().at != operation.birth_at
                {
                    return Err(invalid());
                }
                let frontier = decode_frontier(operation.source_frontier)?;
                if let (Some(before), Some(source)) =
                    (before_vv.as_ref(), document.doc.frontiers_to_vv(&frontier))
                    && !before.includes_vv(&source)
                {
                    return Err(invalid());
                }
                let source = retained_state(document, &frontier)?;
                if let Some(source) = &source {
                    require_source_chain(fact, source)?;
                }
                source
            }
            NativeMapWriteView::Delete => None,
        };
        Ok(NativeMapReplay {
            before: retained_state(document, &before)?,
            source,
        })
    }
}

fn require_source_chain(
    fact: &super::super::codec::recipient::SkillStateFactView<'_>,
    source: &EntityDoc,
) -> Result<()> {
    let operation = fact.operation()?;
    let previous = super::super::register::read_fact(source)?;
    match previous {
        Some(previous) => {
            let prior = previous.view().operation()?;
            if operation.previous != Some(&previous.token()?)
                || prior.ordinal.checked_add(1) != Some(operation.ordinal)
                || prior.state != operation.prior
            {
                return Err(invalid());
            }
        }
        None if operation.previous.is_none() && operation.ordinal == 1 => {}
        None => return Err(invalid()),
    }
    Ok(())
}

fn retained_state(document: &EntityDoc, frontier: &Frontiers) -> Result<Option<EntityDoc>> {
    let Some(version) = document.doc.frontiers_to_vv(frontier) else {
        return Ok(None);
    };
    if document.doc.is_shallow() && !version.includes_vv(&document.doc.shallow_since_vv().to_vv()) {
        return Ok(None);
    }
    document.fork(&frontier.encode()).map(Some)
}

fn invalid() -> Error {
    Error::CorruptedIndex("native SKILL state causal inputs")
}
