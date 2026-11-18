//! A value read for the custody records it names (FIX
//! ERASED-IDENTITY-ONE-STAND-IN, Engine ANSWER 19 Nov 02:54 = B): what an
//! erased bridge request keeps beside its stand-in identity. The erase reads
//! the request with the values custody holds and keeps the records it names,
//! by their handles; the request read for those records' values alone, each
//! as its record's handle, is digested. A call made again is read the same
//! way for the same records, so the two meet only when its values name the
//! same records. Each secret a shape rule places reads as the plan's one
//! stand-in in either read, so no shaped secret is ever digested as written,
//! and no value custody holds is: only its record's handle. Nothing is
//! minted, and each copy is wiped when it drops (FIX 1101).

use std::collections::BTreeSet;
use std::sync::Arc;

use rmpv::Value;

use super::Masker;
use super::held_template::named_records;
use super::side_row::origin;
use super::wipe::PlanTree;
use crate::error::Result;
use crate::store::known_value_index::KnownValues;

/// The custody records `value` names, by their bare handles, once read with
/// the values custody holds, `known`: each handle it holds that names a
/// record custody knows, and each record whose value it holds as written
/// (a row stored before custody held that value). Empty when it names none.
///
/// # Errors
///
/// A value the plan cannot read.
pub(crate) fn custody_records_named(
    value: &Value,
    known: &Arc<KnownValues>,
) -> Result<BTreeSet<String>> {
    let read = records_read(value, known, None)?;
    let mut records = BTreeSet::new();
    named_records(&read.0, &mut records);
    records.retain(|handle| known.holds_handle(handle));
    Ok(records)
}

/// `value` read for the values of `records` alone, through `known`: each
/// value one of them holds, at any generation its history keeps and in any
/// spelling the known-value matcher reads, as its record's handle; each
/// secret a shape rule places as the plan's one stand-in; each handle and
/// every other byte as written. A value another record holds is read as any
/// other text is.
///
/// # Errors
///
/// A value the plan cannot read.
pub(crate) fn custody_record_form(
    value: &Value,
    known: &Arc<KnownValues>,
    records: &BTreeSet<String>,
) -> Result<Value> {
    let mut read = records_read(value, known, Some(records.clone()))?;
    Ok(std::mem::replace(&mut read.0, Value::Nil))
}

/// `value` as the replay plan reads it with `known`, for the values of
/// `records` alone when given. Nothing is minted.
fn records_read(
    value: &Value,
    known: &Arc<KnownValues>,
    records: Option<BTreeSet<String>>,
) -> Result<PlanTree> {
    let mut read = PlanTree(value.clone());
    Masker {
        mints: true,
        records,
        at: Some((origin("replay", &[])?, "replay".to_owned())),
        known: Some(Arc::clone(known)),
        ..Masker::default()
    }
    .mask_value(&mut read.0)?;
    Ok(read)
}
