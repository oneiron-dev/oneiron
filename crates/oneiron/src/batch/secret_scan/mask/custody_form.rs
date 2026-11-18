//! A value read for the custody records it names (FIX
//! ERASED-IDENTITY-ONE-STAND-IN, Engine ANSWER 19 Nov 02:54 = B): what an
//! erased bridge request keeps beside its stand-in identity. The erase reads
//! the request with the values custody holds and keeps the records it names,
//! by their handles; the request read for those records' values alone, each
//! as its record's handle, is digested. A call made again is read the same
//! way for the same records, so the two meet only when its values name the
//! same records. Each secret a shape rule places reads as the plan's one
//! stand-in in either read, so no shaped secret is ever digested as written,
//! and no value custody holds is: only its record's handle. A body a member
//! carries as bytes is read as the side-row wall reads it, as a body of its
//! own. Nothing is minted, and each copy is wiped when it drops (FIX 1101).

use std::collections::BTreeSet;
use std::sync::Arc;

use rmpv::Value;
use zeroize::Zeroizing;

use super::Masker;
use super::held_template::named_records;
use super::side_row::{byte_values, mask_tree, origin, whole_messagepack};
use super::wipe::PlanTree;
use crate::error::Result;
use crate::store::known_value_index::KnownValues;

/// The custody records `value` names, by their bare handles, once read with
/// the values custody holds, `known`: each handle it holds that names a
/// record custody knows, in a body it carries as bytes too, and each record
/// whose value it holds as written (a row stored before custody held that
/// value). Empty when it names none.
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
    records_in(&read.0, &mut records);
    records.retain(|handle| known.holds_handle(handle));
    Ok(records)
}

/// Each record a handle in `value` names, into `records`: in each text, and
/// in each body a member carries as bytes (binary, or an array of byte
/// values), decoded as the side-row wall decodes one.
fn records_in(value: &Value, records: &mut BTreeSet<String>) {
    named_records(value, records);
    match value {
        Value::Binary(bytes) => body_records(bytes, records),
        Value::Array(items) => match byte_values(items).map(Zeroizing::new) {
            Some(bytes) => body_records(&bytes, records),
            None => items.iter().for_each(|item| records_in(item, records)),
        },
        Value::Map(fields) => fields
            .iter()
            .for_each(|(_, member)| records_in(member, records)),
        _ => {}
    }
}

/// [`records_in`] for the body `bytes` spell: a JSON or whole MessagePack
/// body's tree, or else its text.
fn body_records(bytes: &[u8], records: &mut BTreeSet<String>) {
    // The decoded body holds what the request holds: wiped as it drops.
    let body = serde_json::from_slice::<Value>(bytes)
        .ok()
        .or_else(|| whole_messagepack(bytes))
        .map(PlanTree);
    match body {
        Some(body) => records_in(&body.0, records),
        None => named_records(&PlanTree(Value::Binary(bytes.to_vec())).0, records),
    }
}

/// `value` read for the values of `records` alone, through `known`: each
/// value one of them holds, at any generation its history keeps and in any
/// spelling the known-value matcher reads, as its record's handle; each
/// secret a shape rule places as the plan's one stand-in; each handle and
/// every other byte as written. A value another record holds is read as any
/// other text is. A body a member carries as bytes is read as a body.
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

/// `value` as the side-row wall's plan reads a row's value with `known`
/// (each body a member carries as bytes too), for the values of `records`
/// alone when given. Nothing is minted.
fn records_read(
    value: &Value,
    known: &Arc<KnownValues>,
    records: Option<BTreeSet<String>>,
) -> Result<PlanTree> {
    let mut read = PlanTree(value.clone());
    let mut plan = Masker {
        mints: true,
        records,
        at: Some((origin("replay", &[])?, "replay".to_owned())),
        known: Some(Arc::clone(known)),
        ..Masker::default()
    };
    mask_tree(&mut plan, &mut read.0)?;
    Ok(read)
}
