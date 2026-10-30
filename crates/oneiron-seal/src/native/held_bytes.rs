//! What the seal's own copies and decodes allocate, for the holds that
//! admit them to the operation's memory ledger (FIX 12260). Each counts the
//! copy's heap; what sits inline is counted with the struct that holds it.

use std::mem::size_of;

use lopdf::{Dictionary, Object};
use x509_cert::Certificate;
use x509_cert::attr::AttributeTypeAndValue;
use x509_cert::ext::pkix::name::GeneralName;
use x509_cert::ext::{Extension, Extensions};
use x509_cert::name::{Name, RelativeDistinguishedName};
use x509_tsp::TstInfo;

/// What a clone of `obj` allocates: its names' and strings' bytes, its
/// arrays' slots and its dictionaries' maps, as deep as lopdf's parser
/// nests them.
pub(crate) fn object(obj: &Object) -> usize {
    match obj {
        Object::Name(bytes) | Object::String(bytes, _) => bytes.len(),
        Object::Array(items) => array(items),
        Object::Dictionary(dict) => dictionary(dict),
        Object::Stream(stream) => dictionary(&stream.dict).saturating_add(stream.content.len()),
        Object::Null
        | Object::Boolean(_)
        | Object::Integer(_)
        | Object::Real(_)
        | Object::Reference(_) => 0,
    }
}

/// What a clone of `items` allocates: a slot for each object, and what each
/// holds.
pub(crate) fn array(items: &[Object]) -> usize {
    items.iter().fold(
        items.len().saturating_mul(size_of::<Object>()),
        |sum, item| sum.saturating_add(object(item)),
    )
}

/// What a clone of `dict` allocates: its map as lopdf's parser charges it
/// (each entry's hash, key and value, and two index slots and a control
/// byte per entry it has room for), its keys' bytes, and what each value
/// holds.
pub(crate) fn dictionary(dict: &Dictionary) -> usize {
    let entry = size_of::<usize>() + size_of::<Vec<u8>>() + size_of::<Object>();
    let slots = 2 * (size_of::<usize>() + 1);
    dict.iter().fold(
        dict.as_hashmap().capacity().saturating_mul(entry + slots),
        |sum, (key, value)| sum.saturating_add(key.len()).saturating_add(object(value)),
    )
}

/// What a `BTreeMap<K, V>` of at most `entries` entries allocates: every
/// node but the root holds 5 entries or more, so they fit in `1 + entries
/// / 5` nodes of 11 keys, 11 values, 12 child edges and 64 bytes of links
/// and counters (the bound lopdf admits its maps by, FIX 8450).
pub(crate) fn btree<K, V>(entries: usize) -> usize {
    let node = 11 * (size_of::<K>() + size_of::<V>()) + 12 * size_of::<usize>() + 64;
    node.div_ceil(5)
        .saturating_mul(entries)
        .saturating_add(node)
}

/// What a decoded (or cloned) certificate allocates past its struct: the
/// values it keeps, at most its `der_len` DER bytes, and the slots of its
/// names' and extensions' lists.
pub(crate) fn certificate(cert: &Certificate, der_len: usize) -> usize {
    let tbs = &cert.tbs_certificate;
    der_len
        .saturating_add(name(&tbs.issuer))
        .saturating_add(name(&tbs.subject))
        .saturating_add(extensions(tbs.extensions.as_ref()))
}

/// What decoded certificates allocate: a slot each in their list, and what
/// each keeps of its DER in `ders`.
pub(crate) fn certificates(chain: &[Certificate], ders: &[Vec<u8>]) -> usize {
    chain.iter().zip(ders).fold(
        chain.len().saturating_mul(size_of::<Certificate>()),
        |sum, (cert, der)| sum.saturating_add(certificate(cert, der.len())),
    )
}

/// What a decoded TSTInfo allocates past its struct: the values it keeps,
/// at most its `der_len` DER bytes, and the slots of its authority's name
/// and of its extensions.
pub(crate) fn tst_info(tst: &TstInfo, der_len: usize) -> usize {
    let tsa = match &tst.tsa {
        Some(GeneralName::DirectoryName(tsa)) => name(tsa),
        _ => 0,
    };
    der_len
        .saturating_add(tsa)
        .saturating_add(extensions(tst.extensions.as_ref()))
}

/// The slots of a decoded name's lists.
fn name(name: &Name) -> usize {
    name.0.iter().fold(
        name.0
            .capacity()
            .saturating_mul(size_of::<RelativeDistinguishedName>()),
        |sum, rdn| {
            sum.saturating_add(
                decoded_slots(rdn.0.len()).saturating_mul(size_of::<AttributeTypeAndValue>()),
            )
        },
    )
}

/// The slots of a decoded extension list.
fn extensions(extensions: Option<&Extensions>) -> usize {
    extensions.map_or(0, |list| {
        list.capacity().saturating_mul(size_of::<Extension>())
    })
}

/// The slots a list decoded one element at a time holds for `len`
/// elements: std's growth from none, 4 at least, then doubling.
fn decoded_slots(len: usize) -> usize {
    if len == 0 {
        0
    } else {
        len.max(4).checked_next_power_of_two().unwrap_or(usize::MAX)
    }
}
