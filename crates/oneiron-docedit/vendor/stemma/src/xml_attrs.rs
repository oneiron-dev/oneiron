// Reduced to the read-only attribute seam used by the retained document checker.
use xmltree::Element;

pub fn attr_get<'a>(element: &'a Element, qname: &str) -> Option<&'a String> {
    let (want_prefix, want_local) = split_qname(qname);

    if let Some(prefix) = want_prefix {
        for (name, value) in &element.attributes {
            if name.local_name == want_local && name.prefix.as_deref() == Some(prefix) {
                return Some(value);
            }
        }
    }

    for (name, value) in &element.attributes {
        if name.local_name == want_local {
            return Some(value);
        }
    }

    // Fallback for legacy non-namespaced keys like "w:id" that may still exist.
    for (name, value) in &element.attributes {
        if name.local_name == qname {
            return Some(value);
        }
    }

    None
}

fn split_qname(qname: &str) -> (Option<&str>, &str) {
    match qname.split_once(':') {
        Some((prefix, local)) if !prefix.is_empty() && !local.is_empty() => (Some(prefix), local),
        _ => (None, qname),
    }
}

