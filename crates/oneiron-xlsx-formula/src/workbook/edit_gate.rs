//! The recalculated package against the edit round trip's corruption gate:
//! a result the gate would refuse goes to the fallback instead
//! (`keep_gated_bytes`).

use std::collections::BTreeSet;

use oneiron_docedit::retained_opc::Package;

use super::Formulas;
use crate::xml::{REL, Xml, unsupported};
use crate::{Result, route_workbook, storage_form};

/// The edit round trip's corruption gate keeps every part outside its
/// supported set byte for byte, keeps every external link with its part,
/// relationship and content type, and requires the OOXML function prefix in
/// each worksheet whose bytes change (`oneiron::edit_roundtrip`'s
/// `session_validate`). A recalculation that would fail any check goes to
/// the fallback instead: the writer adds or edits `xl/richData/` rich values
/// when it tags a new #SPILL! or #CALC!, and never rewrites formula text.
/// Its other edits (worksheets, `xl/metadata.xml`, and the content types and
/// relationships of added parts) are parts the gate lets change, so long as
/// a relationship part holding an external target, the workbook's link
/// relationships and the links' content types stay as they were. The host
/// reads the result back under its own limits, so the result must fit them.
pub(super) fn keep_gated_bytes(before: &Package, after: &[u8], formulas: &Formulas) -> Result<()> {
    let after = Package::open(after, before.limits(), before.resources())
        .map_err(|_| unsupported("recalculated package exceeds the host's package limits"))?;
    let kept: BTreeSet<&str> = after.names().collect();
    if before.names().any(|name| !kept.contains(name)) {
        return Err(unsupported("recalculation drops a package part"));
    }
    for name in after.names() {
        let part = after.part(name)?;
        if before.part(name)? == part {
            continue;
        }
        if let Some(xml) = &part
            && Xml::parse(xml, before.resources()).is_err()
        {
            return Err(unsupported(format!(
                "recalculated {name} does not read back under the host's XML limits"
            )));
        }
        match formulas.sheets.get(name) {
            Some(sheet)
                if sheet
                    .iter()
                    .all(|formula| storage_form(formula) == *formula) => {}
            Some(_) => {
                return Err(unsupported(
                    "recalculated worksheet has a formula without its OOXML function prefix",
                ));
            }
            None if name.starts_with("xl/externalLinks/") => {
                return Err(unsupported("recalculation changes an external link part"));
            }
            None if name == "[Content_Types].xml" => {
                let before_types = before.part(name)?;
                if link_content_types(before, before_types.as_deref())?
                    != link_content_types(before, part.as_deref())?
                {
                    return Err(unsupported(
                        "recalculation changes the content type of an external link",
                    ));
                }
            }
            None if name.ends_with(".rels") => {
                let before_rels = before.part(name)?;
                if before_rels.as_deref().is_some_and(|rels| {
                    !route_workbook([], [rels], [], before.resources()).is_in_process()
                }) {
                    return Err(unsupported(
                        "recalculation changes a relationship part with an external target",
                    ));
                }
                if name == "xl/_rels/workbook.xml.rels"
                    && link_relationships(before, before_rels.as_deref())?
                        != link_relationships(before, part.as_deref())?
                {
                    return Err(unsupported(
                        "recalculation changes the workbook's external link relationships",
                    ));
                }
            }
            None if name == "xl/metadata.xml" => {}
            None => {
                return Err(unsupported(format!(
                    "recalculation changes {name}, a part the edit gate passes through"
                )));
            }
        }
    }
    Ok(())
}

/// The workbook's external link relationships (`Id`, `Target`, `TargetMode`),
/// which the edit gate joins to its `<externalReference>` list.
fn link_relationships(
    package: &Package,
    rels: Option<&[u8]>,
) -> Result<Vec<(String, String, String)>> {
    let Some(rels) = rels else {
        return Ok(Vec::new());
    };
    let xml = Xml::parse(rels, package.resources())?;
    let mut links: Vec<_> = xml
        .nodes
        .iter()
        .filter(|node| {
            node.is(REL, "Relationship")
                && node
                    .attr("Type")
                    .is_some_and(|kind| kind.ends_with("/externalLink"))
        })
        .map(|node| {
            let attr = |name| node.attr(name).unwrap_or_default().to_owned();
            (attr("Id"), attr("Target"), attr("TargetMode"))
        })
        .collect();
    links.sort();
    Ok(links)
}

/// The content-type entries (`Override` by part name, `Default` by extension)
/// that type the link parts of `package`, from content types `types`.
fn link_content_types(
    package: &Package,
    types: Option<&[u8]>,
) -> Result<Vec<(String, String, String)>> {
    let Some(types) = types else {
        return Ok(Vec::new());
    };
    let xml = Xml::parse(types, package.resources())?;
    let links: BTreeSet<String> = package
        .names()
        .filter(|name| name.starts_with("xl/externalLinks/"))
        .map(|name| format!("/{name}").to_ascii_lowercase())
        .collect();
    let extensions: BTreeSet<String> = links
        .iter()
        .filter_map(|name| {
            name.rsplit_once('.')
                .map(|(_, extension)| extension.to_owned())
        })
        .collect();
    let mut entries: Vec<_> = xml
        .nodes
        .iter()
        .filter_map(|node| {
            let attr = |name| node.attr(name).unwrap_or_default().to_owned();
            if node.name == "Override" && links.contains(&attr("PartName").to_ascii_lowercase()) {
                Some(("Override".to_owned(), attr("PartName"), attr("ContentType")))
            } else if node.name == "Default"
                && extensions.contains(&attr("Extension").to_ascii_lowercase())
            {
                Some(("Default".to_owned(), attr("Extension"), attr("ContentType")))
            } else {
                None
            }
        })
        .collect();
    entries.sort();
    Ok(entries)
}
