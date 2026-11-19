//! Admitting a formula's external references: the workbook names that read
//! a linked workbook (`LinkedBooks::names`) and the walk over one formula
//! (`LinkedBooks::admit`). What a reference's kind and its place in the
//! formula allow is in the parent module.

use std::collections::{BTreeMap, BTreeSet};

use formualizer_parse::parser::{ASTNode, ASTNodeType, ExternalReference, ReferenceType};

use super::{
    BOUND, LINKED_LOCATION, LinkedBook, LinkedBooks, LinkedName, Parent, absolute, bare_name,
    binds_a_link, criteria_range, cropped, hands_on_a_link, link_index, linked_name,
    linked_workbook_name, mentions_link, name_key, one_cell, passed_on, reads_a_range,
    reads_linked_location, reads_past_saved_values, reads_reference, relative_link, used_names,
};
use crate::Result;
use crate::xml::unsupported;

impl LinkedBooks {
    /// The defined names (upper case) that read a linked workbook: through a
    /// linked reference in their formula, or through another such name.
    pub(crate) fn names<'a>(
        &self,
        names: impl IntoIterator<Item = (&'a str, &'a ASTNode)>,
    ) -> BTreeMap<String, LinkedName> {
        let names: Vec<(String, &ASTNode)> = names
            .into_iter()
            .map(|(name, formula)| (name.to_ascii_uppercase(), formula))
            .collect();
        // The definitions that use each name, so a name that reads a linked
        // workbook marks every definition using it in turn.
        let mut users: BTreeMap<String, Vec<usize>> = BTreeMap::new();
        for (index, (_, formula)) in names.iter().enumerate() {
            let mut used = BTreeSet::new();
            used_names(formula, &mut used);
            for name in used {
                users.entry(name).or_default().push(index);
            }
        }
        let mut reads = vec![false; names.len()];
        let mut pending: Vec<usize> = (0..names.len())
            .filter(|&index| mentions_link(names[index].1, &BTreeMap::new()))
            .collect();
        while let Some(index) = pending.pop() {
            if std::mem::replace(&mut reads[index], true) {
                continue;
            }
            pending.extend(users.get(&names[index].0).into_iter().flatten());
        }
        let mut linked = BTreeMap::new();
        for ((name, formula), _) in names.iter().zip(&reads).filter(|(_, reads)| **reads) {
            let shape = match &formula.node_type {
                ASTNodeType::Reference {
                    reference: ReferenceType::External(external),
                    ..
                } if absolute(external.kind) => LinkedName::Reference(external.clone()),
                // A relative reference in a name moves with the cell using
                // it, bare or inside an expression; the fork reads every
                // name's formula at A1 (`evaluate_named_formula`).
                _ if relative_link(formula) => LinkedName::Unclear,
                _ => LinkedName::Expression((*formula).clone()),
            };
            // A name defined in several scopes may hold any of its formulas.
            linked
                .entry(name.clone())
                .and_modify(|known| *known = LinkedName::Unclear)
                .or_insert(shape);
        }
        linked
    }

    /// Admit one formula's external references, or name why they are the
    /// fallback's. `names` are the workbook names that read a linked workbook.
    pub(crate) fn admit<'a>(
        &self,
        formula: &'a ASTNode,
        names: &'a BTreeMap<String, LinkedName>,
    ) -> Result<()> {
        let mut pending = vec![Entry::Node(formula, Parent::Root)];
        let mut active: BTreeSet<*const ASTNode> = BTreeSet::new();
        let mut completed: BTreeSet<NameCheck<'a>> = BTreeSet::new();
        let mut handed_on = false;
        while let Some(entry) = pending.pop() {
            let (node, parent) = match entry {
                Entry::NameDone(done) => {
                    active.remove(&done.expression);
                    completed.insert(done);
                    continue;
                }
                Entry::Node(node, parent) => (node, parent),
            };
            passed_on(node, &parent, names)?;
            match &node.node_type {
                ASTNodeType::Reference { reference, .. } => {
                    // A name holding an expression over linked values is
                    // checked as if its formula were written here.
                    if let Some(expression) = self.reference(reference, &parent, names)? {
                        let check = NameCheck {
                            expression: expression as *const ASTNode,
                            parent: parent.context(),
                        };
                        if completed.contains(&check) {
                            continue;
                        }
                        if !active.insert(check.expression) {
                            return Err(unsupported(
                                "workbook names over linked workbooks in a reference cycle",
                            ));
                        }
                        pending.push(Entry::NameDone(check));
                        pending.push(Entry::Node(expression, parent));
                    }
                }
                ASTNodeType::Literal(_) | ASTNodeType::Omitted => {}
                ASTNodeType::UnaryOp { op, expr } => {
                    pending.push(Entry::Node(expr, Parent::Operator(op)));
                }
                ASTNodeType::BinaryOp { op, left, right } => {
                    // The fork has no intersection, union or range of linked
                    // references, however they are reached (`INDEX(...) INDEX(...)`).
                    if matches!(op.as_str(), ":" | " " | ",")
                        && (mentions_link(left, names) || mentions_link(right, names))
                    {
                        return Err(unsupported("external reference in a reference operator"));
                    }
                    pending.push(Entry::Node(left, Parent::Operator(op)));
                    pending.push(Entry::Node(right, Parent::Operator(op)));
                }
                ASTNodeType::Function { name, args } => {
                    let bare = bare_name(name);
                    if binds_a_link(&bare, args, names) {
                        return Err(unsupported(BOUND));
                    }
                    // One position into what another function or a name
                    // hands on: the shape `reads_a_range` checks is the inner
                    // one (`INDEX(INDEX([1]S!A1:B5,0,0),3)` is #REF! in
                    // Excel, the block's third row in the fork). Refused
                    // after the walk, so a reason found inside wins.
                    handed_on |=
                        bare == "INDEX" && args.len() == 2 && hands_on_a_link(&args[0], names);
                    // INDEX hands on the reference it selects, so its range
                    // is read as a reference wherever the INDEX is.
                    let through = bare == "INDEX"
                        && matches!(
                            parent,
                            Parent::Argument {
                                reference: true,
                                ..
                            }
                        );
                    for (index, arg) in args.iter().enumerate() {
                        pending.push(Entry::Node(
                            arg,
                            Parent::Argument {
                                reference: reads_reference(&bare) || (through && index == 0),
                                function: bare.clone(),
                                index,
                                args,
                            },
                        ));
                    }
                }
                ASTNodeType::Call { callee, args } => {
                    // A LAMBDA's parameters hold its arguments as the fork's
                    // LET names do.
                    if args.iter().any(|arg| mentions_link(arg, names)) {
                        return Err(unsupported(BOUND));
                    }
                    pending.push(Entry::Node(callee, Parent::Operator("")));
                    pending.extend(
                        args.iter()
                            .map(|arg| Entry::Node(arg, Parent::Operator(""))),
                    );
                }
                ASTNodeType::Array(rows) => {
                    pending.extend(
                        rows.iter()
                            .flatten()
                            .map(|arg| Entry::Node(arg, Parent::Operator(""))),
                    );
                }
            }
        }
        if handed_on {
            return Err(unsupported(
                "external range given one INDEX position through another function or a name",
            ));
        }
        Ok(())
    }

    /// Check one reference, and return the expression of a workbook name
    /// that holds one over linked values, to check where it is used.
    fn reference<'a>(
        &self,
        reference: &ReferenceType,
        parent: &Parent<'_>,
        names: &'a BTreeMap<String, LinkedName>,
    ) -> Result<Option<&'a ASTNode>> {
        match reference {
            ReferenceType::External(external) => self.external(external, parent).map(|()| None),
            // A workbook name for a linked reference reads as that reference.
            ReferenceType::NamedRange(name) if !linked_name(name) => {
                match names.get(&name_key(name)) {
                    Some(LinkedName::Reference(external)) => {
                        // A criteria function refuses a closed linked range
                        // written in it (#VALUE!), which the fork does too, and
                        // one a name holds as well, which the fork computes.
                        if criteria_range(parent) {
                            return Err(unsupported(
                                "external range reaching a criteria function through a name",
                            ));
                        }
                        self.external(external, parent).map(|()| None)
                    }
                    Some(LinkedName::Expression(expression)) => Ok(Some(expression)),
                    Some(LinkedName::Unclear) => Err(unsupported(
                        "workbook name holding a relative or repeated linked reference",
                    )),
                    None => Ok(None),
                }
            }
            ReferenceType::NamedRange(name) => linked_workbook_name(name).map(|()| None),
            // A table of a closed linked workbook is #REF! for both.
            _ => Ok(None),
        }
    }

    /// Admit a workbook name's formula. A name that is one linked reference is
    /// read where the formulas using it put it, which `admit` checks there;
    /// here only its link is.
    pub(crate) fn admit_name(
        &self,
        formula: &ASTNode,
        names: &BTreeMap<String, LinkedName>,
    ) -> Result<()> {
        match &formula.node_type {
            ASTNodeType::Reference {
                reference: ReferenceType::External(external),
                ..
            } => self.book(external).map(|_| ()),
            _ => self.admit(formula, names),
        }
    }

    /// The link a reference reads, or why the engine cannot read it.
    fn book(&self, external: &ExternalReference) -> Result<&LinkedBook> {
        let book = link_index(external.book.token())
            .filter(|&index| index > 0)
            .and_then(|index| self.books.get(index - 1))
            .ok_or_else(|| unsupported("external reference outside the workbook's links"))?;
        // `[1]Jan:Dec!A1`: no sheet name holds a colon.
        if external.sheet.contains(':') {
            return Err(unsupported("external 3D reference"));
        }
        Ok(book)
    }

    fn external(&self, external: &ExternalReference, parent: &Parent<'_>) -> Result<()> {
        let book = self.book(external)?;
        if reads_linked_location(parent) {
            return Err(unsupported(LINKED_LOCATION));
        }
        if !one_cell(external.kind) && !reads_a_range(parent, external.kind) {
            return Err(unsupported(
                "external range returned or passed on as a reference",
            ));
        }
        let sheet = external.sheet.to_lowercase();
        // A sheet the link does not name is #REF! for both.
        let unsaved_is_error = book
            .sheets
            .iter()
            .find(|(name, _)| *name == sheet)
            .is_some_and(|(_, unsaved_is_error)| *unsaved_is_error);
        if cropped(external.kind) && !reads_past_saved_values(parent, unsaved_is_error) {
            return Err(unsupported(if unsaved_is_error {
                "external range past the saved values of a sheet Excel could not refresh"
            } else {
                "external range past the saved values of a linked sheet"
            }));
        }
        Ok(())
    }
}

/// A use of a workbook name holding an expression over linked values: the
/// exact expression the map holds, by identity, and the complete incoming
/// context that the checks read.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord)]
struct NameCheck<'a> {
    expression: *const ASTNode,
    parent: ParentContext<'a>,
}

/// Every semantic input the checks read from a `Parent`: the operator
/// itself, or the function's bare upper-case name, the argument's index,
/// whether the function reads it as a reference, and the exact argument
/// list by identity (its contents do not change during the check).
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord)]
enum ParentContext<'a> {
    Root,
    Operator(&'a str),
    Argument {
        function: String,
        index: usize,
        reference: bool,
        args: *const ASTNode,
        len: usize,
    },
}

impl<'a> Parent<'a> {
    fn context(&self) -> ParentContext<'a> {
        match self {
            Parent::Root => ParentContext::Root,
            Parent::Operator(op) => ParentContext::Operator(op),
            Parent::Argument {
                function,
                index,
                args,
                reference,
            } => ParentContext::Argument {
                function: function.clone(),
                index: *index,
                reference: *reference,
                args: args.as_ptr(),
                len: args.len(),
            },
        }
    }
}

/// One item of `admit`'s worklist: a formula node to check, or the end of
/// a workbook name's expression, whose context is then complete.
enum Entry<'a> {
    Node(&'a ASTNode, Parent<'a>),
    NameDone(NameCheck<'a>),
}
