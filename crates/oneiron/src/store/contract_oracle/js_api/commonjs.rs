//! Direct CommonJS declarations, with lexical shadowing and exports detachment.
use super::{Binding, Module};
use oxc_ast::{
    AstKind,
    ast::{
        AssignmentExpression, AssignmentTarget, BindingPattern, Expression, IdentifierReference,
        MemberExpression, Program, Statement,
    },
};
use oxc_semantic::Semantic;
use oxc_syntax::symbol::{SymbolFlags, SymbolId};
use std::collections::BTreeSet;

enum Target {
    Whole,
    Property(Option<String>),
}

// Property receivers are captured from the original module value, before
// evaluating the chain's single fresh terminal value.
enum ChainReference {
    Whole,
    Exports,
    Property(String),
}

pub(super) fn collect(
    program: &Program<'_>,
    semantic: &Semantic<'_>,
    file: &str,
    module: &mut Module,
) {
    let mut alias = true;
    let mut native_module = true;
    let mut commonjs = program.source_type.is_commonjs();
    let mut accounted = BTreeSet::new();
    for statement in &program.body {
        if let Statement::VariableDeclaration(declaration) = statement
            && declaration.kind.is_var()
        {
            for declaration in &declaration.declarations {
                let BindingPattern::BindingIdentifier(binding) = &declaration.id else {
                    continue;
                };
                let Some(value) = &declaration.init else {
                    continue;
                };
                if !binding
                    .symbol_id
                    .get()
                    .is_some_and(|symbol| wrapper_symbol(symbol, semantic))
                {
                    continue;
                }
                if binding.name == "exports" {
                    alias = (native_module && whole_value(value, semantic, &mut accounted))
                        || (alias && wrapper(value, "exports", semantic, &mut accounted));
                } else if binding.name == "module" {
                    native_module =
                        native_module && wrapper(value, "module", semantic, &mut accounted);
                }
            }
            continue;
        }
        let Statement::ExpressionStatement(statement) = statement else {
            continue;
        };
        let mut pending = vec![&statement.expression];
        while let Some(expression) = pending.pop() {
            let expression = expression.get_inner_expression();
            if let Expression::SequenceExpression(sequence) = expression {
                pending.extend(sequence.expressions.iter().rev());
                continue;
            }
            if let Expression::UnaryExpression(unary) = expression {
                if unary.operator.is_delete()
                    && let Some(member) =
                        unary.argument.get_inner_expression().as_member_expression()
                    && let Some(deleted) =
                        target(member, semantic, alias, native_module, &mut accounted)
                {
                    commonjs = true;
                    match deleted {
                        Target::Property(Some(name)) => {
                            module.bindings.remove(&name);
                        }
                        Target::Property(None) => {
                            module
                                .unresolved
                                .insert("commonjs:computed-delete".to_owned());
                        }
                        Target::Whole => {
                            module.bindings.clear();
                            alias = false;
                        }
                    }
                }
                continue;
            }
            let Expression::AssignmentExpression(assignment) = expression else {
                continue;
            };
            if let Some(names) =
                property_chain(assignment, semantic, alias, native_module, &mut accounted)
            {
                commonjs = true;
                for name in names.into_iter().rev() {
                    module.bindings.insert(name.clone(), Binding::Local(name));
                }
                continue;
            }
            if let Some(value) =
                replacement_chain(assignment, semantic, alias, native_module, &mut accounted)
            {
                commonjs = true;
                alias = true;
                module.bindings.clear();
                value_bindings(value, module);
                continue;
            }
            if let Some((references, value)) =
                property_reference_chain(assignment, semantic, alias, native_module, &mut accounted)
            {
                commonjs = true;
                let mut module_replaced = false;
                let mut exports_rebound = false;
                for reference in references.into_iter().rev() {
                    match reference {
                        ChainReference::Whole => {
                            if !module_replaced {
                                module.bindings.clear();
                                value_bindings(value, module);
                                module_replaced = true;
                            }
                        }
                        ChainReference::Exports => exports_rebound = true,
                        ChainReference::Property(name) => {
                            if !module_replaced {
                                module.bindings.insert(name.clone(), Binding::Local(name));
                            }
                        }
                    }
                }
                alias = module_replaced && exports_rebound;
                continue;
            }
            if let AssignmentTarget::AssignmentTargetIdentifier(identifier) = &assignment.left {
                if identifier.name == "exports" && wrapper_reference(identifier, semantic) {
                    alias = assignment.operator.is_assign()
                        && ((native_module
                            && whole_value(&assignment.right, semantic, &mut accounted))
                            || (alias
                                && wrapper(
                                    &assignment.right,
                                    "exports",
                                    semantic,
                                    &mut accounted,
                                )));
                    accounted.insert((identifier.span.start, identifier.span.end));
                } else if identifier.name == "module" && wrapper_reference(identifier, semantic) {
                    native_module = assignment.operator.is_assign()
                        && native_module
                        && wrapper(&assignment.right, "module", semantic, &mut accounted);
                    accounted.insert((identifier.span.start, identifier.span.end));
                }
                continue;
            }
            let Some(member) = assignment.left.as_member_expression() else {
                continue;
            };
            let Some(target) = target(member, semantic, alias, native_module, &mut accounted)
            else {
                continue;
            };
            commonjs = true;
            match target {
                Target::Property(Some(name)) => {
                    if name == "__proto__" && !module.bindings.contains_key(&name) {
                        // Usually the inherited prototype setter, not an own key.
                        // An own key from an earlier literal remains a real export.
                        module
                            .unresolved
                            .insert("commonjs:prototype-assignment".to_owned());
                    } else {
                        module.bindings.insert(name.clone(), Binding::Local(name));
                    }
                }
                Target::Property(None) => {
                    module.unresolved.insert("commonjs:computed-key".to_owned());
                }
                Target::Whole => {
                    if !assignment.operator.is_assign() {
                        module
                            .unresolved
                            .insert("commonjs:compound-replacement".to_owned());
                        continue;
                    }
                    // A replacement changes the object; the wrapper's original
                    // `exports` alias no longer points at it.
                    let value = assignment.right.get_inner_expression();
                    if whole_value(value, semantic, &mut accounted)
                        || (alias && wrapper(value, "exports", semantic, &mut accounted))
                    {
                        continue;
                    }
                    alias = false;
                    module.bindings.clear();
                    if fresh_value(value) {
                        value_bindings(value, module);
                    } else {
                        module.unresolved.insert("commonjs:opaque-value".to_owned());
                    }
                }
            }
        }
    }
    // CommonJS supplies one whole-module value even when it has no named keys.
    if commonjs {
        module
            .bindings
            .insert("default".to_owned(), Binding::CommonJsValue);
    }
    for node in semantic.nodes().iter() {
        let AstKind::IdentifierReference(identifier) = node.kind() else {
            continue;
        };
        if matches!(identifier.name.as_str(), "module" | "exports")
            && wrapper_reference(identifier, semantic)
            && !accounted.contains(&(identifier.span.start, identifier.span.end))
        {
            module.unresolved.insert(format!(
                "commonjs:runtime:{}:{}",
                file, identifier.span.start
            ));
        }
    }
}

fn property_chain(
    assignment: &AssignmentExpression<'_>,
    semantic: &Semantic<'_>,
    alias: bool,
    native_module: bool,
    accounted: &mut BTreeSet<(u32, u32)>,
) -> Option<Vec<String>> {
    if !matches!(
        assignment.right.get_inner_expression(),
        Expression::AssignmentExpression(_)
    ) {
        return None;
    }
    let mut assignment = assignment;
    let mut names = Vec::new();
    let mut chain_accounted = BTreeSet::new();
    loop {
        if !assignment.operator.is_assign() {
            return None;
        }
        let member = assignment.left.as_member_expression()?;
        let Target::Property(Some(name)) =
            target(member, semantic, alias, native_module, &mut chain_accounted)?
        else {
            return None;
        };
        if name == "__proto__" {
            return None;
        }
        names.push(name);
        match assignment.right.get_inner_expression() {
            Expression::AssignmentExpression(next) => assignment = next,
            Expression::SequenceExpression(_) => return None,
            _ => break,
        }
    }
    accounted.extend(chain_accounted);
    Some(names)
}

fn replacement_chain<'ast, 'src>(
    assignment: &'ast AssignmentExpression<'src>,
    semantic: &Semantic<'_>,
    alias: bool,
    native_module: bool,
    accounted: &mut BTreeSet<(u32, u32)>,
) -> Option<&'ast Expression<'src>> {
    let mut assignment = assignment;
    let mut chain_accounted = BTreeSet::new();
    let mut assigns_exports = false;
    let mut assigns_whole = false;
    loop {
        if !assignment.operator.is_assign() {
            return None;
        }
        if let AssignmentTarget::AssignmentTargetIdentifier(identifier) = &assignment.left {
            if identifier.name != "exports" || !wrapper_reference(identifier, semantic) {
                return None;
            }
            assigns_exports = true;
            chain_accounted.insert((identifier.span.start, identifier.span.end));
        } else {
            let member = assignment.left.as_member_expression()?;
            if !matches!(
                target(member, semantic, alias, native_module, &mut chain_accounted),
                Some(Target::Whole)
            ) {
                return None;
            }
            assigns_whole = true;
        }
        match assignment.right.get_inner_expression() {
            Expression::AssignmentExpression(next) => assignment = next,
            value if assigns_exports && assigns_whole && fresh_value(value) => {
                // These references are stable: no link rebinds `module` or
                // targets a property of the replaceable exports value. Every
                // store receives this same value, so both slots re-alias.
                accounted.extend(chain_accounted);
                return Some(value);
            }
            _ => return None,
        }
    }
}

fn fresh_value(value: &Expression<'_>) -> bool {
    matches!(
        value,
        Expression::ObjectExpression(_)
            | Expression::FunctionExpression(_)
            | Expression::ArrowFunctionExpression(_)
            | Expression::ClassExpression(_)
    )
}

fn value_bindings(value: &Expression<'_>, module: &mut Module) {
    let Expression::ObjectExpression(object) = value else {
        return;
    };
    for property in &object.properties {
        let Some(property) = property.as_property() else {
            module
                .unresolved
                .insert("commonjs:object-spread".to_owned());
            continue;
        };
        if let Some(name) = property.key.static_name() {
            // A non-computed colon __proto__ sets the prototype,
            // rather than declaring an own exported property.
            if name == "__proto__"
                && !property.computed
                && !property.shorthand
                && !property.method
                && !property.kind.is_accessor()
            {
                continue;
            }
            module
                .bindings
                .insert(name.to_string(), Binding::Local(name.into_owned()));
        } else {
            module.unresolved.insert("commonjs:computed-key".to_owned());
        }
    }
}

fn property_reference_chain<'ast, 'src>(
    assignment: &'ast AssignmentExpression<'src>,
    semantic: &Semantic<'_>,
    alias: bool,
    native_module: bool,
    accounted: &mut BTreeSet<(u32, u32)>,
) -> Option<(Vec<ChainReference>, &'ast Expression<'src>)> {
    let mut assignment = assignment;
    let mut references = Vec::new();
    let mut chain_accounted = BTreeSet::new();
    let mut has_property = false;
    let mut has_slot = false;
    loop {
        if !assignment.operator.is_assign() {
            return None;
        }
        let reference =
            if let AssignmentTarget::AssignmentTargetIdentifier(identifier) = &assignment.left {
                if identifier.name != "exports" || !wrapper_reference(identifier, semantic) {
                    return None;
                }
                chain_accounted.insert((identifier.span.start, identifier.span.end));
                has_slot = true;
                ChainReference::Exports
            } else {
                let member = assignment.left.as_member_expression()?;
                match target(member, semantic, alias, native_module, &mut chain_accounted)? {
                    Target::Whole => {
                        has_slot = true;
                        ChainReference::Whole
                    }
                    Target::Property(Some(name)) if name != "__proto__" => {
                        has_property = true;
                        ChainReference::Property(name)
                    }
                    _ => return None,
                }
            };
        references.push(reference);
        match assignment.right.get_inner_expression() {
            Expression::AssignmentExpression(next) => assignment = next,
            value if has_property && has_slot && fresh_value(value) => {
                accounted.extend(chain_accounted);
                return Some((references, value));
            }
            _ => return None,
        }
    }
}

fn target(
    member: &MemberExpression<'_>,
    semantic: &Semantic<'_>,
    alias: bool,
    native_module: bool,
    accounted: &mut BTreeSet<(u32, u32)>,
) -> Option<Target> {
    let object = member.object().get_inner_expression();
    if native_module && wrapper(object, "module", semantic, accounted) {
        return (member.static_property_name() == Some("exports")).then_some(Target::Whole);
    }
    if wrapper(object, "exports", semantic, accounted) {
        return alias.then(|| Target::Property(member.static_property_name().map(str::to_owned)));
    }
    let object = object.as_member_expression()?;
    if native_module
        && object.static_property_name() == Some("exports")
        && wrapper(object.object(), "module", semantic, accounted)
    {
        return Some(Target::Property(
            member.static_property_name().map(str::to_owned),
        ));
    }
    None
}

fn whole_value(
    expression: &Expression<'_>,
    semantic: &Semantic<'_>,
    accounted: &mut BTreeSet<(u32, u32)>,
) -> bool {
    let Some(member) = expression.get_inner_expression().as_member_expression() else {
        return false;
    };
    member.static_property_name() == Some("exports")
        && wrapper(member.object(), "module", semantic, accounted)
}

fn wrapper(
    expression: &Expression<'_>,
    name: &str,
    semantic: &Semantic<'_>,
    accounted: &mut BTreeSet<(u32, u32)>,
) -> bool {
    let Expression::Identifier(identifier) = expression.get_inner_expression() else {
        return false;
    };
    if identifier.name != name || !wrapper_reference(identifier, semantic) {
        return false;
    }
    accounted.insert((identifier.span.start, identifier.span.end));
    true
}

fn wrapper_reference(identifier: &IdentifierReference<'_>, semantic: &Semantic<'_>) -> bool {
    if semantic.is_reference_to_global_variable(identifier) {
        return true;
    }
    identifier.reference_id.get().is_some_and(|reference| {
        semantic
            .scoping()
            .get_reference(reference)
            .symbol_id()
            .is_some_and(|symbol| wrapper_symbol(symbol, semantic))
    })
}

fn wrapper_symbol(symbol: SymbolId, semantic: &Semantic<'_>) -> bool {
    let scoping = semantic.scoping();
    if scoping.symbol_scope_id(symbol) != scoping.root_scope_id()
        || scoping.symbol_flags(symbol) != SymbolFlags::FunctionScopedVariable
    {
        return false;
    }
    // A root var redeclares a wrapper parameter. Only direct initializers
    // are modeled; conditional, destructured and loop-carried writes are not.
    scoping.symbol_declarations(symbol).all(|node| {
        let AstKind::VariableDeclarator(declarator) = semantic.nodes().kind(node) else {
            return false;
        };
        let AstKind::VariableDeclaration(declaration) = semantic.nodes().parent_kind(node) else {
            return false;
        };
        matches!(declarator.id, BindingPattern::BindingIdentifier(_))
            && !matches!(
                semantic.nodes().parent_kind(declaration.node_id.get()),
                AstKind::ForInStatement(_) | AstKind::ForOfStatement(_)
            )
            && (declarator.init.is_none()
                || matches!(
                    semantic.nodes().parent_kind(declaration.node_id.get()),
                    AstKind::Program(_)
                ))
    })
}
