//! Direct CommonJS declarations, with lexical shadowing and exports detachment.
use super::{Binding, Module};
use oxc_ast::{
    AstKind,
    ast::{AssignmentTarget, Expression, MemberExpression, Program, Statement},
};
use oxc_semantic::Semantic;
use std::collections::BTreeSet;

enum Target {
    Whole,
    Property(Option<String>),
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
        let Statement::ExpressionStatement(statement) = statement else {
            continue;
        };
        let Expression::AssignmentExpression(assignment) =
            statement.expression.get_inner_expression()
        else {
            continue;
        };
        if let AssignmentTarget::AssignmentTargetIdentifier(identifier) = &assignment.left {
            if identifier.name == "exports" && semantic.is_reference_to_global_variable(identifier)
            {
                alias = assignment.operator.is_assign()
                    && native_module
                    && whole_value(&assignment.right, semantic, &mut accounted);
                accounted.insert((identifier.span.start, identifier.span.end));
            } else if identifier.name == "module"
                && semantic.is_reference_to_global_variable(identifier)
            {
                native_module = false;
                accounted.insert((identifier.span.start, identifier.span.end));
            }
            continue;
        }
        let Some(member) = assignment.left.as_member_expression() else {
            continue;
        };
        let Some(target) = target(member, semantic, alias, native_module, &mut accounted) else {
            continue;
        };
        commonjs = true;
        match target {
            Target::Property(Some(name)) => {
                module.bindings.insert(name.clone(), Binding::Local(name));
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
                    || (alias && global(value, "exports", semantic, &mut accounted))
                {
                    continue;
                }
                alias = false;
                module.bindings.clear();
                if let Expression::ObjectExpression(object) = value {
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
                } else if !matches!(
                    value,
                    Expression::FunctionExpression(_)
                        | Expression::ArrowFunctionExpression(_)
                        | Expression::ClassExpression(_)
                ) {
                    module.unresolved.insert("commonjs:opaque-value".to_owned());
                }
            }
        }
    }
    // CommonJS supplies one whole-module value even when it has no named keys.
    if commonjs {
        module.bindings.insert(
            "default".to_owned(),
            Binding::Local("*commonjs-default*".to_owned()),
        );
    }
    for node in semantic.nodes().iter() {
        let AstKind::IdentifierReference(identifier) = node.kind() else {
            continue;
        };
        if matches!(identifier.name.as_str(), "module" | "exports")
            && semantic.is_reference_to_global_variable(identifier)
            && !accounted.contains(&(identifier.span.start, identifier.span.end))
        {
            module.unresolved.insert(format!(
                "commonjs:runtime:{}:{}",
                file, identifier.span.start
            ));
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
    if native_module && global(object, "module", semantic, accounted) {
        return (member.static_property_name() == Some("exports")).then_some(Target::Whole);
    }
    if global(object, "exports", semantic, accounted) {
        return alias.then(|| Target::Property(member.static_property_name().map(str::to_owned)));
    }
    let object = object.as_member_expression()?;
    if native_module
        && object.static_property_name() == Some("exports")
        && global(object.object(), "module", semantic, accounted)
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
        && global(member.object(), "module", semantic, accounted)
}

fn global(
    expression: &Expression<'_>,
    name: &str,
    semantic: &Semantic<'_>,
    accounted: &mut BTreeSet<(u32, u32)>,
) -> bool {
    let Expression::Identifier(identifier) = expression.get_inner_expression() else {
        return false;
    };
    if identifier.name != name || !semantic.is_reference_to_global_variable(identifier) {
        return false;
    }
    accounted.insert((identifier.span.start, identifier.span.end));
    true
}
