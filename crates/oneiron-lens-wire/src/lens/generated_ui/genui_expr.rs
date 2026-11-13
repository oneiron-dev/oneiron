//! The expression tier of an app component's props (ARCH-0048 G5 #2; the
//! expression system of eiri-dec-0011): a prop is a literal or an expression
//! object, the `$` prefix marks the expression, and a component never sees one.
//! A surface that declares the tier ([`GeneratedUiExpressionProfile`]) resolves
//! each expression against the card's `$state` and hands its component the
//! plain value; on every other surface the component lowers to its node's
//! `fallbackText`.
//!
//! The forms are closed, and there is no general evaluator:
//! - `{"$state": "/<key>"}` reads one declared `$state` key;
//! - `{"$computed": "<function>", "args": {"of": [...]}}` calls one pure function
//!   of the engine's fixed set ([`GeneratedUiComputedFunction`]), which the
//!   client registers; each value of `of` is a prop value in turn;
//! - `{"$cond": <predicate>, "$then": <value>, "$else": <value>}` draws one of
//!   two prop values. The predicate is the closed algebra (ARCH-0048 G5 #2,
//!   eiri-arch-0012): `true` or `false`; `{"$state": "/<key>", "<op>": <literal>}`
//!   with exactly one of `eq`, `neq`, `gt`, `gte`, `lt`, `lte`; a list, which
//!   holds when all of its predicates do; `{"$and": [...]}`; `{"$or": [...]}`;
//! - `{"$template": "text ${/<key>} text"}` draws text around at most one escaped
//!   read of a text, number or token key: the single escaped interpolation point
//!   a text block has.
//!
//! The engine proves every expression at assembly and after every accepted
//! patch: each key it reads is declared and stays present, each comparison and
//! template reads a key of the kind it needs, and each argument has its
//! function's kind. At lowering it resolves the props against the card's
//! `$state` and checks them against the component's declared schema.

use std::borrow::Cow;
use std::cmp::Ordering;

use serde::{Deserialize, Serialize};
use serde_json::{Map, Number, Value};

use super::{GeneratedUiStateSnapshot, SelfUiStateValue};
use crate::lens::wire_ids::SelfUiStateKey;
use crate::{Error, Result};

/// How deeply expressions may nest inside one another: a `$computed` argument
/// or a `$cond` branch that is itself an expression is one level down. Plain
/// lists and records in the props do not count. A `$cond` predicate nests at
/// most as deep.
const MAX_PROP_EXPRESSION_DEPTH: usize = 8;

const STATE_EXPRESSION: &str = "$state";
const COMPUTED_EXPRESSION: &str = "$computed";
const COMPUTED_ARGUMENTS: &str = "args";
const COMPUTED_LIST_ARGUMENT: &str = "of";
const COND_EXPRESSION: &str = "$cond";
const COND_THEN: &str = "$then";
const COND_ELSE: &str = "$else";
const TEMPLATE_EXPRESSION: &str = "$template";
const TEMPLATE_READ_OPEN: &str = "${";
const PREDICATE_ALL: &str = "$and";
const PREDICATE_ANY: &str = "$or";

/// The fixed set of pure functions a `$computed` may call (ARCH-0048 G5 #2: "a
/// client-registered pure function (fixed set), never agent code"). The engine
/// names the set, so it can prove each call's arguments and the props a call
/// yields; a client registers an implementation of each function it draws and
/// names them on its surface ([`GeneratedUiExpressionProfile::computed`]).
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    Serialize,
    Deserialize,
    schemars::JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum GeneratedUiComputedFunction {
    /// How many values of `args.of`, a list of bools, are true.
    Count,
    /// The sum of `args.of`, a list of numbers.
    Sum,
}

impl GeneratedUiComputedFunction {
    fn parse(name: &Value) -> Result<Self> {
        match name.as_str() {
            Some("count") => Ok(Self::Count),
            Some("sum") => Ok(Self::Sum),
            _ => Err(Error::InvalidConfig(format!(
                "generated-ui $computed {name} is not a function of the engine's fixed set"
            ))),
        }
    }

    /// The kind every value of `args.of` has.
    const fn argument_kind(self) -> PropKind {
        match self {
            Self::Count => PropKind::Bool,
            Self::Sum => PropKind::Number,
        }
    }

    /// The function over its resolved `args.of`.
    fn apply(self, values: &[Value]) -> Result<Value> {
        let mismatch = || {
            Error::InvalidConfig(format!(
                "generated-ui $computed {self:?} takes {} values",
                self.argument_kind().name()
            ))
        };
        match self {
            Self::Count => {
                let mut count = 0usize;
                for value in values {
                    if value.as_bool().ok_or_else(mismatch)? {
                        count += 1;
                    }
                }
                Ok(Value::from(count))
            }
            Self::Sum => {
                let mut sum = 0.0_f64;
                for value in values {
                    sum += value.as_f64().ok_or_else(mismatch)?;
                }
                Number::from_f64(sum).map(Value::Number).ok_or_else(|| {
                    Error::InvalidConfig("generated-ui $computed sum must be finite".to_string())
                })
            }
        }
    }
}

/// The expression tier a surface resolves in app-component props. A surface that
/// declares it resolves every `$state` read, `$cond` and `$template`, and the
/// `$computed` functions it names; a surface that does not lowers each component
/// whose props hold an expression to its `fallbackText`.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GeneratedUiExpressionProfile {
    /// The `$computed` functions the client registered.
    #[serde(default)]
    pub computed: Vec<GeneratedUiComputedFunction>,
}

impl GeneratedUiExpressionProfile {
    fn resolves(&self, expression: &PropExpression<'_>) -> bool {
        match expression {
            PropExpression::State(_)
            | PropExpression::Cond { .. }
            | PropExpression::Template(_) => true,
            PropExpression::Computed { function, .. } => self.computed.contains(function),
        }
    }
}

/// The kind of one plain value an expression yields.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PropKind {
    Bool,
    Number,
    Text,
}

impl PropKind {
    fn of_state(value: &SelfUiStateValue) -> Self {
        match value {
            SelfUiStateValue::Bool(_) => Self::Bool,
            SelfUiStateValue::Number(_) => Self::Number,
            SelfUiStateValue::Text(_) | SelfUiStateValue::Token(_) => Self::Text,
        }
    }

    fn of_literal(value: &Value) -> Option<Self> {
        match value {
            Value::Bool(_) => Some(Self::Bool),
            Value::Number(_) => Some(Self::Number),
            Value::String(_) => Some(Self::Text),
            Value::Null | Value::Array(_) | Value::Object(_) => None,
        }
    }

    const fn name(self) -> &'static str {
        match self {
            Self::Bool => "bool",
            Self::Number => "number",
            Self::Text => "text",
        }
    }
}

/// One comparison of the closed predicate algebra.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Comparison {
    Eq,
    Neq,
    Gt,
    Gte,
    Lt,
    Lte,
}

impl Comparison {
    fn parse(name: &str) -> Option<Self> {
        match name {
            "eq" => Some(Self::Eq),
            "neq" => Some(Self::Neq),
            "gt" => Some(Self::Gt),
            "gte" => Some(Self::Gte),
            "lt" => Some(Self::Lt),
            "lte" => Some(Self::Lte),
            _ => None,
        }
    }

    /// Whether this comparison orders numbers rather than matching a value.
    const fn orders(self) -> bool {
        matches!(self, Self::Gt | Self::Gte | Self::Lt | Self::Lte)
    }

    /// Whether `value` stands in this relation to `literal`, a literal of its kind.
    fn holds(self, value: &SelfUiStateValue, literal: &Value) -> Result<bool> {
        let ordering = match (value, literal) {
            (SelfUiStateValue::Bool(value), Value::Bool(literal)) => Some(value.cmp(literal)),
            (SelfUiStateValue::Number(value), Value::Number(literal)) => literal
                .as_f64()
                .and_then(|literal| value.get().partial_cmp(&literal)),
            (SelfUiStateValue::Text(value), Value::String(literal)) => {
                Some(value.as_str().cmp(literal.as_str()))
            }
            (SelfUiStateValue::Token(value), Value::String(literal)) => {
                Some(value.as_str().cmp(literal.as_str()))
            }
            _ => None,
        }
        .ok_or_else(|| {
            Error::InvalidConfig(format!(
                "generated-ui $cond compares a {} $state value with {literal}",
                value.type_name()
            ))
        })?;
        Ok(match self {
            Self::Eq => ordering == Ordering::Equal,
            Self::Neq => ordering != Ordering::Equal,
            Self::Gt => ordering == Ordering::Greater,
            Self::Gte => ordering != Ordering::Less,
            Self::Lt => ordering == Ordering::Less,
            Self::Lte => ordering != Ordering::Greater,
        })
    }
}

/// A `$cond` predicate: the closed algebra, with no general evaluator.
enum Predicate {
    /// `true` or `false`.
    Static(bool),
    /// A list, or `{"$and": [...]}`: every predicate holds.
    All(Vec<Predicate>),
    /// `{"$or": [...]}`: some predicate holds.
    Any(Vec<Predicate>),
    /// `{"$state": "/<key>", "<op>": <literal>}`.
    Compare {
        key: SelfUiStateKey,
        comparison: Comparison,
        literal: Value,
    },
}

impl Predicate {
    fn read(value: &Value, depth: usize) -> Result<Self> {
        if depth >= MAX_PROP_EXPRESSION_DEPTH {
            return Err(Error::InvalidConfig(format!(
                "generated-ui $cond predicates nest at most {MAX_PROP_EXPRESSION_DEPTH} deep"
            )));
        }
        match value {
            Value::Bool(holds) => Ok(Self::Static(*holds)),
            Value::Array(items) => Self::read_all(items, depth).map(Self::All),
            Value::Object(object) => Self::read_object(object, depth),
            Value::Null | Value::Number(_) | Value::String(_) => Err(Error::InvalidConfig(
                format!("generated-ui $cond predicate {value} is not of the closed algebra"),
            )),
        }
    }

    fn read_all(items: &[Value], depth: usize) -> Result<Vec<Self>> {
        if items.is_empty() {
            return Err(Error::InvalidConfig(
                "generated-ui $cond predicate lists must not be empty".to_string(),
            ));
        }
        items
            .iter()
            .map(|item| Self::read(item, depth + 1))
            .collect()
    }

    fn read_list(items: &Value, depth: usize) -> Result<Vec<Self>> {
        let items = items.as_array().ok_or_else(|| {
            Error::InvalidConfig("generated-ui $and and $or take a list".to_string())
        })?;
        Self::read_all(items, depth)
    }

    fn read_object(object: &Map<String, Value>, depth: usize) -> Result<Self> {
        if let Some(items) = object.get(PREDICATE_ALL) {
            only_fields(object, &[PREDICATE_ALL])?;
            return Self::read_list(items, depth).map(Self::All);
        }
        if let Some(items) = object.get(PREDICATE_ANY) {
            only_fields(object, &[PREDICATE_ANY])?;
            return Self::read_list(items, depth).map(Self::Any);
        }
        let not_one_comparison = || {
            Error::InvalidConfig(
                "generated-ui $cond comparison is {\"$state\": \"/<key>\", \"<op>\": <literal>} with exactly one of eq, neq, gt, gte, lt, lte"
                    .to_string(),
            )
        };
        let key = state_pointer_key(
            object
                .get(STATE_EXPRESSION)
                .ok_or_else(not_one_comparison)?,
        )?;
        let mut comparisons = object
            .iter()
            .filter(|(name, _)| name.as_str() != STATE_EXPRESSION);
        let (Some((name, literal)), None) = (comparisons.next(), comparisons.next()) else {
            return Err(not_one_comparison());
        };
        let comparison = Comparison::parse(name).ok_or_else(not_one_comparison)?;
        let literal_fits = match literal {
            Value::Number(_) => true,
            Value::Bool(_) | Value::String(_) => !comparison.orders(),
            Value::Null | Value::Array(_) | Value::Object(_) => false,
        };
        if !literal_fits {
            return Err(Error::InvalidConfig(format!(
                "generated-ui $cond {name} takes a {} literal, not {literal}",
                if comparison.orders() {
                    "number"
                } else {
                    "bool, number or text"
                }
            )));
        }
        Ok(Self::Compare {
            key,
            comparison,
            literal: literal.clone(),
        })
    }

    /// Proves every comparison against `state`: its key is declared and
    /// present, and its literal has the key's kind, so an ordering reads a
    /// number.
    fn check(&self, state: &GeneratedUiStateSnapshot) -> Result<()> {
        match self {
            Self::Static(_) => Ok(()),
            Self::All(items) | Self::Any(items) => {
                items.iter().try_for_each(|item| item.check(state))
            }
            Self::Compare { key, literal, .. } => {
                let kind = PropKind::of_state(read_state(state, key)?);
                if PropKind::of_literal(literal) == Some(kind) {
                    Ok(())
                } else {
                    Err(Error::InvalidConfig(format!(
                        "generated-ui $cond compares the {} key {:?} with {literal}",
                        kind.name(),
                        key.as_str()
                    )))
                }
            }
        }
    }

    fn holds(&self, state: &GeneratedUiStateSnapshot) -> Result<bool> {
        match self {
            Self::Static(holds) => Ok(*holds),
            Self::All(items) => {
                for item in items {
                    if !item.holds(state)? {
                        return Ok(false);
                    }
                }
                Ok(true)
            }
            Self::Any(items) => {
                for item in items {
                    if item.holds(state)? {
                        return Ok(true);
                    }
                }
                Ok(false)
            }
            Self::Compare {
                key,
                comparison,
                literal,
            } => comparison.holds(read_state(state, key)?, literal),
        }
    }
}

/// A `$template`: literal text around at most one escaped read of one key.
struct Template<'a> {
    before: &'a str,
    /// The key read, and the literal text after it.
    read: Option<(SelfUiStateKey, &'a str)>,
}

impl<'a> Template<'a> {
    fn read(template: &'a Value) -> Result<Self> {
        let text = template.as_str().ok_or_else(|| {
            Error::InvalidConfig("generated-ui $template must be a string".to_string())
        })?;
        let Some((before, rest)) = text.split_once(TEMPLATE_READ_OPEN) else {
            return Ok(Self {
                before: text,
                read: None,
            });
        };
        let (pointer, after) = rest.split_once('}').ok_or_else(|| {
            Error::InvalidConfig("generated-ui $template read must close with }".to_string())
        })?;
        if after.contains(TEMPLATE_READ_OPEN) {
            return Err(Error::InvalidConfig(
                "generated-ui $template holds at most one ${/<key>} read, the single escaped interpolation point"
                    .to_string(),
            ));
        }
        let key = state_key_of_pointer(pointer)?;
        Ok(Self {
            before,
            read: Some((key, after)),
        })
    }

    /// A template reads a declared key with one text form: text, a number or a
    /// token, never a bool.
    fn check(&self, state: &GeneratedUiStateSnapshot) -> Result<()> {
        if let Some((key, _)) = &self.read
            && matches!(read_state(state, key)?, SelfUiStateValue::Bool(_))
        {
            return Err(Error::InvalidConfig(
                "generated-ui $template must not read a bool $state value".to_string(),
            ));
        }
        Ok(())
    }

    fn resolve(&self, state: &GeneratedUiStateSnapshot) -> Result<Value> {
        let mut text = self.before.to_owned();
        if let Some((key, after)) = &self.read {
            match read_state(state, key)? {
                SelfUiStateValue::Text(value) => text.push_str(value.as_str()),
                SelfUiStateValue::Token(value) => text.push_str(value.as_str()),
                SelfUiStateValue::Number(value) => text.push_str(&value.get().to_string()),
                SelfUiStateValue::Bool(_) => {
                    return Err(Error::InvalidConfig(
                        "generated-ui $template must not read a bool $state value".to_string(),
                    ));
                }
            }
            text.push_str(after);
        }
        Ok(Value::String(text))
    }
}

/// One expression object of a component's props, read from its JSON.
enum PropExpression<'a> {
    /// `{"$state": "/<key>"}`.
    State(SelfUiStateKey),
    /// `{"$computed": "<function>", "args": {"of": [...]}}`.
    Computed {
        function: GeneratedUiComputedFunction,
        of: &'a [Value],
    },
    /// `{"$cond": <predicate>, "$then": <value>, "$else": <value>}`.
    Cond {
        predicate: Predicate,
        then: &'a Value,
        otherwise: &'a Value,
    },
    /// `{"$template": "... ${/<key>} ..."}`.
    Template(Template<'a>),
}

impl<'a> PropExpression<'a> {
    /// The expression `object` holds: none when no key carries the `$` prefix,
    /// else exactly one closed form, or an error.
    fn read(object: &'a Map<String, Value>) -> Result<Option<Self>> {
        if !object.keys().any(|key| key.starts_with('$')) {
            return Ok(None);
        }
        if let Some(pointer) = object.get(STATE_EXPRESSION) {
            only_fields(object, &[STATE_EXPRESSION])?;
            return state_pointer_key(pointer).map(|key| Some(Self::State(key)));
        }
        if let Some(name) = object.get(COMPUTED_EXPRESSION) {
            only_fields(object, &[COMPUTED_EXPRESSION, COMPUTED_ARGUMENTS])?;
            let function = GeneratedUiComputedFunction::parse(name)?;
            let of = object
                .get(COMPUTED_ARGUMENTS)
                .and_then(Value::as_object)
                .filter(|arguments| arguments.len() == 1)
                .and_then(|arguments| arguments.get(COMPUTED_LIST_ARGUMENT))
                .and_then(Value::as_array)
                .map(Vec::as_slice)
                .ok_or_else(|| {
                    Error::InvalidConfig(format!(
                        "generated-ui $computed {function:?} takes exactly `args: {{\"of\": [...]}}`"
                    ))
                })?;
            return Ok(Some(Self::Computed { function, of }));
        }
        if let Some(predicate) = object.get(COND_EXPRESSION) {
            only_fields(object, &[COND_EXPRESSION, COND_THEN, COND_ELSE])?;
            let branch = |name: &str| {
                object.get(name).ok_or_else(|| {
                    Error::InvalidConfig(format!("generated-ui $cond must carry {name}"))
                })
            };
            return Ok(Some(Self::Cond {
                predicate: Predicate::read(predicate, 0)?,
                then: branch(COND_THEN)?,
                otherwise: branch(COND_ELSE)?,
            }));
        }
        if let Some(template) = object.get(TEMPLATE_EXPRESSION) {
            only_fields(object, &[TEMPLATE_EXPRESSION])?;
            return Template::read(template).map(|template| Some(Self::Template(template)));
        }
        Err(Error::InvalidConfig(format!(
            "generated-ui prop object with fields {:?} is no expression: a `$` key names $state, $computed, $cond or $template",
            object.keys().collect::<Vec<_>>()
        )))
    }

    /// The prop values nested in this expression.
    fn operands(&self) -> Vec<&'a Value> {
        match self {
            Self::State(_) | Self::Template(_) => Vec::new(),
            Self::Computed { of, .. } => of.iter().collect(),
            Self::Cond {
                then, otherwise, ..
            } => vec![*then, *otherwise],
        }
    }

    /// The plain value this expression yields under `state`.
    fn resolve(&self, state: &GeneratedUiStateSnapshot) -> Result<Value> {
        match self {
            Self::State(key) => Ok(state_value_json(read_state(state, key)?)),
            Self::Computed { function, of } => {
                let values = of
                    .iter()
                    .map(|operand| resolve_prop(operand, state))
                    .collect::<Result<Vec<_>>>()?;
                function.apply(&values)
            }
            Self::Cond {
                predicate,
                then,
                otherwise,
            } => {
                let branch = if predicate.holds(state)? {
                    then
                } else {
                    otherwise
                };
                resolve_prop(branch, state)
            }
            Self::Template(template) => template.resolve(state),
        }
    }
}

fn only_fields(object: &Map<String, Value>, fields: &[&str]) -> Result<()> {
    match object.keys().find(|key| !fields.contains(&key.as_str())) {
        Some(unknown) => Err(Error::InvalidConfig(format!(
            "generated-ui {} expression must not carry {unknown:?}",
            fields[0]
        ))),
        None => Ok(()),
    }
}

/// `"/<key>"`: a JSON pointer to one key of the flat `$state` model.
fn state_pointer_key(pointer: &Value) -> Result<SelfUiStateKey> {
    state_key_of_pointer(pointer.as_str().unwrap_or_default())
}

fn state_key_of_pointer(pointer: &str) -> Result<SelfUiStateKey> {
    let key = pointer.strip_prefix('/').ok_or_else(|| {
        Error::InvalidConfig(
            "generated-ui expressions read $state through a \"/<key>\" pointer".to_string(),
        )
    })?;
    SelfUiStateKey::new(key)
}

fn read_state<'s>(
    state: &'s GeneratedUiStateSnapshot,
    key: &SelfUiStateKey,
) -> Result<&'s SelfUiStateValue> {
    state.get(key).ok_or_else(|| {
        Error::InvalidConfig(format!(
            "generated-ui prop expression must read a declared $state key, not {:?}",
            key.as_str()
        ))
    })
}

fn state_value_json(value: &SelfUiStateValue) -> Value {
    match value {
        SelfUiStateValue::Bool(value) => Value::Bool(*value),
        SelfUiStateValue::Number(value) => {
            Number::from_f64(value.get()).map_or(Value::Null, Value::Number)
        }
        SelfUiStateValue::Text(value) => Value::String(value.as_str().to_owned()),
        SelfUiStateValue::Token(value) => Value::String(value.as_str().to_owned()),
    }
}

/// Visits every expression in `value`, outermost first, then the prop values
/// nested in it, one expression level down.
fn visit_expressions<'a>(
    value: &'a Value,
    depth: usize,
    visit: &mut dyn FnMut(&PropExpression<'a>) -> Result<()>,
) -> Result<()> {
    match value {
        Value::Array(items) => {
            for item in items {
                visit_expressions(item, depth, visit)?;
            }
        }
        Value::Object(object) => match PropExpression::read(object)? {
            Some(expression) => {
                if depth >= MAX_PROP_EXPRESSION_DEPTH {
                    return Err(Error::InvalidConfig(format!(
                        "generated-ui prop expressions nest at most {MAX_PROP_EXPRESSION_DEPTH} deep"
                    )));
                }
                visit(&expression)?;
                for operand in expression.operands() {
                    visit_expressions(operand, depth + 1, visit)?;
                }
            }
            None => {
                for field in object.values() {
                    visit_expressions(field, depth, visit)?;
                }
            }
        },
        Value::Null | Value::Bool(_) | Value::Number(_) | Value::String(_) => {}
    }
    Ok(())
}

/// The decode-time check of a component's props, with no `$state` at hand: every
/// expression has one closed form, within the nesting bound, and the props are a
/// record rather than an expression.
pub(super) fn validate_prop_expressions(props: &Value) -> Result<()> {
    if let Value::Object(object) = props
        && PropExpression::read(object)?.is_some()
    {
        return Err(Error::InvalidConfig(
            "generated-ui component props must be a record, not an expression".to_string(),
        ));
    }
    visit_expressions(props, 0, &mut |_| Ok(()))
}

/// Proves every expression in `props` against a `$state` snapshot, at card
/// assembly and after every accepted patch: each key read is declared and still
/// present, and each `$computed` argument has its function's kind.
pub(super) fn check_prop_expressions(
    props: &Value,
    state: &GeneratedUiStateSnapshot,
) -> Result<()> {
    visit_expressions(props, 0, &mut |expression| match expression {
        PropExpression::State(key) => {
            read_state(state, key)?;
            Ok(())
        }
        PropExpression::Cond { predicate, .. } => predicate.check(state),
        PropExpression::Template(template) => template.check(state),
        PropExpression::Computed { function, of } => {
            for operand in *of {
                let kind = prop_kind(operand, state)?;
                if kind != function.argument_kind() {
                    return Err(Error::InvalidConfig(format!(
                        "generated-ui $computed {function:?} takes {} values, not {}",
                        function.argument_kind().name(),
                        kind.name()
                    )));
                }
            }
            Ok(())
        }
    })
}

/// The kind of a plain value a `$computed` argument yields.
fn prop_kind(value: &Value, state: &GeneratedUiStateSnapshot) -> Result<PropKind> {
    let not_plain = || {
        Error::InvalidConfig(
            "generated-ui $computed arguments must be bools, numbers, text or expressions"
                .to_string(),
        )
    };
    let Value::Object(object) = value else {
        return PropKind::of_literal(value).ok_or_else(not_plain);
    };
    match PropExpression::read(object)?.ok_or_else(not_plain)? {
        PropExpression::State(key) => read_state(state, &key).map(PropKind::of_state),
        PropExpression::Computed { .. } => Ok(PropKind::Number),
        PropExpression::Template(_) => Ok(PropKind::Text),
        PropExpression::Cond {
            then, otherwise, ..
        } => {
            let kind = prop_kind(then, state)?;
            if prop_kind(otherwise, state)? == kind {
                Ok(kind)
            } else {
                Err(Error::InvalidConfig(
                    "generated-ui $cond branches in a $computed argument must have one kind"
                        .to_string(),
                ))
            }
        }
    }
}

/// `value` with every expression replaced by the plain value it yields.
fn resolve_prop(value: &Value, state: &GeneratedUiStateSnapshot) -> Result<Value> {
    match value {
        Value::Array(items) => items
            .iter()
            .map(|item| resolve_prop(item, state))
            .collect::<Result<Vec<_>>>()
            .map(Value::Array),
        Value::Object(object) => match PropExpression::read(object)? {
            Some(expression) => expression.resolve(state),
            None => object
                .iter()
                .map(|(name, field)| Ok((name.clone(), resolve_prop(field, state)?)))
                .collect::<Result<Map<_, _>>>()
                .map(Value::Object),
        },
        Value::Null | Value::Bool(_) | Value::Number(_) | Value::String(_) => Ok(value.clone()),
    }
}

/// The props a surface's component receives under `state`: the props as they
/// are when they hold no expression; resolved when the surface declares the
/// expression tier with every function they call; `None` when it cannot draw
/// them, so the component lowers to text.
pub(super) fn props_for_surface<'a>(
    props: &'a Value,
    expressions: Option<&GeneratedUiExpressionProfile>,
    state: &GeneratedUiStateSnapshot,
) -> Option<Cow<'a, Value>> {
    let mut holds_expressions = false;
    let resolvable = visit_expressions(props, 0, &mut |expression| {
        holds_expressions = true;
        if expressions.is_some_and(|profile| profile.resolves(expression)) {
            Ok(())
        } else {
            Err(Error::InvalidConfig(
                "generated-ui surface does not resolve this prop expression".to_string(),
            ))
        }
    });
    match (resolvable, holds_expressions) {
        (Err(_), _) => None,
        (Ok(()), false) => Some(Cow::Borrowed(props)),
        (Ok(()), true) => resolve_prop(props, state).ok().map(Cow::Owned),
    }
}
