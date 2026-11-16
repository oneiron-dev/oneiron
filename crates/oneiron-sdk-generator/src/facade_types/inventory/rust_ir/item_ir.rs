//! The item section of the `Rust type -> IR` walk: a declared struct, enum or alias as what it writes (its `into`
//! type, else its own derive), the private wire type a conversion names, and an enum's variants by its tagging.

use std::rc::Rc;

use super::super::{Context, EnumMeta, Inventory, VariantMeta, VariantShape};
use super::{REPR, Record, Scope, VARIANT};
use crate::error::GenerateError;
use crate::facade_types::index::{Found, ItemRef, Kind, Shape};
use crate::facade_types::reader::{
    Ast, attr_args, case_or, close_of, derives, is_true, leading_attrs, parse_type, prev_char,
    rename, search_bounded, serialize_case, slice, split_top, truthy,
};
use crate::facade_types::{Field, INT, Ir, NULL, width};
use crate::py::text::strip;
use crate::py::value::{Dict, Value};

impl Inventory {
    /// What a type writes, its `into` type, else its own
    /// derive; a type that only reads takes the shape it reads `from`. A wire no caller can name is written under
    /// this type's own name (FIX 11203).
    pub(crate) fn item_ir(&mut self, item: &ItemRef, name: &str) -> Result<Ir, GenerateError> {
        self.enter()?;
        let value = self.item_ir_frame(item, name);
        self.leave();
        value
    }

    /// The body of `item_ir`, inside the frame it opens (two private conversions that name each other recurse here
    /// without end in Python, until its `RecursionError`).
    fn item_ir_frame(&mut self, item: &ItemRef, name: &str) -> Result<Ir, GenerateError> {
        let context = Context::of(item);
        let scope = Scope {
            context: &context,
            params: &item.generics,
        };
        let location = name;
        if item.kind == Kind::Type {
            return self.walk(&parse_type(&item.body)?, scope, location);
        }
        let serde = attr_args(&item.attrs, "serde")?;
        let derived = derives(&item.attrs);
        let conversions: &[&str] = if derived.contains("Serialize") {
            &["into"]
        } else {
            &["into", "try_from", "from"]
        };
        for key in conversions {
            let Some(Value::Str(target)) = serde.get(*key) else {
                continue;
            };
            let target = parse_type(target)?;
            let Some(wire) = self.private_wire(&target, item)? else {
                return self.walk(&target, scope, location);
            };
            let value = self.item_ir(&wire, name)?;
            if item.kind == Kind::Struct && !derived.contains("Debug") {
                self.redacted.insert(location.to_owned());
            }
            return Ok(value);
        }
        if !derived.contains("Serialize") && !derived.contains("Deserialize") {
            return self.manual(item, scope, location);
        }
        if derived.contains("Serialize_repr") || derived.contains("Deserialize_repr") {
            let repr = search_bounded(&REPR, &item.attrs, 0, true, true);
            return Ok(repr.map_or(INT, |found| width(&found[1])));
        }
        let case = serialize_case(serde.get("rename_all"));
        let default =
            is_true(serde.get("default")) || matches!(serde.get("default"), Some(Value::Str(_)));
        if is_true(serde.get("deny_unknown_fields")) {
            self.closed.insert(location.to_owned());
        }
        if item.kind == Kind::Struct && !derived.contains("Debug") {
            self.redacted.insert(location.to_owned());
        }
        if item.kind == Kind::Struct {
            if item.shape == Shape::Unit {
                return Ok(NULL);
            }
            if item.shape == Shape::Tuple {
                let mut values = self.tuple_fields(&item.body, scope, location)?;
                return Ok(if values.len() == 1 {
                    values.swap_remove(0)
                } else {
                    Ir::Tuple(values)
                });
            }
            if truthy(serde.get("transparent")) {
                let (mut fields, mut flat) =
                    self.fields(&item.body, None, false, scope, location)?;
                return Ok(if !fields.is_empty() {
                    fields.swap_remove(0).value
                } else if !flat.is_empty() {
                    flat.swap_remove(0)
                } else {
                    NULL
                });
            }
            let extra = match serde.get("tag") {
                Some(Value::Str(tag)) => {
                    let label = case_or(serialize_case(serde.get("rename")), || {
                        Value::Str(item.name.clone())
                    });
                    vec![Field {
                        key: Value::Str(tag.clone()),
                        value: Ir::Lit(label),
                        optional: false,
                    }]
                }
                _ => Vec::new(),
            };
            return self.object(
                &item.body,
                case.as_ref(),
                default,
                scope,
                location,
                Record { hint: None, extra },
            );
        }
        self.enum_ir(item, &serde, case.as_ref(), scope, location)
    }

    /// The type a conversion of `item` names, when it is
    /// a non-generic one of its own file that is not `pub`; else `None`.
    fn private_wire(
        &mut self,
        ast: &Ast,
        item: &ItemRef,
    ) -> Result<Option<ItemRef>, GenerateError> {
        let Ast::Path(segments, args) = ast else {
            return Ok(None);
        };
        if !args.is_empty() {
            return Ok(None);
        }
        let found = self
            .index
            .resolve(segments, &item.crate_name, &item.file, &item.module, 0)?;
        let Some(Found::Item(found)) = found else {
            return Ok(None);
        };
        if Rc::ptr_eq(&found, item)
            || found.public
            || !found.generics.is_empty()
            || found.kind == Kind::Type
        {
            return Ok(None);
        }
        if (found.crate_name.as_str(), found.file.as_str())
            != (item.crate_name.as_str(), item.file.as_str())
        {
            return Ok(None);
        }
        Ok(Some(found))
    }

    /// Every variant as its member of the union, by the enum's
    /// tagging (untagged, adjacent, internal, external), with its metadata in `variants`.
    fn enum_ir(
        &mut self,
        item: &ItemRef,
        serde: &Dict,
        case: Option<&Value>,
        scope: Scope<'_>,
        location: &str,
    ) -> Result<Ir, GenerateError> {
        let tag = match serde.get("tag") {
            Some(Value::Str(tag)) => Some(tag.clone()),
            _ => None,
        };
        let content = match serde.get("content") {
            Some(Value::Str(content)) => Some(content.clone()),
            _ => None,
        };
        let untagged = is_true(serde.get("untagged"));
        let field_case = serialize_case(serde.get("rename_all_fields"));
        let (mut members, mut variants) = (Vec::new(), Vec::new());
        for chunk in split_top(&item.body, b',') {
            let (attrs, rest) = leading_attrs(chunk);
            let Some(found) = VARIANT.captures(rest) else {
                continue;
            };
            let name = found[1].to_owned();
            let payload = strip(&found[2]).to_owned();
            let variant = attr_args(&attrs, "serde")?;
            if truthy(variant.get("skip"))
                || (truthy(variant.get("skip_serializing"))
                    && truthy(variant.get("skip_deserializing")))
            {
                continue;
            }
            let label = case_or(serialize_case(variant.get("rename")), || {
                Value::Str(rename(&name, case, true))
            });
            let inner_case = match serialize_case(variant.get("rename_all")) {
                Some(value) if value.truthy() => Some(value),
                _ => field_case.clone(),
            };
            let inner_case = inner_case.as_ref();
            let at = format!("{location}.{name}");
            let (shape, body, value) = if payload.starts_with('{') || payload.starts_with('(') {
                let body =
                    slice(&payload, 1, prev_char(&payload, close_of(&payload, 0))).to_owned();
                if payload.starts_with('{') {
                    (VariantShape::Struct, body, None)
                } else {
                    let mut values = self.tuple_fields(&body, scope, &at)?;
                    if values.len() == 1 {
                        (VariantShape::Newtype, body, Some(values.swap_remove(0)))
                    } else {
                        (VariantShape::Tuple, body, Some(Ir::Tuple(values)))
                    }
                }
            } else {
                (VariantShape::Unit, String::new(), None)
            };
            let variant_untagged = truthy(variant.get("untagged"));
            let member = if untagged || variant_untagged {
                match (shape, value) {
                    (VariantShape::Unit, _) => NULL,
                    (VariantShape::Struct, _) => self.object(
                        &body,
                        inner_case,
                        false,
                        scope,
                        &at,
                        Record::hinted(name.clone()),
                    )?,
                    (_, value) => value.unwrap_or(NULL),
                }
            } else if let (Some(tag), Some(content)) = (&tag, &content) {
                let mut fields = vec![Field::new(tag, Ir::Lit(label.clone()), false)];
                match (shape, value) {
                    (VariantShape::Struct, _) => {
                        let record = Record::hinted(format!("{name}Content"));
                        let body = self.object(&body, inner_case, false, scope, &at, record)?;
                        fields.push(Field::new(content, body, false));
                    }
                    (VariantShape::Unit, _) => {}
                    (_, value) => fields.push(Field::new(content, value.unwrap_or(NULL), false)),
                }
                Ir::Object(fields, Some(name.clone()))
            } else if let Some(tag) = &tag {
                let marker = Field::new(tag, Ir::Lit(label.clone()), false);
                match (shape, value) {
                    (VariantShape::Struct, _) => {
                        let record = Record {
                            hint: Some(name.clone()),
                            extra: vec![marker],
                        };
                        self.object(&body, inner_case, false, scope, &at, record)?
                    }
                    (VariantShape::Unit, _) => Ir::Object(vec![marker], Some(name.clone())),
                    (_, value) => Ir::And(vec![
                        value.unwrap_or(NULL),
                        Ir::Object(vec![marker], Some(name.clone())),
                    ]),
                }
            } else {
                match (shape, value) {
                    (VariantShape::Unit, _) => Ir::Lit(label.clone()),
                    (VariantShape::Struct, _) => {
                        let record = Record::hinted(format!("{name}Body"));
                        let body = self.object(&body, inner_case, false, scope, &at, record)?;
                        Ir::Object(
                            vec![Field {
                                key: label.clone(),
                                value: body,
                                optional: false,
                            }],
                            Some(name.clone()),
                        )
                    }
                    (_, value) => Ir::Object(
                        vec![Field {
                            key: label.clone(),
                            value: value.unwrap_or(NULL),
                            optional: false,
                        }],
                        Some(name.clone()),
                    ),
                }
            };
            members.push(member.clone());
            variants.push(VariantMeta {
                name,
                label,
                untagged: untagged || variant_untagged,
                other: is_true(variant.get("other")),
                shape,
                member,
            });
        }
        self.variants.insert(
            location.to_owned(),
            EnumMeta {
                tag,
                content,
                untagged,
                variants,
            },
        );
        Ok(match members.len() {
            0 => Ir::Never,
            1 => members.swap_remove(0),
            _ => Ir::Union(members),
        })
    }
}
