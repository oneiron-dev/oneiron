use super::*;

/// The guest's accessible role names (AT-SPI's), as a page's rows name them.
const ROLES: &[(&str, &str)] = &[
    ("push button", "button"),
    ("toggle button", "button"),
    ("check box", "checkbox"),
    ("radio button", "radio"),
    ("combo box", "combobox"),
    ("spin button", "spinbutton"),
    ("entry", "textbox"),
    ("text", "textbox"),
    ("password text", "textbox"),
    ("editbar", "textbox"),
    ("search box", "searchbox"),
    ("menu item", "menuitem"),
    ("check menu item", "menuitemcheckbox"),
    ("radio menu item", "menuitemradio"),
    ("tear off menu item", "menuitem"),
    ("list item", "option"),
    ("list box", "listbox"),
    ("list", "listbox"),
    ("popup menu", "menu"),
    ("menu bar", "menubar"),
    ("tool bar", "toolbar"),
    ("page tab", "tab"),
    ("page tab list", "tablist"),
    ("tree item", "treeitem"),
    ("tree table", "treegrid"),
    ("table cell", "cell"),
    ("table row", "row"),
    ("status bar", "status"),
];

/// Roles a program reads but does not act on, when they carry a name.
const READS: &[&str] = &[
    "heading",
    "label",
    "static",
    "alert",
    "notification",
    "status",
    "image",
];

/// Roles whose name, when they have one, joins the ref of every row inside.
/// A window's own frame is not one: its title changes as its document does.
const SCOPES: &[&str] = &[
    "dialog",
    "alert",
    "panel",
    "filler",
    "group",
    "grouping",
    "form",
    "section",
    "listbox",
    "table",
    "tree",
    "treegrid",
    "menu",
    "menubar",
    "toolbar",
    "tablist",
    "tab",
    "scroll pane",
    "layered pane",
];

fn frame_of(element: &Value, name: &str) -> Option<Rect> {
    element
        .get(name)
        .and_then(|frame| Rect::read(frame, "w", "h"))
}

fn clip(text: &str) -> String {
    let text = text.split_whitespace().collect::<Vec<_>>().join(" ");
    match text.char_indices().nth(NAME_CHARS) {
        Some((end, _)) => format!("{}…", &text[..end]),
        None => text,
    }
}

/// An element's text field `name`, as the driver names it.
fn text_field<'e>(element: &'e Value, name: &str) -> &'e str {
    element.get(name).and_then(Value::as_str).unwrap_or("")
}

/// The secret kind of an element, as the classifier reads it: a password
/// role is the tree's concealed field; a desktop names no input type or
/// autocomplete token.
fn secret_kind(element: &Value, raw_role: &str, role: &str) -> Option<SecretKind> {
    classify(&FieldFacts {
        role,
        protected: raw_role.contains("password"),
        input_type: None,
        autocomplete: None,
        label: text_field(element, "label"),
        description: text_field(element, "description"),
        value: text_field(element, "value"),
    })
}

/// An element's role as the driver names it, and as its row names it.
fn roles_of(element: &Value) -> (String, String) {
    let raw = element
        .get("role")
        .and_then(Value::as_str)
        .unwrap_or("")
        .trim()
        .to_lowercase();
    let role = ROLES
        .iter()
        .find(|(from, _)| *from == raw)
        .map_or_else(|| raw.clone(), |(_, to)| (*to).to_owned());
    (raw, role)
}

/// Reads a window's elements (in tree order, each with its depth) into
/// rows: every element the driver can act on, and every named one a
/// program reads outside a control. Also where its secret fields are, and
/// the rows that show a secret in place. The window's secret fields are
/// classified first and held through `view`, so no row, locator or name
/// is built from a secret (FIX 8028).
pub(super) fn lines(elements: &[Value], view: &SecretView<'_>) -> (Vec<Line>, Vec<Secret>) {
    let (lines, secrets, typed) = lines_with(elements, view, Vec::new());
    if typed.is_empty() {
        return (lines, secrets);
    }
    // A secret a field holds by what was typed into it shows its handle in
    // every other row that echoes it too (FIX 8338): the rows are made
    // again with it in the echo set, before any name or locator stands.
    let (lines, secrets, _) = lines_with(elements, view, typed);
    (lines, secrets)
}

/// [`lines`], with `extra` in its echo set from the start: the rows, the
/// regions a screenshot masks, and each secret a field holds only by what
/// was typed into it that the echo set lacked.
fn lines_with(
    elements: &[Value],
    view: &SecretView<'_>,
    extra: Vec<(String, String)>,
) -> (Vec<Line>, Vec<Secret>, Vec<(String, String)>) {
    let mut taken = HashMap::new();
    // Each element's secret, as the classifier reads it, and what each
    // secret shows in its place wherever a name or value echoes it, what
    // earlier reads of the run took among them (FIX 8337).
    let mut kinds = Vec::with_capacity(elements.len());
    let mut echoes: Vec<(String, String)> = extra;
    for element in elements {
        let (raw, role) = roles_of(element);
        let kind = secret_kind(element, &raw, &role);
        if let Some(kind) = kind {
            let value = text_field(element, "value");
            if let (Some(shown), _) = view.hold(&mut taken, kind, value)
                && !masked(value)
            {
                echoes.push((value.trim().to_owned(), shown));
            }
        }
        if let Some(secrets) = view.secrets {
            for field in ["label", "value"] {
                for known in secrets.known_in(text_field(element, field)) {
                    if !echoes.iter().any(|(held, _)| *held == known.0) {
                        echoes.push(known);
                    }
                }
            }
        }
        kinds.push(kind);
    }
    let mut typed_echoes: Vec<(String, String)> = Vec::new();
    let shown: Vec<(&str, &str)> = echoes
        .iter()
        .map(|(secret, shown)| (secret.as_str(), shown.as_str()))
        .collect();
    let marks: Vec<(&str, &str)> = echoes
        .iter()
        .map(|(secret, _)| (secret.as_str(), SECRET_MARK))
        .collect();
    let mut scope: Vec<(u64, String)> = Vec::new();
    let mut controls: Vec<u64> = Vec::new();
    let mut seen: HashMap<String, u32> = HashMap::new();
    let mut out: Vec<Line> = Vec::new();
    let mut secrets = Vec::new();
    // Each emitted row whose raw subtree is still open, by its raw depth:
    // every raw node closes those at its depth or below it, emitted or not.
    let mut open: Vec<(u64, usize)> = Vec::new();
    for (element, kind) in elements.iter().zip(kinds) {
        let depth = element.get("depth").and_then(Value::as_u64).unwrap_or(0);
        while open.last().is_some_and(|(open_at, _)| *open_at >= depth) {
            if let Some((_, at)) = open.pop() {
                out[at].closed = true;
            }
        }
        while scope.last().is_some_and(|(at, _)| *at >= depth) {
            scope.pop();
        }
        while controls.last().is_some_and(|at| *at >= depth) {
            controls.pop();
        }
        let (_, role) = roles_of(element);
        let raw_label = text_field(element, "label");
        // A label that echoes a secret shows it as its handle, and its
        // locator and scope key hold `[secret]` there.
        let (label, label_key, echoed) = match secret_echo_policy(raw_label, &shown) {
            Some(shown_label) => {
                let key = secret_echo_policy(raw_label, &marks).unwrap_or_default();
                (clip(&shown_label), clip(&key), true)
            }
            None => (clip(raw_label), clip(raw_label), false),
        };
        let secret = kind.is_some();
        if secret {
            secrets.push(Secret {
                screen: frame_of(element, "frame"),
                shot: frame_of(element, "screenshot_frame"),
            });
        }
        // A secret field's own text can stand in for a missing name (the
        // driver names an unnamed field by its text): it never leaves the
        // session.
        let (name, name_key) = if secret {
            (String::new(), String::new())
        } else {
            (label, label_key)
        };
        let token = element
            .get("element_token")
            .and_then(Value::as_str)
            .map(str::to_owned);
        let read = READS.contains(&role.as_str()) && !name.is_empty() && controls.is_empty();
        if token.is_some() || read {
            let mut key = scope
                .iter()
                .map(|(_, named)| named.as_str())
                .collect::<Vec<_>>()
                .join(" > ");
            key.push_str(&format!(" > {role} \"{name_key}\""));
            // Identical twins are told apart by their order among themselves.
            let twin = seen.entry(key.clone()).or_insert(0);
            *twin += 1;
            if *twin > 1 {
                key.push_str(&format!(" ~{twin}"));
            }
            let hash = blake3::hash(key.as_bytes()).to_hex();
            // A desktop row's ref is its locator: the window has no live
            // handles.
            let locator = format!("d{}", &hash[..12]);
            // A field a type entered a secret into reads as that secret.
            let found = kind;
            let kind = kind.or_else(|| view.typed.get(&locator).copied());
            let mut states = Vec::new();
            if element.get("enabled").and_then(Value::as_bool) == Some(false) {
                states.push("disabled".to_owned());
            }
            if element.get("selected").and_then(Value::as_bool) == Some(true) {
                states.push("selected".to_owned());
            }
            if kind.is_some() {
                states.push("secret".to_owned());
            }
            let raw_value = Some(text_field(element, "value")).filter(|value| !value.is_empty());
            let (value, row_secret, value_echoed) = match kind {
                Some(kind) => {
                    let raw = text_field(element, "value");
                    let (shown, held) = view.hold(&mut taken, kind, raw);
                    let typed_only = found.is_none() && !masked(raw) && !raw.trim().is_empty();
                    if let Some(display) = shown.as_ref().filter(|_| typed_only)
                        && !echoes.iter().any(|(held, _)| held == raw.trim())
                    {
                        typed_echoes.push((raw.trim().to_owned(), display.clone()));
                    }
                    (shown, Some(held), false)
                }
                None => match raw_value.and_then(|raw| secret_echo_policy(raw, &shown)) {
                    Some(echo) => (Some(clip(&echo)), None, true),
                    None => (raw_value.map(clip), None, false),
                },
            };
            let row_masked = row_secret.is_some() || echoed || value_echoed;
            if row_masked && !secret {
                secrets.push(Secret {
                    screen: frame_of(element, "frame"),
                    shot: frame_of(element, "screenshot_frame"),
                });
            }
            out.push(Line {
                row: Row {
                    target: locator.clone(),
                    locator,
                    role: role.clone(),
                    name: name.clone(),
                    value,
                    states,
                    depth: u16::try_from(scope.len()).unwrap_or(u16::MAX),
                    href: None,
                    level: None,
                    datetimes: Vec::new(),
                    unavailable: Vec::new(),
                    secret: row_secret,
                },
                frame: frame_of(element, "frame"),
                token,
                masked: row_masked,
                original: row_masked.then(|| raw_value.map(str::to_owned)).flatten(),
                closed: false,
            });
            open.push((depth, out.len() - 1));
            if out.last().is_some_and(|line: &Line| line.token.is_some()) {
                controls.push(depth);
            }
        }
        if SCOPES.contains(&role.as_str()) && !name.is_empty() {
            scope.push((depth, format!("{role} \"{name_key}\"")));
        }
    }
    (out, secrets, typed_echoes)
}
