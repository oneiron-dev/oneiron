//! Bounded Python adapter call policy. Unknown script formats are not cleared.
//!
//! This is an install rule, not a runtime sandbox. The host qualifier still
//! supplies the sandbox recipe. Strings/comments are opaque; executable tokens
//! (including aliased imports) cannot be concealed by spacing or prose.
#[derive(Debug, PartialEq, Eq)]
enum Token {
    Word(String),
    Symbol(char),
}

pub(super) fn screen_script(path: &str, source: &str) -> Option<&'static str> {
    if !path.ends_with(".py") {
        return Some("unsupported script format for sandbox screening");
    }
    let tokens = match python_tokens(source) {
        Some(tokens) => tokens,
        None => return Some("unverifiable script syntax"),
    };
    let locals: std::collections::BTreeSet<&str> = tokens
        .windows(2)
        .filter_map(|pair| {
            if pair[0] == Token::Word("def".into())
                && let Token::Word(name) = &pair[1]
            {
                return Some(name.as_str());
            }
            None
        })
        .collect();
    for (index, token) in tokens.iter().enumerate() {
        let Token::Word(word) = token else {
            continue;
        };
        let lower = word.to_ascii_lowercase();
        // Import of a host-facing module is unsafe regardless of alias, from-
        // import spelling, or whether the immediate source visibly calls it.
        if [
            "subprocess",
            "os",
            "sys",
            "socket",
            "requests",
            "httpx",
            "urllib",
            "http",
            "importlib",
            "ctypes",
            "shutil",
            "pathlib",
            "builtins",
            "asyncio",
        ]
        .contains(&lower.as_str())
        {
            return Some("call outside the sandbox");
        }
        if [
            "__import__",
            "eval",
            "exec",
            "compile",
            "getattr",
            "setattr",
            "globals",
            "locals",
            "open",
            "popen",
            "system",
        ]
        .contains(&lower.as_str())
            && tokens.get(index + 1) == Some(&Token::Symbol('('))
        {
            return Some("call outside the sandbox");
        }
        if ["fetch", "curl", "wget"].contains(&lower.as_str())
            && tokens.get(index + 1) == Some(&Token::Symbol('('))
            && (index > 0 && tokens[index - 1] == Token::Symbol('.')
                || !locals.contains(word.as_str()))
        {
            return Some("call outside the sandbox");
        }
        if lower == "import" || lower == "from" {
            if lower == "import" && index >= 2 && tokens[index - 2] == Token::Word("from".into()) {
                continue;
            }
            // Dynamic imports and bare module imports beyond the deterministic
            // safe list cannot be vouched for by this static policy.
            let next = tokens.get(index + 1);
            if !matches!(next, Some(Token::Word(_))) {
                return Some("unverifiable script import");
            }
            if let Some(Token::Word(module)) = next {
                if [
                    "subprocess",
                    "os",
                    "sys",
                    "socket",
                    "requests",
                    "httpx",
                    "urllib",
                    "http",
                    "importlib",
                    "ctypes",
                    "shutil",
                    "pathlib",
                    "builtins",
                    "asyncio",
                ]
                .contains(&module.as_str())
                {
                    return Some("call outside the sandbox");
                }
                if !["math", "json", "re", "typing", "collections", "dataclasses"]
                    .contains(&module.as_str())
                {
                    return Some("unverifiable script import");
                }
            }
        }
    }
    None
}

fn python_tokens(source: &str) -> Option<Vec<Token>> {
    let mut chars = source.chars().peekable();
    let mut tokens = Vec::new();
    while let Some(ch) = chars.next() {
        if ch == '#' {
            for c in chars.by_ref() {
                if c == '\n' {
                    break;
                }
            }
            continue;
        }
        if ch == '\'' || ch == '"' {
            // Interpolation can execute a call hidden inside an f-string, while
            // raw strings change escape/quote tokenization. Do not clear an
            // unparsed string grammar as harmless prose.
            if let Some(Token::Word(prefix)) = tokens.last()
                && ["f", "fr", "rf", "r"].contains(&prefix.to_ascii_lowercase().as_str())
            {
                return None;
            }
            let triple = chars.peek() == Some(&ch) && {
                let mut copy = chars.clone();
                copy.next();
                copy.peek() == Some(&ch)
            };
            if triple {
                chars.next();
                chars.next();
            }
            let mut closed = false;
            while let Some(c) = chars.next() {
                if c == '\\' {
                    chars.next()?;
                    continue;
                }
                if c == ch {
                    if !triple {
                        closed = true;
                        break;
                    }
                    let mut copy = chars.clone();
                    if copy.next() == Some(ch) && copy.next() == Some(ch) {
                        chars.next();
                        chars.next();
                        closed = true;
                        break;
                    }
                }
            }
            if !closed {
                return None;
            }
            continue;
        }
        if ch.is_ascii_alphabetic() || ch == '_' {
            let mut word = ch.to_string();
            while chars
                .peek()
                .is_some_and(|c| c.is_ascii_alphanumeric() || *c == '_')
            {
                word.push(chars.next()?);
            }
            tokens.push(Token::Word(word));
        } else if ch == '\\' {
            return None; // line continuations / escaped operators need a real parser
        } else if !ch.is_whitespace() && !ch.is_ascii_digit() {
            tokens.push(Token::Symbol(ch));
        }
    }
    Some(tokens)
}
