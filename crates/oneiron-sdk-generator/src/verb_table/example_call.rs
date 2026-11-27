//! Whether an example calls its verb: a token-level parse of the example's JavaScript.
//!
//! The call is the verb's dotted path as `Ident . Ident ... (` in the token stream, so a mention inside a string, a
//! template, a comment or a regex literal is no call. A `/` starts a regex literal where JavaScript starts one
//! (after nothing, after an operator punctuator, or after a keyword that takes an expression); anywhere else it is
//! division.

/// A lexed token that matching or `/` disambiguation reads: an identifier, a punctuator, or anything else (a number,
/// a string, a template or a regex literal, none of which a call's segments cross).
#[derive(Debug, PartialEq, Eq)]
enum Token {
    Ident(String),
    Punct(Punct),
    Other,
}

/// A punctuator, by the shapes matching and `/` disambiguation read: the member dot, the optional chain, the call
/// paren, the three closers after which a `/` divides, and every other punctuator (`=>` among them).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Punct {
    Dot,
    QuestionDot,
    OpenParen,
    CloseParen,
    CloseBracket,
    CloseBrace,
    Other,
}

/// The previous significant token, as `/` disambiguation reads it: the start, a punctuator, an identifier's text (a
/// keyword takes an expression), or anything else.
enum Prev {
    Start,
    Punct(Punct),
    Word(String),
    Other,
}

impl Prev {
    /// The context a token leaves behind it.
    fn of(token: &Token) -> Self {
        match token {
            Token::Ident(word) => Self::Word(word.clone()),
            Token::Punct(punct) => Self::Punct(*punct),
            Token::Other => Self::Other,
        }
    }
}

/// The keywords after which a `/` starts a regex literal: each takes an expression.
const KEYWORDS: &[&str] = &[
    "return",
    "typeof",
    "instanceof",
    "in",
    "of",
    "new",
    "delete",
    "void",
    "throw",
    "case",
    "do",
    "else",
    "yield",
    "await",
];

/// Whether a `/` after `prev` starts a regex literal (anywhere else it divides).
fn regex_starts(prev: &Prev) -> bool {
    match prev {
        Prev::Start => true,
        Prev::Punct(punct) => !matches!(
            punct,
            Punct::CloseParen | Punct::CloseBracket | Punct::CloseBrace
        ),
        Prev::Word(word) => KEYWORDS.contains(&word.as_str()),
        Prev::Other => false,
    }
}

/// Whether `c` may start an identifier: an ASCII letter, `_`, `$`, or any non-ASCII character.
fn ident_start(c: char) -> bool {
    c.is_ascii_alphabetic() || c == '_' || c == '$' || !c.is_ascii()
}

/// Whether `c` may continue an identifier: a start character or an ASCII digit.
fn ident_continue(c: char) -> bool {
    ident_start(c) || c.is_ascii_digit()
}

/// The example's characters, read by byte position.
struct Lexer<'a> {
    text: &'a str,
    pos: usize,
}

impl<'a> Lexer<'a> {
    /// The rest of the example.
    fn rest(&self) -> &'a str {
        &self.text[self.pos..]
    }

    /// The next character, if any.
    fn peek(&self) -> Option<char> {
        self.rest().chars().next()
    }

    /// The character after the next, if any.
    fn peek_next(&self) -> Option<char> {
        let mut chars = self.rest().chars();
        chars.next();
        chars.next()
    }

    /// Takes the next character.
    fn take(&mut self) -> Option<char> {
        let c = self.peek()?;
        self.pos += c.len_utf8();
        Some(c)
    }

    /// Whether the rest starts with `prefix`.
    fn starts_with(&self, prefix: &str) -> bool {
        self.rest().starts_with(prefix)
    }

    /// Skips white space and comments; an unterminated block comment does not lex.
    fn trivia(&mut self) -> Result<(), String> {
        loop {
            while self.peek().is_some_and(char::is_whitespace) {
                self.take();
            }
            if self.starts_with("//") {
                while !matches!(self.peek(), None | Some('\n')) {
                    self.take();
                }
            } else if self.starts_with("/*") {
                self.pos += 2;
                loop {
                    if self.starts_with("*/") {
                        self.pos += 2;
                        break;
                    }
                    if self.take().is_none() {
                        return Err("the example holds an unterminated block comment".to_owned());
                    }
                }
            } else {
                return Ok(());
            }
        }
    }

    /// Takes an identifier's characters; the first is an identifier start.
    fn ident(&mut self) -> Token {
        let start = self.pos;
        while self.peek().is_some_and(ident_continue) {
            self.take();
        }
        Token::Ident(self.text[start..self.pos].to_owned())
    }

    /// Takes a number; the first character is an ASCII digit.
    fn number(&mut self) -> Token {
        while self
            .peek()
            .is_some_and(|c| c.is_ascii_alphanumeric() || c == '_' || c == '$')
        {
            self.take();
        }
        Token::Other
    }

    /// Takes a string literal; the next character is its quote. Backslash escapes the next character; the string
    /// ends at its quote.
    fn string(&mut self) -> Result<Token, String> {
        let quote = self.take();
        loop {
            match self.take() {
                None => return Err("the example holds an unterminated string".to_owned()),
                Some('\\') => {
                    if self.take().is_none() {
                        return Err("the example holds an unterminated string".to_owned());
                    }
                }
                Some(c) if Some(c) == quote => return Ok(Token::Other),
                Some(_) => {}
            }
        }
    }

    /// Takes a template literal as one token; the next character is its backtick. Backslash escapes the next
    /// character, and each `${` opens a substitution the lexer skips past wholly, so a call inside one is no call.
    fn template(&mut self) -> Result<Token, String> {
        self.take();
        loop {
            match self.take() {
                None => return Err("the example holds an unterminated template".to_owned()),
                Some('\\') => {
                    if self.take().is_none() {
                        return Err("the example holds an unterminated template".to_owned());
                    }
                }
                Some('`') => return Ok(Token::Other),
                Some('$') if self.peek() == Some('{') => {
                    self.take();
                    self.substitution()?;
                }
                Some(_) => {}
            }
        }
    }

    /// Skips a substitution's expression, past its closing brace; `${` is taken. Braces nest; strings, templates,
    /// comments and regex literals lex as code does, so their braces stay theirs.
    fn substitution(&mut self) -> Result<(), String> {
        let mut depth = 1;
        let mut prev = Prev::Start;
        loop {
            self.trivia()?;
            match self.peek() {
                None => return Err("the example holds an unterminated template".to_owned()),
                Some('{') => {
                    self.take();
                    depth += 1;
                    prev = Prev::Punct(Punct::Other);
                }
                Some('}') => {
                    self.take();
                    depth -= 1;
                    if depth == 0 {
                        return Ok(());
                    }
                    prev = Prev::Punct(Punct::CloseBrace);
                }
                Some(_) => {
                    let token = self.token(&prev)?;
                    prev = Prev::of(&token);
                }
            }
        }
    }

    /// Takes a regex literal; the `/` is next and opens one. Backslash escapes the next character, a `[` opens a
    /// class the closing slash stays out of, and flag letters follow the slash.
    fn regex(&mut self) -> Result<Token, String> {
        self.take();
        let mut class = false;
        loop {
            match self.take() {
                None => return Err("the example holds an unterminated regex".to_owned()),
                Some('\\') => {
                    if self.take().is_none() {
                        return Err("the example holds an unterminated regex".to_owned());
                    }
                }
                Some('[') if !class => class = true,
                Some(']') if class => class = false,
                Some('/') if !class => break,
                Some(_) => {}
            }
        }
        while self.peek().is_some_and(|c| c.is_ascii_alphabetic()) {
            self.take();
        }
        Ok(Token::Other)
    }

    /// Takes one token; white space and comments are skipped, so the next character opens one.
    fn token(&mut self, prev: &Prev) -> Result<Token, String> {
        let c = self.peek();
        if c.is_some_and(ident_start) {
            return Ok(self.ident());
        }
        if c.is_some_and(|c| c.is_ascii_digit()) {
            return Ok(self.number());
        }
        match c {
            Some('\'') | Some('"') => self.string(),
            Some('`') => self.template(),
            Some('/') => {
                if regex_starts(prev) {
                    self.regex()
                } else {
                    self.take();
                    Ok(Token::Punct(Punct::Other))
                }
            }
            Some('?') if self.peek_next() == Some('.') => {
                self.take();
                self.take();
                Ok(Token::Punct(Punct::QuestionDot))
            }
            Some('=') if self.peek_next() == Some('>') => {
                self.take();
                self.take();
                Ok(Token::Punct(Punct::Other))
            }
            Some('.') => {
                self.take();
                Ok(Token::Punct(Punct::Dot))
            }
            Some('(') => {
                self.take();
                Ok(Token::Punct(Punct::OpenParen))
            }
            Some(')') => {
                self.take();
                Ok(Token::Punct(Punct::CloseParen))
            }
            Some(']') => {
                self.take();
                Ok(Token::Punct(Punct::CloseBracket))
            }
            Some('}') => {
                self.take();
                Ok(Token::Punct(Punct::CloseBrace))
            }
            Some(_) => {
                self.take();
                Ok(Token::Punct(Punct::Other))
            }
            None => Err("the example ends mid-token".to_owned()),
        }
    }

    /// Every significant token of the example.
    fn tokens(mut self) -> Result<Vec<Token>, String> {
        let mut tokens = Vec::new();
        let mut prev = Prev::Start;
        loop {
            self.trivia()?;
            if self.peek().is_none() {
                return Ok(tokens);
            }
            let token = self.token(&prev)?;
            prev = Prev::of(&token);
            tokens.push(token);
        }
    }
}

/// Whether `token` is the identifier `segment`.
fn is_segment(token: &Token, segment: &str) -> bool {
    matches!(token, Token::Ident(word) if word == segment)
}

/// Whether the member before the first segment is no member access: the call starts the example or follows no dot.
fn starts_call(tokens: &[Token], at: usize) -> bool {
    at == 0
        || !matches!(
            tokens[at - 1],
            Token::Punct(Punct::Dot) | Token::Punct(Punct::QuestionDot)
        )
}

/// Whether the tokens at `tokens[at..]` call `segments`: each segment an identifier, joined by dots, opening a
/// paren.
fn calls_at(tokens: &[Token], at: usize, segments: &[&str]) -> bool {
    let mut pos = at;
    for (index, &segment) in segments.iter().enumerate() {
        if index > 0 {
            if tokens.get(pos) != Some(&Token::Punct(Punct::Dot)) {
                return false;
            }
            pos += 1;
        }
        if tokens
            .get(pos)
            .is_some_and(|token| is_segment(token, segment))
        {
            pos += 1;
        } else {
            return false;
        }
    }
    tokens.get(pos) == Some(&Token::Punct(Punct::OpenParen))
}

/// Whether `example` calls `path`: its tokens hold the path's segments dotted and opening a paren, and the token
/// before the first is no member access. `Err` when the example does not lex.
pub(super) fn calls_exact_path(example: &str, path: &str) -> Result<bool, String> {
    let tokens = (Lexer {
        text: example,
        pos: 0,
    })
    .tokens()?;
    let segments: Vec<&str> = path.split('.').collect();
    for (at, token) in tokens.iter().enumerate() {
        if is_segment(token, segments[0])
            && starts_call(&tokens, at)
            && calls_at(&tokens, at, &segments)
        {
            return Ok(true);
        }
    }
    Ok(false)
}
