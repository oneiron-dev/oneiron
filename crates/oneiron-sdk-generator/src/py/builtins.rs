//! Python's builtin names and keywords, embedded from the reference interpreter.
//!
//! The Python generator read these from the interpreter that ran it, so its outputs changed with the Python
//! version (3.13 added `PythonFinalizationError`; 3.15 adds `ImportCycleError`, `frozendict` and `sentinel`, and the
//! soft keyword `lazy`). The port fixes them at CPython 3.14.7 as nelly runs it, without `-S` (so `site`'s
//! `copyright`, `credits`, `exit`, `help`, `license` and `quit` are builtins). These lists are the contract: no
//! Python version is consulted.

/// `PY_BUILTINS`: the names in `dir(builtins)` that do not start with `_`, sorted. Printed on
/// nelly (Python 3.14.7) by `python3 -c "import builtins; print(sorted(n for n in dir(builtins) if not n.startswith('_')))"`.
pub(crate) const PY_BUILTINS: &[&str] = &[
    "ArithmeticError",
    "AssertionError",
    "AttributeError",
    "BaseException",
    "BaseExceptionGroup",
    "BlockingIOError",
    "BrokenPipeError",
    "BufferError",
    "BytesWarning",
    "ChildProcessError",
    "ConnectionAbortedError",
    "ConnectionError",
    "ConnectionRefusedError",
    "ConnectionResetError",
    "DeprecationWarning",
    "EOFError",
    "Ellipsis",
    "EncodingWarning",
    "EnvironmentError",
    "Exception",
    "ExceptionGroup",
    "False",
    "FileExistsError",
    "FileNotFoundError",
    "FloatingPointError",
    "FutureWarning",
    "GeneratorExit",
    "IOError",
    "ImportError",
    "ImportWarning",
    "IndentationError",
    "IndexError",
    "InterruptedError",
    "IsADirectoryError",
    "KeyError",
    "KeyboardInterrupt",
    "LookupError",
    "MemoryError",
    "ModuleNotFoundError",
    "NameError",
    "None",
    "NotADirectoryError",
    "NotImplemented",
    "NotImplementedError",
    "OSError",
    "OverflowError",
    "PendingDeprecationWarning",
    "PermissionError",
    "ProcessLookupError",
    "PythonFinalizationError",
    "RecursionError",
    "ReferenceError",
    "ResourceWarning",
    "RuntimeError",
    "RuntimeWarning",
    "StopAsyncIteration",
    "StopIteration",
    "SyntaxError",
    "SyntaxWarning",
    "SystemError",
    "SystemExit",
    "TabError",
    "TimeoutError",
    "True",
    "TypeError",
    "UnboundLocalError",
    "UnicodeDecodeError",
    "UnicodeEncodeError",
    "UnicodeError",
    "UnicodeTranslateError",
    "UnicodeWarning",
    "UserWarning",
    "ValueError",
    "Warning",
    "ZeroDivisionError",
    "abs",
    "aiter",
    "all",
    "anext",
    "any",
    "ascii",
    "bin",
    "bool",
    "breakpoint",
    "bytearray",
    "bytes",
    "callable",
    "chr",
    "classmethod",
    "compile",
    "complex",
    "copyright",
    "credits",
    "delattr",
    "dict",
    "dir",
    "divmod",
    "enumerate",
    "eval",
    "exec",
    "exit",
    "filter",
    "float",
    "format",
    "frozenset",
    "getattr",
    "globals",
    "hasattr",
    "hash",
    "help",
    "hex",
    "id",
    "input",
    "int",
    "isinstance",
    "issubclass",
    "iter",
    "len",
    "license",
    "list",
    "locals",
    "map",
    "max",
    "memoryview",
    "min",
    "next",
    "object",
    "oct",
    "open",
    "ord",
    "pow",
    "print",
    "property",
    "quit",
    "range",
    "repr",
    "reversed",
    "round",
    "set",
    "setattr",
    "slice",
    "sorted",
    "staticmethod",
    "str",
    "sum",
    "super",
    "tuple",
    "type",
    "vars",
    "zip",
];

/// `keyword.kwlist`, the hard keywords `keyword.iskeyword` tests.
/// Printed on nelly (Python 3.14.7) by `python3 -c "import keyword; print(keyword.kwlist)"`.
pub(crate) const KEYWORDS: &[&str] = &[
    "False", "None", "True", "and", "as", "assert", "async", "await", "break", "class", "continue",
    "def", "del", "elif", "else", "except", "finally", "for", "from", "global", "if", "import",
    "in", "is", "lambda", "nonlocal", "not", "or", "pass", "raise", "return", "try", "while",
    "with", "yield",
];

/// `name in PY_BUILTINS`.
pub(crate) fn is_builtin(name: &str) -> bool {
    PY_BUILTINS.binary_search(&name).is_ok()
}

/// `keyword.iskeyword(name)`: a hard keyword (`class`, `None`), never a soft one (`match`, `type`).
pub(crate) fn is_keyword(name: &str) -> bool {
    KEYWORDS.contains(&name)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lists_are_the_reference_interpreter_s() {
        assert_eq!(PY_BUILTINS.len(), 150);
        assert!(PY_BUILTINS.is_sorted());
        assert_eq!(KEYWORDS.len(), 35);
        // python3 -c "import builtins, keyword; print('MemoryError' in dir(builtins), 'help' in dir(builtins), 'frozendict' in dir(builtins), keyword.iskeyword('None'), keyword.iskeyword('match'), keyword.iskeyword('print'))"
        // prints: True True False True False False
        assert!(is_builtin("MemoryError"));
        assert!(is_builtin("help"));
        assert!(!is_builtin("frozendict"));
        assert!(!is_builtin("__import__"));
        assert!(is_keyword("None"));
        assert!(!is_keyword("match"));
        assert!(!is_keyword("print"));
    }
}
