//! A machine's request code as the owner reads and types it (FIX 4956): 26
//! Crockford base32 symbols, the alphabet recovery codes and pairing codes use
//! (DEC-0005), so a code survives being read aloud or typed from a screen. One
//! codec for the joining machine that shows it and every door that takes it.
//!
//! ```text
//! text = Crockford base32 of the 16 code bytes, most significant bit first:
//!        128 bits in 26 symbols, the last symbol's two low bits zero
//! ```

use super::RequestCode;

/// Crockford base32: no `I`, `L`, `O` or `U` (CALLS "4956 RequestCode codec").
const ALPHABET: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";
/// 128 bits at 5 bits a symbol.
const SYMBOLS: usize = 26;
/// The bits the last symbol carries past the code's 128.
const TRAILING_BITS: u32 = (SYMBOLS as u32) * 5 - 128;

impl RequestCode {
    /// The code as a joining machine shows it: 26 upper-case symbols.
    #[must_use]
    pub fn to_text(&self) -> String {
        let mut text = String::with_capacity(SYMBOLS);
        let (mut acc, mut bits) = (0u16, 0u32);
        for byte in self.0 {
            acc = (acc << 8) | u16::from(byte);
            bits += 8;
            while bits >= 5 {
                bits -= 5;
                text.push(char::from(ALPHABET[usize::from((acc >> bits) & 31)]));
            }
            acc &= (1 << bits) - 1;
        }
        text.push(char::from(
            ALPHABET[usize::from((acc << TRAILING_BITS) & 31)],
        ));
        text
    }

    /// Reads a typed code back, as recovery codes read: case, `-` and
    /// whitespace are ignored, `O` reads as `0`, and `I` and `L` read as `1`.
    /// Exactly 26 symbols, the last one's two low bits zero, so each code has
    /// one text. These are the codec's bounds, nothing more.
    ///
    /// # Errors
    ///
    /// A symbol outside the alphabet, another count of symbols, or a last
    /// symbol with its trailing bits set; the text names which.
    pub fn from_text(text: &str) -> Result<Self, &'static str> {
        let mut code = [0u8; 16];
        let (mut acc, mut bits, mut symbols, mut at) = (0u16, 0u32, 0usize, 0usize);
        for c in text.chars() {
            let value = match c.to_ascii_uppercase() {
                c if c == '-' || c.is_whitespace() => continue,
                'O' => 0,
                'I' | 'L' => 1,
                c => ALPHABET
                    .iter()
                    .position(|symbol| char::from(*symbol) == c)
                    .ok_or("a request code is Crockford base32: 0-9 and A-Z but I, L, O and U")?
                    as u16,
            };
            symbols += 1;
            if symbols > SYMBOLS {
                return Err("a request code is 26 symbols");
            }
            acc = (acc << 5) | value;
            bits += 5;
            if bits >= 8 && at < code.len() {
                bits -= 8;
                code[at] = (acc >> bits) as u8;
                at += 1;
                acc &= (1 << bits) - 1;
            }
        }
        if symbols != SYMBOLS {
            return Err("a request code is 26 symbols");
        }
        if bits != TRAILING_BITS || acc != 0 {
            return Err("a request code's last symbol is not one a code ends with");
        }
        Ok(Self(code))
    }
}

impl std::fmt::Display for RequestCode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.to_text())
    }
}
