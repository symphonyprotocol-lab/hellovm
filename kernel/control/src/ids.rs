//! Sandbox ids and bearer tokens.

use std::fmt;

/// Fills `buf` from the host's random source.
pub fn random_bytes(buf: &mut [u8]) -> std::io::Result<()> {
    for chunk in buf.chunks_mut(256) {
        // SAFETY: getentropy writes at most `chunk.len()` (<= 256) bytes.
        if unsafe { libc::getentropy(chunk.as_mut_ptr().cast(), chunk.len()) } != 0 {
            return Err(std::io::Error::last_os_error());
        }
    }
    Ok(())
}

/// A sandbox id: `sb-` and 32 lowercase hex digits, 128 random bits, so
/// that no one can guess another tenant's. Its first 64 bits are the
/// sandbox id the kernel gives the egress proxy ([`SandboxId::egress_id`]),
/// so audit lines name the same sandbox (its first 16 hex digits).
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct SandboxId([u8; 16]);

impl SandboxId {
    pub const PREFIX: &'static str = "sb-";

    pub fn random() -> std::io::Result<SandboxId> {
        let mut bytes = [0u8; 16];
        random_bytes(&mut bytes)?;
        Ok(SandboxId(bytes))
    }

    /// Parses the text form; anything else (other case, length, prefix) is
    /// `None`.
    pub fn parse(text: &str) -> Option<SandboxId> {
        let hex = text.strip_prefix(Self::PREFIX)?;
        if hex.len() != 32
            || !hex
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            return None;
        }
        let mut bytes = [0u8; 16];
        for (i, byte) in bytes.iter_mut().enumerate() {
            *byte = u8::from_str_radix(&hex[2 * i..2 * i + 2], 16).ok()?;
        }
        Some(SandboxId(bytes))
    }

    /// The id the egress proxy sees (`hellovm --sandbox-id`).
    pub fn egress_id(&self) -> u64 {
        u64::from_be_bytes(self.0[..8].try_into().unwrap())
    }
}

impl fmt::Display for SandboxId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(Self::PREFIX)?;
        for b in self.0 {
            write!(f, "{b:02x}")?;
        }
        Ok(())
    }
}

impl fmt::Debug for SandboxId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}

/// Compares a presented token with a known one in time that does not
/// depend on where they differ.
pub fn token_eq(presented: &str, known: &str) -> bool {
    let (a, b) = (presented.as_bytes(), known.as_bytes());
    let mut diff = (a.len() ^ b.len()) as u8 | u8::from(a.len() != b.len());
    for (i, &known) in b.iter().enumerate() {
        diff |= a.get(i).copied().unwrap_or(0) ^ known;
    }
    std::hint::black_box(diff) == 0
}

/// Shortest token accepted in a configuration: 128 bits of base64 or hex
/// are at least 22 characters.
pub const MIN_TOKEN_LEN: usize = 22;

/// A new random token (64 hex digits).
pub fn random_token() -> std::io::Result<String> {
    let mut bytes = [0u8; 32];
    random_bytes(&mut bytes)?;
    Ok(bytes.iter().map(|b| format!("{b:02x}")).collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ids_round_trip_and_differ() {
        let a = SandboxId::random().unwrap();
        let b = SandboxId::random().unwrap();
        assert_ne!(a, b);
        let text = a.to_string();
        assert_eq!(text.len(), 35);
        assert_eq!(SandboxId::parse(&text), Some(a));
        assert_eq!(
            format!("{:016x}", a.egress_id()),
            text[3..19],
            "the egress id is the first 16 hex digits"
        );
        for bad in [
            "",
            "sb-",
            &text[..34],
            &format!("{text}0"),
            &text.to_uppercase(),
            &text.replace("sb-", "sx-"),
            "sb-0000000000000000000000000000000g",
            "sb-+0000000000000000000000000000000",
        ] {
            assert_eq!(SandboxId::parse(bad), None, "{bad}");
        }
    }

    #[test]
    fn tokens_compare() {
        assert!(token_eq("abc", "abc"));
        assert!(!token_eq("abd", "abc"));
        assert!(!token_eq("ab", "abc"));
        assert!(!token_eq("abcd", "abc"));
        assert!(!token_eq("", "abc"));
        assert_eq!(random_token().unwrap().len(), 64);
    }
}
