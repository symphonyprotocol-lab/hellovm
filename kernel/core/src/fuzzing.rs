//! Entry points into parsers that are private to the crate, for the
//! fuzzers in `kernel/fuzz` (feature `testutil`). Each one calls the
//! parser exactly as the kernel does, with the same preconditions.

use crate::net::Net;

/// The virtual DNS responder on one query datagram (or TCP frame body).
pub fn dns_reply(net: &mut Net, query: &[u8], outbound: bool) -> Option<Vec<u8>> {
    net.dns_reply(query, outbound)
}

/// The `#!` line parser on a file's contents. Like `execve`, it only
/// looks at files that start with `#!`. Returns the interpreter and its
/// optional argument.
pub fn shebang(file: &[u8]) -> Option<(Vec<u8>, Option<Vec<u8>>)> {
    if !file.starts_with(b"#!") {
        return None;
    }
    crate::syscall::proc::parse_shebang(file).ok()
}
