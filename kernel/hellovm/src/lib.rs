//! The library half of the `hellovm` launcher: only the test-session
//! protocol (`insecure-test-hooks`), shared by the binary and its tests.

#[cfg(feature = "insecure-test-hooks")]
pub mod session;
