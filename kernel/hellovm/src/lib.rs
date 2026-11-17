//! The library half of the `hellovm` launcher: the warm-clone control
//! protocol and its client ([`warm`]), and the test-session protocol
//! (`insecure-test-hooks`), shared by the binary and its tests.

#[cfg(feature = "insecure-test-hooks")]
pub mod session;
#[cfg(target_os = "linux")]
pub mod warm;
