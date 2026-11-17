//! `hellovm-noded`, the node daemon: one per host. It keeps warm templates
//! alive (`hellovm --template` running the sandbox agent with a set of
//! Python modules imported), makes sandboxes by cloning them, carries
//! `exec` and file operations to the agent inside each sandbox, removes
//! sandboxes that are idle, too old or over their memory limit, and
//! reports its capacity. `hellovm-api` is its only caller (see the README,
//! "Control plane").

pub mod agent;
pub mod config;
pub mod output;
#[cfg(target_os = "linux")]
pub mod memory;
#[cfg(target_os = "linux")]
pub mod node;
#[cfg(target_os = "linux")]
pub mod server;
#[cfg(target_os = "linux")]
pub mod template;
